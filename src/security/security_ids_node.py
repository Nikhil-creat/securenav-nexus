"""SecureNav-NEXUS ML intrusion detection + eBPF guardian.

Pipeline:  ROS 2 topic stats + host metrics  ->  1 Hz feature vector  ->  baseline learning
           -> Isolation Forest (+ optional PyTorch autoencoder) ensemble  ->  rule engine
           -> fail-safe response: /sys/e_stop, HSM certificate revocation, /security/alerts, dashboard.

Features (per window): rate+jitter of /cmd_vel,/odom,/scan,/camera/color/image_raw; cpu%, mem%, gpu%,
rx drop ratio, count of unexpected subscribers, count of non-allowlisted /cmd_vel publishers,
eBPF suspicious-event count.  Hard rules fire immediately and are independent of the ML model.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Optional

import numpy as np
import psutil
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from common.logging_setup import get_logger

log = get_logger("nexus.ids")

WATCHED_TOPICS = ("/cmd_vel", "/odom", "/scan", "/camera/color/image_raw")
CMD_VEL_ALLOWLIST = {"nav2_controller", "controller_server", "velocity_smoother", "agentic_brain", "behavior_server"}
SUBSCRIBER_ALLOWLIST = {"vision_perception", "agentic_brain", "sec_ids_guardian", "controller_server", "bt_navigator",
                        "local_costmap", "global_costmap", "planner_server", "velocity_smoother", "behavior_server",
                        "amcl", "dashboard_bridge", "hsm_emulator"}
Z_LIMIT = 8.0  # standardized deviation that is anomalous regardless of the learned models
FEATURE_NAMES = [f"{t}_{s}" for t in WATCHED_TOPICS for s in ("rate", "jitter")] + [
    "cpu", "mem", "gpu", "drop_ratio", "unexpected_subs", "rogue_cmd_pubs", "ebpf_suspicious"]


# ------------------------------------------------------------------ feature extraction
class TopicStats:
    """Thread-safe arrival-time tracker producing per-window rate and jitter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._times: dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=2000))

    def tick(self, topic: str, t: Optional[float] = None) -> None:
        with self._lock:
            self._times[topic].append(t if t is not None else time.monotonic())

    def window(self, topic: str, span: float = 1.0, now: Optional[float] = None) -> tuple[float, float]:
        now = now if now is not None else time.monotonic()
        with self._lock:
            ts = [t for t in self._times[topic] if now - t <= span]
        if len(ts) < 2:
            return float(len(ts)) / span, 0.0
        gaps = np.diff(ts)
        return len(ts) / span, float(np.std(gaps))


def gpu_util() -> float:
    """GPU utilization via nvidia-smi / tegrastats-free fallback (0 if unavailable)."""
    try:
        import subprocess

        out = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=1, check=True).stdout.strip().splitlines()
        return float(out[0])
    except Exception:  # noqa: BLE001
        return 0.0


class NetDrops:
    """Tracks rx dropped/total packet ratio between samples."""

    def __init__(self) -> None:
        self.prev = psutil.net_io_counters()

    def ratio(self) -> float:
        cur = psutil.net_io_counters()
        d_drop = (cur.dropin - self.prev.dropin) + (cur.errin - self.prev.errin)
        d_pk = max(cur.packets_recv - self.prev.packets_recv, 1)
        self.prev = cur
        return d_drop / d_pk


# ------------------------------------------------------------------ eBPF auditor
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct ev_t { u32 pid; u32 uid; char comm[16]; u8 kind; };
BPF_PERF_OUTPUT(events);
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct ev_t e = {}; e.pid = bpf_get_current_pid_tgid() >> 32; e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm)); e.kind = 1; events.perf_submit(args, &e, sizeof(e)); return 0; }
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    struct ev_t e = {}; e.pid = bpf_get_current_pid_tgid() >> 32; e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm)); e.kind = 2; events.perf_submit(ctx, &e, sizeof(e)); return 0; }
"""
EXEC_ALLOW = {"python3", "bash", "sh", "ros2", "nvidia-smi", "cat", "ps", "ls", "uname", "sleep"}
CONNECT_ALLOW = {"python3", "uvicorn", "redis-server", "qdrant", "ros2", "controller_serve"}


class EbpfAuditor:
    """Kernel-level exec/connect auditing via BCC; no-ops (and says so) when BCC/privileges are absent."""

    def __init__(self) -> None:
        self.suspicious: Deque[dict[str, Any]] = deque(maxlen=256)
        self.enabled = False
        self._count_window = 0
        self._lock = threading.Lock()
        try:
            from bcc import BPF  # type: ignore[import-not-found]

            self.bpf = BPF(text=BPF_PROGRAM)
            self.bpf["events"].open_perf_buffer(self._on_event)
            self.enabled = True
            threading.Thread(target=self._poll, daemon=True).start()
            log.info("ebpf auditor attached")
        except Exception as exc:  # noqa: BLE001
            log.warning("ebpf unavailable - running without kernel audit", extra={"fields": {"error": str(exc)}})

    def _poll(self) -> None:
        while True:
            try:
                self.bpf.perf_buffer_poll(timeout=500)
            except Exception:  # noqa: BLE001
                time.sleep(1)

    def _on_event(self, cpu: int, data: Any, size: int) -> None:
        ev = self.bpf["events"].event(data)
        comm = ev.comm.decode(errors="replace")
        allow = EXEC_ALLOW if ev.kind == 1 else CONNECT_ALLOW
        if comm not in allow:
            with self._lock:
                self._count_window += 1
                self.suspicious.append({"pid": ev.pid, "uid": ev.uid, "comm": comm,
                                        "kind": "execve" if ev.kind == 1 else "connect", "ts": time.time()})

    def drain_count(self) -> int:
        with self._lock:
            n, self._count_window = self._count_window, 0
        return n

    def inject(self, comm: str, kind: str = "execve") -> None:
        """Test hook used by the fault-injection harness."""
        with self._lock:
            self._count_window += 1
            self.suspicious.append({"pid": -1, "uid": -1, "comm": comm, "kind": kind, "ts": time.time()})


# ------------------------------------------------------------------ anomaly engine
class Autoencoder:
    """Small PyTorch autoencoder; optional (disabled if torch missing)."""

    def __init__(self, dim: int) -> None:
        self.ok = False
        try:
            import torch
            import torch.nn as nn

            self.torch = torch
            self.net = nn.Sequential(nn.Linear(dim, 12), nn.ReLU(), nn.Linear(12, 4), nn.ReLU(),
                                     nn.Linear(4, 12), nn.ReLU(), nn.Linear(12, dim))
            self.thresh = 1.0
            self.ok = True
        except Exception:  # noqa: BLE001
            self.net = None

    def fit(self, x: np.ndarray, epochs: int = 200) -> None:
        if not self.ok:
            return
        t = self.torch.tensor(x, dtype=self.torch.float32)
        opt = self.torch.optim.Adam(self.net.parameters(), lr=1e-2)
        for _ in range(epochs):
            opt.zero_grad()
            loss = ((self.net(t) - t) ** 2).mean()
            loss.backward()
            opt.step()
        with self.torch.no_grad():
            err = ((self.net(t) - t) ** 2).mean(dim=1).numpy()
        self.thresh = float(np.percentile(err, 99) * 2.0 + 1e-6)

    def score(self, x: np.ndarray) -> float:
        """Reconstruction error divided by threshold (>1 means anomalous)."""
        if not self.ok:
            return 0.0
        with self.torch.no_grad():
            t = self.torch.tensor(x.reshape(1, -1), dtype=self.torch.float32)
            return float(((self.net(t) - t) ** 2).mean()) / self.thresh


@dataclass
class Detection:
    anomalous: bool
    score: float
    reasons: list[str] = field(default_factory=list)
    severity: str = "none"
    rogue_nodes: list[str] = field(default_factory=list)


class AnomalyEngine:
    def __init__(self, warmup: int = 60, contamination: float = 0.01, use_autoencoder: bool = True) -> None:
        self.warmup, self.buf = warmup, []
        self.scaler = StandardScaler()
        self.forest = IsolationForest(n_estimators=150, contamination=contamination, random_state=7)
        self.ae = Autoencoder(len(FEATURE_NAMES)) if use_autoencoder else Autoencoder(0)
        if not use_autoencoder:
            self.ae.ok = False
        self.ready = False

    def observe(self, vec: np.ndarray) -> None:
        """Feed clean baseline data until ready."""
        if self.ready:
            return
        self.buf.append(vec)
        if len(self.buf) >= self.warmup:
            x = self.scaler.fit_transform(np.vstack(self.buf))
            self.forest.fit(x)
            self.ae.fit(x)
            self.ready = True
            log.info("baseline trained", extra={"fields": {"samples": len(self.buf)}})

    def evaluate(self, vec: np.ndarray, cmd_pubs: list[str], estop_active: bool, cmd_rate: float) -> Detection:
        reasons: list[str] = []
        rogue = sorted(set(cmd_pubs) - CMD_VEL_ALLOWLIST)
        severity = "none"
        # Hard rules: independent of ML, always on.
        if rogue:
            reasons.append(f"unauthorized_publisher:/cmd_vel:{','.join(rogue)}")
            severity = "critical"
        if estop_active and cmd_rate > 0:
            reasons.append("cmd_vel_override_during_estop")
            severity = "critical"
        names = FEATURE_NAMES
        if vec[names.index("unexpected_subs")] > 0:
            reasons.append("unknown_participant:unexpected_subscription")
            severity = "high" if severity != "critical" else severity
        if vec[names.index("ebpf_suspicious")] > 0:
            reasons.append("ebpf:suspicious_syscall_activity")
            severity = "high" if severity != "critical" else severity
        score = 0.0
        if self.ready:
            x = self.scaler.transform(vec.reshape(1, -1))
            if_score = float(-self.forest.score_samples(x)[0])  # higher == more anomalous
            ae_score = self.ae.score(x[0])
            zmax = float(np.max(np.abs(x[0])))  # Isolation Forest under-scores far out-of-range values
            score = max(if_score, 0.5 * ae_score, zmax / 20.0)
            if self.forest.predict(x)[0] == -1 or ae_score > 1.0 or zmax > Z_LIMIT:
                top = int(np.argmax(np.abs(x[0])))
                reasons.append(f"ml_anomaly:{names[top]}")
                if severity == "none":
                    severity = "high" if (ae_score > 3.0 or if_score > 0.7 or zmax > 2 * Z_LIMIT) else "medium"
                if vec[names.index("/cmd_vel_rate")] > 5 * max(self.scaler.mean_[names.index("/cmd_vel_rate")], 1.0):
                    reasons.append("flood:/cmd_vel")
                    severity = "high" if severity != "critical" else severity
        return Detection(bool(reasons), score, reasons, severity, rogue)


# ------------------------------------------------------------------ response orchestration
class Responder:
    def __init__(self, estop: Callable[[bool], None], alert: Callable[[dict[str, Any]], None],
                 revoke: Callable[[str, str], None], cooldown: float = 5.0) -> None:
        self.estop, self.alert, self.revoke, self.cooldown = estop, alert, revoke, cooldown
        self.last: dict[str, float] = {}

    def respond(self, det: Detection) -> None:
        if not det.anomalous:
            return
        key = "|".join(det.reasons)
        now = time.time()
        if now - self.last.get(key, 0) < self.cooldown:
            return
        self.last[key] = now
        event = {"ts": now, "type": det.reasons[0].split(":")[0], "reasons": det.reasons, "severity": det.severity,
                 "score": round(det.score, 4), "node": ",".join(det.rogue_nodes) or None}
        if det.severity == "critical":
            self.estop(True)  # fail-safe FIRST, analysis later
            for n in det.rogue_nodes:
                try:
                    self.revoke(n, det.reasons[0])
                except Exception as exc:  # noqa: BLE001 - revocation failure must not block e-stop
                    log.error("revocation failed", extra={"fields": {"node": n, "error": str(exc)}})
        self.alert(event)
        log.warning("threat detected", extra={"fields": event})


# ------------------------------------------------------------------ ROS 2 node
def main() -> None:
    import rclpy
    from rclpy.node import Node
    from rclpy.qos import qos_profile_sensor_data
    from std_msgs.msg import Bool, String

    from security.hsm_emulator import HsmClient

    class IdsNode(Node):
        def __init__(self) -> None:
            super().__init__("sec_ids_guardian")
            self.stats, self.net = TopicStats(), NetDrops()
            self.engine = AnomalyEngine(warmup=int(os.environ.get("IDS_WARMUP", "60")))
            self.ebpf = EbpfAuditor()
            self.hsm = HsmClient(os.environ.get("HSM_SOCKET", "/run/nexus/hsm.sock"))
            self.estop_active = False
            self.estop_pub = self.create_publisher(Bool, "/sys/e_stop", 10)
            self.alert_pub = self.create_publisher(String, "/security/alerts", 10)
            self.dash_buf: Deque[str] = deque(maxlen=500)
            self.responder = Responder(self._estop, self._alert, self._revoke)
            self._subscribe_generic()
            self.create_subscription(Bool, "/sys/e_stop", self._on_estop, 10)
            self.create_timer(1.0, self.tick)
            threading.Thread(target=self._dash_loop, daemon=True).start()
            self.get_logger().info("IDS guardian online (learning baseline)")

        def _subscribe_generic(self) -> None:
            from rclpy.serialization import deserialize_message  # noqa: F401

            for topic in WATCHED_TOPICS:
                self.create_subscription(self._msg_type(topic), topic,
                                         lambda _m, t=topic: self.stats.tick(t), qos_profile_sensor_data)

        @staticmethod
        def _msg_type(topic: str) -> Any:
            from geometry_msgs.msg import Twist
            from nav_msgs.msg import Odometry
            from sensor_msgs.msg import Image, LaserScan

            return {"/cmd_vel": Twist, "/odom": Odometry, "/scan": LaserScan, "/camera/color/image_raw": Image}[topic]

        def _on_estop(self, msg: Bool) -> None:
            self.estop_active = bool(msg.data)

        def _estop(self, engage: bool) -> None:
            self.estop_active = engage
            self.estop_pub.publish(Bool(data=engage))

        def _alert(self, event: dict[str, Any]) -> None:
            self.alert_pub.publish(String(data=json.dumps(event)))
            self.dash_buf.append(json.dumps({"kind": "threat", **event}))

        def _revoke(self, node: str, reason: str) -> None:
            self.hsm.revoke(node, reason)

        def _graph_features(self) -> tuple[int, list[str]]:
            unexpected = 0
            for topic in ("/camera/color/image_raw", "/scan", "/odom"):
                for info in self.get_subscriptions_info_by_topic(topic):
                    if info.node_name not in SUBSCRIBER_ALLOWLIST:
                        unexpected += 1
            pubs = [i.node_name for i in self.get_publishers_info_by_topic("/cmd_vel")]
            return unexpected, pubs

        def tick(self) -> None:
            try:
                row: list[float] = []
                for t in WATCHED_TOPICS:
                    rate, jit = self.stats.window(t)
                    row += [rate, jit]
                unexpected, cmd_pubs = self._graph_features()
                vec = np.array(row + [psutil.cpu_percent(), psutil.virtual_memory().percent, gpu_util(),
                                      self.net.ratio(), unexpected, len(set(cmd_pubs) - CMD_VEL_ALLOWLIST),
                                      self.ebpf.drain_count()], dtype=np.float64)
                clean = not (vec[-1] or vec[-2] or vec[-3])
                if not self.engine.ready and clean:
                    self.engine.observe(vec)
                det = self.engine.evaluate(vec, cmd_pubs, self.estop_active, row[0])
                self.responder.respond(det)
                self.dash_buf.append(json.dumps({"kind": "telemetry", "ts": time.time(), "ready": self.engine.ready,
                                                 "score": det.score, "features": dict(zip(FEATURE_NAMES, map(float, vec))),
                                                 "estop": self.estop_active}))
            except Exception as exc:  # noqa: BLE001
                self.get_logger().error(f"ids tick failed: {exc}")

        def _dash_loop(self) -> None:
            """Forward telemetry to the dashboard hub over WebSocket with reconnect."""
            import asyncio

            import websockets  # type: ignore[import-not-found]

            async def run() -> None:
                url = os.environ.get("DASHBOARD_URL", "ws://dashboard:8080/ws/ingest")
                token = ""
                try:
                    token = open(os.environ.get("DASHBOARD_TOKEN_FILE", "/run/secrets/dashboard_token")).read().strip()
                except OSError:
                    pass
                while True:
                    try:
                        async with websockets.connect(f"{url}?token={token}") as ws:
                            while True:
                                while self.dash_buf:
                                    await ws.send(self.dash_buf.popleft())
                                try:  # operator override from the dashboard (human-in-the-loop)
                                    cmd = json.loads(await asyncio.wait_for(ws.recv(), timeout=0.25))
                                    if cmd.get("kind") == "override":
                                        self._estop(bool(cmd.get("estop")))
                                except asyncio.TimeoutError:
                                    pass
                    except Exception:  # noqa: BLE001
                        await asyncio.sleep(2)

            asyncio.run(run())

    rclpy.init()
    node = IdsNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
