"""Trust-weighted EKF sensor fusion with innovation (Mahalanobis) gating for spoof/GPS-denial defense.

State x = [px, py, heading, speed]. Prediction uses wheel odometry (v, omega); position fixes from GPS,
LiDAR odometry and vision odometry are fused. Each fix is gated by chi-square (2 DoF, 99%) on the innovation:
inconsistent measurements are rejected, the source's trust decays, and a source rejected repeatedly is flagged as
spoofed so the self-healing agent can drop its fusion weight (playbooks PB-02 / PB-04).
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

CHI2_2DOF_99 = 9.21
DEFAULT_SIGMA = {"gps": 0.5, "lidar_odom": 0.3, "vision": 0.8}


@dataclass
class SourceState:
    trust: float = 1.0
    consecutive_rejects: int = 0
    accepted: int = 0
    rejected: int = 0
    last_d2: float = 0.0


@dataclass
class FusionReport:
    state: tuple[float, float, float, float]
    sources: dict[str, SourceState]
    spoofed: list[str] = field(default_factory=list)


class FusionEngine:
    def __init__(self, x0: tuple[float, float] = (0.0, 0.0), heading: float = 0.0, reject_limit: int = 3,
                 sigmas: Optional[dict[str, float]] = None) -> None:
        self.x = np.array([x0[0], x0[1], heading, 0.0], dtype=float)
        self.P = np.diag([1.0, 1.0, 0.1, 0.1])
        self.Q = np.diag([0.02, 0.02, 0.005, 0.05])
        self.sigmas = dict(DEFAULT_SIGMA, **(sigmas or {}))
        self.sources: dict[str, SourceState] = {k: SourceState() for k in self.sigmas}
        self.reject_limit = reject_limit

    def predict(self, dt: float, v: float, omega: float) -> None:
        px, py, th, _ = self.x
        self.x = np.array([px + v * math.cos(th) * dt, py + v * math.sin(th) * dt, th + omega * dt, v])
        F = np.array([[1, 0, -v * math.sin(th) * dt, math.cos(th) * dt],
                      [0, 1, v * math.cos(th) * dt, math.sin(th) * dt],
                      [0, 0, 1, 0], [0, 0, 0, 0]], dtype=float)
        self.P = F @ self.P @ F.T + self.Q * max(dt, 1e-3)

    def update(self, source: str, z: tuple[float, float]) -> bool:
        """Fuse a position fix. Returns True if accepted, False if gated out."""
        st = self.sources.setdefault(source, SourceState())
        sigma = self.sigmas.get(source, 1.0) / max(st.trust, 0.05)  # low trust => larger noise
        R = np.eye(2) * sigma ** 2
        H = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=float)
        innov = np.array(z, dtype=float) - H @ self.x
        S = H @ self.P @ H.T + R
        d2 = float(innov @ np.linalg.inv(S) @ innov)
        st.last_d2 = d2
        if d2 > CHI2_2DOF_99:
            st.rejected += 1
            st.consecutive_rejects += 1
            st.trust = max(0.05, st.trust * 0.7)
            return False
        K = self.P @ H.T @ np.linalg.inv(S)
        self.x = self.x + K @ innov
        self.P = (np.eye(4) - K @ H) @ self.P
        st.accepted += 1
        st.consecutive_rejects = 0
        st.trust = min(1.0, st.trust + 0.02)
        return True

    def step(self, dt: float, v: float, omega: float, fixes: dict[str, tuple[float, float]]) -> FusionReport:
        self.predict(dt, v, omega)
        for name, z in fixes.items():
            self.update(name, z)
        spoofed = [n for n, s in self.sources.items() if s.consecutive_rejects >= self.reject_limit]
        return FusionReport(tuple(float(a) for a in self.x), self.sources, spoofed)  # type: ignore[arg-type]

    def weights(self) -> dict[str, float]:
        """Normalized fusion weights published to /fusion/weights for the navigation stack."""
        tot = sum(s.trust for s in self.sources.values()) or 1.0
        return {n: round(s.trust / tot, 3) for n, s in self.sources.items()}


def spin_ros() -> None:  # pragma: no cover - needs ROS 2
    import time

    import rclpy
    from nav_msgs.msg import Odometry
    from rclpy.node import Node
    from std_msgs.msg import String

    class FusionNode(Node):
        def __init__(self) -> None:
            super().__init__("ekf_fusion")
            self.eng, self.t, self.fixes = FusionEngine(), time.time(), {}
            self.pub = self.create_publisher(String, "/fusion/weights", 10)
            self.create_subscription(Odometry, "/odom", self.on_odom, 10)
            self.create_subscription(String, "/fusion/fixes", self.on_fix, 10)  # JSON {"gps":[x,y],...}

        def on_fix(self, m: String) -> None:
            self.fixes = {k: tuple(v) for k, v in json.loads(m.data).items()}

        def on_odom(self, m: Odometry) -> None:
            now = time.time()
            rep = self.eng.step(now - self.t, m.twist.twist.linear.x, m.twist.twist.angular.z, self.fixes)
            self.t, self.fixes = now, {}
            self.pub.publish(String(data=json.dumps({"weights": self.eng.weights(), "spoofed": rep.spoofed, "state": rep.state})))

    rclpy.init()
    node = FusionNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":  # pragma: no cover
    os.environ.setdefault("NEXUS_SERVICE", "ekf_fusion")
    spin_ros()
