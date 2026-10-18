"""SecureNav-NEXUS agentic brain.

LangGraph workflow with three cooperating agents:
  * Security Audit Agent  - RAG over MITRE ATT&CK for ICS / NIST 800-82 / ISO-SAE 21434 + playbooks
  * Self-Healing Agent    - turns a triaged threat into concrete reconfiguration actions
  * Mission Planner Agent - decomposes natural language directives into Nav2 waypoints/velocity profiles
State is checkpointed in Redis (falls back to in-process memory). Works fully offline: if no LLM
endpoint is configured, deterministic rule-based reasoning is used, so safety never depends on an LLM.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Optional, TypedDict

import httpx
from langgraph.graph import END, StateGraph
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from common.logging_setup import get_logger

log = get_logger("nexus.brain")

EMBED_DIM = 256
COLLECTION = "nexus_security_kb"
KB_DIR = Path(os.environ.get("NEXUS_KB_DIR", "/opt/nexus/knowledge"))
MAX_SPEED = 1.0  # m/s hard ceiling the planner may never exceed


# ------------------------------------------------------------------ embeddings + vector store
def embed(text: str) -> list[float]:
    """Deterministic hashed bag-of-words embedding (no model download needed on the edge)."""
    vec = [0.0] * EMBED_DIM
    for tok in re.findall(r"[a-z0-9_/]+", text.lower()):
        h = int(hashlib.blake2b(tok.encode(), digest_size=8).hexdigest(), 16)
        vec[h % EMBED_DIM] += 1.0 if (h >> 63) & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


class KnowledgeBase:
    """Qdrant-backed knowledge store with in-memory fallback if the server is unreachable."""

    def __init__(self, url: Optional[str]) -> None:
        self.client = self._connect(url)
        self._ensure_collection()
        self.ingest(KB_DIR)

    @staticmethod
    def _connect(url: Optional[str]) -> QdrantClient:
        if url:
            try:
                client = QdrantClient(url=url, timeout=5)
                client.get_collections()
                return client
            except Exception as exc:  # noqa: BLE001
                log.warning("qdrant unreachable, using in-memory store", extra={"fields": {"error": str(exc)}})
        return QdrantClient(":memory:")

    def _ensure_collection(self) -> None:
        names = {c.name for c in self.client.get_collections().collections}
        if COLLECTION not in names:
            self.client.create_collection(
                COLLECTION, vectors_config=qm.VectorParams(size=EMBED_DIM, distance=qm.Distance.COSINE))

    def ingest(self, directory: Path) -> int:
        points: list[qm.PointStruct] = []
        for path in sorted(directory.glob("*.md")) if directory.exists() else []:
            chunks = [c.strip() for c in re.split(r"\n(?=##? )", path.read_text(encoding="utf-8")) if c.strip()]
            for i, chunk in enumerate(chunks):
                pid = int(hashlib.blake2b(f"{path.name}:{i}".encode(), digest_size=7).hexdigest(), 16)
                points.append(qm.PointStruct(id=pid, vector=embed(chunk), payload={"source": path.name, "text": chunk}))
        if points:
            self.client.upsert(COLLECTION, points=points)
        log.info("knowledge ingested", extra={"fields": {"chunks": len(points)}})
        return len(points)

    def query(self, text: str, k: int = 3) -> list[dict[str, Any]]:
        hits = self.client.search(COLLECTION, query_vector=embed(text), limit=k)
        return [{"source": h.payload["source"], "text": h.payload["text"], "score": float(h.score)} for h in hits]


# ------------------------------------------------------------------ optional LLM
def llm_complete(prompt: str) -> Optional[str]:
    """Call an OpenAI-compatible local endpoint if configured; return None otherwise."""
    endpoint = os.environ.get("LLM_ENDPOINT")
    if not endpoint:
        return None
    try:
        r = httpx.post(f"{endpoint.rstrip('/')}/v1/chat/completions", timeout=15, json={
            "model": os.environ.get("LLM_MODEL", "llama3"), "temperature": 0.1,
            "messages": [{"role": "system", "content": "You are a robotics cybersecurity analyst. Answer in JSON only."},
                         {"role": "user", "content": prompt}]})
        r.raise_for_status()
        return str(r.json()["choices"][0]["message"]["content"])
    except Exception as exc:  # noqa: BLE001
        log.warning("llm call failed, using rule-based reasoning", extra={"fields": {"error": str(exc)}})
        return None


# ------------------------------------------------------------------ graph state
class BrainState(TypedDict, total=False):
    event: dict[str, Any]          # incoming alert/directive
    kind: str                      # "alert" | "directive"
    context: list[dict[str, Any]]  # retrieved knowledge
    triage: dict[str, Any]         # classification
    actions: list[dict[str, Any]]  # self-healing actions
    mission: dict[str, Any]        # planned waypoints
    log: list[str]


RULES: list[tuple[str, str, str, str]] = [
    # (keyword in event type, technique, playbook, severity)
    ("cmd_vel", "T0855", "PB-01", "critical"),
    ("unauthorized_publisher", "T0855", "PB-01", "critical"),
    ("spoof", "T0856", "PB-02", "high"),
    ("visual_spoofing", "T0856", "PB-02", "high"),
    ("sensor_desync", "T0856", "PB-02", "high"),
    ("flood", "T0814", "PB-03", "high"),
    ("dos", "T0814", "PB-03", "high"),
    ("gps", "T0856", "PB-04", "medium"),
    ("unknown_participant", "T0886", "PB-05", "high"),
    ("anomaly", "T0856", "PB-02", "medium"),
]


def classify(event: dict[str, Any]) -> dict[str, Any]:
    blob = json.dumps(event).lower()
    for kw, tech, pb, sev in RULES:
        if kw in blob:
            return {"technique": tech, "playbook": pb, "severity": sev, "matched": kw}
    return {"technique": "unknown", "playbook": "PB-05", "severity": "low", "matched": ""}


# ------------------------------------------------------------------ agents (graph nodes)
def make_graph(kb: KnowledgeBase) -> Any:
    def route(state: BrainState) -> str:
        return "security_audit" if state["kind"] == "alert" else "mission_planner"

    def security_audit(state: BrainState) -> BrainState:
        event = state["event"]
        query = f"{event.get('type', '')} {event.get('reason', '')} {event.get('detail', '')}"
        ctx = kb.query(query, k=3)
        triage = classify(event)
        raw = llm_complete(f"Event: {json.dumps(event)}\nContext: {json.dumps(ctx)}\n"
                           'Return {"severity":"low|medium|high|critical","technique":"T####","rationale":"..."}')
        if raw:
            try:
                llm = json.loads(re.search(r"\{.*\}", raw, re.S).group(0))  # type: ignore[union-attr]
                # LLM may only ESCALATE severity, never downgrade a rule-based critical.
                order = ["low", "medium", "high", "critical"]
                if order.index(llm.get("severity", "low")) > order.index(triage["severity"]):
                    triage["severity"] = llm["severity"]
                triage["rationale"] = llm.get("rationale", "")
            except Exception:  # noqa: BLE001
                log.warning("unparseable llm triage ignored")
        return {"context": ctx, "triage": triage, "log": state.get("log", []) + [f"audit:{triage}"]}

    def self_healing(state: BrainState) -> BrainState:
        tri, ev = state["triage"], state["event"]
        actions: list[dict[str, Any]] = []
        pb = tri["playbook"]
        if pb == "PB-01":
            actions += [{"op": "e_stop", "value": True},
                        {"op": "revoke_cert", "node": ev.get("node", ev.get("detail", "unknown"))},
                        {"op": "set_speed_limit", "value": 0.0}]
        elif pb == "PB-02":
            actions += [{"op": "fusion_weights", "camera": 0.1, "lidar": 0.7, "odom": 0.2},
                        {"op": "set_speed_limit", "value": 0.3}]
        elif pb == "PB-03":
            actions += [{"op": "isolate_node", "node": ev.get("node", "unknown")},
                        {"op": "set_speed_limit", "value": 0.4}, {"op": "profile", "value": "degraded_safe"}]
        elif pb == "PB-04":
            actions += [{"op": "localization", "value": "lidar_odom"}, {"op": "set_speed_limit", "value": 0.5}]
        else:
            actions += [{"op": "revoke_cert", "node": ev.get("node", "unknown")}, {"op": "set_speed_limit", "value": 0.3}]
        if tri["severity"] in ("high", "critical"):
            actions.append({"op": "request_operator_ack", "reason": tri["technique"]})
        return {"actions": actions, "log": state.get("log", []) + [f"heal:{len(actions)} actions"]}

    def mission_planner(state: BrainState) -> BrainState:
        directive = str(state["event"].get("text", ""))
        return {"mission": plan_mission(directive), "log": state.get("log", []) + ["plan:ok"]}

    g = StateGraph(BrainState)
    g.add_node("security_audit", security_audit)
    g.add_node("self_healing", self_healing)
    g.add_node("mission_planner", mission_planner)
    g.set_conditional_entry_point(route, {"security_audit": "security_audit", "mission_planner": "mission_planner"})
    g.add_edge("security_audit", "self_healing")
    g.add_edge("self_healing", END)
    g.add_edge("mission_planner", END)
    return g.compile()


# ------------------------------------------------------------------ mission planning
_DIRS = {"north": (0, 1), "south": (0, -1), "east": (1, 0), "west": (-1, 0), "forward": (1, 0), "back": (-1, 0)}


def plan_mission(directive: str, speed_cap: float = MAX_SPEED) -> dict[str, Any]:
    """Parse e.g. 'go to (5,3) then patrol north 10 m at 0.6 m/s' into Nav2-style waypoints."""
    text = directive.lower()
    speed = min(float(m.group(1)) if (m := re.search(r"(\d+(?:\.\d+)?)\s*m/s", text)) else 0.5, speed_cap)
    waypoints: list[dict[str, float]] = []
    x = y = 0.0
    for step in re.split(r"\bthen\b|;|\band\b", text):
        coord = re.search(r"\(?\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\)?", step)
        if coord:
            x, y = float(coord.group(1)), float(coord.group(2))
            waypoints.append({"x": x, "y": y, "yaw": 0.0, "speed": speed})
            continue
        for word, (dx, dy) in _DIRS.items():
            if word in step:
                dist = float(m.group(1)) if (m := re.search(r"(\d+(?:\.\d+)?)\s*m\b(?!/)", step)) else 5.0
                x, y = x + dx * dist, y + dy * dist
                waypoints.append({"x": x, "y": y, "yaw": math.atan2(dy, dx), "speed": speed})
                break
    if not waypoints:
        return {"ok": False, "error": "no actionable waypoints parsed", "waypoints": []}
    return {"ok": True, "waypoints": waypoints, "speed": speed, "frame": "map"}


# ------------------------------------------------------------------ state store
class StateStore:
    def __init__(self, url: Optional[str]) -> None:
        self._mem: dict[str, str] = {}
        self.redis: Any = None
        if url:
            try:
                import redis

                self.redis = redis.Redis.from_url(url, socket_timeout=2)
                self.redis.ping()
            except Exception as exc:  # noqa: BLE001
                log.warning("redis unavailable, in-memory state", extra={"fields": {"error": str(exc)}})
                self.redis = None

    def put(self, key: str, value: dict[str, Any]) -> None:
        data = json.dumps(value)
        (self.redis.set(key, data, ex=86400) if self.redis else self._mem.__setitem__(key, data))

    def get(self, key: str) -> Optional[dict[str, Any]]:
        raw = self.redis.get(key) if self.redis else self._mem.get(key)
        return json.loads(raw) if raw else None


# ------------------------------------------------------------------ ROS 2 bridge
def spin_ros() -> None:
    import rclpy
    from rclpy.node import Node
    from std_msgs.msg import String

    kb = KnowledgeBase(os.environ.get("QDRANT_URL"))
    graph = make_graph(kb)
    store = StateStore(os.environ.get("REDIS_URL"))
    lock = threading.Lock()

    class BrainNode(Node):
        def __init__(self) -> None:
            super().__init__("agentic_brain")
            self.actions_pub = self.create_publisher(String, "/agent/actions", 10)
            self.wp_pub = self.create_publisher(String, "/mission/waypoints", 10)
            self.status_pub = self.create_publisher(String, "/mission/status", 10)
            self.create_subscription(String, "/security/alerts", lambda m: self.handle("alert", m), 10)
            self.create_subscription(String, "/perception/anomaly", lambda m: self.handle("alert", m), 10)
            self.create_subscription(String, "/mission/directive", lambda m: self.handle("directive", m), 10)
            self.get_logger().info("agentic brain online")

        def handle(self, kind: str, msg: String) -> None:
            try:
                event = json.loads(msg.data)
            except json.JSONDecodeError:
                event = {"text": msg.data, "type": "raw"}
            with lock:
                out = graph.invoke({"event": event, "kind": kind, "log": []})
            ts = time.time()
            store.put(f"nexus:last:{kind}", {"ts": ts, "event": event, "result": out})
            if out.get("actions"):
                self.actions_pub.publish(String(data=json.dumps({"ts": ts, "triage": out["triage"], "actions": out["actions"]})))
            if out.get("mission"):
                self.wp_pub.publish(String(data=json.dumps(out["mission"])))
            self.status_pub.publish(String(data=json.dumps({"ts": ts, "kind": kind, "log": out.get("log", [])})))

    rclpy.init()
    node = BrainNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    spin_ros()
