"""SecureNav-NEXUS observability hub: FastAPI + WebSockets.

  /ws/ingest?token=...   robot-side producers (IDS guardian) push telemetry/threat JSON; receive overrides back
  /ws/clients?token=...  browser dashboards receive the live fan-out
  POST /api/override     human-in-the-loop e-stop engage/release (Bearer token), relayed to the robot
  GET  /api/state        last snapshot + recent threats;  GET /health
Auth: shared bearer token from DASHBOARD_TOKEN_FILE (or DASHBOARD_TOKEN). Binds to localhost in compose.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Optional

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from common.audit_ledger import AuditLedger, load_or_create_key, verify_file
from common.metrics import REGISTRY
from assistant.groq_assistant import NexusAssistant, load_key, search_kb_local

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("nexus.dashboard")

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="SecureNav-NEXUS Dashboard", version="1.0")


def _token() -> str:
    if os.environ.get("DASHBOARD_TOKEN"):
        return os.environ["DASHBOARD_TOKEN"]
    f = os.environ.get("DASHBOARD_TOKEN_FILE")
    if f and Path(f).exists():
        return Path(f).read_text().strip()
    return ""


def _authorized(candidate: Optional[str]) -> bool:
    tok = _token()
    if not tok:  # refuse to run open: unauthenticated mode only when explicitly enabled for local dev
        return os.environ.get("DASHBOARD_ALLOW_ANON") == "1"
    return bool(candidate) and hmac.compare_digest(candidate or "", tok)


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.ingest: set[WebSocket] = set()
        self.threats: Deque[dict[str, Any]] = deque(maxlen=200)
        self.latency: Deque[dict[str, float]] = deque(maxlen=300)
        self.last: dict[str, Any] = {}
        self.lock = asyncio.Lock()

    async def broadcast(self, payload: dict[str, Any]) -> None:
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(payload)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    async def handle(self, msg: dict[str, Any]) -> None:
        kind = msg.get("kind")
        if kind == "threat":
            self.threats.appendleft(msg)
            ledger.append({"event": "threat", **{k: msg.get(k) for k in ("type", "severity", "reasons", "score", "node")}})
            REGISTRY.inc("nexus_threats_total", labels={"severity": str(msg.get("severity", "unknown"))}, help_="Threats detected by the IDS")
        elif kind == "telemetry":
            self.last = msg
            REGISTRY.set("nexus_anomaly_score", float(msg.get("score", 0)), help_="Latest IDS anomaly score")
            REGISTRY.set("nexus_estop_engaged", 1.0 if msg.get("estop") else 0.0, help_="1 when the e-stop is engaged")
            feats = msg.get("features", {})
            self.latency.append({"ts": msg.get("ts", time.time()), "score": float(msg.get("score", 0)),
                                 "cmd_vel_rate": float(feats.get("/cmd_vel_rate", 0)), "cpu": float(feats.get("cpu", 0))})
        await self.broadcast(msg)


hub = Hub()
_LEDGER_DIR = Path(os.environ.get("LEDGER_DIR", "/tmp/nexus-ledger"))
ledger = AuditLedger(_LEDGER_DIR / "ledger.jsonl", load_or_create_key(_LEDGER_DIR / "ledger.key"))


class Override(BaseModel):
    estop: bool
    reason: str = "operator"


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "clients": len(hub.clients), "producers": len(hub.ingest)}


@app.get("/metrics")
async def metrics(authorization: Optional[str] = Header(default=None)) -> Any:
    """Prometheus scrape endpoint (bearer token)."""
    from fastapi.responses import PlainTextResponse

    if not _authorized((authorization or "").removeprefix("Bearer ")):
        raise HTTPException(401, "unauthorized")
    REGISTRY.set("nexus_dashboard_clients", float(len(hub.clients)), help_="Connected dashboard clients")
    REGISTRY.set("nexus_robot_producers", float(len(hub.ingest)), help_="Connected robot producers")
    return PlainTextResponse(REGISTRY.render(), media_type="text/plain; version=0.0.4")


@app.get("/api/ledger")
async def ledger_view(n: int = 20, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Tail of the signed audit ledger plus a full-chain verification result."""
    if not _authorized((authorization or "").removeprefix("Bearer ")):
        raise HTTPException(401, "unauthorized")
    ok, bad, root = verify_file(ledger.path, ledger.public_key) if ledger.path.exists() else (True, None, "")
    return {"entries": ledger.tail(max(1, min(n, 200))), "verified": ok, "first_bad_seq": bad, "merkle_root": root,
            "public_key": __import__("base64").b64encode(ledger.public_key).decode()}


@app.get("/api/state")
async def state(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not _authorized((authorization or "").removeprefix("Bearer ")):
        raise HTTPException(401, "unauthorized")
    return {"last": hub.last, "threats": list(hub.threats)[:50], "series": list(hub.latency)}


@app.post("/api/override")
async def override(body: Override, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not _authorized((authorization or "").removeprefix("Bearer ")):
        raise HTTPException(401, "unauthorized")
    if not hub.ingest:
        raise HTTPException(503, "no robot connected")
    cmd = {"kind": "override", "estop": body.estop, "reason": body.reason, "ts": time.time()}
    for ws in list(hub.ingest):
        await ws.send_json(cmd)
    await hub.broadcast({"kind": "threat", "type": "operator_override", "severity": "info", "reasons": [body.reason], "ts": cmd["ts"]})
    ledger.append({"event": "operator_override", "estop": body.estop, "reason": body.reason})
    log.warning("operator override estop=%s", body.estop)
    return {"ok": True, "sent_to": len(hub.ingest)}


class AssistantRequest(BaseModel):
    message: str
    history: list[dict[str, str]] = []


@app.post("/api/assistant")
async def assistant(body: AssistantRequest, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """NEXUS-AI copilot (Groq tool-calling; offline fallback). Operator-token protected."""
    if not _authorized((authorization or "").removeprefix("Bearer ")):
        raise HTTPException(401, "unauthorized")

    async def get_robot_state() -> dict[str, Any]:
        last = hub.last or {}
        return {"score": last.get("score"), "estop": last.get("estop"), "ready": last.get("ready"),
                "features": last.get("features", {}), "producers": len(hub.ingest)}

    async def recent_threats(limit: int = 5) -> list[dict[str, Any]]:
        return list(hub.threats)[: max(1, min(int(limit), 20))]

    async def search_kb(query: str) -> list[dict[str, str]]:
        return search_kb_local(query)

    async def engage_estop(reason: str) -> dict[str, Any]:
        for ws in list(hub.ingest):
            await ws.send_json({"kind": "override", "estop": True, "reason": f"assistant: {reason}", "ts": time.time()})
        return {"ok": bool(hub.ingest), "note": "release requires a human operator"}

    ai = NexusAssistant(load_key())
    return await ai.chat(body.message[:2000], body.history[-10:], {
        "get_robot_state": get_robot_state, "recent_threats": recent_threats,
        "search_kb": search_kb, "engage_estop": engage_estop})


@app.websocket("/ws/ingest")
async def ws_ingest(ws: WebSocket, token: str = Query(default="")) -> None:
    if not _authorized(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    hub.ingest.add(ws)
    log.info("producer connected")
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict):
                await hub.handle(msg)
    except WebSocketDisconnect:
        pass
    finally:
        hub.ingest.discard(ws)


@app.websocket("/ws/clients")
async def ws_clients(ws: WebSocket, token: str = Query(default="")) -> None:
    if not _authorized(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    hub.clients.add(ws)
    await ws.send_json({"kind": "snapshot", "last": hub.last, "threats": list(hub.threats)[:50], "series": list(hub.latency)})
    try:
        while True:
            await ws.receive_text()  # keepalive; clients send nothing meaningful
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


if STATIC.exists():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
