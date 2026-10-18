import base64
import numpy as np
import pytest

from agents.agentic_brain import classify, embed, plan_mission
from security.hsm_emulator import HsmClient, Vault, serve
from security.security_ids_node import FEATURE_NAMES, AnomalyEngine, Responder, TopicStats, Detection


def test_plan_mission_waypoints_and_speed_cap():
    m = plan_mission("go to (5,3) then patrol north 10 m at 9 m/s")
    assert m["ok"] and m["speed"] == 1.0
    assert m["waypoints"][0]["x"] == 5 and m["waypoints"][-1]["y"] == 13


def test_plan_mission_rejects_garbage():
    assert plan_mission("hello there")["ok"] is False


@pytest.mark.parametrize("ev,pb", [({"type": "unauthorized_publisher"}, "PB-01"), ({"reason": "visual_spoofing"}, "PB-02"),
                                   ({"type": "dos flood"}, "PB-03")])
def test_classify(ev, pb):
    assert classify(ev)["playbook"] == pb


def test_embed_is_normalized_and_deterministic():
    a, b = embed("cmd_vel flood"), embed("cmd_vel flood")
    assert a == b and abs(sum(x * x for x in a) - 1) < 1e-6


def _baseline(rng):
    m = np.array([10, .01, 20, .005, 30, .01, 15, .01, 20, 40, 5, 0, 0, 0, 0], float)
    sd = np.array([.5, .001, .5, .001, .5, .001, .5, .001, 2, 2, 1, .001, 0, 0, 0])
    return lambda: m + rng.normal(0, 1, 15) * sd


def test_anomaly_engine_flags_flood_and_rogue():
    rng = np.random.default_rng(0)
    base = _baseline(rng)
    e = AnomalyEngine(warmup=60, use_autoencoder=False)
    for _ in range(60):
        e.observe(base())
    assert e.ready
    assert not e.evaluate(base(), ["controller_server"], False, 10).anomalous
    v = base(); v[FEATURE_NAMES.index("/cmd_vel_rate")] = 500
    assert e.evaluate(v, ["controller_server"], False, 500).anomalous
    d = e.evaluate(base(), ["controller_server", "evil"], False, 10)
    assert d.severity == "critical" and d.rogue_nodes == ["evil"]
    assert e.evaluate(base(), [], True, 5).severity == "critical"


def test_responder_estops_before_alert_and_respects_cooldown():
    order = []
    r = Responder(lambda b: order.append("estop"), lambda ev: order.append("alert"), lambda n, why: order.append("revoke"))
    det = Detection(True, 1.0, ["unauthorized_publisher:/cmd_vel:evil"], "critical", ["evil"])
    r.respond(det); r.respond(det)
    assert order == ["estop", "revoke", "alert"]


def test_topic_stats_rate():
    s = TopicStats()
    for i in range(10):
        s.tick("/x", 100 + i * 0.1)
    rate, jitter = s.window("/x", 1.0, now=101.0)
    assert rate == 10 and jitter < 1e-6


def test_hsm_sign_verify_revoke_persist(tmp_path):
    v = Vault(tmp_path / "v", b"pin")
    serve(str(tmp_path / "s"), v)
    c = HsmClient(str(tmp_path / "s"))
    data = base64.b64encode(b"msg").decode()
    sig = c.call({"op": "sign", "data": data})["sig"]
    assert c.call({"op": "verify", "data": data, "sig": sig})["valid"]
    bad = base64.b64encode(b"tampered").decode()
    assert not c.call({"op": "verify", "data": bad, "sig": sig})["valid"]
    c.revoke("rogue", "test")
    assert "rogue" in Vault(tmp_path / "v", b"pin").revoked
    with pytest.raises(Exception):
        Vault(tmp_path / "v", b"wrong-pin")


def test_dashboard_auth(monkeypatch):
    monkeypatch.setenv("DASHBOARD_TOKEN", "secret")
    from fastapi.testclient import TestClient
    from dashboard.dashboard_backend import app

    c = TestClient(app)
    assert c.get("/health").json()["ok"]
    assert c.get("/api/state").status_code == 401
    assert c.get("/api/state", headers={"Authorization": "Bearer secret"}).status_code == 200
    assert c.post("/api/override", json={"estop": True}, headers={"Authorization": "Bearer secret"}).status_code == 503


def test_assistant_offline_tools():
    import asyncio
    from assistant.groq_assistant import NexusAssistant

    async def st(): return {"score": 0.1, "estop": False, "ready": True}
    async def th(limit=5): return [{"severity": "high", "reasons": ["flood"]}]
    async def kb(query): return [{"text": "PB-03 isolate"}]
    called = []
    async def es(reason): called.append(reason); return {"ok": True}
    tools = {"get_robot_state": st, "recent_threats": th, "search_kb": kb, "engage_estop": es}
    ai = NexusAssistant(None)
    assert asyncio.run(ai.chat("status", [], tools))["mode"] == "offline"
    assert "flood" in asyncio.run(ai.chat("any threats", [], tools))["reply"]
    asyncio.run(ai.chat("emergency stop", [], tools))
    assert called
    assert "release" not in " ".join(t["function"]["name"] for t in __import__("assistant.groq_assistant", fromlist=["TOOLS"]).TOOLS)
