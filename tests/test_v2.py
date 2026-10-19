"""SecureNav-NEXUS v2 tests: policy, ledger, fusion, fleet, supply chain, metrics, CLI, dashboard integration."""
import asyncio
import itertools
import json
import random
import tempfile
from pathlib import Path

import numpy as np

from common.audit_ledger import AuditLedger, load_or_create_key, verify_file
from common.metrics import Registry
from common.mission_parser import plan_mission
from common.policy_engine import default_policy, load_policy, point_in_polygon, validate_mission
from fleet.fleet_manager import FleetManager, Robot, Task, hungarian, make_verifier
from fusion.ekf_fusion import FusionEngine
from security.hsm_emulator import Vault
from supply_chain.model_signer import sign_dir, verify_dir


def _tmp() -> Path:
    return Path(tempfile.mkdtemp())


def test_point_in_polygon():
    sq = [(0, 0), (4, 0), (4, 4), (0, 4)]
    assert point_in_polygon((2, 2), sq) and point_in_polygon((4, 2), sq) and not point_in_polygon((5, 2), sq)


def test_policy_geofence_nogo_and_speed():
    p = default_policy()
    assert validate_mission(p, [{"x": 25, "y": 4}], 0.9).ok
    assert "outside_geofence:wp0:(40.0,3.0)" in validate_mission(p, [{"x": 40, "y": 3}], 1.0).violations
    v = validate_mission(p, [{"x": 10, "y": 10}, {"x": 14, "y": 16}], 0.5, start=(3, 9))
    assert not v.ok and any(x.startswith("enters_nogo") for x in v.violations)
    assert validate_mission(p, [{"x": 4, "y": 3}], 1.0).speed == 0.5  # pedestrian lane
    assert validate_mission(p, [{"x": 5, "y": 5}], 9.0).speed <= 1.0


def test_policy_loads_from_dict():
    pol = load_policy({"zones": [{"name": "a", "polygon": [[0, 0], [5, 0], [5, 5], [0, 5]], "kind": "geofence"}], "max_speed": 0.4})
    assert not validate_mission(pol, [{"x": 9, "y": 9}], 1.0).ok and validate_mission(pol, [{"x": 1, "y": 1}], 1.0).speed == 0.4


def test_mission_parser_still_correct():
    m = plan_mission("go to (5,3) then patrol north 10 m at 9 m/s")
    assert m["ok"] and m["speed"] == 1.0 and m["waypoints"][-1]["y"] == 13
    assert plan_mission("hello")["ok"] is False


def test_ledger_detects_tamper_delete_and_resumes():
    d = _tmp()
    key = load_or_create_key(d / "k")
    led = AuditLedger(d / "l.jsonl", key)
    for i in range(5):
        led.append({"i": i})
    ok, bad, root = verify_file(d / "l.jsonl", led.public_key)
    assert ok and bad is None and len(root) == 64
    lines = (d / "l.jsonl").read_text().splitlines()
    (d / "t.jsonl").write_text("\n".join(lines[:2] + [lines[2].replace('"i": 2', '"i": 9')] + lines[3:]) + "\n")
    assert verify_file(d / "t.jsonl", led.public_key)[:2] == (False, 3)
    (d / "u.jsonl").write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert verify_file(d / "u.jsonl", led.public_key)[0] is False
    AuditLedger(d / "l.jsonl", key).append({"more": 1})
    assert verify_file(d / "l.jsonl", led.public_key)[0] is True
    other = load_or_create_key(d / "k2")
    assert verify_file(d / "l.jsonl", AuditLedger(d / "x.jsonl", other).public_key)[0] is False


def test_ekf_rejects_gps_spoof_and_stays_accurate():
    rng = np.random.default_rng(1)
    eng, tx, errs, rep = FusionEngine(), 0.0, [], None
    for k in range(200):
        tx += 0.1
        fixes = {"gps": (tx + rng.normal(0, .4), rng.normal(0, .4)), "lidar_odom": (tx + rng.normal(0, .25), rng.normal(0, .25))}
        if k >= 100:
            fixes["gps"] = (tx + 60, -30.0)
        rep = eng.step(0.1, 1.0, 0.0, fixes)
        errs.append(float(np.hypot(rep.state[0] - tx, rep.state[1])))
    assert rep is not None and "gps" in rep.spoofed and "lidar_odom" not in rep.spoofed
    assert float(np.mean(errs[110:])) < 0.6
    w = eng.weights()
    assert w["gps"] < w["lidar_odom"]


def test_hungarian_is_optimal():
    random.seed(3)
    for _ in range(30):
        n = random.randint(1, 5)
        m = random.randint(n, 6)
        c = [[random.random() * 10 for _ in range(m)] for _ in range(n)]
        got = sum(c[r][cc] for r, cc in hungarian(c))
        best = min(sum(c[i][p[i]] for i in range(n)) for p in itertools.permutations(range(m), n))
        assert abs(got - best) < 1e-9


def test_fleet_allocation_and_signed_revocation_gossip():
    d = _tmp()
    vault = Vault(d / "v", b"pin")
    rec = vault.revoke("bot2", "rogue publisher")
    fm = FleetManager(make_verifier(vault.ed_pub_bytes()))
    for i, pos in enumerate([(0, 0), (10, 0), (20, 0)]):
        fm.register(Robot(f"bot{i + 1}", pos))
    assert fm.merge_crl({"bot2": rec}) == ["bot2"] and fm.robots["bot2"].status == "quarantined"
    assert fm.merge_crl({"bot2": rec}) == []  # idempotent
    forged = dict(rec, reason="tampered")
    assert FleetManager(make_verifier(vault.ed_pub_bytes())).merge_crl({"bot2": forged}) == []
    assert fm.allocate([Task("t1", (19, 1)), Task("t2", (1, 1))]) == {"bot3": "t1", "bot1": "t2"}
    fm.heartbeat("bot1", (0, 0), 1.0, now=0)
    assert "bot1" in fm.reap(now=100)
    assert fm.register(Robot("bot2")) is False  # revoked identity cannot rejoin


def test_model_supply_chain():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    d = _tmp()
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    (d / "nexus.pt").write_bytes(b"weights")
    sign_dir(d, key)
    assert verify_dir(d, pub) == (True, "ok")
    (d / "nexus.pt").write_bytes(b"poisoned")
    assert verify_dir(d, pub)[0] is False
    assert verify_dir(d, Ed25519PrivateKey.generate().public_key().public_bytes_raw())[0] is False


def test_metrics_render():
    r = Registry()
    r.inc("nexus_threats_total", labels={"severity": "high"}, help_="Threats")
    r.set("nexus_anomaly_score", 0.4)
    r.observe("nexus_latency_seconds", 0.07)
    text = r.render()
    assert 'nexus_threats_total{severity="high"} 1' in text and "# TYPE nexus_latency_seconds histogram" in text
    assert 'nexus_latency_seconds_bucket{le="+Inf"} 1' in text


def test_nexusctl_plan_and_verify(capsys=None):
    import nexusctl
    d = _tmp()
    assert nexusctl.main(["keygen", "--out", str(d / "keys")]) == 0
    assert nexusctl.main(["plan", "go to (25,4) then north 6 m"]) == 0
    assert nexusctl.main(["plan", "go to (4,3) then (14,16)"]) == 3  # crosses the charging-bay no-go zone
    (d / "m").mkdir()
    (d / "m" / "nexus.pt").write_bytes(b"w")
    assert nexusctl.main(["sign-model", str(d / "m"), "--key", str(d / "keys" / "ed25519.key")]) == 0
    assert nexusctl.main(["verify-model", str(d / "m"), "--pub", str(d / "keys" / "ed25519.pub")]) == 0
    (d / "m" / "nexus.pt").write_bytes(b"x")
    assert nexusctl.main(["verify-model", str(d / "m"), "--pub", str(d / "keys" / "ed25519.pub")]) == 2


def test_brain_rejects_policy_violating_mission():
    from agents.agentic_brain import plan_and_validate
    ok = plan_and_validate("go to (25,4) then north 6 m")
    assert ok["ok"] and ok["policy"]["approved"]
    bad = plan_and_validate("go to (4,3) then (14,16)")
    assert bad["ok"] is False and "policy" in bad["error"]


def test_dashboard_ledger_and_metrics(monkeypatch=None):
    import os
    os.environ["DASHBOARD_TOKEN"] = "secret"
    from fastapi.testclient import TestClient
    from dashboard.dashboard_backend import app, hub
    asyncio.run(hub.handle({"kind": "threat", "type": "flood", "severity": "high", "reasons": ["flood:/cmd_vel"], "score": 0.9}))
    c = TestClient(app)
    h = {"Authorization": "Bearer secret"}
    assert c.get("/metrics").status_code == 401
    assert 'nexus_threats_total{severity="high"}' in c.get("/metrics", headers=h).text
    j = c.get("/api/ledger", headers=h).json()
    assert j["verified"] is True and j["entries"] and j["entries"][-1]["data"]["event"] == "threat"
