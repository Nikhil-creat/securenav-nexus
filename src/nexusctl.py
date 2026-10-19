"""nexusctl - operator CLI for SecureNav-NEXUS v2.

  python -m nexusctl keygen --out keys/
  python -m nexusctl sign-model models/ --key keys/ed25519.key
  python -m nexusctl verify-model models/ --pub keys/ed25519.pub
  python -m nexusctl ledger-verify /data/ledger.jsonl --pub keys/ledger.pub
  python -m nexusctl plan "go to (25,4) then north 6 m" [--policy policy.json]
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from common.audit_ledger import load_or_create_key, public_bytes, verify_file
from common.mission_parser import plan_mission
from common.policy_engine import load_policy, validate_mission
from supply_chain.model_signer import sign_dir, verify_dir


def _pub(path: str) -> bytes:
    return base64.b64decode(Path(path).read_text().strip())


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="nexusctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    s = sub.add_parser("sign-model")
    s.add_argument("dir")
    s.add_argument("--key", required=True)
    v = sub.add_parser("verify-model")
    v.add_argument("dir")
    v.add_argument("--pub", required=True)
    lv = sub.add_parser("ledger-verify")
    lv.add_argument("path")
    lv.add_argument("--pub", required=True)
    p = sub.add_parser("plan")
    p.add_argument("directive")
    p.add_argument("--policy")
    p.add_argument("--start", default="3,9")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        out = Path(a.out)
        key = load_or_create_key(out / "ed25519.key")
        (out / "ed25519.pub").write_text(base64.b64encode(public_bytes(key)).decode())
        print(f"wrote {out}/ed25519.key (keep secret) and {out}/ed25519.pub")
        return 0
    if a.cmd == "sign-model":
        m = sign_dir(Path(a.dir), load_or_create_key(Path(a.key)))
        print(f"signed {len(m)} artifacts")
        return 0
    if a.cmd == "verify-model":
        ok, why = verify_dir(Path(a.dir), _pub(a.pub))
        print("OK" if ok else f"FAIL: {why}")
        return 0 if ok else 2
    if a.cmd == "ledger-verify":
        ok, bad, root = verify_file(Path(a.path), _pub(a.pub))
        print(f"ledger OK, merkle root {root}" if ok else f"ledger TAMPERED at seq {bad}")
        return 0 if ok else 2
    if a.cmd == "plan":
        sx, sy = (float(x) for x in a.start.split(","))
        mission = plan_mission(a.directive, start=(sx, sy))
        if not mission["ok"]:
            print(json.dumps(mission))
            return 1
        verdict = validate_mission(load_policy(a.policy), mission["waypoints"], mission["speed"], start=(sx, sy))
        print(json.dumps({"mission": mission, "approved": verdict.ok, "violations": verdict.violations, "speed": verdict.speed}, indent=2))
        return 0 if verdict.ok else 3
    return 1


if __name__ == "__main__":
    sys.exit(main())
