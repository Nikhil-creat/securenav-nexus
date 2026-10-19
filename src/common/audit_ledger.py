"""Tamper-evident audit ledger: append-only JSONL, SHA-256 hash chain, Ed25519 signature per entry.

Every security-relevant event (threats, overrides, revocations, mission approvals) is chained to the previous
entry's hash and signed. Editing, deleting, reordering or truncating-then-appending is detectable by `verify_file`.
A Merkle root over all entry hashes gives a compact checkpoint that can be anchored externally.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 key (raw 32 bytes, base64) or create one with 0600 permissions."""
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(raw).decode())
    return key


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _entry_hash(seq: int, ts: float, prev: str, data: Any) -> str:
    return hashlib.sha256(canonical({"seq": seq, "ts": ts, "prev": prev, "data": data})).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return GENESIS
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


class AuditLedger:
    def __init__(self, path: Path, key: Ed25519PrivateKey) -> None:
        self.path, self.key = Path(path), key
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.last_hash = 0, GENESIS
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    e = json.loads(line)
                    self.seq, self.last_hash = e["seq"], e["hash"]

    @property
    def public_key(self) -> bytes:
        return public_bytes(self.key)

    def append(self, data: dict[str, Any], ts: Optional[float] = None) -> dict[str, Any]:
        with self._lock:
            seq, ts = self.seq + 1, round(ts if ts is not None else time.time(), 6)
            h = _entry_hash(seq, ts, self.last_hash, data)
            entry = {"seq": seq, "ts": ts, "prev": self.last_hash, "data": data, "hash": h,
                     "sig": base64.b64encode(self.key.sign(bytes.fromhex(h))).decode()}
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.seq, self.last_hash = seq, h
            return entry

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return [json.loads(ln) for ln in lines[-n:]]


def verify_file(path: Path, public_key: bytes) -> tuple[bool, Optional[int], str]:
    """Verify chain linkage, hashes and signatures. Returns (ok, first_bad_seq, merkle_root)."""
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    prev, expect, hashes = GENESIS, 1, []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            ok = (e["seq"] == expect and e["prev"] == prev and e["hash"] == _entry_hash(e["seq"], e["ts"], e["prev"], e["data"]))
            if ok:
                pub.verify(base64.b64decode(e["sig"]), bytes.fromhex(e["hash"]))
        except (InvalidSignature, KeyError, ValueError, json.JSONDecodeError):
            return False, expect, merkle_root(hashes)
        if not ok:
            return False, expect, merkle_root(hashes)
        prev, expect = e["hash"], expect + 1
        hashes.append(e["hash"])
    return True, None, merkle_root(hashes)
