"""ML model supply-chain integrity: SHA-256 manifest + Ed25519 signature for model artifacts.

The vision node refuses to load unsigned or modified models when NEXUS_REQUIRE_SIGNED=1, closing the
"poisoned weights / swapped engine" attack path (MITRE ATLAS AML.T0010-class supply-chain risks).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ARTIFACT_EXT = (".pt", ".onnx", ".engine", ".json_meta")
MANIFEST, SIG = "manifest.json", "manifest.sig"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(model_dir: Path) -> dict[str, str]:
    return {p.name: _sha256(p) for p in sorted(Path(model_dir).iterdir()) if p.is_file() and p.suffix in ARTIFACT_EXT}


def sign_dir(model_dir: Path, key: Ed25519PrivateKey) -> dict[str, str]:
    d = Path(model_dir)
    manifest = build_manifest(d)
    blob = json.dumps(manifest, sort_keys=True).encode()
    (d / MANIFEST).write_bytes(blob)
    (d / SIG).write_text(base64.b64encode(key.sign(blob)).decode())
    return manifest


def verify_dir(model_dir: Path, public_key: bytes) -> tuple[bool, str]:
    d = Path(model_dir)
    if not (d / MANIFEST).exists() or not (d / SIG).exists():
        return False, "missing manifest or signature"
    blob = (d / MANIFEST).read_bytes()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(base64.b64decode((d / SIG).read_text()), blob)
    except (InvalidSignature, ValueError):
        return False, "bad signature"
    if json.loads(blob) != build_manifest(d):
        return False, "artifact hash mismatch (modified, added or removed file)"
    return True, "ok"


def enforce(model_dir: Path, pub_b64: Optional[str] = None) -> None:
    """Raise if signing is required and verification fails. Called by the vision node before loading weights."""
    if os.environ.get("NEXUS_REQUIRE_SIGNED", "0") != "1":
        return
    pub = base64.b64decode(pub_b64 or os.environ.get("NEXUS_MODEL_PUBKEY", ""))
    ok, why = verify_dir(model_dir, pub)
    if not ok:
        raise RuntimeError(f"model integrity check failed: {why}")
