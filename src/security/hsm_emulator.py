"""Software HSM emulator for SecureNav-NEXUS.

Provides, over a Unix domain socket (JSON lines, mode 0600):
  sign / verify         - Ed25519, plus CRYSTALS-Dilithium3 hybrid signature when liboqs (`oqs`) is installed
  revoke / revoked      - signed certificate-revocation records (CRL) for compromised node identities
  status                - key fingerprints and PQC availability
Keys live in an AES-256-GCM encrypted vault, key-wrapped with scrypt from the HSM PIN.
This is an EMULATOR for development/HIL - production must use a real HSM/TPM/PKCS#11 device.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature

from common.logging_setup import get_logger

log = get_logger("nexus.hsm")
DILITHIUM_ALG = "Dilithium3"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


class PqcProvider:
    """Thin wrapper around liboqs-python; degrades to 'unavailable' without raising."""

    def __init__(self) -> None:
        try:
            import oqs  # type: ignore[import-not-found]

            self.oqs: Any = oqs
            self.available = DILITHIUM_ALG in oqs.get_enabled_sig_mechanisms()
        except Exception:  # noqa: BLE001
            self.oqs = None
            self.available = False

    def keypair(self) -> tuple[bytes, bytes]:
        with self.oqs.Signature(DILITHIUM_ALG) as sig:
            pub = sig.generate_keypair()
            return pub, sig.export_secret_key()

    def sign(self, secret: bytes, msg: bytes) -> bytes:
        with self.oqs.Signature(DILITHIUM_ALG, secret) as sig:
            return bytes(sig.sign(msg))

    def verify(self, pub: bytes, msg: bytes, signature: bytes) -> bool:
        with self.oqs.Signature(DILITHIUM_ALG) as sig:
            return bool(sig.verify(msg, signature, pub))


class Vault:
    """Encrypted key vault (scrypt -> AES-256-GCM)."""

    def __init__(self, path: Path, pin: bytes) -> None:
        self.path = path
        self.pin = pin
        self.pqc = PqcProvider()
        self.lock = threading.Lock()
        self.revoked: dict[str, dict[str, Any]] = {}
        if path.exists():
            self._load()
        else:
            self._create()

    def _kdf(self, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(self.pin)

    def _create(self) -> None:
        self.ed = Ed25519PrivateKey.generate()
        self.pq_pub: Optional[bytes] = None
        self.pq_sec: Optional[bytes] = None
        if self.pqc.available:
            self.pq_pub, self.pq_sec = self.pqc.keypair()
        self._save()
        log.info("vault created", extra={"fields": {"pqc": self.pqc.available}})

    def _blob(self) -> bytes:
        raw = self.ed.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return json.dumps({"ed": _b64(raw), "pq_pub": _b64(self.pq_pub) if self.pq_pub else None,
                           "pq_sec": _b64(self.pq_sec) if self.pq_sec else None, "revoked": self.revoked}).encode()

    def _save(self) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        ct = AESGCM(self._kdf(salt)).encrypt(nonce, self._blob(), b"nexus-hsm-v1")
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(salt + nonce + ct)
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def _load(self) -> None:
        data = self.path.read_bytes()
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        d = json.loads(AESGCM(self._kdf(salt)).decrypt(nonce, ct, b"nexus-hsm-v1"))
        self.ed = Ed25519PrivateKey.from_private_bytes(_unb64(d["ed"]))
        self.pq_pub = _unb64(d["pq_pub"]) if d.get("pq_pub") else None
        self.pq_sec = _unb64(d["pq_sec"]) if d.get("pq_sec") else None
        self.revoked = d.get("revoked", {})

    # -- operations
    def ed_pub_bytes(self) -> bytes:
        return self.ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, msg: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {"ed25519": _b64(self.ed.sign(msg)), "pqc": None}
        if self.pqc.available and self.pq_sec:
            out["pqc"] = {"alg": DILITHIUM_ALG, "sig": _b64(self.pqc.sign(self.pq_sec, msg))}
        return out

    def verify(self, msg: bytes, sigs: dict[str, Any]) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.ed_pub_bytes()).verify(_unb64(sigs["ed25519"]), msg)
        except (InvalidSignature, KeyError, ValueError):
            return False
        pq = sigs.get("pqc")
        if pq and self.pqc.available and self.pq_pub:  # hybrid: BOTH must verify when PQC present
            return self.pqc.verify(self.pq_pub, msg, _unb64(pq["sig"]))
        return True

    def revoke(self, node: str, reason: str) -> dict[str, Any]:
        with self.lock:
            record = {"node": node, "reason": reason, "ts": time.time(), "serial": hashlib.sha256(f"{node}{time.time()}".encode()).hexdigest()[:16]}
            record["signature"] = self.sign(json.dumps({k: record[k] for k in ("node", "reason", "ts", "serial")}, sort_keys=True).encode())
            self.revoked[node] = record
            self._save()
        log.warning("certificate revoked", extra={"fields": {"node": node, "reason": reason}})
        return record


class _Handler(socketserver.StreamRequestHandler):
    vault: Vault
    on_revoke: Any = None

    def handle(self) -> None:
        for line in self.rfile:
            try:
                req = json.loads(line)
                resp = self.dispatch(req)
            except Exception as exc:  # noqa: BLE001
                resp = {"ok": False, "error": str(exc)}
            self.wfile.write((json.dumps(resp) + "\n").encode())

    def dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        op, v = req.get("op"), self.vault
        if op == "sign":
            return {"ok": True, "sig": v.sign(_unb64(req["data"]))}
        if op == "verify":
            return {"ok": True, "valid": v.verify(_unb64(req["data"]), req["sig"])}
        if op == "revoke":
            rec = v.revoke(str(req["node"]), str(req.get("reason", "unspecified")))
            if self.on_revoke:
                self.on_revoke(rec)
            return {"ok": True, "record": rec}
        if op == "revoked":
            return {"ok": True, "revoked": list(v.revoked)}
        if op == "status":
            return {"ok": True, "pqc": v.pqc.available, "ed25519_fp": hashlib.sha256(v.ed_pub_bytes()).hexdigest()[:16],
                    "revoked_count": len(v.revoked)}
        return {"ok": False, "error": f"unknown op {op}"}


class HsmServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(sock_path: str, vault: Vault, on_revoke: Any = None) -> HsmServer:
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    _Handler.vault, _Handler.on_revoke = vault, staticmethod(on_revoke) if on_revoke else None
    server = HsmServer(sock_path, _Handler)
    os.chmod(sock_path, 0o660)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class HsmClient:
    """Used by the IDS guardian to request signatures/revocations."""

    def __init__(self, sock_path: str, timeout: float = 3.0) -> None:
        self.path, self.timeout = sock_path, timeout

    def call(self, req: dict[str, Any]) -> dict[str, Any]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall((json.dumps(req) + "\n").encode())
            return dict(json.loads(s.makefile().readline()))

    def revoke(self, node: str, reason: str) -> dict[str, Any]:
        return self.call({"op": "revoke", "node": node, "reason": reason})


def main() -> None:
    sock = os.environ.get("HSM_SOCKET", "/run/nexus/hsm.sock")
    pin = Path(os.environ.get("HSM_PIN_FILE", "/run/secrets/hsm_pin")).read_bytes().strip()
    vault = Vault(Path(os.environ.get("HSM_VAULT", "/vault/hsm.vault")), pin)
    import rclpy
    from rclpy.node import Node
    from std_msgs.msg import String

    rclpy.init()
    node = Node("hsm_emulator")
    pub = node.create_publisher(String, "/security/cert_revocations", 10)
    serve(sock, vault, on_revoke=lambda rec: pub.publish(String(data=json.dumps(rec))))
    log.info("hsm ready", extra={"fields": {"socket": sock, "pqc": vault.pqc.available}})
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
