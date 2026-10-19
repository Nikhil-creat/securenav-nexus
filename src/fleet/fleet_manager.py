"""Fleet / swarm orchestration for SecureNav-NEXUS.

  * registry with heartbeats, battery and quarantine state
  * optimal task allocation (Hungarian / Kuhn-Munkres) minimising travel cost with battery feasibility
  * revocation gossip: signed certificate-revocation records merge as a grow-only CRDT, so every robot converges
    on the same blacklist regardless of message order or duplication. Revoked robots are quarantined fleet-wide.
"""
from __future__ import annotations

import base64
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

INF = 1e9


@dataclass
class Robot:
    rid: str
    pos: tuple[float, float] = (0.0, 0.0)
    battery: float = 1.0
    status: str = "ready"  # ready | busy | quarantined | offline
    last_seen: float = field(default_factory=time.time)


@dataclass
class Task:
    tid: str
    pos: tuple[float, float]
    min_battery: float = 0.2


def hungarian(cost: list[list[float]]) -> list[tuple[int, int]]:
    """Minimum-cost assignment for an n x m matrix (n <= m). Returns (row, col) pairs. O(n^2 m)."""
    n, m = len(cost), len(cost[0]) if cost else 0
    if n == 0:
        return []
    if n > m:
        return [(r, c) for c, r in hungarian([list(col) for col in zip(*cost)])]
    u, v, p, way = [0.0] * (n + 1), [0.0] * (m + 1), [0] * (m + 1), [0] * (m + 1)
    for i in range(1, n + 1):
        p[0], j0 = i, 0
        minv, used = [INF * 10] * (m + 1), [False] * (m + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], INF * 10, 0
            for j in range(1, m + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    return [(p[j] - 1, j - 1) for j in range(1, m + 1) if p[j]]


def make_verifier(public_key: bytes) -> Callable[[dict[str, Any]], bool]:
    """Verify a revocation record signed by the HSM (format: hsm_emulator.Vault.revoke)."""
    pub = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(rec: dict[str, Any]) -> bool:
        try:
            msg = json.dumps({k: rec[k] for k in ("node", "reason", "ts", "serial")}, sort_keys=True).encode()
            pub.verify(base64.b64decode(rec["signature"]["ed25519"]), msg)
            return True
        except (InvalidSignature, KeyError, ValueError, TypeError):
            return False

    return verify


class FleetManager:
    def __init__(self, verifier: Optional[Callable[[dict[str, Any]], bool]] = None, heartbeat_timeout: float = 5.0) -> None:
        self.robots: dict[str, Robot] = {}
        self.crl: dict[str, dict[str, Any]] = {}
        self.verifier, self.timeout = verifier, heartbeat_timeout

    # ---- registry
    def register(self, robot: Robot) -> bool:
        if robot.rid in self.crl:
            robot.status = "quarantined"
            self.robots[robot.rid] = robot
            return False
        self.robots[robot.rid] = robot
        return True

    def heartbeat(self, rid: str, pos: tuple[float, float], battery: float, now: Optional[float] = None) -> None:
        r = self.robots.get(rid)
        if not r or r.status == "quarantined":
            return
        r.pos, r.battery, r.last_seen = pos, battery, now if now is not None else time.time()
        if r.status == "offline":
            r.status = "ready"

    def reap(self, now: Optional[float] = None) -> list[str]:
        now = now if now is not None else time.time()
        lost = [r.rid for r in self.robots.values() if r.status in ("ready", "busy") and now - r.last_seen > self.timeout]
        for rid in lost:
            self.robots[rid].status = "offline"
        return lost

    def is_trusted(self, rid: str) -> bool:
        return rid not in self.crl

    # ---- revocation CRDT
    def merge_crl(self, remote: dict[str, dict[str, Any]]) -> list[str]:
        """Merge verified records. Idempotent, commutative, associative (grow-only, newest record per node wins)."""
        added: list[str] = []
        for node, rec in remote.items():
            if self.verifier and not self.verifier(rec):
                continue
            cur = self.crl.get(node)
            if cur is None or rec["ts"] > cur["ts"]:
                self.crl[node] = rec
                added.append(node)
            if node in self.robots:
                self.robots[node].status = "quarantined"
        return added

    # ---- allocation
    def allocate(self, tasks: Sequence[Task]) -> dict[str, str]:
        """Optimal robot->task assignment by distance. Ineligible pairs (battery / not ready) are priced at INF."""
        ready = [r for r in self.robots.values() if r.status == "ready"]
        if not ready or not tasks:
            return {}
        cost = [[(math.dist(r.pos, t.pos) if r.battery >= t.min_battery else INF) for t in tasks] for r in ready]
        out: dict[str, str] = {}
        for ri, ti in hungarian(cost):
            if cost[ri][ti] < INF:
                out[ready[ri].rid] = tasks[ti].tid
                ready[ri].status = "busy"
        return out
