"""Mission safety policy engine: geofence, no-go zones, speed zones, mission limits.

Pure Python (no dependencies) so it runs on the edge, in nexusctl and in CI. The equivalent
declarative rules for OPA live in policy/nexus.rego.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

Point = tuple[float, float]


@dataclass
class Zone:
    name: str
    polygon: list[Point]
    kind: str  # geofence | nogo | slow
    speed_limit: float = 1.0


@dataclass
class Policy:
    zones: list[Zone] = field(default_factory=list)
    max_speed: float = 1.0
    max_waypoints: int = 50
    max_leg_m: float = 60.0
    min_clearance: float = 0.0


@dataclass
class Verdict:
    ok: bool
    violations: list[str]
    speed: float


def point_in_polygon(p: Point, poly: Sequence[Point]) -> bool:
    """Ray casting; points exactly on an edge count as inside."""
    x, y = p
    inside = False
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        if _on_segment(p, (x1, y1), (x2, y2)):
            return True
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            inside = not inside
    return inside


def _on_segment(p: Point, a: Point, b: Point, eps: float = 1e-9) -> bool:
    cross = (p[1] - a[1]) * (b[0] - a[0]) - (p[0] - a[0]) * (b[1] - a[1])
    if abs(cross) > eps:
        return False
    return min(a[0], b[0]) - eps <= p[0] <= max(a[0], b[0]) + eps and min(a[1], b[1]) - eps <= p[1] <= max(a[1], b[1]) + eps


def _orient(a: Point, b: Point, c: Point) -> float:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool:
    o1, o2, o3, o4 = _orient(a, b, c), _orient(a, b, d), _orient(c, d, a), _orient(c, d, b)
    if (o1 > 0) != (o2 > 0) and (o3 > 0) != (o4 > 0) and o1 * o2 < 0 and o3 * o4 < 0:
        return True
    return _on_segment(c, a, b) or _on_segment(d, a, b) or _on_segment(a, c, d) or _on_segment(b, c, d)


def segment_crosses_polygon(a: Point, b: Point, poly: Sequence[Point]) -> bool:
    if point_in_polygon(a, poly) or point_in_polygon(b, poly):
        return True
    return any(segments_intersect(a, b, poly[i], poly[(i + 1) % len(poly)]) for i in range(len(poly)))


def validate_mission(policy: Policy, waypoints: Sequence[dict[str, float]], speed: float, start: Optional[Point] = None) -> Verdict:
    """Check a planned mission against the policy. Speed is clamped, never silently raised."""
    violations: list[str] = []
    if len(waypoints) > policy.max_waypoints:
        violations.append(f"too_many_waypoints:{len(waypoints)}>{policy.max_waypoints}")
    pts: list[Point] = ([start] if start else []) + [(float(w["x"]), float(w["y"])) for w in waypoints]
    geofences = [z for z in policy.zones if z.kind == "geofence"]
    nogos = [z for z in policy.zones if z.kind == "nogo"]
    slows = [z for z in policy.zones if z.kind == "slow"]
    for i, p in enumerate(pts):
        if geofences and not any(point_in_polygon(p, z.polygon) for z in geofences):
            violations.append(f"outside_geofence:wp{i}:({p[0]:.1f},{p[1]:.1f})")
    for i in range(len(pts) - 1):
        a, b = pts[i], pts[i + 1]
        if math.dist(a, b) > policy.max_leg_m:
            violations.append(f"leg_too_long:{i}")
        for z in nogos:
            if segment_crosses_polygon(a, b, z.polygon):
                violations.append(f"enters_nogo:{z.name}:leg{i}")
    clamped = min(speed, policy.max_speed)
    for z in slows:
        if any(point_in_polygon(p, z.polygon) for p in pts) or any(
                segment_crosses_polygon(pts[i], pts[i + 1], z.polygon) for i in range(len(pts) - 1)):
            clamped = min(clamped, z.speed_limit)
    return Verdict(not violations, violations, clamped)


def default_policy() -> Policy:
    """Policy matching the 30x18 m simulation world."""
    return Policy(zones=[
        Zone("arena", [(0, 0), (30, 0), (30, 18), (0, 18)], "geofence"),
        Zone("charging_bay", [(12, 14), (16, 14), (16, 17.5), (12, 17.5)], "nogo"),
        Zone("pedestrian_lane", [(0, 0), (8, 0), (8, 6), (0, 6)], "slow", speed_limit=0.5),
    ], max_speed=1.0, max_waypoints=50, max_leg_m=60.0)


def load_policy(source: Optional[str | Path | dict[str, Any]] = None) -> Policy:
    """Load a policy from a dict / JSON file path, or the default when source is None."""
    if source is None:
        return default_policy()
    data = source if isinstance(source, dict) else json.loads(Path(source).read_text(encoding="utf-8"))
    zones = [Zone(z["name"], [tuple(p) for p in z["polygon"]], z["kind"], float(z.get("speed_limit", 1.0))) for z in data.get("zones", [])]  # type: ignore[misc]
    return Policy(zones, float(data.get("max_speed", 1.0)), int(data.get("max_waypoints", 50)),
                  float(data.get("max_leg_m", 60.0)), float(data.get("min_clearance", 0.0)))
