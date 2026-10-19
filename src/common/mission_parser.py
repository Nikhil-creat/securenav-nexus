"""Natural-language mission parser shared by the agentic brain, nexusctl and tests."""
from __future__ import annotations

import math
import re
from typing import Any

MAX_SPEED = 1.0  # m/s hard ceiling the planner may never exceed
_DIRS = {"north": (0, 1), "south": (0, -1), "east": (1, 0), "west": (-1, 0), "forward": (1, 0), "back": (-1, 0)}


def plan_mission(directive: str, speed_cap: float = MAX_SPEED, start: tuple[float, float] = (0.0, 0.0)) -> dict[str, Any]:
    """Parse e.g. 'go to (5,3) then patrol north 10 m at 0.6 m/s' into Nav2-style waypoints."""
    text = directive.lower()
    speed = min(float(m.group(1)) if (m := re.search(r"(\d+(?:\.\d+)?)\s*m/s", text)) else 0.5, speed_cap)
    waypoints: list[dict[str, float]] = []
    x, y = start
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
