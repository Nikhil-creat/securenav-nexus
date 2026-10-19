"""Minimal Prometheus text-format metrics registry (counters, gauges, histograms) with zero dependencies."""
from __future__ import annotations

import threading
from typing import Iterable

Labels = tuple[tuple[str, str], ...]


def _lbl(labels: dict[str, str] | None) -> Labels:
    return tuple(sorted((labels or {}).items()))


def _fmt(name: str, labels: Labels, value: float, extra: tuple[tuple[str, str], ...] = ()) -> str:
    allv = labels + extra
    body = ",".join(f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"' for k, v in allv)
    return f"{name}{{{body}}} {value:g}" if body else f"{name} {value:g}"


class Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._meta: dict[str, tuple[str, str]] = {}
        self._values: dict[str, dict[Labels, float]] = {}
        self._hist: dict[str, tuple[tuple[float, ...], dict[Labels, list[float]]]] = {}

    def _register(self, name: str, kind: str, help_: str) -> None:
        self._meta.setdefault(name, (kind, help_))

    def inc(self, name: str, amount: float = 1.0, labels: dict[str, str] | None = None, help_: str = "") -> None:
        with self._lock:
            self._register(name, "counter", help_)
            d = self._values.setdefault(name, {})
            d[_lbl(labels)] = d.get(_lbl(labels), 0.0) + amount

    def set(self, name: str, value: float, labels: dict[str, str] | None = None, help_: str = "") -> None:
        with self._lock:
            self._register(name, "gauge", help_)
            self._values.setdefault(name, {})[_lbl(labels)] = float(value)

    def observe(self, name: str, value: float, buckets: Iterable[float] = (.005, .01, .05, .1, .25, .5, 1, 2.5, 5),
                labels: dict[str, str] | None = None, help_: str = "") -> None:
        with self._lock:
            self._register(name, "histogram", help_)
            bk, series = self._hist.setdefault(name, (tuple(buckets), {}))
            row = series.setdefault(_lbl(labels), [0.0] * (len(bk) + 2))  # buckets..., +Inf, sum
            for i, b in enumerate(bk):
                if value <= b:
                    row[i] += 1
            row[len(bk)] += 1
            row[len(bk) + 1] += value

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            for name, (kind, help_) in sorted(self._meta.items()):
                out.append(f"# HELP {name} {help_ or name}")
                out.append(f"# TYPE {name} {kind}")
                if kind == "histogram":
                    bk, series = self._hist[name]
                    for lab, row in sorted(series.items()):
                        for i, b in enumerate(bk):
                            out.append(_fmt(name + "_bucket", lab, row[i], (("le", f"{b:g}"),)))
                        out.append(_fmt(name + "_bucket", lab, row[len(bk)], (("le", "+Inf"),)))
                        out.append(_fmt(name + "_sum", lab, row[len(bk) + 1]))
                        out.append(_fmt(name + "_count", lab, row[len(bk)]))
                else:
                    for lab, v in sorted(self._values.get(name, {}).items()):
                        out.append(_fmt(name, lab, v))
        return "\n".join(out) + "\n"


REGISTRY = Registry()
