"""
Lightweight metrics collector for VScanX.
Stores per-run counters and timings in-memory for later logging/export.
"""

from __future__ import annotations

import time
from typing import Any, Dict


class MetricsCollector:
    def __init__(self) -> None:
        self.start_time = time.time()
        self.counters: Dict[str, int] = {}
        self.timings: Dict[str, float] = {}

    def incr(self, key: str, count: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + count

    def observe_duration(self, key: str, seconds: float) -> None:
        self.timings[key] = seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.start_time,
            "uptime": round(time.time() - self.start_time, 3),
            "counters": self.counters,
            "timings": self.timings,
        }
