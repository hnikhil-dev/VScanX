"""
CLI event reporter for VScanX. Subscribes to the EventBus and prints styled terminal outputs.
"""

from __future__ import annotations

from typing import Any
from core.events.bus import EventBus
from core.console import print_scan_started, print_checking, print_completed, print_finding

class CLIReporter:
    """Subscribes to EventBus scan events to print beautiful hacker-style console output."""
    
    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self.register_listeners()

    def register_listeners(self) -> None:
        self.event_bus.subscribe("scan.started", self.on_scan_started)
        self.event_bus.subscribe("module.started", self.on_module_started)
        self.event_bus.subscribe("finding.added", self.on_finding_added)
        self.event_bus.subscribe("module.completed", self.on_module_completed)

    def on_scan_started(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        print_scan_started(
            target=payload.get("target", "N/A"),
            scan_type=payload.get("scan_type", "mixed"),
            profile_name=payload.get("profile_name"),
            profile_desc=payload.get("profile_desc"),
            threads=payload.get("threads", 10),
            delay=payload.get("delay", 1.0)
        )

    def on_module_started(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        print_checking(payload.get("module", "Unknown Module"))

    def on_finding_added(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        print_finding(payload)

    def on_module_completed(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        print_completed(
            module_name=payload.get("module", "Unknown Module"),
            duration=payload.get("duration", 0.0),
            error=payload.get("error")
        )
