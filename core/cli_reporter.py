"""
CLI event reporter for VScanX. Subscribes to the EventBus and prints styled terminal outputs.
"""

from __future__ import annotations

from typing import Any

from core.console import (
    ProgressBar,
    print_checking,
    print_completed,
    print_finding,
    print_scan_started,
    reset_console_state,
)
from core.events.bus import EventBus


class CLIReporter:
    """Subscribes to EventBus scan events to print beautiful hacker-style console output."""

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self.active_bar: ProgressBar | None = None
        self.active_module: str | None = None
        self.register_listeners()

    def register_listeners(self) -> None:
        self.event_bus.subscribe("scan.started", self.on_scan_started)
        self.event_bus.subscribe("module.started", self.on_module_started)
        self.event_bus.subscribe("module.progress", self.on_module_progress)
        self.event_bus.subscribe("finding.added", self.on_finding_added)
        self.event_bus.subscribe("module.completed", self.on_module_completed)

    def on_scan_started(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        reset_console_state()
        print_scan_started(
            target=payload.get("target", "N/A"),
            scan_type=payload.get("scan_type", "mixed"),
            profile_name=payload.get("profile_name"),
            profile_desc=payload.get("profile_desc"),
            threads=payload.get("threads", 10),
            delay=payload.get("delay", 1.0),
        )

    def on_module_started(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if self.active_bar:
            self.active_bar.finish()
            self.active_bar = None
            self.active_module = None
        print_checking(payload.get("module", "Unknown Module"))

    def on_module_progress(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        module = payload.get("module", "Module")
        total = int(payload.get("total", 1))
        current = int(payload.get("current", 0))
        item = str(payload.get("item", ""))

        if self.active_bar is None or self.active_module != module or self.active_bar.total != total:
            if self.active_bar:
                self.active_bar.finish()
            self.active_module = module
            self.active_bar = ProgressBar(total=total, prefix=f"[*] {module}")

        self.active_bar.update(current=current, item=item)

    def on_finding_added(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if self.active_bar:
            self.active_bar.clear()
        print_finding(payload)

    def on_module_completed(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if self.active_bar:
            self.active_bar.finish()
            self.active_bar = None
            self.active_module = None
        print_completed(
            module_name=payload.get("module", "Unknown Module"),
            duration=payload.get("duration", 0.0),
            error=payload.get("error"),
        )
