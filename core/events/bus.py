from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, DefaultDict, List

from core.events.schemas import validate_event_payload

logger = logging.getLogger("vscanx.events.bus")

EventHandler = Callable[[str, Any], Any]


@dataclass(frozen=True)
class Event:
    type: str
    payload: Any = None
    ts: str = ""


class EventBus:
    """
    Simple internal pub/sub bus.

    - Modules do not need to adopt it immediately.
    - Orchestrator can publish scan lifecycle events for building an internal scan graph.
    """

    def __init__(self, strict: bool = False) -> None:
        self._subs: DefaultDict[str, List[EventHandler]] = defaultdict(list)
        self._event_log: List[Event] = []
        self.strict = bool(strict)
        self.invalid_events = 0
        self.published_events = 0

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._subs[event_type].append(handler)

    def publish(self, event_type: str, payload: Any = None) -> Any:
        ok, err = validate_event_payload(event_type, payload)
        if not ok:
            self.invalid_events += 1
            logger.warning("event_payload_invalid", extra={"event_type": event_type, "error": err})
            if self.strict:
                raise ValueError(f"Event payload invalid for {event_type}: {err}")
        self.published_events += 1
        # Keep a light event log so reporting/debug can reconstruct scan decisions.
        try:
            import datetime

            ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        except Exception:
            ts = ""

        self._event_log.append(Event(type=event_type, payload=payload, ts=ts))

        for h in self._subs.get(event_type, []):
            try:
                res = h(event_type, payload)
                # If handler returns a dict, allow it to enrich the event payload.
                if isinstance(res, dict) and isinstance(payload, dict):
                    payload.update(res)
            except Exception:
                # Never allow an event handler bug to break scanning.
                continue

        return payload

    def get_event_log(self) -> List[Event]:
        return list(self._event_log)

    async def publish_async(self, event_type: str, payload: Any = None) -> None:
        # Async publish for future integrations.
        ok, err = validate_event_payload(event_type, payload)
        if not ok:
            self.invalid_events += 1
            logger.warning("event_payload_invalid", extra={"event_type": event_type, "error": err})
            if self.strict:
                raise ValueError(f"Event payload invalid for {event_type}: {err}")
        self.published_events += 1
        for h in self._subs.get(event_type, []):
            try:
                res = h(event_type, payload)
                if isinstance(res, Awaitable):
                    await res
            except Exception:
                continue
