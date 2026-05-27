from __future__ import annotations

from typing import Any, Dict, List, Tuple, TypedDict


class FindingNormalizedEvent(TypedDict):
    module: str
    normalized: Dict[str, Any]
    raw: Dict[str, Any]


class CrawlInventoryEvent(TypedDict):
    visited_count: int
    param_urls_count: int
    param_names_count: int
    api_endpoints_count: int
    spa_routes_count: int
    param_urls_sample: List[str]
    api_endpoints_sample: List[str]
    spa_routes_sample: List[str]


class VerificationCompletedEvent(TypedDict):
    module: str
    finding_id: str
    state: str
    confidence: str
    notes: str


EVENT_SCHEMAS: Dict[str, Dict[str, List[str]]] = {
    # normalized finding produced by module execution pipeline
    "finding.normalization": {
        "required": ["module", "normalized", "raw"],
        "optional": [],
    },
    # canonical finding inserted into global result set
    "finding.added": {
        "required": [
            "finding_id",
            "module",
            "severity",
            "description",
            "endpoint",
            "confidence",
            "verification_state",
        ],
        "optional": [
            "parameter",
            "verified",
            "verification",
            "reproduction",
            "tags",
            "timestamp",
        ],
    },
    # verification subsystem result envelope
    "verification.completed": {
        "required": ["module", "finding_id", "state", "confidence"],
        "optional": ["notes", "metrics", "verified"],
    },
    # crawler inventory used by scheduling and graph views
    "crawl.inventory_ready": {
        "required": [
            "visited_count",
            "param_urls_count",
            "param_names_count",
            "api_endpoints_count",
            "spa_routes_count",
        ],
        "optional": ["param_urls_sample", "api_endpoints_sample", "spa_routes_sample"],
    },
    "module.completed": {
        "required": ["module"],
        "optional": ["duration", "error"],
    },
    "scan.started": {
        "required": ["target", "scan_type", "threads", "delay"],
        "optional": ["profile_name", "profile_desc"],
    },
    "module.started": {
        "required": ["module"],
        "optional": [],
    },
}


def validate_event_payload(event_type: str, payload: Any) -> Tuple[bool, str]:
    if event_type not in EVENT_SCHEMAS:
        return True, ""
    if not isinstance(payload, dict):
        return False, f"payload for {event_type} must be a dict"
    req = EVENT_SCHEMAS[event_type].get("required", [])
    missing = [k for k in req if k not in payload]
    if missing:
        return False, f"missing required fields for {event_type}: {', '.join(missing)}"
    return True, ""
