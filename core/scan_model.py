from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import NAMESPACE_URL, uuid5


@dataclass
class Finding:
    module: str
    severity: str
    description: str
    finding_id: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: str = ""
    verified: bool | None = None
    verification_state: str = "UNVERIFIED"
    verification: Dict[str, Any] = field(default_factory=dict)
    reproduction: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    first_seen_at: str = ""
    last_seen_at: str = ""
    enrichment_history: List[Dict[str, Any]] = field(default_factory=list)
    remediation: str = ""  # Remediation/mitigation guidance

    def __post_init__(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.first_seen_at:
            self.first_seen_at = self.timestamp or now_iso
        if not self.last_seen_at:
            self.last_seen_at = self.timestamp or now_iso
        if not self.finding_id:
            # Stable identifier based on canonical structural fields.
            key = "|".join(
                [
                    self.module or "",
                    self.endpoint or "",
                    self.parameter or "",
                    self.description or "",
                    str(self.evidence.get("summary", "")) if isinstance(self.evidence, dict) else "",
                ]
            )
            self.finding_id = str(uuid5(NAMESPACE_URL, key))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str = ""
    scan_type: str = "mixed"
    authenticated: bool = False
    start_time: str = ""
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    modules: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "authenticated": self.authenticated,
            "start_time": self.start_time,
            "duration": self.duration,
            "findings": [f.to_dict() for f in self.findings],
            "modules": self.modules,
            "errors": self.errors,
        }
