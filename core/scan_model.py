from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class Finding:
    module: str
    severity: str
    description: str
    parameter: str = ""
    evidence: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    remediation: str = ""  # Remediation/mitigation guidance

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
