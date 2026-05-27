"""
VScanX Base Module
Abstract base class for all scanner modules
"""

from abc import ABC, abstractmethod
import asyncio
from typing import Any, Dict, List


class BaseModule(ABC):
    """
    Abstract base class that all scanner modules must inherit from
    Ensures consistent interface across all modules
    """

    def __init__(self):
        """Initialize module with metadata"""
        self.name = "BaseModule"
        self.description = "Base scanner module"
        self.version = "1.0.0"
        self.results = []
        # Module metadata (used for intelligent scheduling + UI context)
        self.risk_level = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
        self.request_cost = 1  # relative request intensity
        self.requirements: List[str] = []  # e.g. "authenticated", "web"
        self.compatible_tech_stacks: List[str] = []  # e.g. "wordpress", "django"
        self.confidence_reliability = "MEDIUM"  # LOW/MEDIUM/HIGH
        self.dependencies: List[str] = []  # other module keys required
        self.consumes_events: List[str] = []
        self.emits_events: List[str] = []
        self.required_auth_state = "any"  # any/authenticated/unauthenticated
        self.supported_content_types: List[str] = ["text/html"]
        self.supported_technologies: List[str] = []

    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the scanning module

        Args:
            target: Target URL or IP address
            **kwargs: Additional module-specific parameters

        Returns:
            Dictionary containing scan results
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get module metadata

        Returns:
            Dictionary with module information
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "risk_level": self.risk_level,
            "request_cost": self.request_cost,
            "requirements": self.requirements,
            "compatible_tech_stacks": self.compatible_tech_stacks,
            "confidence_reliability": self.confidence_reliability,
            "dependencies": self.dependencies,
            "consumes_events": self.consumes_events,
            "emits_events": self.emits_events,
            "required_auth_state": self.required_auth_state,
            "supported_content_types": self.supported_content_types,
            "supported_technologies": self.supported_technologies,
        }

    def add_result(
        self,
        severity: str,
        finding: str,
        details: str = "",
        remediation: str = "",
        evidence: str = "",
        parameter: str = "",
        confidence: str = "",
        verified: bool | None = None,
        verification: Dict[str, Any] | None = None,
        reproduction: Dict[str, Any] | None = None,
        tags: List[str] | None = None,
        **extra: Any,
    ) -> None:
        """
        Add a finding to results

        Args:
            severity: LOW, MEDIUM, HIGH, CRITICAL
            finding: Brief description
            details: Detailed information
            remediation: Remediation/mitigation advice
        """
        result = {"severity": severity, "finding": finding, "details": details}
        if remediation:
            result["remediation"] = remediation
        if evidence:
            result["evidence"] = evidence
        if parameter:
            result["parameter"] = parameter
        if confidence:
            result["confidence"] = confidence
        if verified is not None:
            result["verified"] = verified
        if verification:
            result["verification"] = verification
        if reproduction:
            result["reproduction"] = reproduction
        if tags:
            result["tags"] = tags
        # Preserve any extra metadata from modules/plugins
        if extra:
            result.update(extra)
        self.results.append(result)

    def get_results(self) -> List[Dict[str, str]]:
        """
        Get all results from this module

        Returns:
            List of finding dictionaries
        """
        return self.results

    def clear_results(self) -> None:
        """Clear all results"""
        self.results = []

    async def run_async(self, target: str, **kwargs) -> Dict[str, Any]:
        """Async compatibility wrapper for modules not yet migrated."""
        return await asyncio.to_thread(self.run, target, **kwargs)
