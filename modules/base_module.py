"""
VScanX Base Module
Abstract base class for all scanner modules
"""

from abc import ABC, abstractmethod
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

    def get_metadata(self) -> Dict[str, str]:
        """
        Get module metadata

        Returns:
            Dictionary with module information
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
        }

    def add_result(
        self, severity: str, finding: str, details: str = "", remediation: str = ""
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
