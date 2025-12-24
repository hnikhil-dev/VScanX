"""
VScanX HTTP Headers Analyzer Module
Analyzes security headers
"""

import logging
from typing import Any, Dict

from core.config import SECURITY_HEADERS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class HeaderAnalyzer(BaseModule):
    """
    HTTP security headers analyzer
    Checks for presence of security headers with remediation guidance
    """

    def __init__(self, handler=None):
        super().__init__()
        self.name = "HTTP Headers Analyzer"
        self.description = "Security headers analysis with remediation notes"
        self.version = "2.0.0"

        # Use provided handler or create new one
        self.handler = handler if handler else RequestHandler()

        # Header remediation mapping
        self.remediation_map = {
            "Strict-Transport-Security": (
                'Add "Strict-Transport-Security: max-age=31536000; '
                'includeSubDomains" header to enforce HTTPS'
            ),
            "Content-Security-Policy": (
                "Implement Content-Security-Policy header to restrict resource "
                "origins and prevent XSS/injection attacks"
            ),
            "X-Frame-Options": (
                'Add "X-Frame-Options: DENY" or "SAMEORIGIN" to prevent '
                'clickjacking attacks'
            ),
            "X-Content-Type-Options": (
                'Add "X-Content-Type-Options: nosniff" to prevent MIME-type '
                'sniffing attacks'
            ),
            "X-XSS-Protection": (
                'Add "X-XSS-Protection: 1; mode=block" for legacy browser '
                'XSS protection'
            ),
            "Referrer-Policy": (
                'Add "Referrer-Policy: strict-origin-when-cross-origin" to '
                'control referrer leakage'
            ),
            "Permissions-Policy": (
                "Implement Permissions-Policy to restrict sensitive browser features"
            ),
        }

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute header analysis on target

        Args:
            target: Target URL
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.header_analyzer")
        self.clear_results()
        self.verbose = verbose

        logger.info("headers_start", extra={"target": target})

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # Get response headers
        response = self.handler.get(target)

        if not response:
            logger.error("headers_fetch_failed", extra={"target": target})
            return {"module": self.name, "target": target, "findings": []}

        headers = response.headers

        logger.debug(
            "headers_analyzing",
            extra={"target": target, "header_count": len(SECURITY_HEADERS)},
        )

        # Check for security headers
        missing_headers = []
        present_headers = []

        for header in SECURITY_HEADERS:
            if header in headers:
                present_headers.append(header)
                self.add_result(
                    severity="INFO",
                    finding=f"Security header present: {header}",
                    details=f"Value: {headers[header]}",
                )
                logger.info("header_present", extra={"header": header})
            else:
                missing_headers.append(header)
                severity = self._get_missing_severity(header)
                remediation = self.remediation_map.get(
                    header, "Configure this security header"
                )
                self.add_result(
                    severity=severity,
                    finding=f"Missing security header: {header}",
                    details=self._get_header_description(header),
                    remediation=remediation,
                )
                logger.warning("header_missing", extra={"header": header})

        # Check for information disclosure headers
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in info_headers:
            if header in headers:
                self.add_result(
                    severity="LOW",
                    finding=f"Information disclosure: {header}",
                    details=f"Server reveals: {headers[header]}",
                    remediation="Remove or obfuscate server information headers to reduce reconnaissance opportunities",
                )
                logger.info("header_info_disclosure", extra={"header": header})

        logger.info(
            "headers_summary",
            extra={"present": len(present_headers), "missing": len(missing_headers)},
        )

        self.handler.close()

        return {
            "module": self.name,
            "target": target,
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "findings": self.get_results(),
        }

    def _get_missing_severity(self, header: str) -> str:
        """
        Determine severity of missing header

        Args:
            header: Header name

        Returns:
            Severity level
        """
        critical_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
        high_headers = ["X-Frame-Options", "X-Content-Type-Options"]

        if header in critical_headers:
            return "MEDIUM"
        elif header in high_headers:
            return "LOW"
        else:
            return "INFO"

    def _get_header_description(self, header: str) -> str:
        """
        Get description of security header

        Args:
            header: Header name

        Returns:
            Description
        """
        descriptions = {
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "Content-Security-Policy": "Prevents XSS and injection attacks",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME-type sniffing",
            "X-XSS-Protection": "Enables browser XSS protection",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features",
        }
        return descriptions.get(header, "Security header")
