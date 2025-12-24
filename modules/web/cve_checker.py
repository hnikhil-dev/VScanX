"""
VScanX CVE Database Checker
Checks software versions against known vulnerabilities
"""

import logging
import re
from typing import Any, Dict, List

from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class CVEChecker(BaseModule):
    """
    CVE vulnerability checker using NVD database
    """

    def __init__(self, handler=None):
        super().__init__()
        self.name = "CVE Database Checker"
        self.description = "Known vulnerability detection using CVE database"
        self.version = "1.0.0"

        # Use provided handler or create new one
        self.handler = handler if handler else RequestHandler()

        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute CVE checking on target

        Args:
            target: Target URL
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.cve_checker")
        self.clear_results()
        self.verbose = verbose

        logger.info("cve_check_start", extra={"target": target})

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # Get server response
        response = self.handler.get(target)

        if not response:
            logger.error("cve_fetch_failed", extra={"target": target})
            return {"module": self.name, "target": target, "findings": []}

        # Detect software versions
        software_versions = self._detect_versions(response)

        if not software_versions:
            logger.info("cve_no_versions", extra={"target": target})
            self.add_result(
                severity="INFO",
                finding="No detectable software versions",
                details="Unable to identify server software",
            )
        else:
            logger.info(
                "cve_versions_detected", extra={"count": len(software_versions)}
            )
            self._check_cves(software_versions)

        self.handler.close()

        return {
            "module": self.name,
            "target": target,
            "software_detected": software_versions,
            "findings": self.get_results(),
        }

    def _detect_versions(self, response) -> List[Dict[str, str]]:
        """
        Detect software versions from HTTP response

        Args:
            response: HTTP response object

        Returns:
            List of detected software with versions
        """
        detected = []
        headers = response.headers

        # Check Server header
        if "Server" in headers:
            server = headers["Server"]
            logging.getLogger("vscanx.module.cve_checker").debug(
                "cve_server_header", extra={"value": server}
            )

            # Parse common formats
            patterns = [
                (r"Apache/([\d.]+)", "Apache HTTP Server"),
                (r"nginx/([\d.]+)", "nginx"),
                (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
                (r"Python/([\d.]+)", "Python"),
                (r"PHP/([\d.]+)", "PHP"),
                (r"OpenSSL/([\d.]+)", "OpenSSL"),
            ]

            for pattern, name in patterns:
                match = re.search(pattern, server)
                if match:
                    version = match.group(1)
                    detected.append(
                        {
                            "software": name,
                            "version": version,
                            "source": "Server header",
                        }
                    )
                    logging.getLogger("vscanx.module.cve_checker").info(
                        "cve_detected", extra={"software": name, "version": version}
                    )

        # Check X-Powered-By header
        if "X-Powered-By" in headers:
            powered = headers["X-Powered-By"]
            logging.getLogger("vscanx.module.cve_checker").debug(
                "cve_x_powered_by", extra={"value": powered}
            )

            php_match = re.search(r"PHP/([\d.]+)", powered)
            if php_match:
                detected.append(
                    {
                        "software": "PHP",
                        "version": php_match.group(1),
                        "source": "X-Powered-By header",
                    }
                )
                logging.getLogger("vscanx.module.cve_checker").info(
                    "cve_detected",
                    extra={"software": "PHP", "version": php_match.group(1)},
                )

        return detected

    def _check_cves(self, software_versions: List[Dict[str, str]]) -> None:
        """
        Check software versions against CVE database

        Args:
            software_versions: List of detected software
        """
        for software in software_versions:
            name = software["software"]
            version = software["version"]

            logging.getLogger("vscanx.module.cve_checker").info(
                "cve_check_component", extra={"software": name, "version": version}
            )

            # Query NVD API (simplified - real implementation needs API key)
            cves = self._query_nvd(name, version)

            if cves:
                for cve in cves:
                    severity = self._map_cvss_to_severity(cve.get("cvss", 0))
                    self.add_result(
                        severity=severity,
                        finding=f"Known vulnerability in {name} {version}: {cve['id']}",
                        details=f"{cve['description']}\nCVSS Score: {cve.get('cvss', 'N/A')}",
                    )
                    logging.getLogger("vscanx.module.cve_checker").info(
                        "cve_found",
                        extra={"id": cve["id"], "cvss": cve.get("cvss", "N/A")},
                    )
            else:
                if self.verbose:
                    logging.getLogger("vscanx.module.cve_checker").info(
                        "cve_none", extra={"software": name, "version": version}
                    )

    def _query_nvd(self, software: str, version: str) -> List[Dict[str, Any]]:
        """
        Query NVD database for CVEs (simplified)

        Args:
            software: Software name
            version: Software version

        Returns:
            List of CVEs
        """
        # Simplified mock data for demonstration
        # In production, use actual NVD API with rate limiting

        known_vulns = {
            "Apache HTTP Server": {
                "2.4.49": [
                    {
                        "id": "CVE-2021-41773",
                        "description": "Path traversal and RCE vulnerability",
                        "cvss": 7.5,
                    }
                ],
                "2.4.50": [
                    {
                        "id": "CVE-2021-42013",
                        "description": "Path traversal vulnerability",
                        "cvss": 9.8,
                    }
                ],
            },
            "PHP": {
                "7.4.3": [
                    {
                        "id": "CVE-2020-7071",
                        "description": "URL validation bypass",
                        "cvss": 5.3,
                    }
                ]
            },
            "nginx": {
                "1.18.0": [
                    {
                        "id": "CVE-2021-23017",
                        "description": "DNS resolver off-by-one heap write",
                        "cvss": 8.1,
                    }
                ]
            },
        }

        return known_vulns.get(software, {}).get(version, [])

    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """
        Map CVSS score to severity level

        Args:
            cvss_score: CVSS score (0-10)

        Returns:
            Severity string
        """
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
