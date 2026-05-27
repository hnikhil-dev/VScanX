"""
VScanX OS Command Injection Detector
Tests input parameters for OS Command Injection vulnerabilities.
"""

import time
import logging
from urllib.parse import parse_qs, urlparse

from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class CmdInjectionDetector(BaseModule):
    """
    OS Command Injection vulnerability detector.
    Tests input parameters with OS-specific command injection payloads.
    Supports output-based and time-based verification.
    """

    def __init__(self, handler=None):
        super().__init__()
        self.name = "OS Command Injection Detector"
        self.description = "Detects OS Command Injection vulnerabilities in input parameters (OWASP A05:2026)"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.request_cost = 4
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html", "application/json"]
        self.supported_technologies = ["generic-web"]

        # Output-based indicators
        self.signatures = [
            {"pattern": "uid=", "desc": "Unix/Linux 'id' command output"},
            {"pattern": "gid=", "desc": "Unix/Linux 'id' command output"},
            {"pattern": "Windows IP Configuration", "desc": "Windows 'ipconfig' command output"},
            {"pattern": "Ethernet adapter", "desc": "Windows 'ipconfig' command output"},
            {"pattern": "Link encap:Local Loopback", "desc": "Linux 'ifconfig' command output"},
            {"pattern": "inet addr:", "desc": "Linux/Unix network info output"}
        ]

        # Payloads to inject
        # Combines command chaining/nesting for both Windows and Linux
        self.payloads = [
            "; id",
            "| id",
            "& id",
            "&& id",
            "$(id)",
            "`id`",
            "; ipconfig",
            "| ipconfig",
            "& ipconfig",
            "&& ipconfig",
            "; ifconfig",
            "| ifconfig",
            "& ifconfig",
            "&& ifconfig",
            # Time-based fallbacks
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "; ping -n 5 127.0.0.1", # Windows ping 5 times
            "; ping -c 5 127.0.0.1", # Linux ping 5 times
        ]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        logger = logging.getLogger("vscanx.module.cmd_injection")
        logger.info("cmd_injection_start", extra={"target": target})

        # Baseline request
        start_time = time.time()
        baseline = self.handler.get(target)
        baseline_duration = time.time() - start_time
        
        if not baseline:
            return {"module": self.name, "target": target, "findings": []}

        params = self._extract_parameters(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No testable parameters found",
                details="URL contains no query parameters",
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name, _ in params.items():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                req_start = time.time()
                resp = self.handler.get(base_url, params=test_params)
                req_duration = time.time() - req_start
                
                if not resp:
                    continue

                # 1. Output-based checks
                is_vuln = False
                vuln_desc = ""
                for sig in self.signatures:
                    if sig["pattern"] in resp.text:
                        is_vuln = True
                        vuln_desc = f"Response body matched signature for {sig['desc']}"
                        break
                
                # 2. Time-based checks (if sleep/ping was injected and took > 4 seconds longer than baseline)
                if not is_vuln and ("sleep" in payload or "ping" in payload):
                    if req_duration - baseline_duration >= 4.0:
                        is_vuln = True
                        vuln_desc = f"Time-based execution delay detected. Baseline: {baseline_duration:.2f}s, Payload request: {req_duration:.2f}s."

                if is_vuln:
                    self.add_result(
                        severity="CRITICAL",
                        finding=f"OS Command Injection Vulnerability in parameter '{param_name}'",
                        details=f"Injected payload: '{payload}' | {vuln_desc}",
                        remediation="Ensure input is fully sanitized and never directly passed to system shell executables. Use safe language APIs or strictly validate input patterns against an alphanumeric allowlist.",
                        confidence="HIGH",
                        verified=True,
                        parameter=param_name,
                        evidence=resp.text[:500] if not ("sleep" in payload or "ping" in payload) else f"Response time delay of {req_duration:.2f}s",
                        tags=["A05:2026", "injection", "rce"]
                    )
                    break # stop testing payloads for this parameter once confirmed

        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No Command Injection detected",
                details="No successful execution signatures or anomalous delays were observed.",
            )

        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        return await self.run_async_wrapper(target, verbose=verbose, **kwargs)

    async def run_async_wrapper(self, target: str, **kwargs):
        import asyncio
        return await asyncio.to_thread(self.run, target, **kwargs)

    def _extract_parameters(self, target: str):
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        return {k: v[-1] for k, v in params.items() if v}
