"""
VScanX Error Handling and Debug Information Prober
Forces HTTP 400/500 error states to check for leaked stack traces, internal paths, and framework versions.
"""

import logging
from urllib.parse import parse_qs, urlparse

from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class ErrorHandlingProber(BaseModule):
    """
    Error Handling and Debug Information Prober.
    Tests input parameters with anomalous payloads to provoke server exceptions and scan for leaked diagnostics (OWASP A10:2026).
    """

    def __init__(self, handler=None):
        super().__init__()
        self.name = "Error Handling Prober"
        self.description = "Forces server error responses (HTTP 400/500) to scan for leaked stack traces and path disclosures (OWASP A10:2026)"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.request_cost = 3
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html", "application/json"]
        self.supported_technologies = ["generic-web"]

        # Anomalous payloads designed to trigger unhandled exceptions
        self.malformed_payloads = [
            "'\"()[]{};:<>?*-+", # special char mixup
            "[]", # Array type confusion
            "%00", # Null byte
            "9999999999999999999999999999999999999999999999999999999999", # Big integer overflow
            "../../../../../../../../etc/passwd", # Path traversal attempt (sometimes causes file handler errors)
        ]

        # Stack trace & directory leak patterns
        self.error_signatures = [
            {"pattern": "traceback (most recent call last)", "desc": "Python Stack Trace"},
            {"pattern": "exception in thread", "desc": "Java Stack Trace"},
            {"pattern": "at org.apache.catalina.", "desc": "Tomcat/Java Stack Trace"},
            {"pattern": "fatal error:", "desc": "PHP Error Log"},
            {"pattern": "unhandled exception:", "desc": "Generic Stack Trace"},
            {"pattern": "stack trace:", "desc": "Generic Stack Trace"},
            {"pattern": "django.views.debug", "desc": "Django Debug Page"},
            {"pattern": "zerodivisionerror:", "desc": "Python Division by Zero"},
            {"pattern": "typeerror:", "desc": "Type Mismatch Exception"},
            {"pattern": "syntaxerror:", "desc": "Syntax/Parser Exception"},
            {"pattern": "file \"", "desc": "Python Code Location Disclosure"},
            {"pattern": "on line", "desc": "PHP/ASP Script Line Disclosure"},
            {"pattern": "in /var/www/", "desc": "Linux Web Directory Path Disclosure"},
            {"pattern": "in C:\\", "desc": "Windows Directory Path Disclosure"},
            {"pattern": "mysqli_sql_exception", "desc": "MySQLi Library Exception"},
            {"pattern": "laravel_session", "desc": "Laravel Session Leak"},
        ]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        logger = logging.getLogger("vscanx.module.error_prober")
        logger.info("error_prober_start", extra={"target": target})

        params = self._extract_parameters(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No parameters to probe",
                details="URL does not contain query parameters, skipping error prober",
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name, _ in params.items():
            for payload in self.malformed_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                resp = self.handler.get(base_url, params=test_params)
                if not resp:
                    continue

                is_vuln = False
                vuln_desc = ""
                matched_text = ""

                # Look for stack trace signatures
                for sig in self.error_signatures:
                    if sig["pattern"] in resp.text.lower():
                        is_vuln = True
                        vuln_desc = f"Server leaked verbose diagnostics: {sig['desc']}"
                        matched_text = sig["pattern"]
                        break

                # Also flag general HTTP 500 Internals if we can find traces of unhandled errors
                if not is_vuln and resp.status_code == 500:
                    # Generic check for standard 500 page vs raw server error leak
                    if any(x in resp.text.lower() for x in ["exception", "error", "stack", "trace", "line"]):
                        is_vuln = True
                        vuln_desc = "Server returned HTTP 500 with descriptive error text, potentially leaking inner state."

                if is_vuln:
                    self.add_result(
                        severity="MEDIUM",
                        finding=f"Verbose Error/Stack Trace Disclosure via parameter '{param_name}'",
                        details=f"Injected malformed payload: '{payload}' resulting in error page disclosure | {vuln_desc}",
                        remediation="Disable verbose error messages/debug mode in production. Implement custom, clean error pages and log actual stack traces in secure server-side logs.",
                        confidence="HIGH",
                        verified=True,
                        parameter=param_name,
                        evidence=f"Matched signature: '{matched_text}' in response body. Status Code: {resp.status_code}",
                        tags=["A10:2026", "error-handling", "information-disclosure"]
                    )
                    break # one crash indicator per parameter is enough

        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="Error Handling secure",
                details="No stack trace leaks or debug information exposures detected.",
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
