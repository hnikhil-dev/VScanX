"""
VScanX Authentication Bypass Detector
Checks common header and token bypass vectors on protected paths.
"""

from urllib.parse import urlparse

from core.config import AUTH_BYPASS_HEADERS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class AuthBypassDetector(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "Authentication Bypass Detector"
        self.description = "Tests proxy/header and token-based auth bypass misconfigurations"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()

    def _protected_candidates(self, target: str):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return [
            target,
            f"{base}/admin",
            f"{base}/dashboard",
            f"{base}/api/admin",
        ]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        self._run_sync(target)
        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        await self._run_async(target)
        return {"module": self.name, "target": target, "findings": self.get_results()}

    def _is_bypass(self, baseline_status: int, test_status: int) -> bool:
        return baseline_status in [401, 403] and test_status in [200, 201, 202, 204, 302]

    def _run_sync(self, target: str) -> None:
        for candidate in self._protected_candidates(target):
            baseline = self.handler.get(candidate, allow_redirects=False)
            if not baseline:
                continue
            for header_set in AUTH_BYPASS_HEADERS:
                resp = self.handler.get(candidate, allow_redirects=False, headers=header_set)
                if resp and self._is_bypass(baseline.status_code, resp.status_code):
                    self.add_result(
                        severity="HIGH",
                        finding="Potential auth bypass via trusted proxy header",
                        details=f"{candidate} switched {baseline.status_code}->{resp.status_code} using {header_set}",
                        remediation="Ignore user-supplied forwarding headers unless added by trusted proxy",
                    )
                    break
            jwt_none = self.handler.get(
                candidate,
                allow_redirects=False,
                headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
            )
            if jwt_none and self._is_bypass(baseline.status_code, jwt_none.status_code):
                self.add_result(
                    severity="CRITICAL",
                    finding="Potential JWT none algorithm acceptance",
                    details=f"{candidate} accepted unsigned-like token behavior ({baseline.status_code}->{jwt_none.status_code})",
                    remediation="Reject alg=none tokens and enforce signature verification",
                )
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious authentication bypass behavior detected",
                details="Baseline and bypass probes did not indicate access-control bypass",
            )

    async def _run_async(self, target: str) -> None:
        for candidate in self._protected_candidates(target):
            baseline = await self.handler.async_get(candidate, allow_redirects=False)
            if not baseline:
                continue
            for header_set in AUTH_BYPASS_HEADERS:
                resp = await self.handler.async_get(candidate, allow_redirects=False, headers=header_set)
                if resp and self._is_bypass(baseline.status_code, resp.status_code):
                    self.add_result(
                        severity="HIGH",
                        finding="Potential auth bypass via trusted proxy header",
                        details=f"{candidate} switched {baseline.status_code}->{resp.status_code} using {header_set}",
                        remediation="Ignore user-supplied forwarding headers unless added by trusted proxy",
                    )
                    break
            jwt_none = await self.handler.async_get(
                candidate,
                allow_redirects=False,
                headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
            )
            if jwt_none and self._is_bypass(baseline.status_code, jwt_none.status_code):
                self.add_result(
                    severity="CRITICAL",
                    finding="Potential JWT none algorithm acceptance",
                    details=f"{candidate} accepted unsigned-like token behavior ({baseline.status_code}->{jwt_none.status_code})",
                    remediation="Reject alg=none tokens and enforce signature verification",
                )
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious authentication bypass behavior detected",
                details="Baseline and bypass probes did not indicate access-control bypass",
            )
