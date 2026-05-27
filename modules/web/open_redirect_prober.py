"""
VScanX Open Redirect Prober
Tests common redirect parameter sinks for external redirect behavior.
"""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.config import OPEN_REDIRECT_PARAM_NAMES
from core.request_handler import RequestHandler
from core.verify.engine import VerificationEngine
from modules.base_module import BaseModule


class OpenRedirectProber(BaseModule):
    def __init__(self, handler=None, attacker_url: str = "https://example.org/"):
        super().__init__()
        self.name = "Open Redirect Prober"
        self.description = "Probes redirect parameters for external redirect vulnerabilities"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.attacker_url = attacker_url
        self.verifier = VerificationEngine()
        self.request_cost = 3
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html", "application/json"]
        self.supported_technologies = ["generic-web"]
        self.consumes_events = ["crawl.inventory_ready"]
        self.emits_events = ["finding.normalization", "verification.completed", "finding.added"]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        artifacts = self._run_sync(target)
        return {"module": self.name, "target": target, "artifacts": artifacts, "findings": self.get_results()}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        artifacts = await self._run_async(target)
        return {"module": self.name, "target": target, "artifacts": artifacts, "findings": self.get_results()}

    def _candidate_params(self, target: str):
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        keys = set(qs.keys())
        common = [k for k in OPEN_REDIRECT_PARAM_NAMES if k in keys]
        return common, parsed, qs

    def _build_url(self, parsed, qs):
        query = urlencode({k: v[-1] for k, v in qs.items()}, doseq=False)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    def _is_external_location(self, location: str, original_host: str) -> bool:
        if not location:
            return False
        loc = location.strip()
        if loc.startswith("//"):
            loc = "https:" + loc
        try:
            parsed = urlparse(loc)
            if parsed.scheme in ["http", "https"] and parsed.netloc and parsed.netloc != original_host:
                return True
        except Exception:
            return False
        return False

    def _run_sync(self, target: str):
        params, parsed, qs = self._candidate_params(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No common redirect parameters detected",
                details="Consider testing specific app routes/flows known to redirect after login/logout",
            )
            return {"tested_params": 0, "vulnerable_params": 0}
        vulnerable = 0
        for key in params:
            mutated = dict(qs)
            mutated[key] = [self.attacker_url]
            url = self._build_url(parsed, mutated)
            resp = self.handler.get(url, allow_redirects=False)
            if not resp:
                continue
            location = resp.headers.get("Location", "")
            if resp.status_code in [301, 302, 303, 307, 308] and self._is_external_location(
                location, parsed.netloc
            ):
                vulnerable += 1
                # Negative control: redirect to same-host path (should not become external)
                neg = dict(qs)
                neg[key] = ["/"]
                neg_url = self._build_url(parsed, neg)
                vr = self.verifier.verify_open_redirect(
                    handler=self.handler,
                    test_url=url,
                    expected_external_location=self.attacker_url.rstrip("/"),
                    negative_control_url=neg_url,
                    runs=3,
                )
                self.add_result(
                    severity="HIGH" if vr.verified else "MEDIUM",
                    finding=f"Open redirect via parameter '{key}'",
                    details=f"Redirected to external location: {location} | {vr.notes}",
                    remediation="Validate redirect targets using allowlists and normalize/parse URLs server-side",
                    confidence=vr.confidence,
                    verified=vr.verified,
                    verification={"notes": vr.notes},
                    evidence=location,
                    parameter=key,
                    reproduction={
                        "type": "open_redirect",
                        "test_url": url,
                        "negative_control_url": neg_url,
                        "expected_external_location": self.attacker_url.rstrip("/"),
                        "runs": 3,
                    },
                )
        if vulnerable == 0:
            self.add_result(
                severity="INFO",
                finding="No open redirect behavior detected in common parameters",
                details="Tested redirect-like parameters did not redirect externally",
            )
        return {"tested_params": len(params), "vulnerable_params": vulnerable}

    async def _run_async(self, target: str):
        params, parsed, qs = self._candidate_params(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No common redirect parameters detected",
                details="Consider testing specific app routes/flows known to redirect after login/logout",
            )
            return {"tested_params": 0, "vulnerable_params": 0}
        vulnerable = 0
        for key in params:
            mutated = dict(qs)
            mutated[key] = [self.attacker_url]
            url = self._build_url(parsed, mutated)
            resp = await self.handler.async_get(url, allow_redirects=False)
            if not resp:
                continue
            location = resp.headers.get("Location", "")
            if resp.status_code in [301, 302, 303, 307, 308] and self._is_external_location(
                location, parsed.netloc
            ):
                vulnerable += 1
                neg = dict(qs)
                neg[key] = ["/"]
                neg_url = self._build_url(parsed, neg)
                # Verification uses sync handler to avoid complicating engine; acceptable (few calls)
                vr = self.verifier.verify_open_redirect(
                    handler=self.handler,
                    test_url=url,
                    expected_external_location=self.attacker_url.rstrip("/"),
                    negative_control_url=neg_url,
                    runs=3,
                )
                self.add_result(
                    severity="HIGH" if vr.verified else "MEDIUM",
                    finding=f"Open redirect via parameter '{key}'",
                    details=f"Redirected to external location: {location} | {vr.notes}",
                    remediation="Validate redirect targets using allowlists and normalize/parse URLs server-side",
                    confidence=vr.confidence,
                    verified=vr.verified,
                    verification={"notes": vr.notes},
                    evidence=location,
                    parameter=key,
                    reproduction={
                        "type": "open_redirect",
                        "test_url": url,
                        "negative_control_url": neg_url,
                        "expected_external_location": self.attacker_url.rstrip("/"),
                        "runs": 3,
                    },
                )
        if vulnerable == 0:
            self.add_result(
                severity="INFO",
                finding="No open redirect behavior detected in common parameters",
                details="Tested redirect-like parameters did not redirect externally",
            )
        return {"tested_params": len(params), "vulnerable_params": vulnerable}

