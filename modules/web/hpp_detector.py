"""
VScanX HTTP Parameter Pollution Detector
Tests duplicate-parameter handling differences in backend processing.
"""

from urllib.parse import parse_qs, urlparse

from core.config import HPP_PAYLOAD_SUFFIXES
from core.request_handler import RequestHandler
from core.verify.engine import VerificationEngine
from modules.base_module import BaseModule


class HPPDetector(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "HTTP Parameter Pollution Detector"
        self.description = "Detects behavior changes from duplicate parameter injection"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
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
        self._run_sync(target)
        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        await self._run_async(target)
        return {"module": self.name, "target": target, "findings": self.get_results()}

    def _extract_params(self, target: str):
        parsed = urlparse(target)
        return parse_qs(parsed.query), f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _build_polluted_params(self, params, target_key, suffix):
        polluted = {}
        for k, vals in params.items():
            base = vals[0] if vals else ""
            if k == target_key:
                polluted[k] = f"{base}&{k}={suffix}"
            else:
                polluted[k] = base
        return polluted

    def _run_sync(self, target: str):
        params, base_url = self._extract_params(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No HPP testable parameters detected",
                details="URL contains no query parameters",
            )
            return
        baseline = self.handler.get(base_url, params={k: v[0] for k, v in params.items()})
        if not baseline:
            return
        base_len = len(baseline.text)
        for key in params.keys():
            for suffix in HPP_PAYLOAD_SUFFIXES:
                polluted = self._build_polluted_params(params, key, suffix)
                resp = self.handler.get(base_url, params=polluted)
                if not resp:
                    continue
                status_change = resp.status_code != baseline.status_code
                size_change = abs(len(resp.text) - base_len) > max(30, int(base_len * 0.15))
                if status_change or size_change:
                    test_url = str(resp.request.url) if getattr(resp, "request", None) else base_url
                    base_url_full = str(baseline.request.url) if getattr(baseline, "request", None) else base_url
                    vr = self.verifier.verify_response_anomaly(
                        handler=self.handler,
                        baseline_url=base_url_full,
                        test_url=test_url,
                        runs=3,
                    )
                    self.add_result(
                        severity="MEDIUM" if vr.verified else "LOW",
                        finding=f"Potential HPP behavior change on '{key}'",
                        details=f"Duplicate-style payload changed response ({baseline.status_code}/{base_len} -> {resp.status_code}/{len(resp.text)}) | {vr.notes}",
                        remediation="Normalize duplicate query parameter handling consistently before authorization/filtering",
                        confidence=vr.confidence,
                        verified=vr.verified,
                        verification={"notes": vr.notes},
                        evidence=str(resp.status_code),
                        parameter=key,
                        reproduction={
                            "type": "response_anomaly",
                            "baseline_url": base_url_full,
                            "test_url": test_url,
                            "runs": 3,
                        },
                    )
                    break
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious HPP behavior anomalies detected",
                details="Duplicate parameter probes did not cause significant backend differences",
            )

    async def _run_async(self, target: str):
        params, base_url = self._extract_params(target)
        if not params:
            self.add_result(
                severity="INFO",
                finding="No HPP testable parameters detected",
                details="URL contains no query parameters",
            )
            return
        baseline = await self.handler.async_get(base_url, params={k: v[0] for k, v in params.items()})
        if not baseline:
            return
        base_len = len(baseline.text)
        for key in params.keys():
            for suffix in HPP_PAYLOAD_SUFFIXES:
                polluted = self._build_polluted_params(params, key, suffix)
                resp = await self.handler.async_get(base_url, params=polluted)
                if not resp:
                    continue
                status_change = resp.status_code != baseline.status_code
                size_change = abs(len(resp.text) - base_len) > max(30, int(base_len * 0.15))
                if status_change or size_change:
                    test_url = str(resp.request.url) if getattr(resp, "request", None) else base_url
                    base_url_full = str(baseline.request.url) if getattr(baseline, "request", None) else base_url
                    vr = self.verifier.verify_response_anomaly(
                        handler=self.handler,
                        baseline_url=base_url_full,
                        test_url=test_url,
                        runs=3,
                    )
                    self.add_result(
                        severity="MEDIUM" if vr.verified else "LOW",
                        finding=f"Potential HPP behavior change on '{key}'",
                        details=f"Duplicate-style payload changed response ({baseline.status_code}/{base_len} -> {resp.status_code}/{len(resp.text)}) | {vr.notes}",
                        remediation="Normalize duplicate query parameter handling consistently before authorization/filtering",
                        confidence=vr.confidence,
                        verified=vr.verified,
                        verification={"notes": vr.notes},
                        evidence=str(resp.status_code),
                        parameter=key,
                        reproduction={
                            "type": "response_anomaly",
                            "baseline_url": base_url_full,
                            "test_url": test_url,
                            "runs": 3,
                        },
                    )
                    break
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious HPP behavior anomalies detected",
                details="Duplicate parameter probes did not cause significant backend differences",
            )
