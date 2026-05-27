"""
VScanX IDOR Detector
Tests numeric/UUID-like parameters for access control weaknesses.
"""

import re
import uuid
from urllib.parse import parse_qs, urlparse

from core.request_handler import RequestHandler
from core.verify.engine import VerificationEngine
from modules.base_module import BaseModule


class IDORDetector(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "IDOR Detector"
        self.description = "Checks direct-object parameters for weak access controls"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.verifier = VerificationEngine()
        self.request_cost = 4
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html", "application/json"]
        self.supported_technologies = ["generic-web", "rest-api"]
        self.consumes_events = ["crawl.inventory_ready"]
        self.emits_events = ["finding.normalization", "verification.completed", "finding.added"]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        result = self._run_sync(target)
        return {"module": self.name, "target": target, "findings": result}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        result = await self._run_async(target)
        return {"module": self.name, "target": target, "findings": result}

    def _extract_candidate_params(self, target: str):
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        candidates = {}
        for key, vals in params.items():
            value = vals[0] if vals else ""
            if re.fullmatch(r"\d+", value):
                candidates[key] = value
            elif re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                value,
            ):
                candidates[key] = value
        return candidates

    def _mutate(self, value: str):
        if re.fullmatch(r"\d+", value):
            num = int(value)
            return [str(max(0, num - 1)), str(num + 1)]
        try:
            parsed_uuid = uuid.UUID(value)
            other = uuid.uuid4()
            if str(other) == str(parsed_uuid):
                other = uuid.uuid4()
            return [str(other)]
        except Exception:
            return []

    def _run_sync(self, target: str):
        baseline = self.handler.get(target)
        if not baseline:
            return []
        baseline_status = baseline.status_code
        baseline_len = len(baseline.text)
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        candidates = self._extract_candidate_params(target)
        for param, value in candidates.items():
            for mutated in self._mutate(value):
                payload_params = parse_qs(parsed.query)
                payload_params[param] = [mutated]
                flat_params = {k: v[-1] for k, v in payload_params.items()}
                resp = self.handler.get(base_url, params=flat_params)
                if not resp:
                    continue
                if resp.status_code in [200, 206] and baseline_status in [200, 206]:
                    if abs(len(resp.text) - baseline_len) > max(25, int(baseline_len * 0.1)):
                        test_url = str(resp.request.url) if getattr(resp, "request", None) else base_url
                        vr = self.verifier.verify_response_anomaly(
                            handler=self.handler,
                            baseline_url=target,
                            test_url=test_url,
                            runs=3,
                        )
                        self.add_result(
                            severity="HIGH" if vr.verified else "MEDIUM",
                            finding=f"Potential IDOR on parameter '{param}'",
                            details=f"Object id changed from {value} to {mutated} with successful response | {vr.notes}",
                            remediation="Enforce object-level authorization checks on resource identifiers",
                            confidence=vr.confidence,
                            verified=vr.verified,
                            verification={"notes": vr.notes},
                            parameter=param,
                            reproduction={
                                "type": "response_anomaly",
                                "baseline_url": target,
                                "test_url": test_url,
                                "runs": 3,
                            },
                        )
                        break
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious IDOR behavior detected",
                details="No successful object-reference anomalies found",
            )
        return self.get_results()

    async def _run_async(self, target: str):
        baseline = await self.handler.async_get(target)
        if not baseline:
            return []
        baseline_status = baseline.status_code
        baseline_len = len(baseline.text)
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        candidates = self._extract_candidate_params(target)
        for param, value in candidates.items():
            for mutated in self._mutate(value):
                payload_params = parse_qs(parsed.query)
                payload_params[param] = [mutated]
                flat_params = {k: v[-1] for k, v in payload_params.items()}
                resp = await self.handler.async_get(base_url, params=flat_params)
                if not resp:
                    continue
                if resp.status_code in [200, 206] and baseline_status in [200, 206]:
                    if abs(len(resp.text) - baseline_len) > max(25, int(baseline_len * 0.1)):
                        test_url = str(resp.request.url) if getattr(resp, "request", None) else base_url
                        vr = self.verifier.verify_response_anomaly(
                            handler=self.handler,
                            baseline_url=target,
                            test_url=test_url,
                            runs=3,
                        )
                        self.add_result(
                            severity="HIGH" if vr.verified else "MEDIUM",
                            finding=f"Potential IDOR on parameter '{param}'",
                            details=f"Object id changed from {value} to {mutated} with successful response | {vr.notes}",
                            remediation="Enforce object-level authorization checks on resource identifiers",
                            confidence=vr.confidence,
                            verified=vr.verified,
                            verification={"notes": vr.notes},
                            parameter=param,
                            reproduction={
                                "type": "response_anomaly",
                                "baseline_url": target,
                                "test_url": test_url,
                                "runs": 3,
                            },
                        )
                        break
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious IDOR behavior detected",
                details="No successful object-reference anomalies found",
            )
        return self.get_results()
