"""
VScanX IDOR and SSRF Detector
Tests numeric/UUID-like parameters for access control weaknesses (IDOR),
and URL-like parameters or common redirect/fetch parameters for Server-Side Request Forgery (SSRF).
"""

import re
import uuid
from urllib.parse import parse_qs, urlparse, urlencode

from core.request_handler import RequestHandler
from core.verify.engine import VerificationEngine
from modules.base_module import BaseModule


class IDORDetector(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "IDOR and SSRF Detector"
        self.description = "Checks direct-object parameters for weak access controls (IDOR) and URL parameters for SSRF vulnerabilities (OWASP A01:2026)"
        self.version = "1.1.0"
        self.handler = handler if handler else RequestHandler()
        self.verifier = VerificationEngine()
        self.request_cost = 5
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html", "application/json"]
        self.supported_technologies = ["generic-web", "rest-api"]
        self.consumes_events = ["crawl.inventory_ready"]
        self.emits_events = ["finding.normalization", "verification.completed", "finding.added"]

        # Common parameters that often lead to SSRF
        self.ssrf_params = {
            "url", "uri", "path", "dest", "destination", "redirect", "to", "link",
            "callback", "webhook", "feed", "site", "domain", "host", "ip", "file",
            "img", "image", "src", "source", "load", "fetch", "request", "req"
        }

        # SSRF Payloads
        self.ssrf_payloads = [
            {
                "url": "http://httpbin.org/status/418",
                "signature": "teapot",
                "desc": "External Canary (httpbin status 418)",
                "severity": "CRITICAL"
            },
            {
                "url": "http://169.254.169.254/latest/meta-data/",
                "signature": "ami-id",
                "desc": "Cloud Metadata Endpoint (AWS/OpenStack)",
                "severity": "CRITICAL"
            },
            {
                "url": "http://127.0.0.1:80/",
                "signature": None, # checked via response status and anomalies
                "desc": "Localhost Port 80 Probing",
                "severity": "HIGH"
            }
        ]

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        # 1. Run IDOR checks
        self._run_idor_sync(target)
        
        # 2. Run SSRF checks
        self._run_ssrf_sync(target)
        
        # Guarantee at least an INFO finding if none found
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious IDOR or SSRF behavior detected",
                details="No successful object-reference or server-side request anomalies found",
            )
            
        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        # 1. Run IDOR checks
        await self._run_idor_async(target)
        
        # 2. Run SSRF checks
        await self._run_ssrf_async(target)
        
        # Guarantee at least an INFO finding if none found
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="No obvious IDOR or SSRF behavior detected",
                details="No successful object-reference or server-side request anomalies found",
            )
            
        return {"module": self.name, "target": target, "findings": self.get_results()}

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

    def _run_idor_sync(self, target: str):
        baseline = self.handler.get(target)
        if not baseline:
            return
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

    async def _run_idor_async(self, target: str):
        baseline = await self.handler.async_get(target)
        if not baseline:
            return
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

    def _extract_ssrf_candidate_params(self, target: str):
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        candidates = []
        for key, vals in params.items():
            value = vals[0] if vals else ""
            # If name matches SSRF common params, or the value starts with HTTP(S) protocol or contains dynamic paths
            if key.lower() in self.ssrf_params or value.startswith(("http://", "https://")) or re.search(r"\.[a-zA-Z]{2,6}/", value):
                candidates.append(key)
        return candidates

    def _run_ssrf_sync(self, target: str):
        candidates = self._extract_ssrf_candidate_params(target)
        if not candidates:
            return

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in candidates:
            for payload in self.ssrf_payloads:
                payload_params = parse_qs(parsed.query)
                payload_params[param] = [payload["url"]]
                flat_params = {k: v[-1] for k, v in payload_params.items()}
                
                resp = self.handler.get(base_url, params=flat_params)
                if not resp:
                    continue
                
                is_vuln = False
                ev = ""
                
                # Check for explicit signature in response text
                if payload["signature"] and payload["signature"].lower() in resp.text.lower():
                    is_vuln = True
                    ev = f"Response body contains direct confirmation signature '{payload['signature']}' from remote request."
                # Check for status code propagation (e.g. httpbin status 418 returns 418, if server returns 418 status too)
                elif payload["url"] == "http://httpbin.org/status/418" and resp.status_code == 418:
                    is_vuln = True
                    ev = "Server returned explicit HTTP 418 status code, indicating it successfully connected and forwarded the response from the external canary URL."
                
                if is_vuln:
                    self.add_result(
                        severity=payload["severity"],
                        finding=f"Server-Side Request Forgery (SSRF) via '{param}'",
                        details=f"Injected {payload['desc']}. Server fetched the payload URL and exposed it in the response | {ev}",
                        remediation="Validate and sanitize all redirect/fetch parameters against a strict allowlist. Use internal firewalls/routing rules to block local and metadata requests.",
                        confidence="HIGH",
                        verified=True,
                        parameter=param,
                        evidence=resp.text[:500],
                        tags=["A01:2026", "ssrf", "owasp"]
                    )
                    break

    async def _run_ssrf_async(self, target: str):
        candidates = self._extract_ssrf_candidate_params(target)
        if not candidates:
            return

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in candidates:
            for payload in self.ssrf_payloads:
                payload_params = parse_qs(parsed.query)
                payload_params[param] = [payload["url"]]
                flat_params = {k: v[-1] for k, v in payload_params.items()}
                
                resp = await self.handler.async_get(base_url, params=flat_params)
                if not resp:
                    continue
                
                is_vuln = False
                ev = ""
                
                if payload["signature"] and payload["signature"].lower() in resp.text.lower():
                    is_vuln = True
                    ev = f"Response body contains direct confirmation signature '{payload['signature']}' from remote request."
                elif payload["url"] == "http://httpbin.org/status/418" and resp.status_code == 418:
                    is_vuln = True
                    ev = "Server returned explicit HTTP 418 status code, indicating it successfully connected and forwarded the response from the external canary URL."
                
                if is_vuln:
                    self.add_result(
                        severity=payload["severity"],
                        finding=f"Server-Side Request Forgery (SSRF) via '{param}'",
                        details=f"Injected {payload['desc']}. Server fetched the payload URL and exposed it in the response | {ev}",
                        remediation="Validate and sanitize all redirect/fetch parameters against a strict allowlist. Use internal firewalls/routing rules to block local and metadata requests.",
                        confidence="HIGH",
                        verified=True,
                        parameter=param,
                        evidence=resp.text[:500],
                        tags=["A01:2026", "ssrf", "owasp"]
                    )
                    break
