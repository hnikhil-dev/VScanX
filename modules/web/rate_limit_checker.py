"""
VScanX Rate Limit Checker
Validates whether endpoints enforce burst throttling and 429 protections.
"""

import asyncio
import time
from typing import Any, Dict

from core.config import RATE_LIMIT_BURST_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class RateLimitChecker(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "Rate Limit Checker"
        self.description = "Burst tests endpoints for effective throttling controls"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler(delay=0.05)

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        window_start = time.time()
        statuses = []
        for _ in range(RATE_LIMIT_BURST_REQUESTS):
            resp = self.handler.get(target, allow_redirects=False)
            if resp:
                statuses.append(resp.status_code)
            if time.time() - window_start > RATE_LIMIT_WINDOW_SECONDS:
                break
        analysis = self._analyze(statuses)
        self._emit_findings(analysis)
        return {
            "module": self.name,
            "target": target,
            "rate_limit_analysis": analysis,
            "findings": self.get_results(),
        }

    async def run_async(
        self, target: str, verbose: bool = False, **kwargs
    ) -> Dict[str, Any]:
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        statuses = []
        window_start = time.time()
        for _ in range(RATE_LIMIT_BURST_REQUESTS):
            resp = await self.handler.async_get(target, allow_redirects=False)
            if resp:
                statuses.append(resp.status_code)
            if time.time() - window_start > RATE_LIMIT_WINDOW_SECONDS:
                break
            await asyncio.sleep(0)

        analysis = self._analyze(statuses)
        self._emit_findings(analysis)
        return {
            "module": self.name,
            "target": target,
            "rate_limit_analysis": analysis,
            "findings": self.get_results(),
        }

    def _analyze(self, statuses) -> Dict[str, Any]:
        status_429 = statuses.count(429)
        status_403 = statuses.count(403)
        controls_present = status_429 > 0 or status_403 > 0
        return {
            "total_requests": len(statuses),
            "status_429": status_429,
            "status_403": status_403,
            "controls_present": controls_present,
        }

    def _emit_findings(self, analysis: Dict[str, Any]) -> None:
        if analysis["controls_present"]:
            self.add_result(
                severity="INFO",
                finding="Rate-limiting behavior detected",
                details=(
                    f"Burst responses: 429={analysis['status_429']}, "
                    f"403={analysis['status_403']}"
                ),
            )
        else:
            self.add_result(
                severity="MEDIUM",
                finding="No clear rate-limiting protection detected",
                details=(
                    f"{analysis['total_requests']} rapid requests completed without 429/403"
                ),
                remediation="Add per-IP and per-user burst limits with 429 responses",
            )
