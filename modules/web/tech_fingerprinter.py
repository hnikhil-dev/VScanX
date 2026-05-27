"""
VScanX Tech Stack Fingerprinter
Detects server/framework/CMS signals for selective scanning.
"""

import re
from typing import Any, Dict, List

from core.config import TECH_FINGERPRINT_PATTERNS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class TechFingerprinter(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "Tech Stack Fingerprinter"
        self.description = "Detects server, framework, and CMS technology markers"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        response = self.handler.get(target)
        if not response:
            return {"module": self.name, "target": target, "findings": []}
        profile = self._build_profile(response.headers, response.text)
        self._emit_findings(profile)
        return {
            "module": self.name,
            "target": target,
            "tech_profile": profile,
            "findings": self.get_results(),
        }

    async def run_async(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        response = await self.handler.async_get(target)
        if not response:
            return {"module": self.name, "target": target, "findings": []}
        profile = self._build_profile(response.headers, response.text)
        self._emit_findings(profile)
        return {
            "module": self.name,
            "target": target,
            "tech_profile": profile,
            "findings": self.get_results(),
        }

    def _build_profile(self, headers, body: str) -> Dict[str, Any]:
        haystack = " ".join(
            [
                str(headers.get("Server", "")),
                str(headers.get("X-Powered-By", "")),
                str(headers.get("X-Generator", "")),
                body[:6000],
            ]
        ).lower()
        detected: Dict[str, List[str]] = {"servers": [], "frameworks": [], "cms": []}
        for group, mapping in TECH_FINGERPRINT_PATTERNS.items():
            for name, pattern in mapping.items():
                if re.search(pattern, haystack, flags=re.IGNORECASE):
                    detected[group].append(name)
        is_static = len(detected["frameworks"]) == 0 and len(detected["cms"]) == 0 and "<?php" not in body.lower()
        return {
            "detected": detected,
            "is_likely_static": is_static,
            "response_headers_seen": [h for h in ["Server", "X-Powered-By", "X-Generator"] if headers.get(h)],
        }

    def _emit_findings(self, profile: Dict[str, Any]) -> None:
        detected = profile.get("detected", {})
        flattened = [
            *detected.get("servers", []),
            *detected.get("frameworks", []),
            *detected.get("cms", []),
        ]
        if flattened:
            self.add_result(
                severity="INFO",
                finding="Tech stack signals detected",
                details=", ".join(sorted(set(flattened))),
            )
        else:
            self.add_result(
                severity="INFO",
                finding="No strong technology signature detected",
                details="Limited fingerprint evidence in headers/body",
            )
