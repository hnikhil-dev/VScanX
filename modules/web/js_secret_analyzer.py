"""
VScanX JS Secret Analyzer
Discovers JavaScript files and scans for credentials and internal endpoints.
"""

import re
from urllib.parse import urljoin

from core.config import JS_SECRET_PATTERNS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class JSSecretAnalyzer(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "JS Secret Analyzer"
        self.description = "Extracts JS assets and scans for high-risk secrets/endpoints"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.endpoint_pattern = re.compile(
            r"""(?i)(?:fetch|axios|XMLHttpRequest|\.open)\s*\(?['"](/api/[A-Za-z0-9/_\-.?=&]+|https?://[A-Za-z0-9\-.]+/[A-Za-z0-9/_\-.?=&]*)['"]"""
        )
        self.script_src_pattern = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        artifacts = self._run_sync(target)
        return {
            "module": self.name,
            "target": target,
            "artifacts": artifacts,
            "findings": self.get_results(),
        }

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        artifacts = await self._run_async(target)
        return {
            "module": self.name,
            "target": target,
            "artifacts": artifacts,
            "findings": self.get_results(),
        }

    def _extract_js_urls(self, base_url: str, html: str):
        urls = set()
        for src in self.script_src_pattern.findall(html or ""):
            urls.add(urljoin(base_url, src))
        return sorted(urls)

    def _analyze_js_text(self, js_url: str, text: str):
        secret_hits = []
        endpoint_hits = []
        for name, pattern in JS_SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                snippet = match.group(0)[:120]
                secret_hits.append({"pattern": name, "value": snippet, "source": js_url})
        for m in self.endpoint_pattern.findall(text):
            endpoint_hits.append({"endpoint": m, "source": js_url})
        return secret_hits, endpoint_hits

    def _run_sync(self, target: str):
        landing = self.handler.get(target)
        if not landing:
            return {"files_scanned": 0, "secrets_found": 0, "endpoints_found": 0}
        js_urls = self._extract_js_urls(target, landing.text)
        all_secrets = []
        all_endpoints = []
        for js_url in js_urls[:40]:
            resp = self.handler.get(js_url)
            if not resp or resp.status_code >= 400:
                continue
            secrets, endpoints = self._analyze_js_text(js_url, resp.text)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)
        self._emit_findings(all_secrets, all_endpoints)
        return {
            "files_scanned": len(js_urls[:40]),
            "secrets_found": len(all_secrets),
            "endpoints_found": len(all_endpoints),
        }

    async def _run_async(self, target: str):
        landing = await self.handler.async_get(target)
        if not landing:
            return {"files_scanned": 0, "secrets_found": 0, "endpoints_found": 0}
        js_urls = self._extract_js_urls(target, landing.text)
        all_secrets = []
        all_endpoints = []
        for js_url in js_urls[:40]:
            resp = await self.handler.async_get(js_url)
            if not resp or resp.status_code >= 400:
                continue
            secrets, endpoints = self._analyze_js_text(js_url, resp.text)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)
        self._emit_findings(all_secrets, all_endpoints)
        return {
            "files_scanned": len(js_urls[:40]),
            "secrets_found": len(all_secrets),
            "endpoints_found": len(all_endpoints),
        }

    def _emit_findings(self, secrets, endpoints):
        for secret in secrets[:30]:
            self.add_result(
                severity="HIGH",
                finding=f"Potential secret in JavaScript ({secret['pattern']})",
                details=f"{secret['source']} -> {secret['value']}",
                remediation="Move secrets server-side and rotate leaked credentials immediately",
            )
        if endpoints:
            self.add_result(
                severity="INFO",
                finding="JavaScript exposed internal/API endpoints",
                details=", ".join(sorted({e["endpoint"] for e in endpoints})[:20]),
            )
        if not secrets and not endpoints:
            self.add_result(
                severity="INFO",
                finding="No obvious JS secrets or internal endpoints detected",
                details="Scanned JavaScript assets did not match configured leak patterns",
            )
