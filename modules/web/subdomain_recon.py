"""
VScanX Subdomain Recon Suite
Performs passive and active DNS discovery for target domains.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from core.config import SUBDOMAIN_WORDLIST
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class SubdomainReconSuite(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "Subdomain Recon Suite"
        self.description = "Enumerates target subdomains using active DNS and passive hints"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()

    def run(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        domain = self._extract_domain(target)
        if not domain:
            self.add_result(
                severity="INFO",
                finding="Subdomain recon skipped",
                details="Target is not a public domain hostname",
            )
            return {"module": self.name, "target": target, "artifacts": {"count": 0}, "findings": self.get_results()}
        found = self._active_lookup_sync(domain)
        self._emit_findings(domain, found)
        return {
            "module": self.name,
            "target": target,
            "artifacts": {"count": len(found), "subdomains": found[:100]},
            "findings": self.get_results(),
        }

    async def run_async(self, target: str, verbose: bool = False, **kwargs):
        self.clear_results()
        domain = self._extract_domain(target)
        if not domain:
            self.add_result(
                severity="INFO",
                finding="Subdomain recon skipped",
                details="Target is not a public domain hostname",
            )
            return {"module": self.name, "target": target, "artifacts": {"count": 0}, "findings": self.get_results()}
        found = await self._active_lookup_async(domain)
        self._emit_findings(domain, found)
        return {
            "module": self.name,
            "target": target,
            "artifacts": {"count": len(found), "subdomains": found[:100]},
            "findings": self.get_results(),
        }

    def _extract_domain(self, target: str):
        raw = target
        if target.startswith(("http://", "https://")):
            raw = urlparse(target).hostname or ""
        raw = raw.strip().lower()
        if not raw or raw in ["localhost"]:
            return None
        try:
            ipaddress.ip_address(raw)
            return None
        except ValueError:
            pass
        if "." not in raw:
            return None
        return raw

    def _resolve(self, host: str):
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False

    def _active_lookup_sync(self, domain: str):
        found = []
        for sub in SUBDOMAIN_WORDLIST:
            candidate = f"{sub}.{domain}"
            if self._resolve(candidate):
                found.append(candidate)
        return sorted(set(found))

    async def _active_lookup_async(self, domain: str):
        async def check(sub):
            candidate = f"{sub}.{domain}"
            ok = await asyncio.to_thread(self._resolve, candidate)
            return candidate if ok else None

        results = await asyncio.gather(*(check(s) for s in SUBDOMAIN_WORDLIST))
        return sorted({r for r in results if r})

    def _emit_findings(self, domain: str, found):
        if found:
            severity = "MEDIUM" if len(found) >= 4 else "LOW"
            self.add_result(
                severity=severity,
                finding=f"Subdomains discovered for {domain}",
                details=", ".join(found[:20]),
                remediation="Review exposed subdomains for stale services and inconsistent security controls",
            )
        else:
            self.add_result(
                severity="INFO",
                finding=f"No subdomains discovered from default wordlist for {domain}",
                details="Consider larger passive/active recon datasets for broader coverage",
            )
