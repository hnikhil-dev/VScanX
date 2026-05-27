"""
VScanX Cryptographic and TLS Analyzer
Checks TLS versions, certificate validity, HSTS headers, and plain HTTP transport weaknesses.
"""

import socket
import ssl
from urllib.parse import urlparse

from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class CryptoTLSAnalyzer(BaseModule):
    def __init__(self, handler=None):
        super().__init__()
        self.name = "Crypto and TLS Analyzer"
        self.description = "Analyzes transport encryption, SSL/TLS configurations, and certificate issues (OWASP A04:2026)"
        self.version = "1.0.0"
        self.handler = handler if handler else RequestHandler()
        self.request_cost = 2
        self.required_auth_state = "any"
        self.supported_content_types = ["text/html"]
        self.supported_technologies = ["generic-web"]

    def run(self, target: str, **kwargs):
        self.clear_results()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
            
        parsed = urlparse(target)
        scheme = parsed.scheme
        hostname = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        
        # 1. Plaintext HTTP Check
        if scheme == "http":
            self.add_result(
                severity="HIGH",
                finding="Insecure Plaintext HTTP Transport",
                details=f"The application uses plain HTTP ({target}) without SSL/TLS. Sensitive data is transmitted in cleartext.",
                remediation="Configure the server to redirect all HTTP traffic to HTTPS and use TLS 1.2 or TLS 1.3.",
                confidence="HIGH",
                verified=True,
                tags=["A04:2026", "cryptography", "tls"]
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}
            
        # 2. HSTS and TLS Check
        self._analyze_tls(hostname, port)
        self._analyze_hsts(target)
        
        if not self.get_results():
            self.add_result(
                severity="INFO",
                finding="Secure TLS Configuration Detected",
                details="SSL/TLS transport uses robust configurations and valid certificates.",
            )
            
        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, **kwargs):
        # We can run it in a thread pool using the base wrapper
        return await self.run_async_wrapper(target, **kwargs)

    async def run_async_wrapper(self, target: str, **kwargs):
        import asyncio
        return await asyncio.to_thread(self.run, target, **kwargs)

    def _analyze_tls(self, hostname: str, port: int):
        if not hostname:
            return
            
        # Check standard TLS connection
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    cert = ssock.getpeercert()
                    
                    # Log security specs
                    if cipher:
                        cipher_name, cipher_ver, cipher_bits = cipher
                        if cipher_bits < 128:
                            self.add_result(
                                severity="HIGH",
                                finding="Weak Cipher Suite Supported",
                                details=f"Connection negotiated with weak cipher {cipher_name} ({cipher_bits} bits).",
                                remediation="Disable support for cipher suites with key sizes less than 128 bits.",
                                confidence="HIGH",
                                tags=["A04:2026", "cryptography"]
                            )
                            
                    # Deprecated protocol version check
                    if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        self.add_result(
                            severity="HIGH",
                            finding=f"Deprecated TLS Version Supported ({version})",
                            details=f"The server allows connections using {version}, which contains known cryptographic flaws.",
                            remediation="Disable support for SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                            confidence="HIGH",
                            tags=["A04:2026", "tls"]
                        )
        except ssl.SSLCertVerificationError as e:
            self.add_result(
                severity="HIGH",
                finding="SSL Certificate Verification Failed",
                details=f"Certificate is untrusted or self-signed. SSL Error: {str(e)}",
                remediation="Install a valid SSL certificate signed by a trusted Certificate Authority (CA).",
                confidence="HIGH",
                verified=True,
                tags=["A04:2026", "tls"]
            )
        except Exception as e:
            # General connection failure or timeout
            pass

    def _analyze_hsts(self, target: str):
        resp = self.handler.get(target)
        if not resp:
            return
            
        hsts = resp.headers.get("Strict-Transport-Security")
        if not hsts:
            self.add_result(
                severity="MEDIUM",
                finding="Strict-Transport-Security (HSTS) Header Missing",
                details="The server does not send the Strict-Transport-Security header on HTTPS responses, leaving it open to SSL stripping attacks.",
                remediation="Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to all HTTPS responses.",
                confidence="HIGH",
                tags=["A04:2026", "hsts", "headers"]
            )
        else:
            if "max-age=0" in hsts:
                self.add_result(
                    severity="LOW",
                    finding="HSTS max-age is set to 0 (Disabled)",
                    details="Strict-Transport-Security header is present but disabled with max-age=0.",
                    remediation="Set the Strict-Transport-Security max-age directive to at least 31536000 seconds (1 year).",
                    confidence="HIGH",
                    tags=["A04:2026", "hsts"]
                )
