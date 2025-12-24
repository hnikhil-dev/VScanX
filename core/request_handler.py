"""
VScanX Request Handler with Authentication Support
Safe HTTP wrapper with rate limiting, retries, and session management
"""

import json
import os
import re
import time
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

# Rate limiting configuration
DEFAULT_DELAY = 1.0  # seconds between requests
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]


class RequestHandler:
    """
    Ethical HTTP request handler with authentication support
    Enforces rate limiting and manages sessions
    """

    def __init__(
        self,
        delay: float = DEFAULT_DELAY,
        custom_headers: Dict[str, str] = None,
        debug_capture: bool = False,
    ):
        """
        Initialize request handler with authentication support

        Args:
            delay: Seconds to wait between requests
            custom_headers: Custom headers (auth tokens, API keys, etc.)
        """
        self.delay = delay
        self.last_request_time = 0
        self.session = requests.Session()
        self.authenticated = False
        self.custom_headers = custom_headers or {}
        self.debug_capture = debug_capture
        self._last_debug: Dict[str, str] = {}

        # Set default headers
        self.session.headers.update(
            {
                "User-Agent": USER_AGENTS[0],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        # Add custom headers
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)

    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a redacted copy of headers for safe logging/export."""
        sensitive = {"authorization", "cookie", "set-cookie", "x-api-key"}
        return {
            k: "<redacted>" if k.lower() in sensitive else v for k, v in headers.items()
        }

    def _redact_payload(self, payload: Dict[str, str]) -> Dict[str, str]:
        """Redact common secret keys in body/query for debug capture."""
        secret_keys = {
            "password",
            "pass",
            "token",
            "apikey",
            "api_key",
            "secret",
            "auth",
            "authorization",
        }
        return {
            k: "<redacted>" if k.lower() in secret_keys else v
            for k, v in payload.items()
        }

    def get_last_debug_capture(self) -> Dict[str, str]:
        """Return last captured request/response metadata (redacted)."""
        return self._last_debug

    def login(
        self,
        login_url: str,
        credentials: Dict[str, str],
        method: str = "POST",
        success_indicator: str = None,
    ) -> bool:
        """
        Authenticate with target website

        Args:
            login_url: URL of login endpoint
            credentials: Dict with 'username' and 'password'
            method: HTTP method (POST or GET)
            success_indicator: String to check in response (indicates success)

        Returns:
            True if login successful, False otherwise
        """
        print(f"[*] Attempting authentication at {login_url}")

        try:
            if method.upper() == "POST":
                response = self.session.post(
                    login_url,
                    data=credentials,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            else:
                response = self.session.get(
                    login_url,
                    params=credentials,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

            # Check if login successful
            if success_indicator:
                if success_indicator.lower() in response.text.lower():
                    print("[+] Authentication successful!")
                    self.authenticated = True
                    return True
                else:
                    print("[!] Authentication failed - success indicator not found")
                    return False
            elif response.status_code in [200, 302]:
                # Assume success if we got cookies and 200/302
                if len(self.session.cookies) > 0:
                    print("[+] Authentication successful (cookies received)!")
                    self.authenticated = True
                    return True
                else:
                    print("[!] Authentication uncertain - no cookies received")
                    return False
            else:
                print(
                    f"[!] Authentication failed - status code: {response.status_code}"
                )
                return False

        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return False

    def set_bearer_token(self, token: str) -> None:
        """
        Set Bearer token for API authentication

        Args:
            token: Bearer token string
        """
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        print("[+] Bearer token configured")

    def set_api_key(self, key: str, header_name: str = "X-API-Key") -> None:
        """
        Set API key header

        Args:
            key: API key value
            header_name: Header name for API key
        """
        self.session.headers[header_name] = key
        self.authenticated = True
        print(f"[+] API key configured in {header_name}")

    def save_session(self, filename: str = "session.json") -> None:
        """
        Save current session cookies to file

        Args:
            filename: File to save session
        """
        cookies_dict = dict(self.session.cookies)
        headers_dict = dict(self.session.headers)

        session_data = {
            "cookies": cookies_dict,
            "headers": headers_dict,
            "authenticated": self.authenticated,
        }

        os.makedirs("sessions", exist_ok=True)
        filepath = os.path.join("sessions", filename)

        with open(filepath, "w") as f:
            json.dump(session_data, f, indent=2)

        print(f"[+] Session saved to {filepath}")

    def load_session(self, filename: str = "session.json") -> bool:
        """
        Load session from file

        Args:
            filename: File to load session from

        Returns:
            True if loaded successfully
        """
        filepath = os.path.join("sessions", filename)

        if not os.path.exists(filepath):
            print(f"[!] Session file not found: {filepath}")
            return False

        try:
            with open(filepath, "r") as f:
                session_data = json.load(f)

            # Restore cookies
            for name, value in session_data.get("cookies", {}).items():
                self.session.cookies.set(name, value)

            # Restore headers (except User-Agent)
            for name, value in session_data.get("headers", {}).items():
                if name.lower() != "user-agent":
                    self.session.headers[name] = value

            self.authenticated = session_data.get("authenticated", False)

            print(f"[+] Session loaded from {filepath}")
            return True

        except Exception as e:
            print(f"[!] Error loading session: {e}")
            return False

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def get(
        self, url: str, params: Dict = None, **kwargs
    ) -> Optional[requests.Response]:
        """
        Safe GET request with authentication support

        Args:
            url: Target URL
            params: Query parameters
            **kwargs: Additional requests arguments

        Returns:
            Response object or None if failed
        """
        self._rate_limit()

        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    timeout=kwargs.get("timeout", REQUEST_TIMEOUT),
                    allow_redirects=kwargs.get("allow_redirects", True),
                )
                if self.debug_capture and response is not None:
                    self._last_debug = {
                        "method": "GET",
                        "url": url,
                        "params": json.dumps(self._redact_payload(params or {})),
                        "request_headers": json.dumps(
                            self._redact_headers(dict(self.session.headers))
                        ),
                        "status_code": str(response.status_code),
                        "response_headers": json.dumps(
                            self._redact_headers(dict(response.headers))
                        ),
                    }
                return response

            except requests.exceptions.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    print(f"[!] Request failed after {MAX_RETRIES} attempts: {e}")
                    return None
                time.sleep(1)

        return None

    def post(
        self, url: str, data: Dict = None, json_data: Dict = None, **kwargs
    ) -> Optional[requests.Response]:
        """
        Safe POST request with authentication support

        Args:
            url: Target URL
            data: Form data
            json_data: JSON data
            **kwargs: Additional requests arguments

        Returns:
            Response object or None if failed
        """
        self._rate_limit()

        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.post(
                    url,
                    data=data,
                    json=json_data,
                    timeout=kwargs.get("timeout", REQUEST_TIMEOUT),
                    allow_redirects=kwargs.get("allow_redirects", True),
                )
                if self.debug_capture and response is not None:
                    self._last_debug = {
                        "method": "POST",
                        "url": url,
                        "data": json.dumps(self._redact_payload(data or {})),
                        "json": json.dumps(self._redact_payload(json_data or {})),
                        "request_headers": json.dumps(
                            self._redact_headers(dict(self.session.headers))
                        ),
                        "status_code": str(response.status_code),
                        "response_headers": json.dumps(
                            self._redact_headers(dict(response.headers))
                        ),
                    }
                return response

            except requests.exceptions.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    print(f"[!] Request failed after {MAX_RETRIES} attempts: {e}")
                    return None
                time.sleep(1)

        return None

    def is_authenticated(self) -> bool:
        """Check if handler is authenticated"""
        return self.authenticated

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies"""
        return dict(self.session.cookies)

    def close(self) -> None:
        """Close the session"""
        self.session.close()


def validate_target(target: str) -> bool:
    """
    Validate target URL, IP, or hostname

    Args:
        target: Target to validate

    Returns:
        True if valid, False otherwise
    """
    import ipaddress

    if not target or not isinstance(target, str):
        return False

    # Normalize and parse URL if scheme present; otherwise treat as host[:port]
    try:
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port
        else:
            # Accept optional port with IPv6 in brackets or IPv4/hostname
            match = re.match(r"^\[([^\]]+)\](?::(\d{1,5}))?$", target)
            if match:
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else None
            else:
                # Split only on last colon to allow IPv6 check later
                if ":" in target and target.count(":") == 1:
                    host_part, port_part = target.rsplit(":", 1)
                    hostname, port = host_part, int(port_part)
                else:
                    hostname, port = target, None
    except (ValueError, AttributeError):
        return False

    if port is not None and not (0 < port < 65536):
        return False

    if not hostname:
        return False

    # Validate IP (v4/v6) or hostname
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # If looks like dotted IPv4 but failed ipaddress parsing, reject (e.g., 999.999.999.999)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        return False

    # Hostname RFC-ish validation: labels 1-63 chars, overall <=253
    if len(hostname) > 253:
        return False

    label_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    if all(label_regex.match(label) for label in labels):
        return True

    return False
