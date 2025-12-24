"""
VScanX XSS Detector Module
Safe reflected XSS vulnerability detection with custom payload support
"""

import logging
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from core.config import XSS_PAYLOADS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class XSSDetector(BaseModule):
    """
    Reflected XSS vulnerability detector
    Tests input parameters with safe payloads
    """

    def __init__(self, custom_payloads: List[str] = None, handler=None):
        super().__init__()
        self.name = "XSS Detector"
        self.description = "Reflected Cross-Site Scripting detection"
        self.version = "2.0.0"

        # Use provided handler or create new one
        self.handler = handler if handler else RequestHandler()

        # Verbose flag (default False) so helper methods can reference safely
        self.verbose = False

        # Use custom payloads if provided
        if custom_payloads:
            self.payloads = custom_payloads
        else:
            self.payloads = XSS_PAYLOADS

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute XSS detection on target URL

        Args:
            target: Target URL to test
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.xss_detector")
        self.clear_results()
        self.verbose = verbose

        logger.info("xss_start", extra={"target": target})
        if verbose:
            logger.debug("xss_payload_count", extra={"count": len(self.payloads)})

        # Get initial page
        response = self.handler.get(target)
        if not response:
            logger.error("xss_fetch_failed", extra={"target": target})
            return {"module": self.name, "target": target, "findings": []}

        # Find testable parameters
        params = self._extract_parameters(target)

        if not params:
            logger.info("xss_no_params", extra={"target": target})
            self.add_result(
                severity="INFO",
                finding="No testable parameters found",
                details="URL contains no query parameters",
            )
        else:
            logger.info("xss_params_found", extra={"count": len(params)})
            self._test_parameters(target, params)

        self.handler.close()

        return {"module": self.name, "target": target, "findings": self.get_results()}

    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract query parameters from URL

        Args:
            url: Target URL

        Returns:
            Dictionary of parameter names and values
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Flatten lists to single values
        return {k: v[0] if v else "" for k, v in params.items()}

    def _test_parameters(self, url: str, params: Dict[str, str]) -> None:
        """
        Test each parameter with XSS payloads

        Args:
            url: Base URL
            params: Parameters to test
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        logger = logging.getLogger("vscanx.module.xss_detector")
        for param_name, _original_value in params.items():
            logger.info("xss_param_test", extra={"param": param_name})

            for payload in self.payloads:
                if self.verbose:
                    logger.debug(
                        "xss_payload",
                        extra={"param": param_name, "payload": payload[:80]},
                    )

                if self._test_payload(base_url, params, param_name, payload):
                    self.add_result(
                        severity="HIGH",
                        finding=f"Reflected XSS in parameter '{param_name}'",
                        details=f"Payload reflected: {payload}",
                    )
                    logger.info("xss_vulnerable", extra={"param": param_name})
                    break  # Move to next parameter after finding vulnerability

    def _test_payload(
        self,
        base_url: str,
        params: Dict[str, str],
        test_param: str,
        payload: str,
        baseline_length: int = None,
        baseline_status: int = None,
    ) -> bool:
        """
        Test a single payload against a parameter

        Args:
            base_url: Base URL without query string
            params: All parameters
            test_param: Parameter to inject payload into
            payload: XSS payload to test
            baseline_length: (unused) kept for API compatibility with SQLi
            baseline_status: (unused) kept for API compatibility with SQLi

        Returns:
            True if vulnerable, False otherwise
        """
        # Create modified parameters
        test_params = params.copy()
        test_params[test_param] = payload

        # Make request
        response = self.handler.get(base_url, params=test_params)

        if not response:
            return False

        # Check if payload is reflected in response
        # Simple check: payload appears unencoded in HTML
        if payload in response.text:
            # Additional validation: check if it's in a dangerous context
            return self._validate_reflection(response.text, payload)

        return False

    def _validate_reflection(self, html: str, payload: str) -> bool:
        """
        Validate that reflection is actually exploitable

        Args:
            html: Response HTML
            payload: Tested payload

        Returns:
            True if likely exploitable, False otherwise
        """
        # Check if payload appears outside of safe contexts
        # This is a simplified check - production tools use more sophisticated methods

        # Look for payload in potentially dangerous locations
        dangerous_contexts = [
            f">{payload}<",  # Between tags
            f"='{payload}'",  # In attribute value
            f'="{payload}"',  # In attribute value
            f"={payload} ",  # In unquoted attribute
        ]

        logger = logging.getLogger("vscanx.module.xss_detector")

        # If payload appears between > and <, treat as dangerous unless it's clearly content
        # inside a valid tag pair (e.g. '<div>payload</div>')
        between_tags = f">{payload}<"
        if between_tags in html:
            idx = html.find(between_tags)
            pos_after_lt = idx + len(between_tags)
            next_char = html[pos_after_lt] if pos_after_lt < len(html) else ""

            # If a closing tag immediately follows the '<' after payload (e.g. </div>)
            if next_char != "/":
                # Check if the '>' before payload is actually the end of an opening tag
                pos_lt_before = html.rfind("<", 0, idx)
                if not (pos_lt_before != -1 and ">" not in html[pos_lt_before:idx]):
                    if self.verbose:
                        logger.debug("xss_dangerous_between_tags")
                    return True

        # Only check for dangerous contexts when payload looks like an active/XSS payload
        lc_payload = payload.lower()
        if any(k in lc_payload for k in ["<", "javascript", "script"]):
            # If payload contains HTML tags and is reflected verbatim, this is dangerous
            if "<" in lc_payload and payload in html:
                if self.verbose:
                    logger.debug("xss_dangerous_tag_reflection")
                return True

            # If payload looks like a javascript URI and appears verbatim, it's dangerous
            if "javascript:" in lc_payload and "javascript:" in html.lower():
                if self.verbose:
                    logger.debug("xss_dangerous_javascript_uri")
                return True

            for context in dangerous_contexts:
                if context in html:
                    # Special-case: if payload appears as >payload< but is immediately followed by a
                    # closing tag (</...>) then treat as content inside a proper element and skip
                    if context.startswith(">") and context.endswith("<"):
                        idx = html.find(context)
                        pos_after_lt = idx + len(context)
                        next_char = (
                            html[pos_after_lt] if pos_after_lt < len(html) else ""
                        )

                        # If a closing tag immediately follows the '<' after payload (e.g. </div>)
                        if next_char == "/":
                            continue

                        # If the '>' before payload is actually the end of an opening tag
                        # (e.g. '<div>payload</div>'), treat as safe and skip
                        pos_lt_before = html.rfind("<", 0, idx)
                        if pos_lt_before != -1 and ">" not in html[pos_lt_before:idx]:
                            # looks like an opening tag before payload, skip as likely safe
                            continue

                    if self.verbose:
                        logger.debug(
                            "xss_dangerous_context", extra={"context": context}
                        )
                    return True

        # If payload appears verbatim with script tags, it's likely vulnerable
        if "<script>" in lc_payload and payload in html:
            if self.verbose:
                logger.debug("xss_script_reflection")
            return True

        return False
