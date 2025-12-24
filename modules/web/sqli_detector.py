"""
VScanX SQL Injection Detector Module
Detects SQL injection vulnerabilities
"""

import logging
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from core.config import SQLI_PAYLOADS
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class SQLiDetector(BaseModule):
    """
    SQL Injection vulnerability detector
    Tests input parameters with SQLi payloads
    Supports: error-based, boolean-based, and time-based detection
    """

    def __init__(self, custom_payloads: List[str] = None, handler=None):
        super().__init__()
        self.name = "SQL Injection Detector"
        self.description = (
            "SQL injection vulnerability detection (error-based, boolean-based)"
        )
        self.version = "2.0.0"

        # Use provided handler or create new one
        self.handler = handler if handler else RequestHandler()

        # Use custom payloads if provided, otherwise use defaults
        self.payloads = custom_payloads if custom_payloads else SQLI_PAYLOADS

        # Verbose flag (default False) so helper methods can reference safely
        self.verbose = False

        # Database error patterns for error-based detection
        self.error_patterns = [
            r"sql syntax",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"mysqli",
            r"sqlstate",
            r"pg_query",
            r"pg_exec",
            r"sqlite_query",
            r"sqlite_exec",
            r"odbc_exec",
            r"ora-\d+",
            r"error in your sql",
            r"warning: mysql",
            r"unclosed quotation",
            r"quoted string not properly terminated",
            r"literal not closed",
            r"syntax error",
            r"unexpected end of statement",
            r"invalid column",
            r"table.*not found",
            r"unknown column",
            r"division by zero",
            r"operator missing",
        ]

        # Boolean-based test payloads (true/false pairs)
        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' OR '1'='1", "' OR '1'='2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1' OR '1'='1", "1' OR '1'='2"),
        ]

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute SQLi detection on target URL

        Args:
            target: Target URL to test
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.sqli_detector")
        self.clear_results()
        self.verbose = verbose

        logger.info("sqli_start", extra={"target": target})

        # Get initial page
        response = self.handler.get(target)
        if not response:
            logger.error("sqli_fetch_failed", extra={"target": target})
            return {"module": self.name, "target": target, "findings": []}

        # Store baseline response
        baseline_length = len(response.text)
        baseline_status = response.status_code

        # Find testable parameters
        params = self._extract_parameters(target)

        if not params:
            logger.info("sqli_no_params", extra={"target": target})
            self.add_result(
                severity="INFO",
                finding="No testable parameters found",
                details="URL contains no query parameters",
            )
        else:
            logger.info("sqli_params_found", extra={"count": len(params)})
            self._test_parameters(target, params, baseline_length, baseline_status)

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

    def _test_parameters(
        self,
        url: str,
        params: Dict[str, str],
        baseline_length: int,
        baseline_status: int,
    ) -> None:
        """
        Test each parameter with SQLi payloads
        Tries error-based, boolean-based, and traditional detection

        Args:
            url: Base URL
            params: Parameters to test
            baseline_length: Normal response length
            baseline_status: Normal status code
        """
        logger = logging.getLogger("vscanx.module.sqli_detector")
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name, _original_value in params.items():
            logger.info("sqli_param_test", extra={"param": param_name})

            # Try error-based detection first
            if self._test_error_based(base_url, params, param_name):
                self.add_result(
                    severity="HIGH",
                    finding=f"SQL Injection (Error-based) in '{param_name}'",
                    details="Database error patterns detected in response",
                    remediation="Implement prepared statements or parameterized queries",
                )
                logging.getLogger("vscanx.module.sqli_detector").info(
                    "sqli_vulnerable_error_based", extra={"param": param_name}
                )
                continue

            # Try boolean-based detection
            bool_result = self._test_boolean_based(
                base_url, params, param_name, baseline_length
            )
            if bool_result:
                self.add_result(
                    severity="HIGH",
                    finding=f"SQL Injection (Boolean-based) in '{param_name}'",
                    details="Boolean-based condition differences detected",
                    remediation="Implement prepared statements or parameterized queries",
                )
                logging.getLogger("vscanx.module.sqli_detector").info(
                    "sqli_vulnerable_boolean", extra={"param": param_name}
                )
                continue

            # Try traditional payload-based detection
            for payload in self.payloads:
                if self._test_payload(
                    base_url,
                    params,
                    param_name,
                    payload,
                    baseline_length,
                    baseline_status,
                ):
                    self.add_result(
                        severity="HIGH",
                        finding=f"SQL Injection in parameter '{param_name}'",
                        details=f"Payload triggered anomaly: {payload}",
                        remediation="Implement prepared statements or parameterized queries",
                    )
                    logging.getLogger("vscanx.module.sqli_detector").info(
                        "sqli_vulnerable_payload", extra={"param": param_name}
                    )
                    break

    def _test_payload(
        self,
        base_url: str,
        params: Dict[str, str],
        test_param: str,
        payload: str,
        baseline_length: int,
        baseline_status: int,
    ) -> bool:
        """
        Test a single payload against a parameter

        Args:
            base_url: Base URL without query string
            params: All parameters
            test_param: Parameter to inject payload into
            payload: SQLi payload to test
            baseline_length: Normal response length
            baseline_status: Normal status code

        Returns:
            True if vulnerable, False otherwise
        """
        import re

        logger = logging.getLogger("vscanx.module.sqli_detector")

        # Create modified parameters
        test_params = params.copy()
        test_params[test_param] = payload

        # Make request
        response = self.handler.get(base_url, params=test_params)

        if not response:
            return False

        response_lower = response.text.lower()

        # Check for error messages using regex patterns
        for pattern in self.error_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                if self.verbose:
                    logger.debug("sqli_error_pattern", extra={"pattern": pattern})
                return True

        # Check for response length anomalies (potential blind SQLi)
        length_diff = abs(len(response.text) - baseline_length)
        if length_diff > baseline_length * 0.2:  # 20% difference
            if self.verbose:
                logger.debug("sqli_length_anomaly", extra={"diff": length_diff})
            return True

        # Check for status code changes
        if response.status_code != baseline_status and response.status_code >= 500:
            if self.verbose:
                logger.debug(
                    "sqli_status_anomaly", extra={"status": response.status_code}
                )
            return True

        return False

    def _test_error_based(
        self, base_url: str, params: Dict[str, str], test_param: str
    ) -> bool:
        """
        Test for error-based SQL injection
        Looks for database error patterns in response

        Args:
            base_url: Base URL without query string
            params: All parameters
            test_param: Parameter to test

        Returns:
            True if error-based SQLi detected, False otherwise
        """
        import re

        logger = logging.getLogger("vscanx.module.sqli_detector")

        # Test with quote characters to trigger syntax errors
        error_payloads = ["'", '"', "';", '";', "1'", '1"']

        for error_payload in error_payloads:
            test_params = params.copy()
            test_params[test_param] = error_payload

            response = self.handler.get(base_url, params=test_params)

            if not response:
                continue

            response_lower = response.text.lower()

            # Check for database error patterns
            for pattern in self.error_patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    if self.verbose:
                        logger.debug(
                            "sqli_error_based_match", extra={"pattern": pattern}
                        )
                    return True

        return False

    def _test_boolean_based(
        self,
        base_url: str,
        params: Dict[str, str],
        test_param: str,
        baseline_length: int,
    ) -> bool:
        """
        Test for boolean-based blind SQL injection
        Compares responses to true/false conditions

        Args:
            base_url: Base URL without query string
            params: All parameters
            test_param: Parameter to test
            baseline_length: Normal response length

        Returns:
            True if boolean-based SQLi detected, False otherwise
        """

        logger = logging.getLogger("vscanx.module.sqli_detector")
        for true_payload, false_payload in self.boolean_payloads:
            # Test true condition
            test_params = params.copy()
            test_params[test_param] = true_payload
            response_true = self.handler.get(base_url, params=test_params)

            # Test false condition
            test_params = params.copy()
            test_params[test_param] = false_payload
            response_false = self.handler.get(base_url, params=test_params)

            if not response_true or not response_false:
                continue

            # Compare responses
            true_len = len(response_true.text)
            false_len = len(response_false.text)

            # If lengths differ significantly, likely boolean-based SQLi
            length_diff = abs(true_len - false_len)
            if length_diff > baseline_length * 0.15:  # 15% threshold
                if self.verbose:
                    logger.debug(
                        "sqli_boolean_diff",
                        extra={
                            "true_len": true_len,
                            "false_len": false_len,
                            "payload_true": true_payload,
                            "payload_false": false_payload,
                        },
                    )
                return True

        return False
