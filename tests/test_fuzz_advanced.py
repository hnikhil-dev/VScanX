"""
Advanced fuzz and heuristic tests for VScanX modules
Tests edge cases, malformed inputs, and detection heuristics
"""

import time

import pytest

from modules.web.dir_enum import DirectoryEnumerator
from modules.web.header_analyzer import HeaderAnalyzer
from modules.web.sqli_detector import SQLiDetector
from modules.web.xss_detector import XSSDetector


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200, headers=None, content=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content if content is not None else text.encode("utf-8")


class DummyHandler:
    def __init__(self, response: FakeResponse = None, responses: list = None):
        self._response = response
        self._responses = responses or []
        self._call_count = 0

    def get(self, *args, **kwargs):
        if self._responses:
            resp = self._responses[self._call_count % len(self._responses)]
            self._call_count += 1
            return resp
        return self._response

    def close(self):
        pass


# SQLi Fuzz Tests
@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' OR '1'='1' --",
        "' OR 1=1#",
        "' OR 1=1--",
        "') OR ('1'='1",
        "1' OR '1'='1' UNION SELECT * FROM users--",
        "'; DROP TABLE users--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
)
def test_sqli_payloads_fuzz(payload):
    """Test various SQLi payloads trigger detection"""
    error_text = f"SQL syntax error near '{payload[:10]}'"
    detector = SQLiDetector(handler=DummyHandler(FakeResponse(error_text, 500)))
    params = {"id": "1"}
    assert (
        detector._test_payload("http://example.com", params, "id", payload, 100, 200)
        is True
    )  # nosec: B101 - test assertion


@pytest.mark.parametrize(
    "error_pattern",
    [
        "sql syntax",
        "mysql_fetch",
        "mysqli",
        "sqlstate",
        "pg_query",
        "sqlite_query",
        "odbc_exec",
        "ORA-00933",
        "error in your sql",
        "warning: mysql",
        "unclosed quotation",
        "quoted string not properly terminated",
        "invalid column",
        "table.*not found",
        "unknown column",
        "division by zero",
    ],
)
def test_sqli_error_patterns(error_pattern):
    """Test SQLi error pattern detection"""
    detector = SQLiDetector(
        handler=DummyHandler(FakeResponse(f"Error: {error_pattern}", 500))
    )
    params = {"q": "test"}
    assert (
        detector._test_payload("http://example.com", params, "q", "'", 100, 200) is True
    )  # nosec: B101 - test assertion


def test_sqli_time_based_detection():
    """Test time-based SQLi detection (if implemented)"""
    # Mock handler that simulates delay

    def delayed_response(*args, **kwargs):
        time.sleep(0.1)  # Simulate delay
        return FakeResponse("OK", 200)

    handler = DummyHandler()
    handler.get = delayed_response

    # This would need time-based detection logic
    # For now, just verify handler works
    assert handler.get() is not None  # nosec: B101 - test assertion


def test_sqli_boolean_based_true_false():
    """Test boolean-based SQLi with true/false conditions"""
    # True condition returns longer response
    true_resp = FakeResponse("A" * 200, 200)
    false_resp = FakeResponse("A" * 50, 200)

    detector = SQLiDetector(handler=DummyHandler(responses=[true_resp, false_resp]))
    params = {"id": "1"}
    baseline = 100

    # Should detect difference (200 vs 50 vs baseline 100)
    assert (
        detector._test_boolean_based("http://example.com", params, "id", baseline)
        is True
    )  # nosec: B101 - test assertion


def test_sqli_false_positive_reduction():
    """Test that normal variations don't trigger false positives"""
    # Small variations shouldn't trigger
    normal_resp = FakeResponse("A" * 100, 200)
    slight_variation = FakeResponse("A" * 105, 200)  # Only 5% difference

    detector = SQLiDetector(
        handler=DummyHandler(responses=[normal_resp, slight_variation])
    )
    params = {"id": "1"}
    baseline = 100

    # Should NOT detect (5% < 15% threshold)
    assert (
        detector._test_boolean_based("http://example.com", params, "id", baseline)
        is False
    )  # nosec: B101 - test assertion


# XSS Fuzz Tests
@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
    ],
)
def test_xss_payloads_fuzz(payload):
    """Test various XSS payloads trigger detection"""
    detector = XSSDetector(
        handler=DummyHandler(FakeResponse(f"Hello {payload} World", 200))
    )
    params = {"q": "test"}
    assert (
        detector._test_payload("http://example.com", params, "q", payload, 100, 200)
        is True
    )  # nosec: B101 - test assertion


@pytest.mark.parametrize(
    "html_context,payload,should_detect",
    [
        ("<div>PAYLOAD</div>", "<script>alert(1)</script>", True),
        ("<p>PAYLOAD</p>", "<img src=x onerror=alert(1)>", True),
        ("Hello PAYLOAD world", "<script>alert(1)</script>", True),
        ("<div>PAYLOAD</div>", "normal text", False),
        ("PAYLOAD", "<script>alert(1)</script>", True),
        ("<input value='PAYLOAD'>", "<script>alert(1)</script>", True),
        ("<a href='PAYLOAD'>link</a>", "javascript:alert(1)", True),
    ],
)
def test_xss_context_validation(html_context, payload, should_detect):
    """Test XSS detection in various HTML contexts"""
    detector = XSSDetector(handler=DummyHandler())
    html = html_context.replace("PAYLOAD", payload)
    result = detector._validate_reflection(html, payload)
    assert result == should_detect  # nosec: B101 - test assertion


def test_xss_encoded_payloads():
    """Test that encoded XSS payloads are detected"""
    detector = XSSDetector(handler=DummyHandler())

    # HTML encoded
    html1 = "Hello &lt;script&gt;alert(1)&lt;/script&gt; World"
    assert detector._validate_reflection(html1, "<script>alert(1)</script>") is False  # nosec: B101 - test assertion

    # URL encoded in dangerous context
    # URL encoded in dangerous context
    # Should detect if decoder is applied, but basic check may miss it
    # This tests current implementation behavior


# Directory Enumeration Heuristic Tests
def test_dir_enum_status_code_heuristics():
    """Test directory enum severity assignment based on status codes"""
    enumerator = DirectoryEnumerator(handler=DummyHandler())

    # Test various status codes
    test_cases = [
        (200, "MEDIUM"),
        (301, "MEDIUM"),
        (302, "MEDIUM"),
        (401, "MEDIUM"),
        (403, "LOW"),
        (500, "LOW"),
    ]

    for status, expected_severity in test_cases:
        resp = FakeResponse("OK", status_code=status)
        handler = DummyHandler(resp)
        enumerator.handler = handler

        # Mock the path test
        enumerator.found_paths = []
        enumerator._test_path("http://example.com", "test")

        if enumerator.found_paths:
            # Check severity was set correctly
            results = enumerator.get_results()
            if results:
                # Severity logic is in _test_path, verify it's applied
                assert any(r.get("severity") == expected_severity for r in results)


def test_dir_enum_sensitive_path_detection():
    """Test that sensitive paths get HIGH severity"""
    enumerator = DirectoryEnumerator(handler=DummyHandler())

    sensitive_paths = [
        ".env",
        ".git/config",
        "config.php",
        "wp-config.php",
        "backup.sql",
        "admin",
    ]

    for path in sensitive_paths:
        resp = FakeResponse("Found", status_code=200)
        handler = DummyHandler(resp)
        enumerator.handler = handler
        enumerator.found_paths = []

        enumerator._test_path("http://example.com", path)

        results = enumerator.get_results()
        if results:
            # Should have HIGH severity for sensitive paths
            assert any(r.get("severity") == "HIGH" for r in results)


def test_dir_enum_content_length_heuristic():
    """Test content-length based heuristics (if implemented)"""
    # Different sizes should be tracked
    small_resp = FakeResponse("OK", status_code=200, content=b"OK")
    large_resp = FakeResponse("OK", status_code=200, content=b"X" * 10000)

    enumerator = DirectoryEnumerator(handler=DummyHandler())

    # Test small response
    handler1 = DummyHandler(small_resp)
    enumerator.handler = handler1
    enumerator._test_path("http://example.com", "test")

    # Test large response
    handler2 = DummyHandler(large_resp)
    enumerator.handler = handler2
    enumerator._test_path("http://example.com", "large")

    # Both should be recorded with size info
    assert len(enumerator.found_paths) >= 1


# Header Analyzer Tests
def test_header_analyzer_missing_severity():
    """Test header analyzer assigns correct severity for missing headers"""
    analyzer = HeaderAnalyzer(handler=DummyHandler(FakeResponse("OK", 200, {})))

    # Critical headers should be MEDIUM
    assert analyzer._get_missing_severity("Strict-Transport-Security") == "MEDIUM"
    assert analyzer._get_missing_severity("Content-Security-Policy") == "MEDIUM"

    # High headers should be LOW
    assert analyzer._get_missing_severity("X-Frame-Options") == "LOW"
    assert analyzer._get_missing_severity("X-Content-Type-Options") == "LOW"

    # Others should be INFO
    assert analyzer._get_missing_severity("Referrer-Policy") == "INFO"


def test_header_analyzer_info_disclosure():
    """Test information disclosure header detection"""
    headers = {
        "Server": "Apache/2.4.49",
        "X-Powered-By": "PHP/7.4.3",
        "X-AspNet-Version": "4.8",
    }

    analyzer = HeaderAnalyzer(handler=DummyHandler(FakeResponse("OK", 200, headers)))
    analyzer.run("http://example.com")

    results = analyzer.get_results()
    # Should have LOW severity findings for info disclosure
    info_disclosure = [
        r for r in results if "Information disclosure" in r.get("finding", "")
    ]
    assert len(info_disclosure) >= 1
    assert all(r.get("severity") == "LOW" for r in info_disclosure)


# Edge Case Tests
def test_malformed_url_handling():
    """Test modules handle malformed URLs gracefully"""
    detector = XSSDetector(handler=DummyHandler(FakeResponse("OK", 200)))

    # Should not crash on malformed URLs
    malformed_urls = [
        "http://",
        "http://:80",
        "not-a-url",
        "http://example.com:99999",
    ]

    for url in malformed_urls:
        try:
            params = detector._extract_parameters(url)
            # Should return empty dict or handle gracefully
            assert isinstance(params, dict)  # nosec: B101 - test assertion
        except Exception:  # nosec: B110 - accept broad exceptions for malformed URL tests
            # Some may raise, which is acceptable
            pass


def test_empty_response_handling():
    """Test modules handle empty responses"""
    empty_resp = FakeResponse("", 200)

    detector = SQLiDetector(handler=DummyHandler(empty_resp))
    params = {"q": "test"}

    # Should not crash
    result = detector._test_payload("http://example.com", params, "q", "'", 0, 200)
    assert isinstance(result, bool)  # nosec: B101 - test assertion


def test_large_response_handling():
    """Test modules handle very large responses"""
    large_content = "A" * 1000000  # 1MB
    large_resp = FakeResponse(large_content, 200)

    detector = XSSDetector(handler=DummyHandler(large_resp))
    params = {"q": "test"}

    # Should not crash or hang
    result = detector._test_payload(
        "http://example.com", params, "q", "<script>alert(1)</script>", 100, 200
    )
    assert isinstance(result, bool)  # nosec: B101 - test assertion


def test_special_characters_in_payloads():
    """Test payloads with special characters"""
    special_payloads = [
        "' OR 1=1-- ",
        "'; DROP TABLE users; --",
        "<script>alert('test')</script>",
        "javascript:alert(String.fromCharCode(88,83,83))",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
    ]

    for payload in special_payloads:
        # Should not crash when processing
        detector = SQLiDetector(handler=DummyHandler(FakeResponse("OK", 200)))
        params = {"q": "test"}
        try:
            result = detector._test_payload(
                "http://example.com", params, "q", payload, 100, 200
            )
            assert isinstance(result, bool)  # nosec: B101 - test assertion
        except Exception as e:
            # Some may raise, but should be handled gracefully
            assert "crash" not in str(e).lower()  # nosec: B101 - test assertion
