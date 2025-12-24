from modules.web.sqli_detector import SQLiDetector
from modules.web.xss_detector import XSSDetector


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class DummyHandler:
    def __init__(self, response: FakeResponse):
        self._response = response

    def get(self, *args, **kwargs):
        return self._response


def test_sqli_payload_detects_error_pattern():
    detector = SQLiDetector(
        handler=DummyHandler(FakeResponse("SQL syntax error near 'test'", 500))
    )
    params = {"q": "test"}
    assert (
        detector._test_payload("http://example.com", params, "q", "payload", 100, 200)
        is True
    )


def test_sqli_payload_detects_length_anomaly():
    detector = SQLiDetector(handler=DummyHandler(FakeResponse("A" * 150, 200)))
    params = {"q": "test"}
    # baseline length 100, response 150 => 50% diff > 20%
    assert (
        detector._test_payload("http://example.com", params, "q", "payload", 100, 200)
        is True
    )


def test_sqli_payload_detects_status_anomaly():
    detector = SQLiDetector(handler=DummyHandler(FakeResponse("OK", 503)))
    params = {"q": "test"}
    assert (
        detector._test_payload("http://example.com", params, "q", "payload", 100, 200)
        is True
    )


def test_xss_validate_reflection_dangerous_context():
    detector = XSSDetector(handler=DummyHandler(FakeResponse("", 200)))
    # Dangerous context: between tags
    html = "Hello >PAYLOAD< world"
    assert detector._validate_reflection(html, "PAYLOAD") is True  # nosec: B101 - test assertion


def test_xss_validate_reflection_script_tag():
    detector = XSSDetector(handler=DummyHandler(FakeResponse("", 200)))
    payload = "<script>alert(1)</script>"
    html = f"prefix {payload} suffix"
    assert detector._validate_reflection(html, payload) is True
