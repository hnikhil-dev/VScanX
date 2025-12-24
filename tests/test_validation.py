import pytest

from core.request_handler import validate_target
from core.utils import validate_scan_result_schema


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://example.com:8443",
        "192.168.1.10",
        "10.0.0.1:8080",
        "[2001:db8::1]",
        "[2001:db8::1]:443",
        "example.com",
        "sub.domain.example",
    ],
)
def test_validate_target_accepts_valid(target):
    assert validate_target(target) is True


@pytest.mark.parametrize(
    "target",
    [
        "",
        None,
        "http://",
        "http://:80",
        "http://example.com:99999",
        "http://example.com:0",
        "999.999.999.999",
        "no-dot-host",
    ],
)
def test_validate_target_rejects_invalid(target):
    assert validate_target(target) is False


def test_scan_result_schema_minimal_valid():
    results = {
        "target": "http://example.com",
        "scan_type": "web",
        "authenticated": False,
        "start_time": "2025-01-01T00:00:00Z",
        "duration": 0.1,
        "findings": [],
        "modules": [],
        "errors": [],
    }
    validate_scan_result_schema(results)  # should not raise
