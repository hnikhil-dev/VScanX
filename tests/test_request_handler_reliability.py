import httpx

from core.request_handler import RequestHandler


def test_apply_body_cap_truncates_and_marks_extensions():
    h = RequestHandler(max_response_bytes=64 * 1024)
    r = httpx.Response(200, content=b"x" * (128 * 1024))
    out = h._apply_body_cap(r)
    assert out is not None  # nosec: B101
    assert len(out.content) == 64 * 1024  # nosec: B101
    assert out.extensions.get("vscanx_truncated") is True  # nosec: B101
    assert out.extensions.get("vscanx_original_size") == 128 * 1024  # nosec: B101


def test_request_handler_stats_shape():
    h = RequestHandler()
    s = h.get_stats()
    assert "requests_total" in s  # nosec: B101
    assert "latency_ms_avg" in s  # nosec: B101
    assert s.get("max_response_bytes") is not None  # nosec: B101
