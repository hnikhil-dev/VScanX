import httpx

from core.state.reverify import reverify_results


class DummyHandler:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url: str, allow_redirects: bool = False):
        return self.mapping.get(url)


def _resp(url: str, status: int = 200, body: str = "", headers=None):
    headers = headers or {}
    return httpx.Response(
        status,
        headers=headers,
        content=(body or "").encode("utf-8", errors="ignore"),
        request=httpx.Request("GET", url),
    )


def test_replay_verify_open_redirect_updates_state():
    test_url = "http://t.local/login?next=https://example.org/"
    neg_url = "http://t.local/login?next=/"
    h = DummyHandler(
        {
            test_url: _resp(test_url, 302, "", headers={"Location": "https://example.org/"}),
            neg_url: _resp(neg_url, 302, "", headers={"Location": "/"}),
        }
    )
    results = {
        "findings": [
            {
                "finding_id": "X",
                "module": "Open Redirect Prober",
                "severity": "MEDIUM",
                "description": "Open redirect",
                "reproduction": {
                    "type": "open_redirect",
                    "test_url": test_url,
                    "negative_control_url": neg_url,
                    "expected_external_location": "https://example.org",
                    "runs": 3,
                },
            }
        ]
    }
    out, st = reverify_results(results, h)
    f = out["findings"][0]
    assert st["reverified"] == 1  # nosec: B101
    assert f["verification_state"] in ["VERIFIED", "CANDIDATE"]  # nosec: B101
    assert "enrichment_history" in f  # nosec: B101
