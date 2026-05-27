from core.crawl.url_utils import normalize_url, same_origin


def test_normalize_url_sorts_query_and_drops_fragment():
    u = "https://example.com/a?b=2&a=1#frag"
    n = normalize_url(u)
    assert "#frag" not in n  # nosec: B101
    assert n.endswith("/a?a=1&b=2")  # nosec: B101


def test_same_origin():
    assert same_origin("https://a.com/x", "https://a.com/y") is True  # nosec: B101
    assert same_origin("https://a.com/x", "http://a.com/y") is False  # nosec: B101
