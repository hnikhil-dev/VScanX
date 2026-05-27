import httpx

from core.crawl.crawler import AuthenticatedCrawler, CrawlConfig


class DummyHandler:
    def __init__(self, mapping):
        self.mapping = mapping

    async def async_get(self, url: str, allow_redirects: bool = True):
        return self.mapping.get(url)


def _resp(url: str, ctype: str, body: str, truncated: bool = False):
    r = httpx.Response(
        200,
        headers={"Content-Type": ctype},
        content=body.encode("utf-8", errors="ignore"),
        request=httpx.Request("GET", url),
    )
    if truncated:
        r.extensions["vscanx_truncated"] = True
        r.extensions["vscanx_original_size"] = len(r.content) + 10
    return r


def test_crawler_records_skip_reasons_and_truncation():
    start = "http://example.local/"
    img = "http://example.local/logo.png"
    page = "http://example.local/page"

    mapping = {
        start: _resp(start, "text/html", f'<a href="{page}">p</a><a href="{img}">i</a>', truncated=True),
        page: _resp(page, "text/html", "<html><body>ok</body></html>"),
        img: _resp(img, "image/png", "xxxx"),
    }

    crawler = AuthenticatedCrawler(handler=DummyHandler(mapping))
    out = __import__("asyncio").run(
        crawler.crawl(start, CrawlConfig(max_urls=10, max_depth=1, max_frontier=10))
    )
    diag = out.get("diagnostics", {})
    assert diag.get("truncated_pages", 0) >= 1  # nosec: B101
    assert diag.get("denied_by_content_type", 0) >= 1  # nosec: B101
    assert isinstance(diag.get("skipped_reasons", {}), dict)  # nosec: B101

