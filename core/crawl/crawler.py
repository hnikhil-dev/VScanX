from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Set
from urllib.parse import parse_qs, urljoin, urlparse

from core.crawl.html_extract import extract_from_html
from core.crawl.url_utils import normalize_url, same_origin


@dataclass
class CrawlConfig:
    max_urls: int = 60
    max_depth: int = 2
    include_forms: bool = True
    include_js_routes: bool = True
    max_frontier: int = 500
    max_parse_chars: int = 200_000


class AuthenticatedCrawler:
    """
    Session-aware crawler designed for ethical scanning:
    - stays on same origin
    - deduplicates via normalization
    - supports robots.txt + sitemap.xml ingestion
    - extracts links, script src, and forms
    - lightweight JS route discovery (safe regex heuristics)
    """

    def __init__(self, handler):
        self.handler = handler
        self._js_route_re = re.compile(r"""(?i)(/api/[A-Za-z0-9/_\-.?=&]+)""")
        # Conservative content-type gating for reliability (avoid heavy binaries).
        self._deny_ctype_prefixes = (
            "image/",
            "video/",
            "audio/",
            "font/",
        )
        self._deny_ctype_substrings = (
            "application/octet-stream",
            "application/zip",
            "application/x-gzip",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/pdf",
        )

    async def crawl(self, start_url: str, config: CrawlConfig) -> Dict[str, Any]:
        start_url = normalize_url(start_url)
        parsed_start = urlparse(start_url)
        start_origin = f"{parsed_start.scheme}://{parsed_start.netloc}"
        visited: Set[str] = set()
        frontier = deque([{"url": start_url, "depth": 0}])
        max_frontier_len = 1
        skipped_reasons: Dict[str, int] = {}

        def _skip(reason: str) -> None:
            skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1

        discovered_forms: List[Dict[str, Any]] = []
        discovered_scripts: Set[str] = set()
        discovered_param_names: Set[str] = set()
        params_by_url: Dict[str, List[str]] = {}
        api_endpoints: Set[str] = set()
        spa_routes: Set[str] = set()
        truncated_pages = 0
        denied_by_ctype = 0

        # Seed from robots/sitemap (best effort)
        for seed in await self._seed_from_robots_and_sitemap(start_url):
            if len(frontier) >= max(10, int(config.max_frontier)):
                break
            frontier.append({"url": seed, "depth": 0})

        while frontier and len(visited) < config.max_urls:
            item = frontier.popleft()
            url = normalize_url(item["url"])
            depth = int(item.get("depth", 0))
            if url in visited:
                continue
            if not same_origin(url, start_url):
                _skip("off_origin")
                continue
            if depth > config.max_depth:
                _skip("max_depth")
                continue
            visited.add(url)

            resp = await self.handler.async_get(url, allow_redirects=True)
            if not resp or resp.status_code >= 400:
                _skip("fetch_failed")
                continue

            ctype = (resp.headers.get("Content-Type") or "").lower()
            if any(ctype.startswith(p) for p in self._deny_ctype_prefixes) or any(
                s in ctype for s in self._deny_ctype_substrings
            ):
                denied_by_ctype += 1
                _skip("denied_content_type")
                continue

            # Respect handler-level truncation markers and keep parsing bounded.
            try:
                if getattr(resp, "extensions", {}).get("vscanx_truncated"):
                    truncated_pages += 1
            except Exception:
                pass

            try:
                text = (resp.text or "")[: max(1024, int(config.max_parse_chars))]
            except Exception:
                text = ""
                _skip("decode_failed")

            # Quick API detection for budgeting/target selection later.
            try:
                if "/api/" in urlparse(url).path:
                    api_endpoints.add(url)
            except Exception:
                pass

            # Parse HTML
            if "text/html" in ctype or "<html" in text.lower():
                extracted = extract_from_html(text)
                # Deterministic queueing: sort extracted links.
                for href in sorted(extracted["links"] or []):
                    full = normalize_url(urljoin(url, href))
                    if same_origin(full, start_url) and full not in visited:
                        if depth + 1 <= config.max_depth and len(frontier) < int(config.max_frontier):
                            frontier.append({"url": full, "depth": depth + 1})
                            max_frontier_len = max(max_frontier_len, len(frontier))
                            qp = urlparse(full).query
                            if qp:
                                keys = list(parse_qs(qp).keys())
                                if keys:
                                    discovered_param_names.update(keys)
                                    params_by_url[full] = sorted(set(keys))
                        else:
                            _skip("frontier_full")

                for src in sorted(extracted["scripts"] or []):
                    full = normalize_url(urljoin(url, src))
                    if same_origin(full, start_url):
                        discovered_scripts.add(full)

                if config.include_forms:
                    for f in extracted["forms"]:
                        action = f.get("action") or url
                        full_action = normalize_url(urljoin(url, action))
                        if same_origin(full_action, start_url):
                            discovered_forms.append(
                                {
                                    "page": url,
                                    "action": full_action,
                                    "method": f.get("method", "GET"),
                                    "inputs": f.get("inputs", []),
                                }
                            )

                # Lightweight SPA route inference:
                # - fragments like "#/app/dashboard"
                # - history API calls pushState(..., ..., '/route')
                # This improves crawl intelligence without executing JS.
                try:
                    for frag in re.findall(r"(?i)#\/[A-Za-z0-9/_\-.]+", text):
                        spa_routes.add(frag.lstrip("#"))
                    for m in re.findall(
                        r"(?i)pushState\([^,]+,[^,]+,(['\"])(.*?)\1\)",
                        text,
                    ):
                        # m is a tuple(matchquote, route)
                        route = m[1] if isinstance(m, tuple) and len(m) > 1 else ""
                        if route.startswith("/"):
                            spa_routes.add(route)
                            spafull = normalize_url(start_origin + route)
                            if same_origin(spafull, start_url) and spafull not in visited:
                                if depth + 1 <= config.max_depth:
                                    frontier.append({"url": spafull, "depth": depth + 1})
                except Exception:
                    pass

            # JS route discovery: fetch a few scripts and extract /api/ routes
            js_routes: Set[str] = set()
            # Budget JS fetching to avoid excessive requests on large sites.
            js_fetch_budget = max(10, min(40, config.max_urls // 2))
            js_fetched = 0
            if config.include_js_routes and discovered_scripts:
                for js_url in sorted(list(discovered_scripts))[:15]:
                    if js_fetched >= js_fetch_budget:
                        break
                    js_resp = await self.handler.async_get(js_url, allow_redirects=True)
                    js_fetched += 1
                    if not js_resp or js_resp.status_code >= 400:
                        _skip("js_fetch_failed")
                        continue
                    js_text = ""
                    try:
                        js_text = (js_resp.text or "")[:200_000]
                    except Exception:
                        _skip("js_decode_failed")
                        js_text = ""
                    for m in self._js_route_re.findall(js_text):
                        full = normalize_url(urljoin(start_url, m))
                        if same_origin(full, start_url):
                            js_routes.add(full)
                            api_endpoints.add(full)

            for r in sorted(js_routes):
                if r not in visited and depth + 1 <= config.max_depth:
                    if len(frontier) < int(config.max_frontier):
                        frontier.append({"url": r, "depth": min(depth + 1, config.max_depth)})
                        max_frontier_len = max(max_frontier_len, len(frontier))
                    else:
                        _skip("frontier_full")

            # Also track param-bearing pages discovered even if HTML parsing fails.
            try:
                qp = urlparse(url).query
                if qp:
                    keys = list(parse_qs(qp).keys())
                    if keys:
                        discovered_param_names.update(keys)
                        params_by_url[url] = sorted(set(keys))
            except Exception:
                pass

            # JSON content: try to harvest embedded endpoint strings.
            # (Best-effort; never fail the crawl if parsing fails.)
            if "application/json" in ctype or text.lstrip().startswith(("{", "[")):
                try:
                    for rel in re.findall(r"""(?i)['"](/api/[A-Za-z0-9/_\-.?=&]+)['"]""", text[:20000]):
                        full = normalize_url(urljoin(start_origin, rel))
                        if same_origin(full, start_url):
                            api_endpoints.add(full)
                    for absu in re.findall(r"""(?i)['"](https?://[^'"]+/api/[A-Za-z0-9/_\-.?=&]+)['"]""", text[:20000]):
                        full = normalize_url(absu)
                        if same_origin(full, start_url):
                            api_endpoints.add(full)
                except Exception:
                    pass

        # Extract param-bearing URLs for selective probing
        param_urls = [u for u in visited if urlparse(u).query]
        # Ensure param names are complete (covers URLs discovered via non-HTML paths)
        for u in param_urls:
            try:
                qp = urlparse(u).query
                if qp:
                    keys = list(parse_qs(qp).keys())
                    if keys:
                        discovered_param_names.update(keys)
                        params_by_url.setdefault(u, sorted(set(keys)))
            except Exception:
                continue

        return {
            "start_url": start_url,
            "visited_count": len(visited),
            "urls": sorted(visited)[:1000],
            "param_urls": sorted(param_urls)[:250],
            "param_names": sorted(discovered_param_names)[:200],
            "params_by_url": {k: v for k, v in list(params_by_url.items())[:250]},
            "scripts": sorted(discovered_scripts)[:250],
            "forms": discovered_forms[:250],
            "api_endpoints": sorted(api_endpoints)[:250],
            "spa_routes": sorted(spa_routes)[:200],
            "diagnostics": {
                "max_urls": int(config.max_urls),
                "max_depth": int(config.max_depth),
                "max_frontier": int(config.max_frontier),
                "max_parse_chars": int(config.max_parse_chars),
                "frontier_highwater": int(max_frontier_len),
                "skipped_reasons": skipped_reasons,
                "truncated_pages": int(truncated_pages),
                "denied_by_content_type": int(denied_by_ctype),
            },
        }

    async def _seed_from_robots_and_sitemap(self, start_url: str) -> List[str]:
        p = urlparse(start_url)
        base = f"{p.scheme}://{p.netloc}"
        seeds: Set[str] = set()

        robots = await self.handler.async_get(f"{base}/robots.txt", allow_redirects=True)
        if robots and robots.status_code < 400:
            for line in (robots.text or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm:
                        seeds.add(normalize_url(sm))
                if line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
                    try:
                        path = line.split(":", 1)[1].strip()
                        if path.startswith("/"):
                            seeds.add(normalize_url(base + path))
                    except Exception:
                        pass

        # Try default sitemap.xml if not specified
        if not any("sitemap" in s for s in seeds):
            seeds.add(normalize_url(f"{base}/sitemap.xml"))

        # Parse sitemap URLs (best-effort, regex to avoid extra deps)
        expanded: Set[str] = set()
        for s in list(seeds)[:3]:
            sm_resp = await self.handler.async_get(s, allow_redirects=True)
            if not sm_resp or sm_resp.status_code >= 400:
                continue
            for loc in re.findall(r"<loc>([^<]+)</loc>", sm_resp.text or "", flags=re.I):
                full = normalize_url(loc.strip())
                if same_origin(full, start_url):
                    expanded.add(full)
        return sorted(expanded)[:50]
