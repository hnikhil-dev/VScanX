from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Normalize URL for deduplication:
    - drop fragments
    - sort query parameters
    - preserve scheme/host/path/query
    """
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url
    query_pairs = parse_qsl(p.query, keep_blank_values=True)
    query_pairs.sort(key=lambda kv: (kv[0], kv[1]))
    norm_query = urlencode(query_pairs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, norm_query, ""))


def same_origin(a: str, b: str) -> bool:
    pa = urlparse(a)
    pb = urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

