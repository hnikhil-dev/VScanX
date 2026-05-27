from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List, Tuple


class _Extractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict] = []
        self._active_form: Dict | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]):
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and attr.get("href"):
            self.links.append(attr["href"])
        if tag.lower() == "script" and attr.get("src"):
            self.scripts.append(attr["src"])
        if tag.lower() == "form":
            self._active_form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "GET").upper(),
                "inputs": [],
            }
        if tag.lower() == "input" and self._active_form is not None:
            name = attr.get("name", "")
            itype = (attr.get("type") or "text").lower()
            value = attr.get("value", "")
            if name:
                self._active_form["inputs"].append({"name": name, "type": itype, "value": value})

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None


def extract_from_html(html: str) -> Dict[str, List]:
    p = _Extractor()
    try:
        p.feed(html or "")
    except Exception:
        # nosec B110
        # tolerate broken HTML
        pass
    return {"links": p.links, "scripts": p.scripts, "forms": p.forms}
