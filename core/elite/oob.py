import secrets
from dataclasses import dataclass


@dataclass
class OOBManager:
    """
    Minimal OOB hook manager.
    This does NOT perform exploitation; it only provisions unique callback URLs
    for authorized testing modules to use (e.g. blind SSRF/RCE detectors).
    """

    base_url: str = ""

    def enabled(self) -> bool:
        return bool(self.base_url)

    def make_callback(self, tag: str = "vscanx") -> str:
        if not self.base_url:
            return ""
        token = secrets.token_urlsafe(10)
        base = self.base_url.rstrip("/")
        safe_tag = "".join(c for c in (tag or "vscanx") if c.isalnum() or c in "-_")[:24]
        return f"{base}/{safe_tag}/{token}"
