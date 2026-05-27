from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse


@dataclass
class VariantResult:
    url: str
    status_code: int
    length: int


class DefensiveVariantGenerator:
    """
    Defensive request-variant generator.

    Goal: detect inconsistent URL normalization/canonicalization and routing behavior
    (useful for defenders and bug triage).

    It deliberately avoids payload obfuscation/encoding engines intended to bypass controls.
    """

    def generate_variants(self, target: str) -> List[str]:
        parsed = urlparse(target)
        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return []

        path = parsed.path or "/"
        variants: List[str] = []

        def build(p: str) -> str:
            return urlunparse((parsed.scheme, parsed.netloc, p, parsed.params, parsed.query, parsed.fragment))

        # Conservative normalization variants
        if not path.endswith("/"):
            variants.append(build(path + "/"))
        if path.endswith("/") and path != "/":
            variants.append(build(path.rstrip("/")))

        # Duplicate slashes
        if "//" not in path:
            variants.append(build(path.replace("/", "//", 1)))

        # Dot-segment variant (kept minimal)
        if path.endswith("/"):
            variants.append(build(path + "./"))
        else:
            variants.append(build(path + "/./"))

        # Case variant (only safe if path has letters)
        if any(c.isalpha() for c in path):
            variants.append(build(path.swapcase()))

        # De-duplicate, keep within safe bounds
        uniq = []
        seen = set()
        for v in variants:
            if v not in seen and v != target:
                seen.add(v)
                uniq.append(v)
        return uniq[:8]

    def analyze(
        self,
        handler,
        target: str,
        max_variants: int = 8,
        strict: bool = True,
    ) -> Dict[str, Any]:
        baseline = handler.get(target, allow_redirects=False)
        if not baseline:
            return {"tested": 0, "inconsistencies": 0, "variants": []}

        base_status = baseline.status_code
        base_len = len(baseline.content or b"")
        variants = self.generate_variants(target)[:max_variants]

        inconsistencies: List[VariantResult] = []
        for v in variants:
            resp = handler.get(v, allow_redirects=False)
            if not resp:
                continue
            status = resp.status_code
            length = len(resp.content or b"")

            # Strict mode: only status changes (ultra-low false positives)
            # Non-strict: also consider large content deltas.
            if strict:
                inconsistent = status != base_status
            else:
                inconsistent = status != base_status or abs(length - base_len) > max(120, int(base_len * 0.35))

            if inconsistent:
                inconsistencies.append(VariantResult(url=v, status_code=status, length=length))

        return {
            "tested": len(variants),
            "inconsistencies": len(inconsistencies),
            "strict": strict,
            "baseline": {"status_code": base_status, "length": base_len},
            "variants": [i.__dict__ for i in inconsistencies][:20],
        }
