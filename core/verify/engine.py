from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class VerificationResult:
    verified: bool
    confidence: str
    similarity: float
    notes: str


class VerificationEngine:
    """
    Precision & verification engine (Tier‑1):
    - multi-run determinism checks
    - negative controls
    - similarity scoring
    - confidence levels
    """

    def similarity(self, a: str, b: str) -> float:
        a = a or ""
        b = b or ""
        return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()

    def _normalize_text(self, text: str) -> str:
        """
        Normalize response text to reduce noise from dynamic tokens.

        This is intentionally conservative: it only strips well-known high-variance
        token patterns (UUIDs, long hex/base64, timestamps, and number runs).
        """
        import re

        t = (text or "").strip()
        if len(t) < 4:
            return t

        # UUIDs / GUIDs
        t = re.sub(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "[uuid]",
            t,
        )
        # Epoch timestamps
        t = re.sub(r"\b\d{10,13}\b", "[ts]", t)
        # ISO-ish timestamps
        t = re.sub(
            r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b",
            "[ts]",
            t,
        )
        # Long hex blobs
        t = re.sub(r"\b[0-9a-fA-F]{16,}\b", "[hex]", t)
        # Base64-ish blobs (common in tokens)
        t = re.sub(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", "[b64]", t)
        # Numeric runs: keep structure but drop exact values
        t = re.sub(r"\b\d+\b", "[num]", t)
        return t

    def _entropy(self, text: str) -> float:
        import math
        from collections import Counter

        t = (text or "")[:4000]
        if not t:
            return 0.0
        counts = Counter(t)
        total = len(t)
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def verify_open_redirect(
        self,
        handler,
        test_url: str,
        expected_external_location: str,
        negative_control_url: str,
        runs: int = 3,
    ) -> VerificationResult:
        external_hits = 0
        last_loc = ""
        for _ in range(max(1, runs)):
            r = handler.get(test_url, allow_redirects=False)
            if not r:
                continue
            loc = (r.headers.get("Location") or "").strip()
            loc = self._normalize_text(loc)
            last_loc = loc
            if r.status_code in [301, 302, 303, 307, 308] and expected_external_location in loc:
                external_hits += 1

        neg = handler.get(negative_control_url, allow_redirects=False)
        neg_loc = (neg.headers.get("Location") or "").strip() if neg else ""
        try:
            neg_loc = self._normalize_text(neg_loc)
        except Exception:
            pass
        neg_external = bool(neg_loc) and expected_external_location in neg_loc

        verified = external_hits >= max(2, runs - 1) and not neg_external
        confidence = "HIGH" if verified else ("MEDIUM" if external_hits > 0 else "LOW")
        return VerificationResult(
            verified=verified,
            confidence=confidence,
            similarity=1.0,
            notes=f"external_hits={external_hits}/{runs}, neg_external={neg_external}, last_location={last_loc[:140]}",
        )

    def verify_response_anomaly(
        self,
        handler,
        baseline_url: str,
        test_url: str,
        runs: int = 3,
        status_ok: Optional[set[int]] = None,
    ) -> VerificationResult:
        status_ok = status_ok or {200, 201, 202, 204, 206, 301, 302, 303, 307, 308, 401, 403}
        baseline = handler.get(baseline_url, allow_redirects=False)
        test = handler.get(test_url, allow_redirects=False)
        if not baseline or not test:
            return VerificationResult(False, "LOW", 0.0, "baseline/test fetch failed")

        base_status = baseline.status_code
        test_status = test.status_code
        base_text = baseline.text or ""
        test_text = test.text or ""
        base_norm = self._normalize_text(base_text)
        test_norm = self._normalize_text(test_text)
        sim = self.similarity(base_norm, test_norm)
        ent_base = self._entropy(base_norm)
        ent_test = self._entropy(test_norm)

        # Determinism check
        stable = 0
        for _ in range(max(1, runs)):
            r = handler.get(test_url, allow_redirects=False)
            if not r:
                continue
            if r.status_code == test_status:
                stable += 1

        anomaly = (base_status != test_status) or (sim < 0.75)
        verified = anomaly and stable >= max(2, runs - 1) and base_status in status_ok and test_status in status_ok
        # Probabilistic-ish anomaly scoring (kept simple and robust).
        stability_score = stable / max(1, runs)
        sim_score = sim  # 0..1
        entropy_delta = abs(ent_base - ent_test)
        prob_anomaly = (1.0 - sim_score) * 0.55 + stability_score * 0.35 + min(1.0, entropy_delta / 6.0) * 0.10
        confidence = (
            "HIGH" if verified and prob_anomaly >= 0.55 else ("MEDIUM" if (anomaly or prob_anomaly >= 0.35) else "LOW")
        )
        return VerificationResult(
            verified=verified,
            confidence=confidence,
            similarity=sim,
            notes=(
                f"base_status={base_status}, test_status={test_status}, "
                f"similarity={sim:.2f}, stable={stable}/{runs}, entropy_base={ent_base:.2f}, "
                f"entropy_test={ent_test:.2f}, prob_anomaly={prob_anomaly:.2f}"
            ),
        )

    def to_finding_fields(self, vr: VerificationResult) -> Dict[str, Any]:
        return {
            "tags": [f"confidence:{vr.confidence}", "verified" if vr.verified else "unverified"],
            "evidence": f"{vr.notes}",
        }
