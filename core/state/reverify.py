from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from core.verify.engine import VerificationEngine


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verification_state_from(vr_verified: bool | None, confidence: str) -> str:
    if vr_verified is True:
        return "VERIFIED"
    if vr_verified is False:
        return "REJECTED"
    if str(confidence or "").upper() in ["HIGH", "MEDIUM"]:
        return "CANDIDATE"
    return "UNVERIFIED"


def reverify_results(
    results: Dict[str, Any],
    handler,
    *,
    runs_default: int = 3,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Deterministically re-run verification only, using stored reproduction contracts.

    - does not crawl
    - does not run scanning modules
    - only reruns VerificationEngine methods for findings that provide reproduction contracts
    """
    out = deepcopy(results or {})
    eng = VerificationEngine()
    stats = {
        "findings_total": 0,
        "reverified": 0,
        "skipped_no_repro": 0,
        "skipped_unknown_type": 0,
        "errors": 0,
    }

    findings = out.get("findings") or []
    if not isinstance(findings, list):
        return out, stats

    for f in findings:
        if not isinstance(f, dict):
            continue
        stats["findings_total"] += 1
        repro = f.get("reproduction") or {}
        if not isinstance(repro, dict) or not repro.get("type"):
            stats["skipped_no_repro"] += 1
            continue

        rtype = str(repro.get("type"))
        try:
            if rtype == "open_redirect":
                vr = eng.verify_open_redirect(
                    handler=handler,
                    test_url=str(repro.get("test_url", "")),
                    expected_external_location=str(repro.get("expected_external_location", "")),
                    negative_control_url=str(repro.get("negative_control_url", "")),
                    runs=int(repro.get("runs", runs_default)),
                )
            elif rtype == "response_anomaly":
                vr = eng.verify_response_anomaly(
                    handler=handler,
                    baseline_url=str(repro.get("baseline_url", "")),
                    test_url=str(repro.get("test_url", "")),
                    runs=int(repro.get("runs", runs_default)),
                )
            else:
                stats["skipped_unknown_type"] += 1
                continue

            # Update canonical verification fields
            f["verified"] = vr.verified
            f["confidence"] = vr.confidence
            f["verification_state"] = _verification_state_from(vr.verified, vr.confidence)
            f["verification"] = dict(f.get("verification") or {})
            f["verification"]["notes"] = vr.notes
            f["verification"]["similarity"] = vr.similarity

            f["last_seen_at"] = _now()
            hist = f.get("enrichment_history")
            if not isinstance(hist, list):
                hist = []
            hist.append(
                {
                    "stage": "replay_verify",
                    "ts": _now(),
                    "verification_state": f.get("verification_state"),
                    "confidence": f.get("confidence"),
                    "notes": vr.notes[:240],
                }
            )
            f["enrichment_history"] = hist
            stats["reverified"] += 1
        except Exception:
            stats["errors"] += 1
            continue

    return out, stats

