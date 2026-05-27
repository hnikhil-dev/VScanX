from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _finding_key(f: Dict[str, Any]) -> str:
    # Prefer canonical id; fall back to a stable composite for legacy data.
    fid = str(f.get("finding_id") or "").strip()
    if fid:
        return fid
    return "|".join(
        [
            str(f.get("module", "")),
            str(f.get("endpoint", "")),
            str(f.get("parameter", "")),
            str(f.get("description", "")),
        ]
    )


def _evidence_summary(f: Dict[str, Any]) -> str:
    ev = f.get("evidence", "")
    if isinstance(ev, dict):
        return str(ev.get("summary", ""))[:500]
    return str(ev)[:500]


def diff_scan_results(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a finding-level diff between two ScanResult dicts.

    Output categories:
    - NEW: present in B, not in A
    - RESOLVED: present in A, not in B
    - CHANGED: same key in both but key fields differ
    - UNCHANGED: same key and fields match
    """
    fa = {_finding_key(f): f for f in (a.get("findings") or []) if isinstance(f, dict)}
    fb = {_finding_key(f): f for f in (b.get("findings") or []) if isinstance(f, dict)}

    a_keys = set(fa.keys())
    b_keys = set(fb.keys())

    new_keys = sorted(b_keys - a_keys)
    resolved_keys = sorted(a_keys - b_keys)
    common = sorted(a_keys & b_keys)

    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []

    for k in common:
        a1 = fa[k]
        b1 = fb[k]
        diffs: Dict[str, Tuple[Any, Any]] = {}

        for field, av, bv in [
            ("severity", a1.get("severity"), b1.get("severity")),
            ("confidence", a1.get("confidence"), b1.get("confidence")),
            ("verification_state", a1.get("verification_state"), b1.get("verification_state")),
            ("verified", a1.get("verified"), b1.get("verified")),
            ("evidence.summary", _evidence_summary(a1), _evidence_summary(b1)),
        ]:
            if av != bv:
                diffs[field] = (av, bv)

        if diffs:
            changed.append(
                {
                    "finding_id": k,
                    "module": b1.get("module") or a1.get("module"),
                    "endpoint": b1.get("endpoint") or a1.get("endpoint"),
                    "description": b1.get("description") or a1.get("description"),
                    "diff": {kk: {"from": vv[0], "to": vv[1]} for kk, vv in diffs.items()},
                }
            )
        else:
            unchanged.append(
                {
                    "finding_id": k,
                    "module": b1.get("module") or a1.get("module"),
                    "endpoint": b1.get("endpoint") or a1.get("endpoint"),
                    "description": b1.get("description") or a1.get("description"),
                }
            )

    out = {
        "meta": {
            "a": {"scan_id": a.get("scan_id", ""), "target": a.get("target", "")},
            "b": {"scan_id": b.get("scan_id", ""), "target": b.get("target", "")},
        },
        "counts": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "new": [fb[k] for k in new_keys if k in fb],
        "resolved": [fa[k] for k in resolved_keys if k in fa],
        "changed": changed,
        "unchanged": unchanged,
    }
    return out
