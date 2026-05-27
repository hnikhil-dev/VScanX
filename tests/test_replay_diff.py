from core.state.diff import diff_scan_results


def test_diff_scan_results_new_resolved_changed():
    a = {
        "target": "t",
        "findings": [
            {
                "finding_id": "A",
                "module": "m",
                "severity": "LOW",
                "confidence": "LOW",
                "verification_state": "UNVERIFIED",
                "evidence": {"summary": "x"},
            },
            {
                "finding_id": "B",
                "module": "m",
                "severity": "LOW",
                "confidence": "LOW",
                "verification_state": "UNVERIFIED",
                "evidence": {"summary": "y"},
            },
        ],
    }
    b = {
        "target": "t",
        "findings": [
            {
                "finding_id": "A",
                "module": "m",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "verification_state": "CANDIDATE",
                "evidence": {"summary": "x"},
            },
            {
                "finding_id": "C",
                "module": "m",
                "severity": "LOW",
                "confidence": "LOW",
                "verification_state": "UNVERIFIED",
                "evidence": {"summary": "z"},
            },
        ],
    }
    out = diff_scan_results(a, b)
    counts = out["counts"]
    assert counts["new"] == 1  # nosec: B101
    assert counts["resolved"] == 1  # nosec: B101
    assert counts["changed"] == 1  # nosec: B101
