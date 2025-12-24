from core.orchestrator import Orchestrator


def test_module_findings_attached():
    orch = Orchestrator()
    sample = {
        "module": "XSS Detector",
        "findings": [
            {
                "severity": "HIGH",
                "finding": "Reflected XSS in 'q'",
                "details": "evidence",
                "parameter": "q",
            }
        ],
    }

    # Call the protected method to simulate a module result
    orch._add_module_result(sample)

    # Ensure module metadata has findings and they contain expected keys
    modules = orch.scan_result.modules
    assert any(m["module"] == "XSS Detector" for m in modules)  # nosec: B101 - test assertion
    mod = next(m for m in modules if m["module"] == "XSS Detector")
    assert "findings" in mod  # nosec: B101 - test assertion
    assert mod["findings"][0]["details"] == "evidence"  # nosec: B101 - test assertion
    assert mod["findings"][0]["parameter"] == "q"  # nosec: B101 - test assertion
    assert mod["findings"][0]["severity"] == "HIGH"  # nosec: B101 - test assertion
