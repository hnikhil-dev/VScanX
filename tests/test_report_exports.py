import os
from datetime import datetime

from reporting.export_formats import ExportHandler
from reporting.report_generator import ReportGenerator


def make_sample():
    results = {
        "target": "http://example.local",
        "scan_type": "web",
        "start_time": datetime.now().isoformat(),
        "duration": 0.5,
        "authenticated": False,
        "errors": [],
        "findings": [
            {
                "module": "XSS Detector",
                "severity": "HIGH",
                "description": "Reflected XSS in 'q'",
                "parameter": "q",
                "evidence": "<script>alert(1)</script>",
            }
        ],
        "modules": [
            {
                "module": "XSS Detector",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
                "findings": [
                    {
                        "severity": "HIGH",
                        "finding": "Reflected XSS in 'q'",
                        "details": "<script>alert(1)</script>",
                    }
                ],
            }
        ],
    }

    summary = {
        "total_findings": 1,
        "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "modules_run": 1,
        "by_module": {"XSS Detector": 1},
        "authenticated": False,
        "target": results["target"],
        "scan_type": results["scan_type"],
        "start_time": results["start_time"],
        "duration": results["duration"],
    }

    return results, summary


def test_validate_mismatch():
    results, summary = make_sample()
    # Case: summary claims findings but results.findings empty
    bad_results = results.copy()
    bad_results["findings"] = []

    import pytest

    from core.utils import validate_results_summary

    with pytest.raises(ValueError):
        validate_results_summary(bad_results, summary)


def test_orchestrator_summary_consistency():
    from core.orchestrator import Orchestrator
    from core.scan_model import Finding, ScanResult

    orch = Orchestrator(verbose=True)
    sr = ScanResult(
        target="http://example.local",
        scan_type="web",
        findings=[
            Finding(module="XSS Detector", severity="HIGH", description="Reflected XSS")
        ],
        modules=[
            {
                "module": "XSS Detector",
                "findings": [
                    {
                        "severity": "HIGH",
                        "finding": "Reflected XSS",
                        "details": "evidence",
                    }
                ],
            }
        ],
    )
    orch.scan_result = sr
    summary = orch.get_summary()
    assert summary["total_findings"] == 1  # nosec: B101 - test assertion
    assert len(orch.scan_result.findings) == 1  # nosec: B101 - test assertion


def test_generate_reports(tmp_path):
    results, summary = make_sample()
    gen = ReportGenerator(output_dir=str(tmp_path))
    base = os.path.join(str(tmp_path), "test_report")

    html_path = gen.generate_html_report(results, summary, base)
    assert os.path.exists(html_path)  # nosec: B101 - test assertion

    json_path = gen.generate_json_report(results, summary, base)
    assert os.path.exists(json_path)  # nosec: B101 - test assertion

    csv_path = gen.generate_csv_report(results, summary, base)
    assert os.path.exists(csv_path)  # nosec: B101 - test assertion

    txt_path = gen.generate_txt_report(results, summary, base)
    assert os.path.exists(txt_path)  # nosec: B101 - test assertion

    # PDF may require reportlab; if generated, ensure file exists; otherwise generate_pdf_report returns None
    pdf_path = gen.generate_pdf_report(results, summary, base)
    if pdf_path:
        assert os.path.exists(pdf_path)  # nosec: B101 - test assertion

    # Also test ExportHandler CSV/JSON/TXT wrappers
    exporter = ExportHandler()
    json_wrapper = exporter.export_json(results, "smoke_export")
    assert os.path.exists(json_wrapper)  # nosec: B101 - test assertion

    csv_wrapper = exporter.export_csv(results, "smoke_export")
    assert os.path.exists(csv_wrapper)  # nosec: B101 - test assertion

    txt_wrapper = exporter.export_txt(results, summary, "smoke_export")
    assert os.path.exists(txt_wrapper)  # nosec: B101 - test assertion
