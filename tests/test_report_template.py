import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "reporting", "templates")


def make_sample_results():
    return {
        "target": "http://example.local",
        "scan_type": "web",
        "timestamp": "2025-12-24T12:00:00",
        "duration": 0.5,
        "modules": [
            {
                "module": "XSS Detector",
                "findings": [
                    {
                        "severity": "HIGH",
                        "finding": "Reflected XSS in 'q'",
                        "details": "<script>alert(1)</script>",
                        "parameter": "q",
                        "evidence": "<script>alert(1)</script>",
                    }
                ],
            }
        ],
    }


def test_template_shows_details_parameter_evidence():
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template("report.html")
    rendered = tpl.render(
        title="Test Report",
        results=make_sample_results(),
        summary={
            "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        },
        generation_time="2025-12-24",
    )

    assert "Details:" in rendered  # nosec: B101 - test assertion
    assert "Parameter:" in rendered  # nosec: B101 - test assertion
    assert "Evidence:" in rendered  # nosec: B101 - test assertion
    # Evidence should be HTML-escaped to avoid raw script injection
    assert "<script>alert(1)</script>" not in rendered  # nosec: B101 - test assertion
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered  # nosec: B101 - test assertion
