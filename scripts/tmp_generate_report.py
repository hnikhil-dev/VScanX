import os
import tempfile
from datetime import datetime

from reporting.report_generator import ReportGenerator

results = {
    "target": "http://example.local",
    "scan_type": "web",
    "start_time": datetime.now().isoformat(),
    "duration": 0.5,
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

tmp = tempfile.mkdtemp()
rg = ReportGenerator(output_dir=tmp)
path = rg.generate_html_report(results, summary, os.path.join(tmp, "smoke_report"))
print("Generated:", path)
with open(path, "r", encoding="utf-8") as f:
    content = f.read()
    print("Details present?", "Details:" in content)
    print("Parameter present?", "Parameter:" in content)
    print("Evidence present?", "Evidence:" in content)
    print("\n--- snippet ---\n")
    start = content.find("Detailed Findings")
    print(content[start : start + 800])
