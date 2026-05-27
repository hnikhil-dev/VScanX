"""
Report generator for VScanX scan results
Supports HTML, JSON, CSV, TXT, and PDF export formats
"""

import html
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reporting.export_validator import sanitize_for_export, validate_before_export

logger = logging.getLogger("vscanx.report_generator")


class ReportGenerator:
    """Generate vulnerability scan reports in multiple formats"""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator

        Args:
            output_dir: Directory to save reports (default: reports/)
        """
        self.timestamp = datetime.now()
        self.output_dir = output_dir

        # Create reports directory if it doesn't exist
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def _get_filepath(self, filename: str, extension: str) -> str:
        """Get full filepath for report and ensure parent directory exists"""
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(filename)).strip("._-")
        if not safe_name:
            safe_name = "report"
        # Prevent path traversal by resolving inside output_dir
        base_dir = Path(self.output_dir).resolve()
        path = (base_dir / f"{safe_name}.{extension}").resolve()
        if base_dir not in path.parents and path != base_dir:
            raise ValueError("Invalid report filename")
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)

    def generate_html_report(self, results: Dict, summary: Dict, filename: str) -> str:
        """Generate HTML report"""
        # Validate before export
        validate_before_export(results, "html")
        sanitized_results = sanitize_for_export(results)

        html_content = self._build_html(sanitized_results, summary)
        filepath = self._get_filepath(filename, "html")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info("html_report_generated", extra={"path": filepath})
        print(f"[+] HTML report generated: {filepath}")
        return filepath

    def generate_pdf_report(self, results: Dict, summary: Dict, filename: str) -> str:
        """Generate PDF report using reportlab"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError:
            print("[!] reportlab not installed. Install with: pip install reportlab")
            return None

        filepath = self._get_filepath(filename, "pdf")
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1F2121"),
            spaceAfter=30,
            alignment=TA_CENTER,
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#208080"),
            spaceAfter=12,
            spaceBefore=12,
        )

        # Title
        story.append(Paragraph("VScanX Security Scan Report", title_style))
        story.append(Spacer(1, 0.3 * inch))

        # Summary section
        story.append(Paragraph("Scan Summary", heading_style))

        summary_data = [
            ["Target", summary.get("target", "N/A")],
            ["Scan Type", summary.get("scan_type", "N/A")],
            ["Start Time", summary.get("start_time", "N/A")],
            ["Duration", f"{summary.get('duration', 0):.2f} seconds"],
            ["Total Findings", str(summary.get("total_findings", 0))],
            ["CRITICAL", str(summary.get("by_severity", {}).get("CRITICAL", 0))],
            ["HIGH", str(summary.get("by_severity", {}).get("HIGH", 0))],
            ["MEDIUM", str(summary.get("by_severity", {}).get("MEDIUM", 0))],
            ["LOW", str(summary.get("by_severity", {}).get("LOW", 0))],
            ["INFO", str(summary.get("by_severity", {}).get("INFO", 0))],
        ]

        summary_table = Table(summary_data, colWidths=[2 * inch, 4 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )

        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Findings section
        if results.get("findings"):
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", heading_style))

            for severity_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                findings = [
                    f
                    for f in results["findings"]
                    if f.get("severity") == severity_level
                ]

                if findings:
                    story.append(
                        Paragraph(
                            f"{severity_level} Severity Issues", styles["Heading3"]
                        )
                    )

                    for finding in findings:
                        finding_text = f"""
                        <b>Module:</b> {html.escape(str(finding.get('module', 'N/A')))}<br/>
                        <b>Issue:</b> {html.escape(str(finding.get('description', 'N/A')))}<br/>
                        <b>Parameter:</b> {html.escape(str(finding.get('parameter', 'N/A')))}<br/>
                        <b>Evidence:</b> {html.escape(str(finding.get('evidence', 'N/A')[:100]))}<br/>
                        """
                        story.append(Paragraph(finding_text, styles["Normal"]))
                        story.append(Spacer(1, 0.1 * inch))

        try:
            doc.build(story)
            print(f"[+] PDF report generated: {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error generating PDF: {e}")
            return None

    def generate_json_report(self, results: Dict, summary: Dict, filename: str) -> str:
        """Generate JSON report"""
        # Validate before export
        validate_before_export(results, "json")
        sanitized_results = sanitize_for_export(results)

        report_data = {
            "summary": summary,
            "findings": sanitized_results.get("findings", []),
            "metadata": {"generated": datetime.now().isoformat(), "version": "2.0.0"},
        }

        # Validate JSON structure
        from reporting.export_validator import validate_json_export

        validate_json_export(report_data)

        filepath = self._get_filepath(filename, "json")

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        logger.info("json_report_generated", extra={"path": filepath})
        print(f"[+] JSON report generated: {filepath}")
        return filepath

    def generate_csv_report(self, results: Dict, summary: Dict, filename: str) -> str:
        """Generate CSV report"""
        import csv

        filepath = self._get_filepath(filename, "csv")

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Module", "Severity", "Description", "Parameter", "Evidence"]
            )

            for finding in results.get("findings", []):
                writer.writerow(
                    [
                        finding.get("module", ""),
                        finding.get("severity", ""),
                        finding.get("description", ""),
                        finding.get("parameter", ""),
                        str(finding.get("evidence", ""))[:100],
                    ]
                )

        print(f"[+] CSV report generated: {filepath}")
        return filepath

    def generate_txt_report(self, results: Dict, summary: Dict, filename: str) -> str:
        """Generate text report"""
        filepath = self._get_filepath(filename, "txt")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("VScanX VULNERABILITY SCAN REPORT\n")
            f.write("=" * 70 + "\n\n")

            f.write("SCAN SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Target: {summary.get('target')}\n")
            f.write(f"Scan Type: {summary.get('scan_type')}\n")
            f.write(f"Start Time: {summary.get('start_time')}\n")
            f.write(f"Duration: {summary.get('duration', 0):.2f} seconds\n")
            f.write(f"Total Findings: {summary.get('total_findings', 0)}\n\n")

            by_sev = summary.get("by_severity", {})
            f.write(f"CRITICAL: {by_sev.get('CRITICAL', 0)}\n")
            f.write(f"HIGH: {by_sev.get('HIGH', 0)}\n")
            f.write(f"MEDIUM: {by_sev.get('MEDIUM', 0)}\n")
            f.write(f"LOW: {by_sev.get('LOW', 0)}\n")
            f.write(f"INFO: {by_sev.get('INFO', 0)}\n\n")

            if results.get("findings"):
                f.write("DETAILED FINDINGS\n")
                f.write("=" * 70 + "\n\n")

                for i, finding in enumerate(results["findings"], 1):
                    f.write(f"[{i}] {finding.get('module', 'N/A')}\n")
                    f.write(f"    Severity: {finding.get('severity', 'N/A')}\n")
                    f.write(f"    Description: {finding.get('description', 'N/A')}\n")
                    f.write(f"    Parameter: {finding.get('parameter', 'N/A')}\n")
                    f.write(
                        f"    Evidence: {str(finding.get('evidence', 'N/A'))[:100]}\n"
                    )
                    f.write("\n")

        print(f"[+] Text report generated: {filepath}")
        return filepath

    def _build_html(self, results: Dict, summary: Dict) -> str:
        """Build HTML content with remediation notes"""

        def _severity_color(sev: str) -> str:
            return {
                "CRITICAL": "#C01530",
                "HIGH": "#E67E22",
                "MEDIUM": "#F39C12",
                "LOW": "#3498DB",
                "INFO": "#95A5A6",
            }.get((sev or "").upper(), "#7F8C8D")

        def _render_finding_card(finding: Dict[str, Any]) -> str:
            severity_color = _severity_color(finding.get("severity"))

            # Build remediation section if present
            remediation_html = ""
            if finding.get("remediation"):
                rem_val = html.escape(str(finding.get("remediation")))
                remediation_html = (
                    '<div style="background: #E8F4F8; border-left: 3px solid #208080; '
                    'padding: 12px; margin-top: 10px; border-radius: 4px;>'
                    f'<p style="margin: 0;"><strong>Remediation:</strong> {rem_val}</p>'
                    '</div>'
                )

            # Prefer explicit details key, fall back to description or evidence so fields are never left blank
            verification = finding.get("verification") if isinstance(finding.get("verification"), dict) else {}
            verification_notes = ""
            try:
                verification_notes = str(verification.get("notes", "") or "")
            except Exception:
                verification_notes = ""

            details_text = (
                finding.get("details")
                or verification_notes
                or finding.get("description")
                or finding.get("evidence")
                or "N/A"
            )
            parameter_text = finding.get("parameter", "")
            evidence_obj = finding.get("evidence", "")
            if isinstance(evidence_obj, dict):
                evidence_text = evidence_obj.get("summary", "") or str(evidence_obj)
            else:
                evidence_text = evidence_obj

            module_html = f'<h4 style="margin-top: 0; color: {severity_color};">{finding.get("module", "N/A")}</h4>'
            severity_html = (
                f'<p><strong>Severity:</strong> '
                f'<span style="color: {severity_color}; font-weight: bold;">'
                f'{finding.get("severity", "N/A")}</span></p>'
            )
            desc_val = html.escape(str(finding.get("description", "N/A")))
            description_html = f'<p><strong>Description:</strong> {desc_val}</p>'
            details_html = f'<p class="finding-details"><strong>Details:</strong> {html.escape(str(details_text))}</p>'
            parameter_html = (
                f'<p class="finding-details"><strong>Parameter:</strong> '
                f'<code class="inline">{html.escape(str(parameter_text))}</code></p>'
            )
            evidence_val = html.escape(str(evidence_text)[:300])
            evidence_html = f'<p class="finding-details"><strong>Evidence:</strong> <code>{evidence_val}</code></p>'
            confidence_html = ""
            if finding.get("confidence"):
                conf_val = html.escape(str(finding.get("confidence")))
                confidence_html = (
                    f'<p class="finding-details"><strong>Confidence:</strong> '
                    f"{conf_val}</p>"
                )
            verified_html = ""
            verified_val = finding.get("verified", None)
            if verified_val is not None:
                verified_html = (
                    '<p class="finding-details"><strong>Verified:</strong> '
                    f"{'Yes' if verified_val else 'No'}</p>"
                )

            return (
                '<div style="border-left: 4px solid '
                f'{severity_color}; padding: 15px; margin-bottom: 15px; background: #F8F9FA;>'
                + module_html
                + severity_html
                + description_html
                + details_html
                + confidence_html
                + verified_html
                + parameter_html
                + evidence_html
                + remediation_html
                + '</div>'
            )

        all_findings: List[Dict[str, Any]] = list(results.get("findings", []))
        # Group by endpoint so testers can triage by affected URL first.
        default_endpoint = summary.get("target", "N/A")
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for f in all_findings:
            ep = f.get("endpoint") or default_endpoint or "N/A"
            grouped.setdefault(str(ep), []).append(f)

        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        def _group_sort_key(item: Any) -> Any:
            ep, fs = item
            if not fs:
                return (999, ep)
            # Sort groups by their highest severity rank first.
            best = min(severity_rank.get((x.get("severity") or "").upper(), 999) for x in fs)
            return (best, len(fs), ep)

        findings_html = ""
        for endpoint, endpoint_findings in sorted(grouped.items(), key=_group_sort_key):
            # Compute per-endpoint severity counts for a quick visual.
            by_sev_local = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in endpoint_findings:
                sev = (f.get("severity") or "INFO").upper()
                if sev in by_sev_local:
                    by_sev_local[sev] += 1
            top_color = _severity_color(endpoint_findings[0].get("severity"))
            endpoint_header = html.escape(str(endpoint))
            endpoint_summary = (
                f"Critical {by_sev_local['CRITICAL']}, High {by_sev_local['HIGH']}, "
                f"Medium {by_sev_local['MEDIUM']}, Low {by_sev_local['LOW']}, "
                f"Info {by_sev_local['INFO']}"
            )
            group_body = "".join(_render_finding_card(f) for f in endpoint_findings)
            findings_html += (
                '<details style="margin-bottom: 18px;">'
                f'<summary style="cursor:pointer; font-weight: 700; color: {top_color};">'
                f"{endpoint_header}</summary>"
                f'<div style="padding-left: 14px; margin-top: 10px;">'
                f'<p style="margin: 0 0 10px 0; opacity: 0.85;">{html.escape(endpoint_summary)}</p>'
                + group_body
                + '</div></details>'
            )

        # Finding timeline: sorted by timestamp (desc) for triage flow.
        def _fmt_ts(ts: str) -> str:
            try:
                # Keep stable formatting even with timezone offsets.
                if not ts:
                    return "unknown"
                return str(ts)[:19].replace("T", " ")
            except Exception:
                return "unknown"

        timeline_html = ""
        try:
            sorted_findings = sorted(
                all_findings,
                key=lambda f: str(f.get("timestamp") or ""),
                reverse=True,
            )
            for f in sorted_findings[:50]:
                sev = (f.get("severity") or "INFO").upper()
                timeline_html += (
                    '<div class="timeline-item">'
                    f'<span class="timeline-ts">{html.escape(_fmt_ts(f.get("timestamp","")))}</span>'
                    f'<span class="timeline-sev" style="color: {_severity_color(sev)};">{sev}</span>'
                    f'<span class="timeline-mod">{html.escape(str(f.get("module","N/A")))}</span>'
                    f'<span class="timeline-desc">{html.escape(str(f.get("description",""))[:90])}</span>'
                    '</div>'
                )
        except Exception:
            timeline_html = ""

        by_sev = summary.get("by_severity", {})
        target_html = html.escape(str(summary.get("target", "N/A")))
        modules_html = ""
        recon_html = ""
        elite_html = ""
        for module in results.get("modules", []):
            module_name = html.escape(str(module.get("module", "Unknown module")))
            finding_count = len(module.get("findings", []))
            duration = module.get("duration")
            duration_text = (
                f"{float(duration):.2f}s"
                if isinstance(duration, (int, float))
                else "n/a"
            )
            artifact_text = ""
            artifacts = module.get("artifacts", {})
            if isinstance(artifacts, dict) and artifacts:
                preview = ", ".join(
                    [f"{k}={v}" for k, v in artifacts.items() if not isinstance(v, list)]
                )
                artifact_text = f"<p><strong>Artifacts:</strong> {html.escape(preview[:120])}</p>"
            modules_html += (
                '<div class="module-card">'
                f"<h4>{module_name}</h4>"
                f"<p><strong>Findings:</strong> {finding_count}</p>"
                f"<p><strong>Duration:</strong> {duration_text}</p>"
                f"{artifact_text}"
                "</div>"
            )
            if module_name in ["JS Secret Analyzer", "Subdomain Recon Suite"]:
                recon_html += (
                    '<div class="module-card">'
                    f"<h4>{module_name}</h4>"
                    f"<p><strong>Findings:</strong> {finding_count}</p>"
                    f"<p><strong>Details:</strong> {html.escape(str(artifacts)[:260])}</p>"
                    "</div>"
                )
            if module_name in [
                "Vulnerability Chaining Engine",
                "PoC Generator",
                "OOB Hooks",
                "Defensive Variant Generator",
            ]:
                elite_html += (
                    '<div class="module-card">'
                    f"<h4>{module_name}</h4>"
                    f"<p><strong>Findings:</strong> {finding_count}</p>"
                    f"<p><strong>Details:</strong> {html.escape(str(artifacts)[:260])}</p>"
                    "</div>"
                )

        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VScanX Security Report</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background: #F5F5F5;
                }}
                .container {{
                    max-width: 900px;
                    margin: 0 auto;
                    padding: 20px;
                    background: white;
                }}
                header {{
                    background: linear-gradient(135deg, #208080 0%, #1F2121 100%);
                    color: white;
                    padding: 40px 20px;
                    text-align: center;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }}
                header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
                header p {{ font-size: 1.1em; opacity: 0.9; }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .summary-card {{
                    background: #F8F9FA;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #208080;
                }}
                .summary-card h3 {{ color: #208080; margin-bottom: 10px; }}
                .summary-card p {{ font-size: 1.8em; font-weight: bold; color: #1F2121; }}
                .severity-breakdown {{
                    display: flex;
                    gap: 10px;
                    margin-top: 15px;
                    flex-wrap: wrap;
                }}
                .module-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                    gap: 12px;
                    margin-top: 12px;
                }}
                .module-card {{
                    background: #F8F9FA;
                    border: 1px solid #E4E8EA;
                    border-radius: 8px;
                    padding: 12px;
                }}
                .module-card h4 {{
                    color: #1F2121;
                    margin-bottom: 8px;
                    font-size: 1em;
                }}
                .module-card p {{
                    font-size: 0.92em;
                    color: #4B5761;
                    margin: 2px 0;
                }}
                .timeline-item {{
                    display: grid;
                    grid-template-columns: 160px 90px 160px 1fr;
                    gap: 10px;
                    align-items: center;
                    background: #F8F9FA;
                    border: 1px solid #E4E8EA;
                    border-radius: 8px;
                    padding: 10px 12px;
                    margin-bottom: 10px;
                }}
                .timeline-ts {{
                    font-family: 'Monaco', 'Courier New', monospace;
                    font-size: 0.85em;
                    color: #4B5761;
                }}
                .timeline-sev {{
                    font-weight: bold;
                    font-size: 0.9em;
                }}
                .timeline-mod {{
                    color: #1F2121;
                    font-weight: 600;
                    font-size: 0.9em;
                }}
                .timeline-desc {{
                    color: #4B5761;
                    font-size: 0.92em;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }}
                .severity-badge {{
                    padding: 8px 12px;
                    border-radius: 4px;
                    color: white;
                    font-weight: bold;
                    font-size: 0.9em;
                }}
                .critical {{ background: #C01530; }}
                .high {{ background: #E67E22; }}
                .medium {{ background: #F39C12; }}
                .low {{ background: #3498DB; }}
                .info {{ background: #95A5A6; }}
                h2 {{
                    color: #1F2121;
                    border-bottom: 2px solid #208080;
                    padding-bottom: 10px;
                    margin: 30px 0 20px 0;
                }}
                code {{
                    background: #F0F0F0;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Monaco', 'Courier New', monospace;
                }}
                .finding-details p {{
                    margin: 6px 0;
                    font-size: 0.95em;
                }}
                .finding-details p strong {{
                    color: #495057;
                    display: inline-block;
                    width: 80px;
                }}
                .finding-details code {{
                    background: #F0F0F0;
                    padding: 8px;
                    display: block;
                    border-radius: 4px;
                    margin-top: 5px;
                    font-size: 0.9em;
                    white-space: pre-wrap;
                    word-break: break-word;
                    font-family: 'Monaco', 'Courier New', monospace;
                    max-height: 220px;
                    overflow: auto;
                }}
                .finding-details code.inline {{
                    display: inline-block;
                    padding: 2px 6px;
                    margin-top: 0;
                }}
                footer {{
                    text-align: center;
                    padding: 20px;
                    color: #7F8C8D;
                    border-top: 1px solid #E0E0E0;
                    margin-top: 30px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>VScanX Security Report</h1>
                    <p>Ethical Vulnerability Scanner v2.0</p>
                </header>

                <section class="summary">
                    <div class="summary-card" style="grid-column: 1 / -1;">
                        <h3>Target</h3>
                        <p style="font-size: 1.0em; word-break: break-all;">{target_html}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Scan Type</h3>
                        <p>{str(summary.get('scan_type', 'N/A')).upper()}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Total Findings</h3>
                        <p>{summary.get('total_findings', 0)}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Duration</h3>
                        <p>{summary.get('duration', 0):.2f}s</p>
                    </div>

                    <div class="summary-card" style="grid-column: 1 / -1;">
                        <h3>Severity Breakdown</h3>
                        <div class="severity-breakdown">
                            <span class="severity-badge critical">CRITICAL: {by_sev.get('CRITICAL', 0)}</span>
                            <span class="severity-badge high">HIGH: {by_sev.get('HIGH', 0)}</span>
                            <span class="severity-badge medium">MEDIUM: {by_sev.get('MEDIUM', 0)}</span>
                            <span class="severity-badge low">LOW: {by_sev.get('LOW', 0)}</span>
                            <span class="severity-badge info">INFO: {by_sev.get('INFO', 0)}</span>
                        </div>
                    </div>
                </section>

                <h2>Module Execution</h2>
                <div class="module-grid">
                    {modules_html if modules_html else '<p style="color: #7F8C8D;">No module execution metadata</p>'}
                </div>
                <h2>Recon & Data Mining</h2>
                <div class="module-grid">
                    {recon_html if recon_html else '<p style="color: #7F8C8D;">No recon artifacts captured</p>'}
                </div>
                <h2>Elite Automation</h2>
                <div class="module-grid">
                    {elite_html if elite_html else '<p style="color: #7F8C8D;">Elite automation not enabled</p>'}
                </div>

                <h2>Finding Timeline</h2>
                {timeline_html if timeline_html else '<p style="color: #7F8C8D;">No timeline available</p>'}

                <h2>Endpoint Grouping</h2>
                {findings_html if findings_html else '<p style="color: #7F8C8D;">No vulnerabilities found</p>'}

                <footer>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>VScanX - Ethical Vulnerability Scanner</p>
                </footer>
            </div>
        </body>
        </html>
        """

        return html_template
