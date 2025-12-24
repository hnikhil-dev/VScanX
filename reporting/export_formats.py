"""
VScanX Export Formats
Handles JSON, CSV, and TXT exports
"""

import csv
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from core.config import REPORT_OUTPUT_DIR
from reporting.export_validator import sanitize_for_export, validate_before_export

logger = logging.getLogger("vscanx.export_formats")


class ExportHandler:
    """
    Handles exporting scan results to various formats
    """

    def __init__(self):
        """Initialize export handler"""
        Path(REPORT_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    def _safe_output_path(self, filename: str, extension: str) -> str:
        """Return a sanitized path inside the reports directory."""
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(filename)).strip("._-")
        if not safe_name:
            safe_name = "report"
        base_dir = Path(REPORT_OUTPUT_DIR).resolve()
        path = (base_dir / f"{safe_name}.{extension}").resolve()
        if base_dir not in path.parents and path != base_dir:
            raise ValueError("Invalid report filename")
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)

    def export_json(self, results: Dict[str, Any], filename: str) -> str:
        """
        Export results as JSON

        Args:
            results: Scan results dictionary
            filename: Output filename (without extension)

        Returns:
            Path to exported file
        """
        # Validate and sanitize before export
        validate_before_export(results, "json")
        sanitized_results = sanitize_for_export(results)

        output_path = self._safe_output_path(filename, "json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sanitized_results, f, indent=2, ensure_ascii=False)

        logger.info("json_export_complete", extra={"path": output_path})
        return os.path.abspath(output_path)

    def export_csv(self, results: Dict[str, Any], filename: str) -> str:
        """
        Export findings as CSV

        Args:
            results: Scan results dictionary
            filename: Output filename (without extension)

        Returns:
            Path to exported file
        """
        # Validate before export
        validate_before_export(results, "csv")
        sanitized_results = sanitize_for_export(results)

        output_path = self._safe_output_path(filename, "csv")

        # Flatten findings from central findings list
        findings = []
        for finding in sanitized_results.get("findings", []):
            findings.append(
                {
                    "Module": finding.get("module", "Unknown"),
                    "Severity": finding.get("severity", "INFO"),
                    "Finding": finding.get("description", ""),
                    "Details": finding.get("evidence", "")[:500],  # Limit length
                }
            )

        # Write CSV
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            if findings:
                writer = csv.DictWriter(
                    f, fieldnames=["Module", "Severity", "Finding", "Details"]
                )
                writer.writeheader()
                writer.writerows(findings)
            else:
                # Empty CSV with headers
                writer = csv.DictWriter(
                    f, fieldnames=["Module", "Severity", "Finding", "Details"]
                )
                writer.writeheader()

        logger.info("csv_export_complete", extra={"path": output_path})
        return os.path.abspath(output_path)

    def export_txt(
        self, results: Dict[str, Any], summary: Dict[str, Any], filename: str
    ) -> str:
        """
        Export results as plain text

        Args:
            results: Scan results dictionary
            summary: Summary statistics
            filename: Output filename (without extension)

        Returns:
            Path to exported file
        """
        # Validate before export
        validate_before_export(results, "txt")
        sanitized_results = sanitize_for_export(results)

        output_path = self._safe_output_path(filename, "txt")

        with open(output_path, "w", encoding="utf-8") as f:
            # Header
            f.write("=" * 60 + "\n")
            f.write("VScanX Security Scan Report\n")
            f.write("=" * 60 + "\n\n")

            # Metadata
            f.write(f"Target:    {results.get('target', 'N/A')}\n")
            f.write(f"Scan Type: {results.get('scan_type', 'N/A').upper()}\n")
            f.write(f"Timestamp: {results.get('timestamp', 'N/A')}\n")
            f.write(f"Duration:  {results.get('duration', 0)}s\n\n")

            # Summary
            f.write("=" * 60 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 60 + "\n")
            f.write(f"Total Findings: {summary['total_findings']}\n")
            f.write(f"  CRITICAL: {summary['by_severity']['CRITICAL']}\n")
            f.write(f"  HIGH:     {summary['by_severity']['HIGH']}\n")
            f.write(f"  MEDIUM:   {summary['by_severity']['MEDIUM']}\n")
            f.write(f"  LOW:      {summary['by_severity']['LOW']}\n")
            f.write(f"  INFO:     {summary['by_severity']['INFO']}\n\n")

            # Detailed Findings
            f.write("=" * 60 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 60 + "\n\n")

            # Use central findings list
            findings_list = sanitized_results.get("findings", [])
            if not findings_list:
                f.write("No findings.\n\n")
            else:
                for finding in findings_list:
                    f.write(
                        f"[{finding.get('severity', 'INFO')}] {finding.get('module', 'Unknown')}\n"
                    )
                    f.write(f"    Description: {finding.get('description', 'N/A')}\n")
                    if finding.get("evidence"):
                        f.write(f"    Evidence: {finding.get('evidence', '')[:200]}\n")
                    if finding.get("remediation"):
                        f.write(
                            f"    Remediation: {finding.get('remediation', '')[:200]}\n"
                        )
                    f.write("\n")

            # Footer
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n")

        logger.info("txt_export_complete", extra={"path": output_path})
        return os.path.abspath(output_path)
