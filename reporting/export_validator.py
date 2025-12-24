"""
Export validation for VScanX reports
Validates scan results against schema before export
"""

import logging
from typing import Any, Dict

from core.utils import validate_scan_result_schema

logger = logging.getLogger("vscanx.export_validator")


class ExportValidationError(Exception):
    """Raised when export validation fails"""

    pass


def validate_before_export(results: Dict[str, Any], export_format: str) -> None:
    """
    Validate scan results before exporting

    Args:
        results: Scan results dictionary
        export_format: Export format (html, json, csv, txt, pdf)

    Raises:
        ExportValidationError: If validation fails
    """
    try:
        # Validate using a sanitized copy so presentation-only fields (e.g. module.findings)
        # are ignored during schema validation
        sanitized = sanitize_for_export(results)
        validate_scan_result_schema(sanitized)
        logger.debug("export_validation_passed", extra={"format": export_format})
    except Exception as e:
        logger.error(
            "export_validation_failed", extra={"format": export_format, "error": str(e)}
        )
        raise ExportValidationError(
            f"Export validation failed for {export_format}: {e}"
        ) from e


def validate_json_export(data: Dict[str, Any]) -> None:
    """
    Validate JSON export data structure

    Args:
        data: JSON export data

    Raises:
        ExportValidationError: If validation fails
    """
    required_keys = ["summary", "findings", "metadata"]

    for key in required_keys:
        if key not in data:
            raise ExportValidationError(f"JSON export missing required key: {key}")

    # Validate findings is a list
    if not isinstance(data["findings"], list):
        raise ExportValidationError("JSON export 'findings' must be a list")

    # Validate metadata
    if not isinstance(data["metadata"], dict):
        raise ExportValidationError("JSON export 'metadata' must be a dict")

    logger.debug("json_export_validation_passed")


def sanitize_for_export(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize results for export (remove sensitive data)

    Args:
        results: Scan results dictionary

    Returns:
        Sanitized results dictionary
    """
    sanitized = results.copy()

    # Remove any potential sensitive fields from findings
    if "findings" in sanitized:
        sanitized_findings = []
        for finding in sanitized["findings"]:
            sanitized_finding = finding.copy()

            # Redact potential tokens/secrets in evidence
            if "evidence" in sanitized_finding:
                evidence = sanitized_finding["evidence"]
                # Basic redaction patterns
                import re

                # Redact bearer tokens
                evidence = re.sub(
                    r"Bearer\s+[A-Za-z0-9\-_]+", "Bearer [REDACTED]", evidence
                )
                # Redact API keys (basic pattern)
                evidence = re.sub(
                    r"[A-Za-z0-9]{32,}",
                    lambda m: "[REDACTED]" if len(m.group()) > 32 else m.group(),
                    evidence,
                )
                sanitized_finding["evidence"] = evidence

            sanitized_findings.append(sanitized_finding)

        sanitized["findings"] = sanitized_findings

    # Remove per-module 'findings' entries (they are a presentation convenience, not part of the schema)
    if "modules" in sanitized and isinstance(sanitized["modules"], list):
        sanitized_modules = []
        for module in sanitized["modules"]:
            mod_copy = module.copy()
            if "findings" in mod_copy:
                mod_copy.pop("findings")
            sanitized_modules.append(mod_copy)
        sanitized["modules"] = sanitized_modules

    logger.debug("export_sanitization_complete")
    return sanitized
