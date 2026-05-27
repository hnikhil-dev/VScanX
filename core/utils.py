from typing import Any, Dict

from jsonschema import validate
from jsonschema.exceptions import ValidationError

from core.schemas import ScanResultSchema


def validate_results_summary(results: Dict[str, Any], summary: Dict[str, Any]) -> None:
    """Raise ValueError if summary indicates findings but no findings present in results."""
    if not isinstance(results, dict):
        raise ValueError(f"Expected results to be a dict, got {type(results).__name__}")

    total = summary.get("total_findings", 0)
    # Use .get() to avoid KeyError and handle missing 'findings' gracefully
    findings = results.get("findings", [])

    if total > 0 and len(findings) == 0:
        raise ValueError("Summary indicates findings but no finding objects present")


def validate_scan_result_schema(results: Dict[str, Any]) -> None:
    """Validate scan results dict against JSON Schema; raises ValidationError if invalid."""
    try:
        validate(instance=results, schema=ScanResultSchema)
    except ValidationError as exc:
        raise ValueError(f"ScanResult schema validation failed: {exc.message}") from exc
