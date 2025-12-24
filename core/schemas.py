"""
JSON Schemas for validating ScanResult and Finding structures.
"""

ScanFindingSchema = {
    "type": "object",
    "required": ["module", "severity", "description"],
    "properties": {
        "module": {"type": "string", "minLength": 1},
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        },
        "description": {"type": "string"},
        "parameter": {"type": "string"},
        "evidence": {"type": "string"},
        "remediation": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "timestamp": {"type": "string"},
    },
    "additionalProperties": False,
}

ScanModuleSchema = {
    "type": "object",
    "required": ["module", "start_time", "end_time"],
    "properties": {
        "module": {"type": "string"},
        "start_time": {"type": "string"},
        "end_time": {"type": "string"},
        "duration": {"type": "number"},
        "error": {"type": "string"},
    },
    "additionalProperties": False,
}

ScanResultSchema = {
    "type": "object",
    "required": [
        "target",
        "scan_type",
        "authenticated",
        "start_time",
        "duration",
        "findings",
        "modules",
        "errors",
    ],
    "properties": {
        "target": {"type": "string"},
        "scan_type": {"type": "string", "enum": ["web", "network", "mixed"]},
        "authenticated": {"type": "boolean"},
        "start_time": {"type": "string"},
        "duration": {"type": "number"},
        "findings": {"type": "array", "items": ScanFindingSchema},
        "modules": {"type": "array", "items": ScanModuleSchema},
        "errors": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}
