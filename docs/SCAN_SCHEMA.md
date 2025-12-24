# Scan Result Schema

## Finding
- `module` (string, required)
- `severity` (enum: CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `description` (string, required)
- `parameter` (string, optional)
- `evidence` (string, optional, redacted)
- `remediation` (string, optional)
- `tags` (array[string], optional)
- `timestamp` (string, ISO8601)

## ScanResult
- `target` (string)
- `scan_type` (enum: web, network, mixed)
- `authenticated` (bool)
- `start_time` (string, ISO8601)
- `duration` (number, seconds)
- `findings` (array[Finding])
- `modules` (array of module metadata: module, start_time, end_time, duration?, error?)
- `errors` (array[string])

Validation is enforced via JSON Schema in `core/schemas.py` and checked before exports.

## Sample (sanitized)
```json
{
  "target": "http://example.com",
  "scan_type": "web",
  "authenticated": false,
  "start_time": "2025-01-01T00:00:00Z",
  "duration": 2.34,
  "findings": [
    {
      "module": "SQL Injection Detector",
      "severity": "HIGH",
      "description": "SQL Injection in parameter 'id'",
      "parameter": "id",
      "evidence": "Payload triggered anomaly",
      "remediation": "Use parameterized queries",
      "tags": [],
      "timestamp": "2025-01-01T00:00:01Z"
    }
  ],
  "modules": [
    {
      "module": "SQL Injection Detector",
      "start_time": "2025-01-01T00:00:00Z",
      "end_time": "2025-01-01T00:00:02Z",
      "duration": 2.0
    }
  ],
  "errors": []
}
```

