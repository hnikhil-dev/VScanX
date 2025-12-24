# VScanX Quick Reference

## Installation & Setup

```bash
# Clone & setup
git clone <repo-url>
cd VScanX
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt
pip install pytest reportlab  # For testing
```

## Running VScanX

### Basic Web Scan

```bash
python vscanx.py -t http://example.com -s web --skip-warning
```

### Network Scan (with port range)

```bash
python vscanx.py -t 192.168.1.1 -s network -p 1-1000 --skip-warning
```

### Mixed Scan (web + network)

```bash
python vscanx.py -t http://example.com -s mixed --skip-warning
```

### With Authentication

```bash
python vscanx.py -t http://example.com/admin \
  --login-url http://example.com/login \
  --username admin \
  --password secret \
  --success-indicator "Welcome" \
  --skip-warning
```

### Custom Profiles

```bash
# Quick scan (fewer checks, faster)
python vscanx.py -t http://example.com --profile quick --skip-warning

# Full scan (comprehensive, slower)
python vscanx.py -t http://example.com --profile full --skip-warning

# Stealth scan (slow, careful)
python vscanx.py -t http://example.com --profile stealth --skip-warning
```

### Multiple Report Formats

```bash
python vscanx.py -t http://example.com -s web \
  --format html,json,csv,txt \
  --skip-warning
```

Reports are saved to `reports/` directory.

## Testing

### Run All Tests

```bash
pytest -q
```

### Run Specific Test

```bash
# Unit tests for report generation
pytest tests/test_report_exports.py -q

# Full integration test (server + CLI + reports)
pytest tests/test_integration_smoke.py::test_end_to_end_smoke -q -s
```

### Manual Smoke Scan (against local test server)

```bash
# Terminal 1: Start test server
python vulnerable_server.py

# Terminal 2: Run scan
python vscanx.py -t "http://127.0.0.1:8080/search?q=test" -s web --skip-warning
```

## CLI Flags Reference

| Flag | Purpose | Example |
|------|---------|---------|
| `-t, --target` | Target URL or IP | `-t http://example.com` |
| `-s, --scan-type` | web / network / mixed | `-s web` |
| `-p, --ports` | Port range | `-p 1-1024` |
| `--profile` | Predefined profile | `--profile quick` |
| `--format` | Export format(s) | `--format html,json,csv,txt` |
| `-o, --output` | Output filename | `-o my_report` |
| `--xss-payload` | Custom XSS payload | `--xss-payload "<img src=x onerror=alert(1)>"` |
| `--skip-warning` | Skip legal warning | `--skip-warning` |
| `-v, --verbose` | Verbose output | `-v` |
| `--threads` | Thread count | `--threads 20` |
| `--delay` | Delay between requests | `--delay 0.5` |

## Report Formats

### HTML
- Visual design with severity colors
- Grouped findings per module
- Summary statistics
- Located in: `reports/vscanx_*.html`

### JSON
- Machine-readable structured data
- Matches internal ScanResult model
- Suitable for automation/API integration
- Located in: `reports/vscanx_*.json`

### CSV
- Spreadsheet-friendly format
- One finding per row
- Columns: Module, Severity, Description, Parameter, Evidence
- Located in: `reports/vscanx_*.csv`

### TXT
- Plain text for archival
- Human-readable summary + detailed findings
- Located in: `reports/vscanx_*.txt`

## Troubleshooting

### UnicodeEncodeError on Windows

**Problem**: `UnicodeEncodeError: 'charmap' codec can't encode character`

**Fix**: Set environment variable
```powershell
$env:PYTHONIOENCODING = "utf-8"
python vscanx.py -t http://example.com -s web --skip-warning
```

### Port Already in Use

**Problem**: `OSError: Address already in use`

**Fix**: Kill stray process
```bash
# Linux/Mac
lsof -ti :8080 | xargs kill -9

# Windows
netstat -ano | findstr :8080
taskkill /PID <PID> /F
```

### Timeout During Scan

**Problem**: Request timeout or slow responses

**Fix**: Increase timeout or decrease threads
```bash
python vscanx.py -t http://example.com -s web --delay 2.0 --threads 5 --skip-warning
```

## Architecture Overview

```
VScanX/
├── Core
│   ├── orchestrator.py       ← Main scan coordinator
│   ├── scan_model.py         ← ScanResult & Finding dataclasses
│   ├── request_handler.py    ← HTTP handling + auth
│   └── config.py             ← Constants & profiles
├── Modules
│   ├── Web
│   │   ├── xss_detector.py
│   │   ├── sqli_detector.py
│   │   ├── header_analyzer.py
│   │   ├── dir_enum.py
│   │   └── cve_checker.py
│   └── Network
│       ├── port_scanner.py
│       └── socket_scanner.py
├── Reporting
│   ├── report_generator.py   ← Main report creator
│   └── export_formats.py     ← JSON/CSV/TXT handlers
└── CLI
    └── vscanx.py             ← Entry point
```

## Development

### Adding a New Detector Module

1. Create file in `modules/web/` or `modules/network/`
2. Inherit from `BaseModule`
3. Implement `run(target, **kwargs)` method
4. Return dict with `{"module": name, "findings": [...]}`
5. Register in `orchestrator.py`

Example:
```python
from modules.base_module import BaseModule

class MyDetector(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "My Detector"
    
    def run(self, target, **kwargs):
        findings = []
        # ... detection logic ...
        return {
            "module": self.name,
            "findings": findings
        }
```

### Running Tests with Coverage

```bash
pip install pytest-cov
pytest --cov=core --cov=modules --cov-report=html
```

## Further Reading

- [TESTING.md](TESTING.md) — Complete testing guide
- [ROADMAP.md](ROADMAP.md) — Feature roadmap & priorities
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) — Architecture & delivery details

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security](https://portswigger.net/web-security)
- [SecLists](https://github.com/danielmiessler/SecLists) — Wordlists & payloads

---

**Questions?** Check the README or TESTING.md for more help.
