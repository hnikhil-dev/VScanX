## CI/CD Setup & Local Testing

VScanX includes automated testing and continuous integration (CI) to verify code quality and report generation.

### GitHub Actions Workflow

The project includes `.github/workflows/ci.yml` which:

1. **Runs on push and PRs** to the `main` branch
2. **Installs dependencies** including Python 3.11 and `requirements.txt`
3. **Runs unit tests** (`pytest`) to verify core functionality
4. **Starts the vulnerable test server** locally (`vulnerable_server.py`)
5. **Executes a smoke scan** via CLI against the test server
6. **Verifies all report formats** are produced (HTML, PDF, JSON, CSV, TXT)
7. **Uploads the `reports/` directory** as a workflow artifact for inspection

### Running Tests Locally

#### Unit Tests

```bash
# Install test dependencies
pip install pytest reportlab

# Run all unit tests
pytest -q

# Run specific test module
pytest tests/test_report_exports.py -q

# Run specific test
pytest tests/test_integration_smoke.py::test_end_to_end_smoke -q -s
```

#### Integration Smoke Test

The integration test (`tests/test_integration_smoke.py::test_end_to_end_smoke`) is the end-to-end validation:

```bash
# Runs in isolation:
# 1. Starts vulnerable_server.py on http://127.0.0.1:8080
# 2. Executes VScanX CLI against the test server
# 3. Verifies reports (HTML, JSON, CSV, TXT) are generated
# 4. Cleans up server process and generated reports
pytest tests/test_integration_smoke.py::test_end_to_end_smoke -q -s
```

#### Manual Smoke Scan

You can run the CLI directly against the local test server:

```bash
# Terminal 1: Start the test server
python vulnerable_server.py

# Terminal 2: Run VScanX
python vscanx.py -t "http://127.0.0.1:8080/search?q=test" -s web --skip-warning --format html,json,csv,txt
```

This creates `reports/vscanx_127.0.0.1_web_*.{html,json,csv,txt}`.

### What Each Test Validates

| Test | Coverage | Validates |
|------|----------|-----------|
| `test_report_exports.py` | Report generation | HTML/JSON/CSV/TXT files created with correct metadata |
| `test_validate_mismatch()` | Sanity check | Catches summary/findings mismatch (fail-fast) |
| `test_orchestrator_summary_consistency()` | Orchestrator | Central `ScanResult` model consistency |
| `test_end_to_end_smoke` | Full pipeline | Server startup → CLI scan → all formats → cleanup |

### CI Artifacts

When a GitHub Actions workflow runs:

1. If all tests pass, the `reports/` directory is uploaded as **`vscanx-ci-reports`** artifact
2. Artifacts are available for 90 days (GitHub default)
3. Download to inspect sample HTML report, JSON schema, CSV findings, etc.

### Troubleshooting Local Tests

**Issue:** `UnicodeEncodeError` on Windows console  
**Cause:** CLI prints unicode characters (box-drawing, emoji) in cp1252 console  
**Fix:** CLI now uses ASCII-safe banners; if you see errors, set `PYTHONIOENCODING=utf-8`

```bash
set PYTHONIOENCODING=utf-8
python vscanx.py -t http://127.0.0.1:8080/search?q=test -s web --skip-warning
```

**Issue:** `TimeoutError` in integration test  
**Cause:** Server takes too long to start or ports are in use  
**Fix:** Ensure port 8080 is free and increase timeout in `test_integration_smoke.py` if needed

**Issue:** `OSError: Address already in use`  
**Cause:** Leftover process from previous test run  
**Fix:** Kill stray processes: `lsof -ti :8080 | xargs kill -9` (Linux/Mac) or `netstat -ano` on Windows

### Next Steps for CI Maturity

1. **Code coverage**: Add `pytest-cov` and enforce minimum coverage thresholds
2. **Linting**: Add `pylint` or `flake8` to CI
3. **Security scanning**: Add `bandit` to check for vulnerable patterns
4. **Performance testing**: Benchmark scan times to catch regressions
5. **Docker CI**: Build and test in containerized environment for consistency

### Schema & Contracts

The test suite validates the `ScanResult` and `Finding` dataclass contracts:

- `ScanResult.findings` is always populated when `summary.total_findings > 0`
- Each `Finding` has required fields: `module`, `severity`, `description`
- JSON export schema matches the internal model structure

See `core/scan_model.py` for the dataclass definitions.
