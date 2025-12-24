# VScanX - Ethical Vulnerability Scanner

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![CI](https://github.com/hnikhil-dev/VScanX/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/vscanx.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**VScanX** is a lightweight, modular, ethical vulnerability scanner designed for authorized security testing. It combines web and network scanning capabilities with a focus on clean architecture, professional code quality, and responsible disclosure practices.

## ⚙️ Installation (quick)

```bash
# Option 1: From source
git clone https://github.com/hnikhil-dev/VScanX.git && cd VScanX
pip install -r requirements.txt
python vscanx.py -h

# Option 2: Via pip (once published)
pipx install vscanx
```

## ⚠️ Legal Warning

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

You must have explicit written permission to scan any target system. Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom  
- Similar laws in other jurisdictions

**By using this tool, you agree to:**
- Only scan systems you own or have written authorization to test
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions

The developers assume NO liability for misuse of this tool. See [LEGAL.md](LEGAL.md) for complete terms.

## 🎯 Features

### What it does today
- **Authenticated scanning**: optional bearer/API-key/login/session support.
- **Web modules**: SQLi (error/boolean/time-based), XSS, headers, dir enum, CVE check.
- **Network**: TCP port scanning with service hints; optional parallel web modules.
- **Structured output**: JSON schema validation, sanitized exports (HTML/JSON/CSV/TXT/PDF).
- **Observability**: JSON logging, metrics artifact, optional debug capture with redaction.
- **Ethical defaults**: legal warning, rate limiting, safe payloads, opt-in parallelism.
- **CI/tests**: ruff + pytest/coverage, fuzz/heuristic tests, schema validation, no-print check in modules.

### Future Planned Features
- Service fingerprinting
- Plugin loader (dynamic module discovery)
- Packaging & distribution (PyPI/installer)

## 🧪 Testing & CI/CD

VScanX includes automated testing and continuous integration:
- Ruff linting (GitHub Actions)
- Pytest with coverage (unit + smoke + fuzz/heuristics)
- CI check to block `print()` in modules
- Local testing: see [TESTING.md](TESTING.md) for complete guide

Run all tests locally:
```bash
pip install -r requirements.txt
pytest -q
```

## 🛣️ Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed feature roadmap, completed work, and next priorities.

**Current focus**: Production readiness — linting, CI polish, documentation, and legal/packaging items

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip package manager
- Root/Administrator privileges (required for Scapy port scanning)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/hnikhil-dev/VScanX.git
cd VScanX
