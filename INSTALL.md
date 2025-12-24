# Installation Guide

## Prerequisites
- Python 3.11+
- pip

## Setup
```bash
git clone <repo-url>
cd VScanX
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Quick run
```bash
python vscanx.py -t http://example.com -s mixed --format html,json
```

## Development checks
```bash
ruff check .
pytest --maxfail=1 --disable-warnings
```


