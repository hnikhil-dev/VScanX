# Changelog

All notable changes to this project will be documented here.

## [Unreleased]
- Added structured JSON logging and log setup helper.
- Hardened target validation (IPv4/IPv6/hostname/ports).
- Added JSON Schema validation for scan results and findings.
- Sanitized report/export filenames to prevent path traversal.
- Added basic metrics collection and per-module timing.
- Added CI workflow (ruff + pytest with coverage) on Linux/Windows.
- Added SECURITY, CONTRIBUTING, CODE_OF_CONDUCT policy docs.

## [2.1.0] - 2025-12-24
- Phase 2 wrap-up: SQLi/dir-enum/header remediation improvements, expanded heuristics.
- Phase 3 enhancements: structured logging, metrics, optional parallel modules, debug capture with redaction.
- Export hardening: JSON Schema validation, sanitized exports, export validation layer.
- Docs: schema documentation and sanitized sample report; README/CI/test updates.
- Packaging: setuptools + pyproject metadata, MANIFEST for templates, pip/pipx ready.
- Tests: fuzz/heuristic suites for SQLi/XSS/dir enum; CI check to block print() in modules.


