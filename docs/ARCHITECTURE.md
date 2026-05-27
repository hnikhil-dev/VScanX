# VScanX Architecture (Framework Core)

VScanX is evolving from “a scanner with modules” into **an event-driven security analysis pipeline**.

This document is the source of truth for:
- canonical finding semantics
- event lifecycle + contracts
- module capability declarations
- orchestration flow

## Core principles

- **Resilience by default**: malformed plugins/data should not crash a scan.
- **Strictness is opt-in**: use strict modes in CI/dev, not in default runtime.
- **Canonical, stable data**: findings must be consistent across modules and time.

---

## Orchestration lifecycle (high level)

1. **CLI** (`vscanx.py`) builds an `Orchestrator`
2. **Orchestrator** executes scan phases
   - network scan (optional)
   - web scan (crawler → modules)
   - elite post-processing (optional)
3. **Module results** are normalized through `_add_module_result(...)`
4. **Canonical findings** are appended to `ScanResult.findings`
5. **Events** are published to the internal `EventBus` to record/validate/enrich the lifecycle
6. **Reporting/export** consumes `ScanResult` and validated schema output

---

## Strict events mode

Default mode is **warn + continue** on bad event payloads.

- Enable strict mode in CI/dev:
  - CLI: `--strict-events`
  - Env: `VSCANX_STRICT_EVENTS=1`

Strict mode raises on invalid payloads to prevent contract drift.

