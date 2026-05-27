# Event contracts

Event payloads are governed by typed contracts in `core/events/schemas.py`.

## Why

Without contracts, orchestration “entropy” grows:
- payload shape becomes convention-based
- plugins diverge
- downstream correlation breaks

## Validation behavior

- **Default runtime**: invalid payload ⇒ warning + continue
- **Strict mode** (`--strict-events` or `VSCANX_STRICT_EVENTS=1`): invalid payload ⇒ exception

## Current event types

### `finding.normalization`

- **Producer**: orchestrator normalization stage
- **Purpose**: allow enrichment subscribers (confidence/verification) to modify normalized fields
- **Required keys**: `module`, `normalized`, `raw`

### `finding.added`

- **Producer**: orchestrator after canonical finding insertion
- **Purpose**: scan graph reconstruction, telemetry, correlation
- **Required keys**: `finding_id`, `module`, `severity`, `description`, `endpoint`, `confidence`, `verification_state`

### `verification.completed`

- **Producer**: orchestrator (when verification metadata exists on a finding)
- **Required keys**: `module`, `finding_id`, `state`, `confidence`

### `crawl.inventory_ready`

- **Producer**: authenticated crawler integration
- **Purpose**: scheduling inputs + recon visibility
- **Required keys**: `visited_count`, `param_urls_count`, `param_names_count`, `api_endpoints_count`, `spa_routes_count`

### `module.completed`

- **Producer**: orchestrator on module completion (and sometimes “skipped” decisions)
- **Required keys**: `module`

