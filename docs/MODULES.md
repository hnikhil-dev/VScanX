# Module capability declarations

Modules inherit from `modules/base_module.py::BaseModule`.

## Why this matters

Capability declarations allow orchestration to become:
- budget-aware (`request_cost`)
- context-aware (auth state requirements)
- signal-aware (tech compatibility)
- target-aware (content type suitability)

## Metadata fields

Returned by `BaseModule.get_metadata()`:

- `risk_level`: LOW/MEDIUM/HIGH/CRITICAL (module risk posture)
- `request_cost`: relative intensity cost used for budgeting
- `requirements`: free-form list of prerequisites (e.g., `["web"]`, `["authenticated"]`)
- `compatible_tech_stacks`: list of stacks; if set, orchestrator can gate on tech signals
- `confidence_reliability`: LOW/MEDIUM/HIGH (expected FP/TP quality)
- `dependencies`: other module keys required

Capability fields (framework-core):
- `consumes_events`: events the module can consume
- `emits_events`: events the module can emit
- `required_auth_state`: `any | authenticated | unauthenticated`
- `supported_content_types`: content types the module is designed for
- `supported_technologies`: broad technology tags (e.g., `rest-api`, `wordpress`)

## Orchestrator use

Current orchestration uses:
- auth gating via `required_auth_state`
- simple budgeting via `request_cost` and profile `module_budget`

