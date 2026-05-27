# Canonical finding model

The canonical finding object is `core/scan_model.py::Finding`.

## Goals

- Stable identity for dedupe/correlation (`finding_id`)
- Consistent evidence representation (`evidence` object)
- Explicit verification semantics (`verification_state`)
- Support “evolving findings” via `enrichment_history`

## Key fields (summary)

- **`finding_id`**: stable UUID (derived from canonical fields; stable across runs for same finding)
- **`timestamp`**: event time for this observation
- **`first_seen_at` / `last_seen_at`**: lifecycle timestamps for dedupe + replay
- **`module` / `severity` / `description`**: core descriptor fields
- **`endpoint` / `parameter`**: where the finding applies
- **`evidence`**: structured object
  - `summary`: short text for reports
  - `details`: longer text
  - `raw`: raw evidence fragment
- **`confidence`**: coarse confidence label (e.g. LOW/MEDIUM/HIGH)
- **`verified`**: boolean or null
- **`verification_state`**: `UNVERIFIED | CANDIDATE | VERIFIED | REJECTED`
- **`verification`**: verifier metadata (notes, metrics, similarity, etc.)
- **`reproduction`**: reproduction material (curl, steps)
- **`enrichment_history`**: list of enrichment steps with timestamps and reasoning

## Backward compatibility

Some exports/tests may still include legacy evidence strings. The JSON schema tolerates this by accepting `evidence` as object or string.

