This folder holds small developer utilities and temporary scripts used during local testing.

- `tmp_generate_report.py` — moved here from `tests/`; use to render a local HTML report for manual inspection.

Notes:
- Generated reports have been archived to `reports/archive/` to keep the repository tidy.
- These files are for developer convenience only and are not required for normal operation or CI.
- If you want them removed entirely, run: `Remove-Item -Path reports/archive/* -Recurse -Force`