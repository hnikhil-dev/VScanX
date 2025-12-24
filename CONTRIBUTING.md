# Contributing to VScanX

## Ground rules
- Use the tool only on authorized targets.
- Follow the code of conduct in this repository.
- Keep secrets out of logs, issues, and PRs.

## Getting started
1. Fork and clone the repo.
2. Create a virtual environment with Python 3.11.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run lint and tests before sending a PR:
   ```bash
   ruff check .
   pytest --maxfail=1 --disable-warnings
   ```

## Pull requests
- Describe the change and the risk surface.
- Add or update tests and docs.
- Keep changes small and focused; separate refactors from features.

## Security
- If you find a vulnerability, follow `SECURITY.md` (do not open a public issue).


