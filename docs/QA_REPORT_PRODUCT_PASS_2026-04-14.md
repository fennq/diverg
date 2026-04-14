# Product QA pass — 2026-04-14

Automated runs from repo root unless noted. **Manual browser checks** were not executed in this session; use the checklist below on staging or production with a test account.

## Summary

| Layer | Result | Notes |
|-------|--------|--------|
| `pytest tests/` | **174 passed**, 6 skipped | Full suite; stricter than CI subset |
| `flake8 orchestrator.py api_server.py` | **Pass** | Via `python3 -m flake8` |
| `scripts/verify_functional.py` | **Pass** | Requires deps from `requirements.txt` (`openai`, `python-telegram-bot`); real recon step tolerates DNS noise |
| `native/diverg-recon` `cargo test` | **Pass** | 1 test |
| `test_security.py` | **36/36 pass** | Server on **5017** + `DIVERG_TRUST_PROXY=1` + `TEST_SECURITY_*` env (see [test_security.py](../test_security.py) docstring); macOS **port 5000 is AirPlay**, not Flask |
| Chrome extension | **Not run** | Static review: `extension/manifest.json` MV3, host permissions include `https://*/*` |
| diverg-landing | **Static** | `resources/docs/changelog.html` and 15 doc HTML files present in sibling repo |

## CI gap

[`.github/workflows/python-quality.yml`](../.github/workflows/python-quality.yml) runs **flake8 on two files** and **three** pytest files only. Failures elsewhere would **not** block merge. **Enhancement:** add job step `pytest -q tests/` (or nightly).

## Fixes applied during QA

- **[test_security.py](../test_security.py):** Configurable `TEST_SECURITY_BASE` / `TEST_SECURITY_CORS_ORIGIN`; HSTS assertion allows omission on plain HTTP (matches production behavior); CSP check aligned with dashboard `script-src` (still forbids `unsafe-eval`); top-of-file runbook for macOS + trust proxy.

## Manual UI checklist (for you to run)

**Dashboard (authenticated):** login (email + Privy if enabled); Scanner stream; Scan Diff + verification strip; Site watchlist add/run; Credits + Phantom link; Tokens + mint watchlist; History/Findings/Settings; forced session expiry → login with `?session=expired`.

**Extension:** Load unpacked `extension/`; set API URL + JWT; popup, options, one scan or investigation path.

**diverg-landing:** Home → Changelog → Docs index; mobile width spot check.

## Enhancements (backlog)

- Document **`test_security.py` one-liner** in [AGENTS.md](../AGENTS.md) next to security tests bullet.
- **Extension:** add minimal automated check (manifest JSON schema / lint) or Playwright smoke.
- **venv discipline:** CI/dev should use full `pip install -r requirements.txt` so `verify_functional.py` does not fail on missing `openai` / `telegram`.
