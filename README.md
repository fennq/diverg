# Security testing pipeline

CLI and HTTP API for running security checks against a target URL. Python 3.11+.

## Run

```bash
pip install -r requirements.txt
cp .env.example .env
# Set OPENAI_API_KEY in .env

# CLI
python orchestrator.py --target https://example.com --scope full

# API (for extension or other clients)
python api_server.py
```

## Layout

- `orchestrator.py` — CLI entry; runs scan profiles (full, quick, web, api, recon).
- `api_server.py` — HTTP API (scan, stream, PoC simulate).
- `intent_skills.py` — Goal-to-skill mapping.
- `skills/` — Scan modules (headers, recon, web, API, etc.).
- `rag/` — Index and citations (reads from local content; not in repo).
- `extension/` — Chrome extension UI (full extension lives in separate repo).

Internal content, runbooks, and product docs are not included in this repo. Use authorized targets only.

## License

MIT
