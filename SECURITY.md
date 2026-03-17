# Security — keep the repo safe for public hackathon

Before pushing to GitHub (or any public remote), ensure we do **not** leak tech or secrets.

## Checklist

- [ ] **No secrets in repo** — No `.env`, API keys, tokens, or passwords in code or config. All secrets live in environment variables; use `.env.example` only as a template with placeholders.
- [ ] **No internal URLs** — No hardcoded internal hostnames, staging URLs, or customer-specific targets in docs/code that shouldn’t be public. Extension/API default to `127.0.0.1` for local dev only.
- [ ] **Sensitive outputs** — `results/`, `reports/`, `data/`, `*.brain.json`, and scan result JSON in `content/` are gitignored; do not force-add them.
- [ ] **Config** — `config.json` uses `${OPENCLAW_AUTH_TOKEN}`; real values come from env. Do not commit a `config.local.json` or any file with real tokens.

## If you added new secrets or config

1. Put real values in `.env` (never committed).
2. Add any new secret file patterns to `.gitignore`.
3. If you need to document a new env var, add a placeholder to `.env.example` only.

## Verifying before push

```bash
# Ensure .env is not staged
git status
# Should NOT list .env

# Optional: search for common leak patterns (no matches expected in committed files)
git grep -E 'sk-[a-zA-Z0-9]{20,}' -- '*.py' '*.js' '*.json' '*.md' '*.yml' || true
git grep -E 'ghp_[a-zA-Z0-9]{36}' -- '*.py' '*.js' '*.json' '*.md' || true
```
