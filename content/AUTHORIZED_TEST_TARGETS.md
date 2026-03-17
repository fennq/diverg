# Example test targets (public / hackathon)

Use only targets you are **authorized** to test (e.g. your own apps or intentionally vulnerable demos).

| Target | Purpose |
|--------|--------|
| https://testphp.vulnweb.com | Intentionally vulnerable (Acunetix); for scanner validation. May time out. |
| https://example.com | Generic example; replace with your own target. |

Add URLs here when you have written authorization. Run scans with:

```bash
./venv/bin/python orchestrator.py --target <URL> --scope web
# or
./venv/bin/python orchestrator.py --target <URL> --scope full
```

**Do not** commit internal or customer-specific URLs to the public repo.
