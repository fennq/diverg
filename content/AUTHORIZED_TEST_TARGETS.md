# Authorized test targets

Targets below are authorized for Diverg security testing (contractual scope or intentionally vulnerable).

| Target | Purpose |
|--------|--------|
| https://testphp.vulnweb.com | Intentionally vulnerable (Acunetix); for scanner validation and exploit discovery. |
| https://www.perplexity.ai/computer/new | Authorized assessment; discover novel or not-yet-public issues; multi-site applicability noted. |
| https://x.com/home | Authorized assessment; discover novel or not-yet-public issues; multi-site applicability noted. |

Add more URLs here when you have written authorization. Run scans with:
`./venv/bin/python orchestrator.py --target <URL> --scope web`
or `--scope full` for full assessment.
