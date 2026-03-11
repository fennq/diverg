#!/usr/bin/env python3
"""
Run a proof scan against an authorized target (e.g. OWASP Juice Shop) and save
results to JSON. Use the output to fill content/we-ran-diverg-on-juice-shop.md
with real findings.

Usage:
    python scripts/run_proof_scan.py https://juice-shop.herokuapp.com
    python scripts/run_proof_scan.py http://localhost:3000

Output: content/juice-shop-proof-results.json (or content/<host>-proof-results.json)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Project root and skill paths (match bot.py)
ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
for sub in ("", "recon", "web_vulns", "headers_ssl", "auth_test", "api_test"):
    sys.path.insert(0, str(SKILLS / sub) if sub else str(SKILLS))
sys.path.insert(0, str(ROOT))

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/run_proof_scan.py <target_url>")
        print("Example: python scripts/run_proof_scan.py https://juice-shop.herokuapp.com")
        sys.exit(1)

    target = sys.argv[1].strip()
    if not target.startswith("http"):
        target = f"https://{target}"

    from urllib.parse import urlparse
    host = urlparse(target).netloc.replace(":", "_")
    out_dir = ROOT / "content"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"{host}-proof-results.json"

    skills_to_run = [
        ("headers_ssl", "full"),
        ("crypto_security", "full"),
        ("data_leak_risks", "full"),
        ("payment_financial", "full"),
        ("high_value_flaws", "full"),
    ]

    results = {"target": target, "skills": {}, "findings_summary": []}

    for skill_name, scan_type in skills_to_run:
        print(f"Running {skill_name} ({scan_type})...")
        try:
            if skill_name == "headers_ssl":
                import headers_ssl
                raw = headers_ssl.run(target, scan_type=scan_type)
            elif skill_name == "crypto_security":
                import crypto_security
                raw = crypto_security.run(target, scan_type=scan_type)
            elif skill_name == "data_leak_risks":
                import data_leak_risks
                raw = data_leak_risks.run(target, scan_type=scan_type)
            elif skill_name == "payment_financial":
                import payment_financial
                raw = payment_financial.run(target, scan_type=scan_type)
            elif skill_name == "high_value_flaws":
                import high_value_flaws
                raw = high_value_flaws.run(target, scan_type=scan_type)
            else:
                raw = "{}"
            data = json.loads(raw) if isinstance(raw, str) else raw
            results["skills"][f"{skill_name}:{scan_type}"] = data
            for f in data.get("findings", []) or data.get("header_findings", []) or data.get("ssl_findings", []):
                if isinstance(f, dict):
                    results["findings_summary"].append({
                        "skill": skill_name,
                        "title": f.get("title") or f.get("header") or f.get("check") or "Finding",
                        "severity": f.get("severity", "Info"),
                        "remediation": f.get("remediation") or f.get("recommendation", ""),
                        "evidence": (f.get("evidence") or f.get("detail") or "")[:300],
                    })
        except Exception as e:
            results["skills"][f"{skill_name}:{scan_type}"] = {"error": str(e)}
        print(f"  Done.")

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {out_file}")
    print(f"Findings count: {len(results['findings_summary'])}")
    for i, s in enumerate(results["findings_summary"][:10], 1):
        print(f"  {i}. [{s['severity']}] {s['title'][:60]}...")
    if len(results["findings_summary"]) > 10:
        print(f"  ... and {len(results['findings_summary']) - 10} more.")
    print("\nUse the JSON to fill content/we-ran-diverg-on-juice-shop.md with real findings.")

if __name__ == "__main__":
    main()
