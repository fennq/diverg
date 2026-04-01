"""Tests for heuristic Web3 / wallet-abuse signals (wallet_drainer_signals)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills"))
os.chdir(ROOT)


def test_benign_first_party_request_accounts_only_no_high() -> None:
    import wallet_drainer_signals as wds

    base = "https://example.com"
    js_url = "https://example.com/static/app.js"
    content = "async function c(){ await window.ethereum.request({method:'eth_requestAccounts'}); }"
    out = wds.analyze_wallet_abuse_js(content, js_url, base, deep=False)
    assert not any(f.severity == "High" for f in out)


def test_malicious_third_party_approval_and_send_tx_heuristic() -> None:
    import wallet_drainer_signals as wds

    base = "https://example.com"
    js_url = "https://evil-cdn.test/drain.js"
    content = """
    contract.approve(spender, maxUint);
    provider.request({ method: 'eth_sendTransaction', params: [{}] });
    """
    out = wds.analyze_wallet_abuse_js(content, js_url, base, deep=False)
    assert any(f.severity in ("High", "Medium") for f in out)
    assert any("Third-party" in f.title or "third-party" in f.evidence.lower() for f in out)


def test_allowlisted_cdn_suppressed() -> None:
    import wallet_drainer_signals as wds

    base = "https://example.com"
    js_url = "https://cdn.jsdelivr.net/npm/some-pkg/drain-shaped.js"
    content = """
    token.approve(attacker, amount);
    ethereum.request({ method: 'eth_sendTransaction' });
    """
    out = wds.analyze_wallet_abuse_js(content, js_url, base, deep=False)
    assert out == []


def test_third_party_obfuscation_only_in_deep_scan() -> None:
    import wallet_drainer_signals as wds

    base = "https://example.com"
    js_url = "https://evil-cdn.test/packed.js"
    content = "eval(x); var _ = 'ethereum' + 'sendTransaction';"
    shallow = wds.analyze_wallet_abuse_js(content, js_url, base, deep=False)
    assert not any("eval/Function" in f.title for f in shallow)
    deep = wds.analyze_wallet_abuse_js(content, js_url, base, deep=True)
    assert any("eval/Function" in f.title for f in deep)
