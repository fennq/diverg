from __future__ import annotations

import pytest

import api_server
from skills import blockchain_investigation as bi


@pytest.fixture(autouse=True)
def _clear_arkham_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ARKHAM_API_KEY", raising=False)


def test_arkham_capabilities_server_managed_without_key() -> None:
    caps = api_server._arkham_capabilities(required=True)
    assert caps["provider"] == "arkham"
    assert caps["mode"] == "server_managed"
    assert caps["required_for_endpoint"] is True
    assert caps["available"] is False
    assert caps["client_supplied_key_allowed"] is False


def test_arkham_missing_response_has_capability_block() -> None:
    with api_server.app.app_context():
        resp, status = api_server._arkham_env_error_response("full blockchain investigation")
        payload = resp.get_json()
    assert status == 503
    assert "Arkham intelligence is currently unavailable" in payload["error"]
    assert payload["intelligence_capabilities"]["provider"] == "arkham"
    assert payload["intelligence_capabilities"]["available"] is False
    assert payload["intelligence_capabilities"]["required_for_endpoint"] is True


def test_normalize_token_candidates_filters_invalid() -> None:
    chain = "solana"
    bad = "http://example.com/not-a-mint"
    good = "5Kd3NBUAdUnwY9fM5hA4N2YzW4qYQJvN7Q3qMw4M4C9F"
    dup = good
    system_program = "11111111111111111111111111111111"
    out = bi._normalize_token_candidates([bad, good, dup, system_program], chain)
    assert out == [good]


def test_sniper_heuristic_ignores_non_user_and_late_noise() -> None:
    token_a = "7xK9mN2pQ4w8v1Bz6hC3dE5fG7jK9LmN2pQ4w8v1Bz6h"
    token_b = "8yL3mN2pQ4w8v1Bz6hC3dE5fG7jK9LmN2pQ4w8v1Bz6i"
    wallet = "4N2pQ4w8v1Bz6hC3dE5fG7jK9LmN2pQ4w8v1Bz6hC3dE"
    txs = {
        token_a: [
            {"to": wallet, "from": "11111111111111111111111111111111", "timeStamp": 100},
            {"to": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "timeStamp": 101},
            {"to": wallet, "from": "x", "timeStamp": 9000},  # late noise (outside first window)
        ],
        token_b: [
            {"to": wallet, "from": "x", "timeStamp": 110},
            {"to": wallet, "from": "x", "timeStamp": 111},
        ],
    }
    alerts = bi._heuristic_sniper(txs, same_wallet_min_tokens=2)
    assert alerts, "Expected curated sniper alert for shared early wallet"
    assert alerts[0]["wallet"] == wallet
    assert alerts[0]["token_count"] == 2


def test_concentration_heuristic_filters_lp_labels() -> None:
    holders = [
        {"owner": "LPWallet", "amount": 800, "owner_label": "Raydium liquidity pool"},
        {"owner": "UserA", "amount": 150},
        {"owner": "UserB", "amount": 50},
    ]
    alerts = bi._heuristic_concentrated_holders(holders, top_n=2, threshold_pct=40.0)
    # LP should be excluded; remaining top2 = 200/1000 = 20% < threshold
    assert alerts == []


def test_api_server_evm_chain_normalization_supports_multichain() -> None:
    assert api_server._normalize_evm_chain_slug("base") == "base"
    assert api_server._normalize_evm_chain_slug("arb") == "arbitrum"
    assert api_server._normalize_evm_chain_slug("xdai") == "gnosis"
    assert api_server._normalize_evm_chain_slug("unknown-chain") == "ethereum"


def test_arkham_chain_slug_mapping_supports_extended_evm() -> None:
    from investigation import arkham_intel as ai

    assert ai.evm_chain_slug_for_arkham("linea") == "linea"
    assert ai.evm_chain_slug_for_arkham("scroll") == "scroll"
    assert ai.evm_chain_slug_for_arkham("blast") == "blast"
    assert ai.evm_chain_slug_for_arkham("celo") == "celo"
    assert ai.evm_chain_slug_for_arkham("ftm") == "fantom"


def test_health_includes_arkham_status_block() -> None:
    with api_server.app.test_client() as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        payload = res.get_json()
    assert isinstance(payload, dict)
    assert isinstance(payload.get("arkham"), dict)
    assert payload["arkham"]["provider"] == "arkham"
    assert payload["arkham"]["mode"] == "server_managed"


def test_strict_evidence_findings_drops_review_and_weak_items() -> None:
    def _f(
        *,
        title: str,
        source: str,
        confidence: str,
        proof: str,
        verified: bool,
    ) -> bi.Finding:
        return bi.Finding(
            title=title,
            severity="Info",
            url="https://example.test",
            category="Blockchain / Test",
            evidence=proof or "test",
            impact="test",
            remediation="test",
            source=source,
            confidence=confidence,
            proof=proof,
            verified=verified,
        )

    src = [
        _f(
            title="Cross-chain asset hints [REVIEW]",
            source="cross_chain_hints",
            confidence="medium",
            proof="chain-map maybe",
            verified=False,
        ),
        _f(
            title="Wallet labeled (Arkham Intel): Test",
            source="arkham_api",
            confidence="high",
            proof="addr -> label",
            verified=True,
        ),
        _f(
            title="Stated fee vs on-chain fee mismatch [REVIEW]",
            source="solscan_api",
            confidence="low",
            proof="",
            verified=False,
        ),
    ]
    kept, dropped = bi._strict_evidence_findings(src)
    assert dropped == 2
    assert len(kept) == 1
    assert kept[0].source == "arkham_api"
