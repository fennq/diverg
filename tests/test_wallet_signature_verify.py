"""Tests for wallet signature decoding/verification compatibility."""
from __future__ import annotations

import base64
import unittest

import base58
from nacl.signing import SigningKey

import api_server as server


class TestWalletSignatureVerify(unittest.TestCase):
    def test_verify_accepts_base58_base64_and_bytes(self) -> None:
        sk = SigningKey.generate()
        vk = sk.verify_key
        wallet_b58 = base58.b58encode(bytes(vk)).decode("ascii")
        msg = "Diverg wallet link\nUser: u1\nWallet: X\nNonce: n\nIssuedAt: now"
        sig = sk.sign(msg.encode("utf-8")).signature

        sig_b58 = base58.b58encode(sig).decode("ascii")
        sig_b64 = base64.b64encode(sig).decode("ascii")
        sig_bytes = list(sig)

        self.assertTrue(server._verify_wallet_signature(wallet_b58, msg, signature_b58=sig_b58))
        self.assertTrue(server._verify_wallet_signature(wallet_b58, msg, signature_base64=sig_b64))
        self.assertTrue(server._verify_wallet_signature(wallet_b58, msg, signature_bytes=sig_bytes))

    def test_verify_rejects_wrong_message(self) -> None:
        sk = SigningKey.generate()
        vk = sk.verify_key
        wallet_b58 = base58.b58encode(bytes(vk)).decode("ascii")
        sig = sk.sign(b"message A").signature
        sig_b58 = base58.b58encode(sig).decode("ascii")
        self.assertFalse(server._verify_wallet_signature(wallet_b58, "message B", signature_b58=sig_b58))


if __name__ == "__main__":
    unittest.main()
