"""Tests for Privy auth bridge helpers."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import api_server as srv


class _Claims:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.app_id = "app"


class _UsersClient:
    def verify_access_token(self, token: str):
        if token == "good-token":
            return _Claims("did:privy:abc123")
        raise ValueError("bad token")


class _PrivyClient:
    def __init__(self):
        self.users = _UsersClient()


class TestPrivyAuthBridge(unittest.TestCase):
    def test_obj_to_dict(self):
        out = srv._obj_to_dict(_Claims("did:privy:demo"))
        self.assertEqual(out.get("user_id"), "did:privy:demo")
        self.assertEqual(out.get("app_id"), "app")

    def test_verify_privy_access_token(self):
        with patch.object(srv, "PRIVY_ENABLED", True), patch.object(srv, "_privy_client", return_value=_PrivyClient()):
            ok = srv._verify_privy_access_token("good-token")
            self.assertIsNotNone(ok)
            self.assertEqual(ok.get("did"), "did:privy:abc123")

            bad = srv._verify_privy_access_token("bad-token")
            self.assertIsNone(bad)


if __name__ == "__main__":
    unittest.main()
