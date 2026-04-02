from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills"))


class SentinelApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        os.environ["DIVERG_DB_PATH"] = str(Path(self.tmpdir.name) / "dashboard.db")
        os.environ["SENTINEL_ENABLED"] = "1"
        module = importlib.import_module("api_server")
        self.api = importlib.reload(module)
        self.client = self.api.app.test_client()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def create_user(self, email: str) -> dict:
        user_id = str(uuid.uuid4())
        with self.api._db() as conn:
            conn.execute(
                """INSERT INTO users (id, email, name, password, provider, avatar_url, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, email, email.split("@")[0], "", "email", "", "2026-04-02T00:00:00+00:00"),
            )
        return {
            "id": user_id,
            "email": email,
            "token": self.api.create_token(user_id, email),
        }

    def auth_headers(self, user: dict) -> dict[str, str]:
        return {"Authorization": f"Bearer {user['token']}"}

    def create_scan(self, user_id: str, scan_id: str, target_url: str, created_at: str, risk_score: int = 5):
        report = {
            "target_url": target_url,
            "findings": [
                {
                    "title": "Missing CSP",
                    "severity": "High",
                    "url": target_url,
                    "category": "Transport and Browser Security",
                    "evidence": "Content-Security-Policy missing",
                }
            ],
            "scanned_at": created_at,
            "risk_score": risk_score,
            "risk_verdict": "High Risk",
        }
        with self.api._db() as conn:
            conn.execute(
                """INSERT INTO scans
                   (id, user_id, target_url, scope, scanned_at, status, risk_score, risk_verdict,
                    total, critical, high, medium, low, info, label, report_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    user_id,
                    target_url,
                    "full",
                    created_at,
                    "completed",
                    risk_score,
                    "High Risk",
                    1,
                    0,
                    1,
                    0,
                    0,
                    0,
                    "",
                    json.dumps(report),
                    created_at,
                ),
            )

    def test_sentinel_requires_auth(self):
        response = self.client.get("/api/sentinel/diff?scan_id=scan-1")
        self.assertEqual(response.status_code, 401)

    def test_sentinel_diff_auto_selects_previous_scan(self):
        user = self.create_user("alice@example.com")
        self.create_scan(user["id"], "scan-old", "https://example.com/", "2026-04-01T00:00:00+00:00", risk_score=2)
        self.create_scan(user["id"], "scan-new", "https://example.com/", "2026-04-02T00:00:00+00:00", risk_score=7)

        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return {"summary": {"new_count": 1}}

        with mock.patch.object(self.api, "_ensure_sentinel_available", return_value=None), \
             mock.patch.object(self.api, "_run_sentinel", side_effect=fake_run):
            response = self.client.get("/api/sentinel/diff?scan_id=scan-new", headers=self.auth_headers(user))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            captured["args"],
            (
                "diff",
                "--scan-a", "scan-old",
                "--scan-b", "scan-new",
                "--db", str(self.api.DB_PATH),
            ),
        )
        payload = response.get_json()
        self.assertEqual(payload["compare_to"], "scan-old")
        self.assertTrue(payload["auto_selected_previous"])

    def test_sentinel_diff_enforces_scan_ownership(self):
        user_a = self.create_user("alice@example.com")
        user_b = self.create_user("bob@example.com")
        self.create_scan(user_a["id"], "scan-a", "https://example.com/", "2026-04-02T00:00:00+00:00")

        with mock.patch.object(self.api, "_ensure_sentinel_available", return_value=None), \
             mock.patch.object(self.api, "_run_sentinel") as run_mock:
            response = self.client.get("/api/sentinel/diff?scan_id=scan-a", headers=self.auth_headers(user_b))

        self.assertEqual(response.status_code, 404)
        run_mock.assert_not_called()

    def test_sentinel_disabled_returns_503(self):
        user = self.create_user("alice@example.com")
        self.api.SENTINEL_ENABLED = False
        response = self.client.get(
            "/api/sentinel/surface/history?target_url=https%3A%2F%2Fexample.com%2F",
            headers=self.auth_headers(user),
        )
        self.assertEqual(response.status_code, 503)
        self.assertTrue(response.get_json()["sentinel_disabled"])

    def test_sentinel_regression_create_maps_headers_params_and_assertions(self):
        user = self.create_user("alice@example.com")
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            return {"regression": {"id": 1}}

        with mock.patch.object(self.api, "_ensure_sentinel_available", return_value=None), \
             mock.patch.object(self.api, "_run_sentinel", side_effect=fake_run):
            response = self.client.post(
                "/api/sentinel/regressions",
                headers=self.auth_headers(user),
                json={
                    "target_url": "https://example.com/",
                    "finding_title": "IDOR replay",
                    "method": "GET",
                    "request_url": "https://example.com/api/users",
                    "headers": {"Authorization": "Bearer token"},
                    "params": {"id": "2"},
                    "expected_status": 200,
                    "match_pattern": "admin",
                },
            )

        self.assertEqual(response.status_code, 200)
        args = captured["args"]
        self.assertIn("--header", args)
        self.assertIn("Authorization=Bearer token", args)
        self.assertIn("--param", args)
        self.assertIn("id=2", args)
        self.assertIn("--expected-status", args)
        self.assertIn("200", args)
        self.assertIn("--match-pattern", args)
        self.assertIn("admin", args)

    def test_sentinel_regression_create_rejects_non_object_headers(self):
        user = self.create_user("alice@example.com")
        with mock.patch.object(self.api, "_ensure_sentinel_available", return_value=None):
            response = self.client.post(
                "/api/sentinel/regressions",
                headers=self.auth_headers(user),
                json={
                    "target_url": "https://example.com/",
                    "finding_title": "IDOR replay",
                    "method": "GET",
                    "request_url": "https://example.com/api/users",
                    "headers": ["bad"],
                    "expected_status": 200,
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("headers", response.get_json()["message"])

    def test_sentinel_regression_run_uses_authenticated_user_scope(self):
        user_a = self.create_user("alice@example.com")
        user_b = self.create_user("bob@example.com")
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            return {"summary": {"total": 0}, "results": []}

        with mock.patch.object(self.api, "_ensure_sentinel_available", return_value=None), \
             mock.patch.object(self.api, "_run_sentinel", side_effect=fake_run):
            response = self.client.post(
                "/api/sentinel/regressions/run",
                headers=self.auth_headers(user_b),
                json={"target_url": "https://example.com/", "user_id": user_a["id"]},
            )

        self.assertEqual(response.status_code, 200)
        args = captured["args"]
        user_id_index = args.index("--user-id")
        self.assertEqual(args[user_id_index + 1], user_b["id"])


if __name__ == "__main__":
    unittest.main()
