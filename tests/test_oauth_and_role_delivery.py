import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

try:
    from api.verification_api import (
        RoleGrantError,
        _discord_authorization_url,
        _load_oauth_signals,
        _oauth_result_url,
        _oauth_state_digest,
    )
    from modules.verificacion import VerificationManager
except ModuleNotFoundError as exc:
    raise unittest.SkipTest(
        f"Dependencia opcional no instalada: {exc.name}"
    ) from exc


class OAuthFlowTests(unittest.TestCase):
    def test_authorization_url_uses_identify_and_exact_redirect(self):
        with (
            patch("api.verification_api.DISCORD_CLIENT_ID", 123456789),
            patch(
                "api.verification_api.DISCORD_OAUTH_REDIRECT_URI",
                "https://guardian.example/oauth/callback",
            ),
        ):
            authorization_url = _discord_authorization_url("state_value")

        parsed = urlsplit(authorization_url)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "discord.com")
        self.assertEqual(parsed.path, "/oauth2/authorize")
        self.assertEqual(query["scope"], ["identify"])
        self.assertEqual(query["state"], ["state_value"])
        self.assertEqual(
            query["redirect_uri"],
            ["https://guardian.example/oauth/callback"],
        )

    def test_oauth_state_is_stored_as_digest(self):
        state = "x" * 43
        digest = _oauth_state_digest(state)
        self.assertEqual(len(digest), 64)
        self.assertNotIn(state, digest)
        self.assertEqual(digest, _oauth_state_digest(state))

    def test_result_url_keeps_status_in_fragment(self):
        with patch(
            "api.verification_api.FRONTEND_URL",
            "https://example.github.io/verification",
        ):
            result_url = _oauth_result_url("received")
        parsed = urlsplit(result_url)
        self.assertEqual(parsed.query, "")
        self.assertEqual(parsed.fragment, "result=received")

    def test_postgres_json_text_is_restored_as_oauth_signals(self):
        signals = _load_oauth_signals(
            '{"language":"es","signal_version":1}'
        )
        self.assertEqual(signals["language"], "es")
        self.assertEqual(signals["signal_version"], 1)


class RoleDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_discord_role_completes_pending_delivery(self):
        row = {
            "id": 42,
            "guild_id": 1,
            "user_id": 2,
            "token_id": "token-id",
            "role_attempts": 1,
            "role_error_notified_at": None,
        }
        completed = {
            **row,
            "user_notified_at": None,
            "staff_notified_at": None,
        }
        member = SimpleNamespace(id=2)
        manager = VerificationManager(SimpleNamespace())
        manager._manual_review_member = AsyncMock(return_value=member)
        manager._notify_completed_role_delivery = AsyncMock()

        with (
            patch(
                "core.database.claim_pending_role_delivery",
                AsyncMock(return_value=row),
            ),
            patch(
                "api.verification_api._grant_verified_role",
                AsyncMock(return_value=False),
            ),
            patch(
                "core.database.complete_role_delivery",
                AsyncMock(return_value=completed),
            ) as complete,
        ):
            result = await manager.process_pending_role_delivery(42)

        self.assertEqual(result, "granted")
        complete.assert_awaited_once_with(42)
        manager._notify_completed_role_delivery.assert_awaited_once()

    async def test_permanent_role_error_is_saved_for_reconciliation(self):
        row = {
            "id": 43,
            "guild_id": 1,
            "user_id": 2,
            "token_id": "token-id",
            "role_attempts": 1,
            "role_error_notified_at": None,
        }
        member = SimpleNamespace(id=2)
        manager = VerificationManager(SimpleNamespace())
        manager._manual_review_member = AsyncMock(return_value=member)
        error = RoleGrantError("Falta jerarquía")
        failed = {**row, "role_error_notified_at": None}

        with (
            patch(
                "core.database.claim_pending_role_delivery",
                AsyncMock(return_value=row),
            ),
            patch(
                "api.verification_api._grant_verified_role",
                AsyncMock(side_effect=error),
            ),
            patch(
                "core.database.reschedule_role_delivery",
                AsyncMock(return_value=failed),
            ) as reschedule,
            patch(
                "api.verification_api._send_role_error_alert",
                AsyncMock(),
            ),
            patch(
                "core.database.mark_role_notification",
                AsyncMock(),
            ),
        ):
            result = await manager.process_pending_role_delivery(43)

        self.assertEqual(result, "pending")
        self.assertTrue(reschedule.await_args.kwargs["permanent"])
        self.assertEqual(
            reschedule.await_args.kwargs["retry_after_seconds"],
            21600,
        )


if __name__ == "__main__":
    unittest.main()
