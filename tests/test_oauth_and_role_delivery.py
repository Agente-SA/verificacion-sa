import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlsplit

from aiohttp.test_utils import TestClient, TestServer

try:
    from api.verification_api import (
        RoleGrantError,
        create_verification_app,
        _discord_authorization_url,
        _force_regional_manual_review,
        _frontend_origins,
        _load_oauth_signals,
        _member_regional_review_role_ids,
        _oauth_result_url,
        _oauth_state_digest,
        _remove_legacy_verified_role,
        _wait_for_guardian_ready,
    )
    from core.verification_risk import RiskAssessment
    from modules.verificacion import (
        VerificationManager,
        _attempt_regional_review_role_ids,
    )
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
            "api.verification_api.VERIFICATION_PUBLIC_URL",
            "https://guardian.example",
        ):
            result_url = _oauth_result_url("received")
        parsed = urlsplit(result_url)
        self.assertEqual(parsed.query, "")
        self.assertEqual(parsed.fragment, "result=received")

    def test_public_and_legacy_frontends_are_allowed_during_migration(self):
        with (
            patch(
                "api.verification_api.VERIFICATION_PUBLIC_URL",
                "https://guardian.example",
            ),
            patch(
                "api.verification_api.FRONTEND_URL",
                "https://example.github.io/verification",
            ),
        ):
            origins = _frontend_origins()

        self.assertEqual(
            origins,
            frozenset(
                {
                    "https://guardian.example",
                    "https://example.github.io",
                }
            ),
        )

    def test_postgres_json_text_is_restored_as_oauth_signals(self):
        signals = _load_oauth_signals(
            '{"language":"es","signal_version":1}'
        )
        self.assertEqual(signals["language"], "es")
        self.assertEqual(signals["signal_version"], 1)


class ServiceReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_transient_gateway_reconnect_gets_a_grace_window(self):
        bot = SimpleNamespace(
            is_ready=Mock(side_effect=(False, True)),
            wait_until_ready=AsyncMock(),
        )

        with patch("api.verification_api.database.bot_pool", object()):
            ready = await _wait_for_guardian_ready(bot)

        self.assertTrue(ready)
        bot.wait_until_ready.assert_awaited_once_with()


class StaticWebServingTests(unittest.IsolatedAsyncioTestCase):
    async def test_guardian_serves_frontend_and_assets_from_its_origin(self):
        bot = SimpleNamespace(is_ready=lambda: True)
        client = TestClient(TestServer(create_verification_app(bot)))
        await client.start_server()
        try:
            index_response = await client.get("/")
            index_body = await index_response.text()
            asset_response = await client.get("/assets/js/app.js")

            self.assertEqual(index_response.status, 200)
            self.assertIn("Verifica tu cuenta", index_body)
            self.assertIn(
                "connect-src 'self'",
                index_response.headers["Content-Security-Policy"],
            )
            self.assertEqual(asset_response.status, 200)
            self.assertEqual(
                asset_response.headers["Cache-Control"],
                "public, max-age=3600",
            )
        finally:
            await client.close()


class RoleDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_role_is_removed_when_present(self):
        legacy_role = SimpleNamespace(id=1409401827065204786)
        member = SimpleNamespace(
            get_role=lambda role_id: (
                legacy_role if role_id == legacy_role.id else None
            ),
            remove_roles=AsyncMock(),
        )

        removed = await _remove_legacy_verified_role(
            member,
            [legacy_role],
            reason="Prueba de limpieza",
        )

        self.assertTrue(removed)
        member.remove_roles.assert_awaited_once_with(
            legacy_role,
            reason="Prueba de limpieza",
        )

    async def test_legacy_role_cleanup_is_noop_when_absent(self):
        legacy_role = SimpleNamespace(id=1409401827065204786)
        member = SimpleNamespace(
            get_role=lambda _role_id: None,
            remove_roles=AsyncMock(),
        )

        removed = await _remove_legacy_verified_role(
            member,
            [legacy_role],
            reason="Prueba de limpieza",
        )

        self.assertFalse(removed)
        member.remove_roles.assert_not_awaited()

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


class RegionalReviewTests(unittest.IsolatedAsyncioTestCase):
    def test_member_filter_roles_are_detected_and_sorted(self):
        member = SimpleNamespace(
            roles=[
                SimpleNamespace(id=999),
                SimpleNamespace(id=1328006434847195208),
                SimpleNamespace(id=1288218486363132008),
            ]
        )

        self.assertEqual(
            _member_regional_review_role_ids(member),
            (1288218486363132008, 1328006434847195208),
        )

    def test_regional_role_forces_review_without_inflating_risk(self):
        assessment = RiskAssessment(
            score=5,
            level="low",
            decision="approved",
            possible_main_user_id=None,
            reasons=("Ingreso reciente",),
            related_user_count=0,
        )

        forced = _force_regional_manual_review(
            assessment,
            (1328006434847195208,),
        )

        self.assertEqual(forced.decision, "review")
        self.assertEqual(forced.score, 5)
        self.assertEqual(forced.level, "low")
        self.assertIn(
            "Rol regional sujeto a revisión manual obligatoria",
            forced.reasons,
        )

    def test_persisted_filter_roles_survive_json_roundtrip(self):
        row = {
            "signals": (
                '{"regional_review_role_ids":['
                '"1328006434847195208",999,true]}'
            )
        }

        self.assertEqual(
            _attempt_regional_review_role_ids(row),
            (1328006434847195208,),
        )

    async def test_filtered_role_rejection_is_notified_in_portuguese(self):
        member = SimpleNamespace(id=123, send=AsyncMock())
        manager = VerificationManager(SimpleNamespace())

        await manager._notify_reviewed_user(
            member,
            accepted=False,
            regional_rejection=True,
        )

        member.send.assert_awaited_once_with(
            "Região incorreta. Verificação recusada."
        )


if __name__ == "__main__":
    unittest.main()
