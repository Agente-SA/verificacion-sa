import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlsplit

from aiohttp.test_utils import TestClient, TestServer

try:
    from api.verification_api import (
        RoleGrantError,
        _authenticated_signal_context,
        create_verification_app,
        _discord_authorization_url,
        _force_direct_manual_review,
        _force_regional_manual_review,
        _frontend_origins,
        _load_oauth_signals,
        _member_regional_review_role_ids,
        _oauth_result_url,
        _oauth_state_digest,
        _remove_legacy_verified_role,
        _wait_for_guardian_ready,
        prepare_direct_oauth_authorization,
    )
    from core.verification_risk import RiskAssessment
    from modules.verificacion import (
        VerificationManager,
        _attempt_manual_provider,
        _attempt_flow_label,
        _attempt_regional_review_role_ids,
        _forced_discord_observations,
        _normalize_country_code,
        _normalize_provider,
        _stored_vpn_summary,
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


class DirectOAuthFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_session_has_no_untrusted_initial_ip(self):
        oauth_session = {
            "session_id": "direct-session",
            "expires_at": "later",
        }
        create_session = AsyncMock(return_value=oauth_session)
        with (
            patch(
                "api.verification_api.database.create_oauth_session",
                create_session,
            ),
            patch("api.verification_api.DISCORD_CLIENT_ID", 123456789),
            patch(
                "api.verification_api.DISCORD_OAUTH_REDIRECT_URI",
                "https://guardian.example/oauth/callback",
            ),
        ):
            prepared = await prepare_direct_oauth_authorization(
                token_id="token-id",
                verification_token_digest="a" * 64,
                guild_id=1,
                user_id=2,
            )

        call = create_session.await_args.kwargs
        self.assertIsNone(call["initial_ip_hash"])
        self.assertIsNone(call["initial_ip_network_hash"])
        self.assertEqual(call["signals"]["flow_mode"], "direct_oauth")
        self.assertEqual(prepared["session_id"], "direct-session")
        parsed = urlsplit(prepared["authorization_url"])
        self.assertEqual(parsed.netloc, "discord.com")
        self.assertTrue(parse_qs(parsed.query)["state"][0])
        self.assertNotEqual(
            parse_qs(parsed.query)["state"][0],
            call["state_digest"],
        )

    async def test_direct_callback_uses_headers_without_js_fingerprint(self):
        request = SimpleNamespace(
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 14; Mobile) "
                    "AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
                ),
                "Accept-Language": "es-CO,es;q=0.9",
            }
        )

        context = _authenticated_signal_context(
            request,
            {"flow_mode": "direct_oauth", "signal_version": 1},
        )

        self.assertIsNone(context["fingerprint_hash"])
        self.assertEqual(context["fingerprint_hashes"], ())
        self.assertIsNone(context["timezone_name"])
        self.assertEqual(context["language"], "es-CO")
        self.assertEqual(context["browser_family"], "Chrome")
        self.assertEqual(context["os_family"], "Android")
        self.assertEqual(context["device_class"], "phone")
        self.assertEqual(
            context["stored_signals"]["flow_mode"],
            "direct_oauth",
        )


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
    async def test_direct_result_is_sent_as_a_normal_dm_message(self):
        followup = SimpleNamespace(send=AsyncMock())
        interaction = SimpleNamespace(guild=None, followup=followup)
        manager = VerificationManager(SimpleNamespace())
        manager.remember_result_interaction("token-id", 2, interaction)

        delivered = await manager.send_verification_result(
            "token-id",
            2,
            "approved",
        )

        self.assertTrue(delivered)
        followup.send.assert_awaited_once_with(
            "Tu cuenta ha sido Verificada con Éxito ✅",
            ephemeral=False,
        )

    async def test_review_dm_uses_a_plain_role_label(self):
        followup = SimpleNamespace(send=AsyncMock())
        interaction = SimpleNamespace(guild=None, followup=followup)
        manager = VerificationManager(SimpleNamespace())
        manager.remember_result_interaction("token-id", 2, interaction)

        delivered = await manager.send_verification_result(
            "token-id",
            2,
            "review",
        )

        self.assertTrue(delivered)
        message = followup.send.await_args.args[0]
        self.assertIn("**@Verificado-ES**", message)
        self.assertNotIn("<@&", message)

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
    def test_direct_flow_always_requires_manual_review(self):
        for original_decision in ("approved", "rejected"):
            with self.subTest(original_decision=original_decision):
                assessment = RiskAssessment(
                    score=5 if original_decision == "approved" else 90,
                    level="low" if original_decision == "approved" else "high",
                    decision=original_decision,
                    possible_main_user_id=(
                        None if original_decision == "approved" else 999
                    ),
                    reasons=("Evaluación original",),
                    related_user_count=0,
                )

                forced = _force_direct_manual_review(assessment, True)

                self.assertEqual(forced.decision, "review")
                self.assertEqual(forced.score, assessment.score)
                self.assertEqual(forced.level, assessment.level)
                self.assertIn(
                    "Verificacion directa solicitada por el staff",
                    forced.reasons,
                )

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


class GuardianUserQueryTests(unittest.TestCase):
    def test_forced_verification_inputs_are_normalized(self):
        self.assertEqual(_normalize_country_code(" cu "), "CU")
        self.assertEqual(
            _normalize_provider("  ETECSA   Móvil "),
            "ETECSA Móvil",
        )
        with self.assertRaises(ValueError):
            _normalize_country_code("Cuba")
        with self.assertRaises(ValueError):
            _normalize_provider(" ")

    def test_forced_verification_uses_discord_observations_only(self):
        legacy_role = SimpleNamespace(id=1409401827065204786)
        regional_role = SimpleNamespace(id=1328006434847195208)
        member = SimpleNamespace(
            created_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
            joined_at=datetime(2026, 7, 25, tzinfo=timezone.utc),
            roles=[legacy_role, regional_role],
        )
        member.get_role = lambda role_id: next(
            (role for role in member.roles if role.id == role_id),
            None,
        )

        reasons, signals = _forced_discord_observations(
            member,
            now=datetime(2026, 8, 5, tzinfo=timezone.utc),
        )

        self.assertIn(
            "Verificación forzada por staff; análisis de red no realizado.",
            reasons,
        )
        self.assertIn(
            "Cuenta de Discord creada hace menos de 30 días.",
            reasons,
        )
        self.assertIn(
            "Ingreso al servidor hace menos de 30 días.",
            reasons,
        )
        self.assertEqual(
            signals["regional_review_role_ids"],
            [1328006434847195208],
        )
        self.assertTrue(signals["legacy_role_present"])

    def test_forced_flow_and_provider_are_identified(self):
        signals = {
            "flow_mode": "forced_manual",
            "manual_provider": "ETECSA Móvil",
        }
        self.assertEqual(_attempt_flow_label(signals), "Forzada por staff")
        self.assertEqual(_attempt_manual_provider(signals), "ETECSA Móvil")

    def test_stored_provider_results_are_rendered_for_staff(self):
        summary = _stored_vpn_summary(
            {
                "proxycheck.io": {
                    "available": True,
                    "detected": False,
                    "checks": {"vpn": False},
                    "risk_score": 3,
                    "confidence_score": 100,
                    "last_seen": None,
                    "network_type": "Business",
                    "network_provider": "Example Telecom",
                },
                "ipapi.is": {
                    "available": False,
                    "detected": False,
                },
            },
            datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertIn("**proxycheck.io**", summary)
        self.assertIn("VPN `No`", summary)
        self.assertIn("Confianza `100/100`", summary)
        self.assertIn("Proveedor: `Example Telecom`", summary)
        self.assertIn("**ipapi.is**", summary)
        self.assertIn("Servicio sin respuesta", summary)

    def test_user_guardian_embed_marks_direct_review_and_resolution(self):
        row = {
            "id": 29,
            "country_code": "BR",
            "risk_score": 45,
            "risk_level": "medium",
            "decision": "review",
            "role_granted": False,
            "role_delivery_status": "not_required",
            "possible_main_user_id": 999,
            "manual_review_status": "accepted",
            "reviewed_by": 123,
            "reviewed_at": datetime(2026, 8, 4, 12, 5, tzinfo=timezone.utc),
            "risk_reasons": ["Rango de red coincidente"],
            "vpn_provider_results": {},
            "vpn_checked_at": None,
            "signals": {"flow_mode": "direct_oauth"},
            "created_at": datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        }
        member = SimpleNamespace(id=2, mention="<@2>")

        embed = VerificationManager.user_guardian_embed(member, row)
        fields = {field.name: field.value for field in embed.fields}

        self.assertEqual(fields["Flujo"], "Verificación directa por DM")
        self.assertIn("Rango de red coincidente", fields["Coincidencias"])
        self.assertIn("**ACEPTADA** por <@123>", fields["Resolución"])
        self.assertEqual(fields["Verificación interna"], "`29`")

    def test_user_guardian_embed_marks_forced_verification_as_not_evaluated(self):
        row = {
            "id": 30,
            "country_code": "CU",
            "risk_score": 0,
            "risk_level": "pending",
            "decision": "approved",
            "role_granted": True,
            "role_delivery_status": "granted",
            "possible_main_user_id": None,
            "manual_review_status": "accepted",
            "reviewed_by": 123,
            "reviewed_at": datetime(2026, 8, 5, 12, 5, tzinfo=timezone.utc),
            "risk_reasons": [
                "Verificación forzada por staff; análisis de red no realizado."
            ],
            "vpn_provider_results": {},
            "vpn_checked_at": None,
            "signals": {
                "flow_mode": "forced_manual",
                "manual_provider": "ETECSA",
            },
            "created_at": datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc),
        }
        member = SimpleNamespace(id=2, mention="<@2>")

        embed = VerificationManager.user_guardian_embed(member, row)
        fields = {field.name: field.value for field in embed.fields}

        self.assertEqual(fields["Flujo"], "Forzada por staff")
        self.assertEqual(fields["Riesgo"], "NO EVALUADO")
        self.assertEqual(fields["Proveedor informado"], "ETECSA")


if __name__ == "__main__":
    unittest.main()
