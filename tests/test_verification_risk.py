import unittest
from datetime import datetime, timedelta, timezone

from core.verification_risk import assess_verification_risk


NOW = datetime(2026, 8, 2, tzinfo=timezone.utc)


def attempt(**overrides):
    values = {
        "user_id": 1,
        "ip_hash": "ip-current",
        "ip_network_hash": "network-current",
        "fingerprint_hash": "fingerprint-current",
        "country_code": "BR",
        "timezone": "America/Sao_Paulo",
        "browser_family": "Chrome",
        "os_family": "Windows",
        "device_type": "desktop",
        "decision": "approved",
        "role_granted": True,
        "created_at": NOW - timedelta(days=45),
    }
    values.update(overrides)
    return values


class VerificationRiskTests(unittest.TestCase):
    def test_new_account_and_recent_join_do_not_reject_without_matches(self):
        result = assess_verification_risk(
            attempt(),
            [],
            now=NOW,
            account_created_at=NOW - timedelta(days=10),
            server_joined_at=NOW - timedelta(days=5),
        )

        self.assertEqual(result.score, 10)
        self.assertEqual(result.decision, "approved")
        self.assertEqual(len(result.reasons), 2)

    def test_country_does_not_score_without_network_match(self):
        candidate = attempt(
            user_id=2,
            ip_hash="different-ip",
            ip_network_hash="different-network",
            fingerprint_hash="fingerprint-current",
            country_code="BR",
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 15)
        self.assertNotIn(
            "Pais coincidente junto a la conexion de red",
            result.reasons,
        )

    def test_country_scores_with_matching_network(self):
        candidate = attempt(
            user_id=2,
            ip_hash="different-ip",
            ip_network_hash="network-current",
            fingerprint_hash="different-fingerprint",
            country_code="BR",
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 35)
        self.assertEqual(result.decision, "review")
        self.assertIn(
            "Pais coincidente junto a la conexion de red",
            result.reasons,
        )

    def test_age_signals_can_raise_existing_suspicion_to_review(self):
        candidate = attempt(
            user_id=2,
            ip_hash="different-ip",
            ip_network_hash="different-network",
            fingerprint_hash="fingerprint-current",
            created_at=NOW - timedelta(hours=2),
        )

        result = assess_verification_risk(
            attempt(),
            [candidate],
            now=NOW,
            account_created_at=NOW - timedelta(days=10),
            server_joined_at=NOW - timedelta(days=5),
        )

        self.assertEqual(result.score, 40)
        self.assertEqual(result.decision, "review")

    def test_exact_ip_within_thirty_days_still_forces_review(self):
        candidate = attempt(
            user_id=2,
            fingerprint_hash="different-fingerprint",
            country_code="AR",
            created_at=NOW - timedelta(days=20),
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 50)
        self.assertEqual(result.decision, "review")

    def test_archived_exact_ip_alone_requires_review(self):
        candidate = attempt(
            user_id=2,
            fingerprint_hash="different-fingerprint",
            country_code="AR",
            timezone=None,
            browser_family=None,
            os_family=None,
            device_type=None,
            created_at=NOW - timedelta(days=100),
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 45)
        self.assertEqual(result.decision, "review")

    def test_archived_exact_ip_and_fingerprint_still_require_review(self):
        candidate = attempt(
            user_id=2,
            country_code="AR",
            timezone=None,
            browser_family=None,
            os_family=None,
            device_type=None,
            created_at=NOW - timedelta(days=100),
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 60)
        self.assertEqual(result.decision, "review")
        self.assertEqual(result.possible_main_user_id, 2)

    def test_one_vpn_provider_forces_manual_review(self):
        result = assess_verification_risk(
            attempt(),
            [],
            now=NOW,
            vpn_detected_by=("proxycheck.io",),
        )

        self.assertEqual(result.score, 50)
        self.assertEqual(result.level, "medium")
        self.assertEqual(result.decision, "review")
        self.assertIsNone(result.possible_main_user_id)

    def test_two_vpn_providers_are_high_confidence(self):
        result = assess_verification_risk(
            attempt(),
            [],
            now=NOW,
            vpn_detected_by=("proxycheck.io", "ipapi.is"),
        )

        self.assertEqual(result.score, 100)
        self.assertEqual(result.level, "high")
        self.assertEqual(result.decision, "rejected")

    def test_one_unavailable_vpn_provider_uses_reduced_confidence(self):
        result = assess_verification_risk(
            attempt(),
            [],
            now=NOW,
            vpn_unavailable_by=("ipapi.is",),
        )

        self.assertEqual(result.score, 5)
        self.assertEqual(result.decision, "approved")

    def test_combined_signals_at_sixty_five_are_rejected(self):
        candidate = attempt(
            user_id=2,
            created_at=NOW - timedelta(hours=2),
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 85)
        self.assertEqual(result.decision, "rejected")

    def test_versioned_hash_match_flags_are_honored(self):
        candidate = attempt(
            user_id=2,
            ip_hash="old-secret-hash",
            ip_network_hash="old-network-hash",
            fingerprint_hash="old-fingerprint-hash",
            exact_ip_match=True,
            network_match=True,
            fingerprint_match=True,
        )

        result = assess_verification_risk(attempt(), [candidate], now=NOW)

        self.assertEqual(result.score, 70)
        self.assertEqual(result.decision, "rejected")


if __name__ == "__main__":
    unittest.main()
