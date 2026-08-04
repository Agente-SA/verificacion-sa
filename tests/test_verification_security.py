import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

try:
    from core.verification_security import (
        ExpiredVerificationToken,
        create_signed_verification_token,
        hash_ip_address,
        hash_ip_address_candidates,
        hash_ip_network_candidates,
        hash_limited_fingerprint_candidates,
        validate_signed_verification_token,
    )
except ModuleNotFoundError as exc:
    raise unittest.SkipTest(f"Dependencia opcional no instalada: {exc.name}") from exc


class VerificationHashRotationTests(unittest.TestCase):
    def test_current_and_previous_secrets_generate_comparison_candidates(self):
        with (
            patch("core.verification_security.IP_HASH_SECRET", "a" * 48),
            patch(
                "core.verification_security.IP_HASH_SECRET_PREVIOUS",
                "b" * 48,
            ),
        ):
            candidates = hash_ip_address_candidates("203.0.113.10")
            network_candidates = hash_ip_network_candidates("203.0.113.10")
            fingerprint_candidates = hash_limited_fingerprint_candidates(
                {"browser": "Chrome", "device": "desktop"}
            )

            self.assertEqual(len(candidates), 2)
            self.assertEqual(len(network_candidates), 2)
            self.assertEqual(len(fingerprint_candidates), 2)
            self.assertEqual(hash_ip_address("203.0.113.10"), candidates[0])
            self.assertNotEqual(candidates[0], candidates[1])

    def test_without_previous_secret_only_current_hash_is_used(self):
        with (
            patch("core.verification_security.IP_HASH_SECRET", "a" * 48),
            patch("core.verification_security.IP_HASH_SECRET_PREVIOUS", ""),
        ):
            self.assertEqual(
                len(hash_ip_address_candidates("2001:db8::1")),
                1,
            )


class VerificationTokenLifecycleTests(unittest.TestCase):
    def test_reserved_flow_can_validate_signature_after_link_expiration(self):
        issued_at = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
        validation_time = issued_at + timedelta(minutes=16)
        with (
            patch("core.verification_security.TOKEN_SECRET", "s" * 48),
            patch("core.verification_security.TOKEN_EXPIRATION_MINUTES", 15),
            patch(
                "core.verification_security.VERIFICATION_PUBLIC_URL",
                "https://guardian.example",
            ),
        ):
            issued = create_signed_verification_token(
                980073134411644939,
                1436110324796358758,
                now=issued_at,
            )
            with self.assertRaises(ExpiredVerificationToken):
                validate_signed_verification_token(
                    issued.value,
                    now=validation_time,
                )
            recovered = validate_signed_verification_token(
                issued.value,
                now=validation_time,
                allow_expired=True,
            )

        self.assertEqual(recovered.token_id, issued.payload.token_id)


if __name__ == "__main__":
    unittest.main()
