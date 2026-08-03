import unittest
from unittest.mock import patch

try:
    from core.verification_security import (
        hash_ip_address,
        hash_ip_address_candidates,
        hash_ip_network_candidates,
        hash_limited_fingerprint_candidates,
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


if __name__ == "__main__":
    unittest.main()
