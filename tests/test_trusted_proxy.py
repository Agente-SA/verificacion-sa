import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    from api.verification_api import InvalidSubmission, _client_ip, _country_code
except ModuleNotFoundError as exc:
    raise unittest.SkipTest(f"Dependencia opcional no instalada: {exc.name}") from exc


class TrustedProxyTests(unittest.TestCase):
    def test_untrusted_remote_cannot_spoof_cloudflare_header(self):
        request = SimpleNamespace(
            remote="198.51.100.20",
            headers={"CF-Connecting-IP": "203.0.113.10"},
        )
        with patch(
            "api.verification_api.TRUSTED_PROXY_NETWORKS",
            (ipaddress.ip_network("10.0.0.0/8"),),
        ):
            with self.assertRaises(InvalidSubmission):
                _client_ip(request)

    def test_trusted_proxy_can_supply_client_ip_and_country(self):
        request = SimpleNamespace(
            remote="10.1.2.3",
            headers={
                "CF-Connecting-IP": "203.0.113.10",
                "CF-IPCountry": "br",
            },
        )
        with patch(
            "api.verification_api.TRUSTED_PROXY_NETWORKS",
            (ipaddress.ip_network("10.0.0.0/8"),),
        ):
            self.assertEqual(_client_ip(request), "203.0.113.10")
            self.assertEqual(_country_code(request), "BR")

    def test_direct_request_uses_socket_address_without_country_header(self):
        request = SimpleNamespace(
            remote="203.0.113.11",
            headers={"CF-IPCountry": "BR"},
        )
        self.assertEqual(_client_ip(request), "203.0.113.11")
        self.assertIsNone(_country_code(request))


if __name__ == "__main__":
    unittest.main()
