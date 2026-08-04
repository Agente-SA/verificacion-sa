import unittest

from core.vpn_detection import (
    InvalidProviderResponse,
    ProviderVerdict,
    VPNCheckResult,
    parse_ipapi_response,
    parse_proxycheck_response,
)


class VPNDetectionParserTests(unittest.TestCase):
    def test_proxycheck_preserves_precise_detection_metadata(self):
        result = parse_proxycheck_response(
            {
                "status": "ok",
                "203.0.113.10": {
                    "risk": 52,
                    "network": {
                        "type": "Wireless",
                        "provider": "Example Mobile",
                    },
                    "operator": {"name": "Example VPN"},
                    "detections": {
                        "anonymous": True,
                        "vpn": True,
                        "proxy": False,
                        "tor": False,
                        "hosting": False,
                        "confidence": 91,
                        "last_seen": "2026-08-03T22:15:00Z",
                    }
                },
            },
            "203.0.113.10",
        )

        self.assertTrue(result.available)
        self.assertTrue(result.detected)
        self.assertEqual(result.signals, ("vpn",))
        self.assertIs(result.signal_state("vpn"), True)
        self.assertIsNone(result.signal_state("proxy"))
        self.assertIsNone(result.signal_state("datacenter"))
        self.assertEqual(result.risk_score, 52)
        self.assertEqual(result.confidence_score, 91)
        self.assertEqual(result.last_seen, "2026-08-03T22:15:00Z")
        self.assertEqual(result.service, "Example VPN")
        self.assertEqual(result.network_type, "Wireless")
        self.assertEqual(result.network_provider, "Example Mobile")

    def test_proxycheck_hosting_field_does_not_affect_vpn_detection(self):
        result = parse_proxycheck_response(
            {
                "status": "ok",
                "203.0.113.10": {
                    "risk": 33,
                    "network": {"type": "Hosting"},
                    "detections": {
                        "anonymous": False,
                        "vpn": False,
                        "proxy": False,
                        "tor": False,
                        "hosting": True,
                        "confidence": 88,
                        "last_seen": "2026-08-03T22:15:00Z",
                    },
                },
            },
            "203.0.113.10",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.signals, ())

    def test_ipapi_proxy_without_vpn_is_context_only(self):
        result = parse_ipapi_response(
            {
                "ip": "203.0.113.10",
                "is_vpn": False,
                "is_proxy": True,
                "is_tor": False,
                "is_datacenter": True,
                "company": {
                    "name": "Example Hosting",
                    "type": "hosting",
                },
            },
            "203.0.113.10",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.signals, ())
        self.assertEqual(result.network_provider, "Example Hosting")

    def test_ipapi_does_not_reject_datacenter_alone(self):
        result = parse_ipapi_response(
            {
                "ip": "203.0.113.10",
                "is_vpn": False,
                "is_proxy": False,
                "is_tor": False,
                "is_datacenter": True,
            },
            "203.0.113.10",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.signals, ())

    def test_ipapi_preserves_vpn_service_and_last_seen(self):
        result = parse_ipapi_response(
            {
                "ip": "203.0.113.10",
                "is_vpn": True,
                "is_proxy": False,
                "is_tor": False,
                "is_datacenter": False,
                "vpn": {
                    "service": "ExampleVPN",
                    "last_seen_str": "2026-08-03T22:15:00Z",
                },
            },
            "203.0.113.10",
        )

        self.assertTrue(result.detected)
        self.assertEqual(result.service, "ExampleVPN")
        self.assertEqual(result.last_seen, "2026-08-03T22:15:00Z")

    def test_invalid_provider_payload_is_rejected(self):
        with self.assertRaises(InvalidProviderResponse):
            parse_proxycheck_response(
                {"status": "ok", "203.0.113.10": {}},
                "203.0.113.10",
            )

    def test_ipapi_accepts_equivalent_ipv6_format(self):
        result = parse_ipapi_response(
            {
                "ip": "2001:db8:0:0:0:0:0:1",
                "is_vpn": False,
                "is_proxy": False,
                "is_tor": False,
            },
            "2001:db8::1",
        )

        self.assertTrue(result.available)
        self.assertFalse(result.detected)

    def test_provider_details_preserve_partial_status(self):
        result = VPNCheckResult(
            proxycheck=ProviderVerdict(
                provider="proxycheck.io",
                available=True,
                detected=False,
            ),
            ipapi=ProviderVerdict.unavailable("ipapi.is"),
        )

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.unavailable_providers, ("ipapi.is",))
        self.assertFalse(result.provider_results()["ipapi.is"]["available"])

    def test_provider_results_and_summary_include_precision_details(self):
        result = VPNCheckResult(
            proxycheck=ProviderVerdict(
                provider="proxycheck.io",
                available=True,
                detected=False,
                signals=(),
                signal_states=(("vpn", False),),
                risk_score=61,
                confidence_score=89,
                last_seen="2026-08-03T22:15:00Z",
            ),
            ipapi=ProviderVerdict(
                provider="ipapi.is",
                available=True,
                detected=False,
                signal_states=(("vpn", False),),
            ),
        )

        stored = result.provider_results()["proxycheck.io"]
        self.assertNotIn("proxy", stored["checks"])
        self.assertEqual(stored["risk_score"], 61)
        self.assertEqual(stored["confidence_score"], 89)
        self.assertEqual(stored["last_seen"], "2026-08-03T22:15:00Z")
        summary = result.discord_summary()
        self.assertIn("VPN `No`", summary)
        self.assertNotIn("Proxy", summary)
        self.assertNotIn("Tor", summary)
        self.assertNotIn("Hosting", summary)
        self.assertNotIn("Datacenter", summary)
        self.assertNotIn("Señal aislada", summary)

    def test_both_unavailable_are_not_evaluated(self):
        result = VPNCheckResult(
            proxycheck=ProviderVerdict.unavailable("proxycheck.io"),
            ipapi=ProviderVerdict.unavailable("ipapi.is"),
        )

        self.assertEqual(result.status, "not_evaluated")
        self.assertEqual(result.available_count, 0)


if __name__ == "__main__":
    unittest.main()
