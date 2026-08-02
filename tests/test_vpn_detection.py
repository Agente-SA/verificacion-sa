import unittest

from core.vpn_detection import (
    InvalidProviderResponse,
    parse_ipapi_response,
    parse_proxycheck_response,
)


class VPNDetectionParserTests(unittest.TestCase):
    def test_proxycheck_detects_anonymous_connection(self):
        result = parse_proxycheck_response(
            {
                "status": "ok",
                "203.0.113.10": {
                    "detections": {
                        "anonymous": True,
                        "vpn": True,
                    }
                },
            },
            "203.0.113.10",
        )

        self.assertTrue(result.available)
        self.assertTrue(result.detected)
        self.assertIn("vpn", result.signals)

    def test_ipapi_detects_vpn_proxy_or_tor(self):
        result = parse_ipapi_response(
            {
                "ip": "203.0.113.10",
                "is_vpn": False,
                "is_proxy": True,
                "is_tor": False,
                "is_datacenter": True,
            },
            "203.0.113.10",
        )

        self.assertTrue(result.detected)
        self.assertEqual(result.signals, ("proxy",))

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


if __name__ == "__main__":
    unittest.main()
