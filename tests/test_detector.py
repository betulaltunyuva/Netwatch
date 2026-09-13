import unittest

from detector import ThreatDetector


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = ThreatDetector()

    def test_port_scan_detection(self):
        alerts = []

        for port in range(1000, 1015):
            alerts.extend(
                self.detector.analyze_packet(
                    "10.0.0.5",
                    "TCP",
                    destination_port=port,
                    tcp_flags="S"
                )
            )

        self.assertIn(
            "PORT_SCAN",
            [alert["alert_type"] for alert in alerts]
        )

    def test_flood_rules(self):
        cases = [
            ("TCP", 80, "S", 100, "SYN_FLOOD"),
            ("ICMP", None, "", 50, "ICMP_FLOOD"),
            ("UDP", 53, "", 100, "HIGH_DNS_TRAFFIC"),
        ]

        for protocol, port, flags, count, expected_type in cases:
            detector = ThreatDetector()
            alerts = []

            for _ in range(count):
                alerts.extend(
                    detector.analyze_packet(
                        "10.0.0.8",
                        protocol,
                        destination_port=port,
                        tcp_flags=flags
                    )
                )

            self.assertIn(
                expected_type,
                [alert["alert_type"] for alert in alerts]
            )


if __name__ == "__main__":
    unittest.main()