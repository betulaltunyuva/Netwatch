import unittest
from unittest.mock import patch

from sniffer import NetworkMonitor


class NetworkMonitorTests(unittest.TestCase):
    def test_sample_mode_summary(self):
        monitor = NetworkMonitor()

        monitor.activate_sample_mode(
            "Test capture failure."
        )

        summary = monitor.get_summary()

        self.assertEqual(
            summary["data_mode"],
            "sample"
        )

        self.assertEqual(
            summary["total_packets"],
            48
        )

        self.assertEqual(
            summary["tcp_packets"],
            6
        )

        self.assertEqual(
            summary["udp_packets"],
            42
        )

        self.assertEqual(
            len(summary["recent_packets"]),
            10
        )

    def test_pending_records_are_written_as_one_batch(self):
        monitor = NetworkMonitor()

        monitor.pending_packets = [
            {"id": 1},
            {"id": 2}
        ]

        monitor.pending_alerts = [
            {"id": 3}
        ]

        with (
            patch(
                "sniffer.save_packets"
            ) as save_packets,
            patch(
                "sniffer.save_alerts"
            ) as save_alerts
        ):
            saved_count = monitor.flush_database(
                force=True
            )

        self.assertEqual(saved_count, 2)

        save_packets.assert_called_once_with(
            [{"id": 1}, {"id": 2}]
        )

        save_alerts.assert_called_once_with(
            [{"id": 3}]
        )

        self.assertEqual(
            monitor.pending_packets,
            []
        )

        self.assertEqual(
            monitor.pending_alerts,
            []
        )


if __name__ == "__main__":
    unittest.main()