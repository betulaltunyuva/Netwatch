import tempfile
import unittest
from pathlib import Path

import database

from device_manager import (
    get_devices_data,
    register_device
)

from export_manager import create_packet_csv
from packet_search import search_packets


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        self.original_data_dir = (
            database.DATA_DIR
        )

        self.original_database_path = (
            database.DATABASE_PATH
        )

        database.DATA_DIR = Path(
            self.temporary_directory.name
        )

        database.DATABASE_PATH = (
            database.DATA_DIR / "test.db"
        )

        database.init_database()

    def tearDown(self):
        database.DATA_DIR = (
            self.original_data_dir
        )

        database.DATABASE_PATH = (
            self.original_database_path
        )

        self.temporary_directory.cleanup()

    def test_packet_search_export_and_device_tracking(self):
        database.save_packets(
            [
                {
                    "captured_at":
                        "2026-09-12 12:00:00",
                    "source_ip":
                        "192.168.1.10",
                    "destination_ip":
                        "8.8.8.8",
                    "protocol":
                        "UDP",
                    "source_port":
                        50000,
                    "destination_port":
                        53,
                    "packet_length":
                        60
                }
            ]
        )

        result = search_packets(
            source_ip="192.168.1",
            protocol="udp",
            limit=10
        )

        self.assertEqual(
            result["summary"]["total_packets"],
            1
        )

        self.assertEqual(
            result["packets"][0][
                "destination_port"
            ],
            53
        )

        self.assertEqual(
            create_packet_csv()[
                "record_count"
            ],
            1
        )

        self.assertTrue(
            register_device(
                "192.168.1.10",
                "AA:BB:CC:DD:EE:FF",
                "2026-09-12 12:00:00"
            )
        )

        self.assertEqual(
            get_devices_data()[
                "summary"
            ]["total_devices"],
            1
        )

    def test_cleanup_deletes_only_old_records(self):
        database.save_packets(
            [
                {
                    "captured_at":
                        "2000-01-01 00:00:00",
                    "source_ip":
                        "10.0.0.1",
                    "destination_ip":
                        "10.0.0.2",
                    "protocol":
                        "TCP",
                    "source_port":
                        1000,
                    "destination_port":
                        80,
                    "packet_length":
                        40
                },
                {
                    "captured_at":
                        "2999-01-01 00:00:00",
                    "source_ip":
                        "10.0.0.1",
                    "destination_ip":
                        "10.0.0.2",
                    "protocol":
                        "TCP",
                    "source_port":
                        1001,
                    "destination_port":
                        443,
                    "packet_length":
                        40
                }
            ]
        )

        result = database.cleanup_old_records(
            days=30
        )

        self.assertEqual(
            result["deleted_packets"],
            1
        )

        self.assertEqual(
            database.get_packet_count(),
            1
        )


if __name__ == "__main__":
    unittest.main()