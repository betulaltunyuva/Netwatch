import importlib.util
import unittest
from unittest.mock import patch


DEPENDENCIES_AVAILABLE = all(
    importlib.util.find_spec(package) is not None
    for package in (
        "flask",
        "flask_socketio"
    )
)


@unittest.skipUnless(
    DEPENDENCIES_AVAILABLE,
    "Flask dependencies are not installed."
)
class AppRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_pages_are_available(self):
        paths = (
            "/",
            "/history",
            "/search",
            "/devices",
            "/exports"
        )

        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(
                    response.status_code,
                    200
                )

                self.assertEqual(
                    response.headers[
                        "X-Frame-Options"
                    ],
                    "DENY"
                )

    def test_json_endpoints_are_available(self):
        paths = (
            "/api/history?minutes=60",
            "/api/packets/search?limit=10",
            "/api/devices",
            "/api/exports/info"
        )

        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(
                    response.status_code,
                    200
                )

                self.assertTrue(
                    response.is_json
                )

    def test_cleanup_endpoint_uses_requested_retention(self):
        cleanup_result = {
            "retention_days": 30,
            "deleted_packets": 5,
            "deleted_alerts": 1
        }

        with patch(
            "app.cleanup_old_records",
            return_value=cleanup_result
        ) as cleanup:
            response = self.client.post(
                "/api/data/cleanup",
                json={
                    "retention_days": 30
                }
            )

        self.assertEqual(
            response.status_code,
            200
        )

        cleanup.assert_called_once_with(
            days=30
        )

        self.assertEqual(
            response.get_json()[
                "deleted_packets"
            ],
            5
        )


if __name__ == "__main__":
    unittest.main()