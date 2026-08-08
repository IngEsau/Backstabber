import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.control_plane import ControlPlane, ControlPlaneError
from core.persistence import Database
from core.worker import JobWorker


class AllowAllScopePolicy:
    def validate_network(self, value):
        return ipaddress.ip_network(value, strict=False)


class FakeScanner:
    def scan(self, target, ports="1-1024", extra_args=""):
        return {
            "hosts": [
                {
                    "ip": "192.0.2.10",
                    "hostname": None,
                    "open_ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
                }
            ],
            "raw": {},
        }


class ControlPlaneTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        db = Database(Path(self.tempdir.name) / "backstabber.db")
        self.plane = ControlPlane(db=db, scope_policy=AllowAllScopePolicy())

    def tearDown(self):
        self.tempdir.cleanup()

    def test_dry_run_records_execution_without_creating_job(self):
        engagement = self.plane.create_engagement("Lab", ["192.0.2.0/24"])

        plan = self.plane.build_plan(
            engagement["id"],
            "network.scan",
            {"target": "192.0.2.0/24", "ports": "22,80"},
            dry_run=True,
        )
        execution = self.plane.record_dry_run(
            engagement["id"],
            "network.scan",
            plan["payload"],
            plan,
        )

        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["requires_approval"])
        self.assertEqual(plan["payload"]["ports"], "22,80")
        self.assertEqual(execution["status"], "dry_run")
        self.assertEqual(self.plane.list_jobs(), [])

    def test_enqueue_requires_approval_then_moves_to_queue(self):
        engagement = self.plane.create_engagement("Lab", ["192.0.2.0/24"])

        result = self.plane.enqueue_job(
            engagement["id"],
            "network.scan",
            {"target": "192.0.2.0/24", "ports": "22"},
        )

        self.assertEqual(result["job"]["status"], "waiting_approval")
        self.assertEqual(result["approval"]["status"], "pending")

        approved = self.plane.approve_job(result["approval"]["id"], actor="tester")

        self.assertEqual(approved["approval"]["status"], "approved")
        self.assertEqual(approved["job"]["status"], "queued")

    def test_asset_must_stay_inside_engagement_scope(self):
        engagement = self.plane.create_engagement("Lab", ["192.0.2.0/24"])

        asset = self.plane.add_asset(engagement["id"], "192.0.2.50", tags=["linux"])

        self.assertEqual(asset["address"], "192.0.2.50")
        with self.assertRaises(ControlPlaneError):
            self.plane.add_asset(engagement["id"], "198.51.100.10")

    def test_worker_records_successful_network_scan(self):
        engagement = self.plane.create_engagement(
            "Lab",
            ["192.0.2.0/24"],
            approval_required=False,
        )
        queued = self.plane.enqueue_job(
            engagement["id"],
            "network.scan",
            {"target": "192.0.2.0/24", "ports": "22"},
        )

        with mock.patch("core.scanner_adapter.get_default_scanner", return_value=FakeScanner()):
            result = JobWorker(self.plane).run_once()

        self.assertIsNotNone(result)
        self.assertEqual(result["job"]["id"], queued["job"]["id"])
        self.assertEqual(result["job"]["status"], "succeeded")
        self.assertEqual(result["execution"]["status"], "succeeded")
        self.assertEqual(result["execution"]["result"]["host_count"], 1)


if __name__ == "__main__":
    unittest.main()
