import unittest

from PyQt5.QtCore import QCoreApplication

import core.arp_manager as arp_manager_module
from core.arp_manager import ARPManager


_app = QCoreApplication.instance() or QCoreApplication([])


TARGET = "192.0.2.10"
GATEWAY = "192.0.2.1"


class FakeThread:
    def __init__(self, wait_result=True):
        self.wait_result = wait_result
        self.stop_calls = 0
        self.wait_calls = []

    def stop(self):
        self.stop_calls += 1

    def wait(self, timeout_ms):
        self.wait_calls.append(timeout_ms)
        return self.wait_result


class FakeVerifyThread:
    def __init__(self):
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1


class ARPManagerStopLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.original_check = arp_manager_module.check_arp_spoof_success
        arp_manager_module.check_arp_spoof_success = lambda target, gateway: False
        self.manager = ARPManager()
        self.stopped_events = []
        self.manager.spoof_stopped.connect(
            lambda target, gateway, restored: self.stopped_events.append((target, gateway, restored))
        )

    def tearDown(self):
        arp_manager_module.check_arp_spoof_success = self.original_check

    def install_running_thread(self, thread):
        self.manager._thread = thread
        self.manager._state.update({
            "state": "RUNNING",
            "running": True,
            "target": TARGET,
            "gateway": GATEWAY,
            "iface": None,
            "verified": False,
            "started_at": 123.0,
        })

    def test_timeout_keeps_worker_active_and_does_not_emit_stopped(self):
        thread = FakeThread(wait_result=False)
        self.install_running_thread(thread)

        restored = self.manager.stop_spoof(wait_for_restore=True, timeout_ms=250)

        self.assertFalse(restored)
        self.assertEqual(thread.stop_calls, 1)
        self.assertEqual(thread.wait_calls, [250])
        self.assertIs(self.manager._thread, thread)
        self.assertEqual(self.manager.status()["state"], "STOPPING")
        self.assertTrue(self.manager.status()["running"])
        self.assertEqual(self.stopped_events, [])

    def test_async_stop_keeps_worker_active_and_does_not_emit_stopped(self):
        thread = FakeThread(wait_result=True)
        verify_thread = FakeVerifyThread()
        self.install_running_thread(thread)
        self.manager._verify_thread = verify_thread

        restored = self.manager.stop_spoof(wait_for_restore=False)

        self.assertFalse(restored)
        self.assertEqual(thread.stop_calls, 1)
        self.assertEqual(thread.wait_calls, [])
        self.assertEqual(verify_thread.stop_calls, 1)
        self.assertIs(self.manager._thread, thread)
        self.assertEqual(self.manager.status()["state"], "STOPPING")
        self.assertEqual(self.stopped_events, [])

    def test_successful_wait_clears_state_and_emits_stopped_once(self):
        thread = FakeThread(wait_result=True)
        self.install_running_thread(thread)

        restored = self.manager.stop_spoof(wait_for_restore=True, timeout_ms=250)
        self.manager._on_thread_finished(thread, TARGET, GATEWAY)

        self.assertTrue(restored)
        self.assertIsNone(self.manager._thread)
        self.assertFalse(self.manager.status()["running"])
        self.assertEqual(self.manager.status()["state"], "SUCCEEDED")
        self.assertEqual(self.stopped_events, [(TARGET, GATEWAY, True)])

    def test_thread_finished_is_idempotent_for_same_worker(self):
        thread = FakeThread(wait_result=True)
        verify_thread = FakeVerifyThread()
        self.install_running_thread(thread)
        self.manager._verify_thread = verify_thread

        self.manager._on_thread_finished(thread, TARGET, GATEWAY)
        self.manager._on_thread_finished(thread, TARGET, GATEWAY)

        self.assertIsNone(self.manager._thread)
        self.assertIsNone(self.manager._verify_thread)
        self.assertEqual(verify_thread.stop_calls, 1)
        self.assertFalse(self.manager.status()["running"])
        self.assertEqual(self.stopped_events, [(TARGET, GATEWAY, True)])

    def test_verification_result_is_ignored_while_stopping(self):
        verified_events = []
        failed_events = []
        self.manager.spoof_verified.connect(lambda *args: verified_events.append(args))
        self.manager.spoof_failed.connect(lambda *args: failed_events.append(args))
        thread = FakeThread(wait_result=False)
        self.install_running_thread(thread)
        self.manager._state["state"] = "STOPPING"

        self.manager._on_verify_result(True, "verified", TARGET, GATEWAY)

        self.assertEqual(verified_events, [])
        self.assertEqual(failed_events, [])
        self.assertFalse(self.manager.status()["verified"])


if __name__ == "__main__":
    unittest.main()
