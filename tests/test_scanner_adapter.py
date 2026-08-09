import unittest
from unittest import mock

from core.scanner_adapter import build_nmap_command


class ScannerAdapterTest(unittest.TestCase):
    def test_unprivileged_default_uses_tcp_connect_scan(self):
        with mock.patch("core.scanner_adapter.os.geteuid", return_value=1000):
            command = build_nmap_command("/usr/bin/nmap", "192.0.2.1/32", ports="22,80", extra_args="-Pn")

        self.assertEqual(
            command,
            ["/usr/bin/nmap", "-sT", "-Pn", "-p", "22,80", "-oX", "-", "192.0.2.1/32"],
        )

    def test_privileged_default_uses_syn_scan(self):
        with mock.patch("core.scanner_adapter.os.geteuid", return_value=0):
            command = build_nmap_command("/usr/bin/nmap", "192.0.2.1/32", ports="443")

        self.assertEqual(
            command,
            ["/usr/bin/nmap", "-sS", "-p", "443", "-oX", "-", "192.0.2.1/32"],
        )


if __name__ == "__main__":
    unittest.main()
