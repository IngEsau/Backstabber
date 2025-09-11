# src/gui/main_window.py

from PyQt5.QtWidgets import QMainWindow, QTabWidget
from gui.network_scanner_tab import NetworkScannerTab
from gui.arp_spoof_tab       import ARPSpoofTab
from gui.packet_capture_tab import PacketCaptureTab

class BTMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Backstabber - Toolkit")
        self.setGeometry(200, 200, 800, 600)

        tabs = QTabWidget()

        self.network_scanner_tab = NetworkScannerTab()
        self.arp_spoof_tab       = ARPSpoofTab(self.network_scanner_tab)
        self.packet_capture_tab = PacketCaptureTab()

        self.network_scanner_tab.scan_completed_callback = (
            self.arp_spoof_tab.populate_after_scan
        )

        tabs.addTab(self.network_scanner_tab, "Network Scanner")
        tabs.addTab(self.arp_spoof_tab,       "ARP Spoofing")
        tabs.addTab(self.packet_capture_tab, "Packet Capture")

        self.setCentralWidget(tabs)
