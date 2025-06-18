from PyQt5.QtWidgets import QMainWindow, QTabWidget
from gui.network_scanner_tab import NetworkScannerTab
from gui.arp_spoof_tab        import ARPSpoofTab

class RedEyeMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RedEye Toolkit")
        self.setGeometry(100, 100, 700, 500)

        tabs = QTabWidget()
        self.scan_tab = NetworkScannerTab()
        tabs.addTab(self.scan_tab,           "Escaneo de Red")
        tabs.addTab(ARPSpoofTab(self.scan_tab), "ARP Spoofing")

        self.setCentralWidget(tabs)
