# src/gui/arp_spoof_tab.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox,
    QHBoxLayout, QComboBox
)
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QColor, QPalette
from scapy.all import conf, get_if_hwaddr

from core.arp_spoof import ARPSpoofThread, check_arp_spoof_success
from utils.net import in_same_subnet, get_default_gateway, evaluate_best_target


class ARPSpoofTab(QWidget):
    def __init__(self, scanner_tab):
        super().__init__()
        self.scanner_tab    = scanner_tab
        self.thread         = None
        self.check_attempts = 0
        self.max_attempts   = 3
        self.best_target_ip = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        # Target IP + suggestion label
        layout.addWidget(QLabel("Target IP:"))
        self.target_ip_input = QLineEdit()
        layout.addWidget(self.target_ip_input)
        self.suggestion_label = QLabel("Suggested Target: (none)")
        self._set_label_color(self.suggestion_label, "gray")
        layout.addWidget(self.suggestion_label)

        # Hosts dropdown
        layout.addWidget(QLabel("Discovered Hosts:"))
        self.discovered_combo = QComboBox()
        layout.addWidget(self.discovered_combo)
        self.discovered_combo.currentIndexChanged.connect(self._on_dropdown_change)

        # Gateway selector
        layout.addWidget(QLabel("Gateway IP:"))
        self.gateway_combo = QComboBox()
        for gw in get_default_gateway():
            self.gateway_combo.addItem(gw)
        layout.addWidget(self.gateway_combo)

        # Control buttons
        btn_layout = QHBoxLayout()
        self.start_button = QPushButton("Start ARP Spoof")
        self.stop_button  = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        btn_layout.addWidget(self.start_button)
        btn_layout.addWidget(self.stop_button)
        layout.addLayout(btn_layout)

        # Log area
        layout.addWidget(QLabel("Logs:"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        # Conection buttons
        self.start_button.clicked.connect(self.start_spoof)
        self.stop_button.clicked.connect(self.stop_spoof)

        self.setLayout(layout)

    def _on_dropdown_change(self):
        # When the user chooses any host, it adds it to input.
        ip = self.discovered_combo.currentText()
        if ip:
            self.target_ip_input.setText(ip)

    def populate_after_scan(self, hosts, raw_output):
        """
        Call from main_window when the scan is complete:

        - fill the dropdown
        - calculate the best IP and color it
        """
        self.discovered_combo.clear()
        for ip in hosts:
            self.discovered_combo.addItem(ip)

        own_ip    = get_if_hwaddr(conf.iface)
        gateway   = self.gateway_combo.currentText()
        best_ip   = evaluate_best_target(raw_output, hosts, own_ip, gateway)
        self.best_target_ip = best_ip

        if best_ip:
            self._set_label_color(self.suggestion_label, "green")
            self.suggestion_label.setText(
                f"Suggested: {best_ip} (most open ports)"
            )
            idx = self.discovered_combo.findText(best_ip)
            if idx != -1:
                self.discovered_combo.setCurrentIndex(idx)
        else:
            self._set_label_color(self.suggestion_label, "red")
            self.suggestion_label.setText("No suitable target found.")

    def _set_label_color(self, label: QLabel, color: str):
        pal = label.palette()
        pal.setColor(QPalette.WindowText, QColor(color))
        label.setPalette(pal)

    def start_spoof(self):
        target_ip = self.target_ip_input.text().strip()
        gateway   = self.gateway_combo.currentText().strip()

        if not target_ip or not gateway:
            QMessageBox.warning(self, "Error", "Please set both a target IP and a gateway.")
            return

        if not in_same_subnet(target_ip, gateway):
            self.log_area.append("[✖] Target and gateway are not in the same subnet.")
            return

        self.thread = ARPSpoofThread(target_ip, gateway)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_area.append(f"[✔] ARP spoofing started against {target_ip}.")
        self.check_attempts = 0
        QTimer.singleShot(4000, lambda: self.verify_spoof_success(target_ip, gateway))

    def verify_spoof_success(self, victim_ip, gateway_ip):
        """Usa la nueva función para chequear la caché ARP de la víctima."""
        if check_arp_spoof_success(victim_ip, gateway_ip):
            self.log_area.append("[✔] ARP Spoofing is working properly.")
        else:
            self.check_attempts += 1
            if self.check_attempts < self.max_attempts:
                self.log_area.append("[…] Verification failed, retrying...")
                QTimer.singleShot(3000, lambda: self.verify_spoof_success(victim_ip, gateway_ip))
            else:
                self.log_area.append("[✖] Spoofing not detected after multiple attempts.")

    def stop_spoof(self):
        if self.thread:
            self.thread.stop()
            self.thread.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_area.append("[✘] ARP spoofing stopped.")

    def on_thread_finished(self):
        self.log_area.append("[✔] ARP table restored.")