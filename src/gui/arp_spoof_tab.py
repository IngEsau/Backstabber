# src/gui/arp_spoof_tab.py
import os
import datetime
import json
import csv

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox,
    QHBoxLayout, QComboBox, QFileDialog
)
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QColor, QPalette
from scapy.all import conf, get_if_hwaddr

# Centralized ARP manager instead of creating threads locally
from core.arp_manager import arp_manager

from utils.net import in_same_subnet, get_default_gateway, evaluate_best_target


class ARPSpoofTab(QWidget):
    def __init__(self, scanner_tab):
        super().__init__()
        self.scanner_tab    = scanner_tab
        self.logs           = []  # Store logs in memory
        self.check_attempts = 0
        self.max_attempts   = 3
        self.best_target_ip = None
        os.makedirs("logs", exist_ok=True)
        self._build_ui()

        # subscribe to manager signals
        try:
            arp_manager.log_event.connect(self._on_arp_log_event)
            arp_manager.spoof_started.connect(self._on_spoof_started_signal)
            arp_manager.spoof_verified.connect(self._on_spoof_verified_signal)
            arp_manager.spoof_failed.connect(self._on_spoof_failed_signal)
            arp_manager.spoof_stopped.connect(self._on_spoof_stopped_signal)
        except Exception:
            pass

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

        # Export buttons
        export_layout = QHBoxLayout()
        self.export_csv_btn = QPushButton("Export Logs (CSV)")
        self.export_json_btn = QPushButton("Export Logs (JSON)")
        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_json_btn)
        layout.addLayout(export_layout)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_spoof)
        self.stop_button.clicked.connect(self.stop_spoof)
        self.export_csv_btn.clicked.connect(self.export_logs_csv)
        self.export_json_btn.clicked.connect(self.export_logs_json)

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

        # use arp_manager to start spoof (non-blocking)
        started = arp_manager.start_spoof(target_ip, gateway)
        if started:
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.log_message(f"[✔] ARP spoofing started against {target_ip}.")
            # manager will emit verification/logs asynchronously
        else:
            self.log_message("[✖] Failed to start spoof (another spoof may be running).")
            QMessageBox.warning(self, "Start failed", "Could not start ARP spoof (another spoof may be active).")

    def log_message(self, message: str):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        full_msg = f"{timestamp} {message}"
        self.logs.append({"timestamp": timestamp, "message": message})
        self.log_area.append(full_msg)
        # Also write to file as before
        os.makedirs("logs", exist_ok=True)
        with open("logs/arp_spoof_gui_log.txt", "a") as f:
            f.write(full_msg + "\n")

    def stop_spoof(self):
        # ask manager to stop and wait for restoration
        target_ip = self.target_ip_input.text().strip()
        gateway   = self.gateway_combo.currentText().strip()
        ok = arp_manager.stop_spoof(wait_for_restore=True, timeout_ms=5000)
        if ok:
            self.log_message("[✘] ARP spoofing stopped (restore likely successful).")
        else:
            self.log_message("[✘] ARP spoofing stopped (restore may have failed).")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # signal handlers from arp_manager
    def _on_arp_log_event(self, message: str):
        self.log_message(message)

    def _on_spoof_started_signal(self, target: str, gateway: str):
        self.log_message(f"[i] Manager: spoof started for {target} <-> {gateway}")

    def _on_spoof_verified_signal(self, target: str, gateway: str, msg: str):
        self.log_message(f"[✔] Manager: spoof verified for {target} <-> {gateway}: {msg}")

    def _on_spoof_failed_signal(self, target: str, gateway: str, reason: str):
        self.log_message(f"[✖] Manager: spoof verification failed: {reason}")

    def _on_spoof_stopped_signal(self, target: str, gateway: str, restored: bool):
        if restored:
            self.log_message("[✔] ARP table restored (manager confirmed).")
        else:
            self.log_message("[!] ARP table restoration may have failed (manager).")

    def export_logs_csv(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, "w", newline="") as csvfile:
                    fieldnames = self.logs[0].keys() if self.logs else []
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    for log in self.logs:
                        writer.writerow(log)

                QMessageBox.information(self, "Success", "Logs exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {e}")

    def export_logs_json(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save JSON File", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, "w") as jsonfile:
                    json.dump(self.logs, jsonfile, indent=4)

                QMessageBox.information(self, "Success", "Logs exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {e}")