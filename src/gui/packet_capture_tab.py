# src/gui/packet_capture_tab.py
"""
Packet Capture GUI tab with MITM UX safety improvements.

This version is integrated with the centralized ARPManager (arp_manager).
"""

from typing import Optional, Dict, Any
import time
import os

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QFileDialog,
    QMessageBox, QCheckBox, QSizePolicy, QSpinBox
)
from PyQt5.QtCore import Qt, pyqtSlot

# Import capture backend and adapter helpers
try:
    from core.capture import TrafficCapture
except Exception:
    TrafficCapture = None

from core.capture_adapter import list_interfaces, supported_filters, map_filter, check_tshark_installed
# Centralized ARP manager
from core.arp_manager import arp_manager

# optional scapy restore helper (still used for emergency restore fallback)
try:
    from scapy.all import getmacbyip, conf as scapy_conf
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

MAX_ROWS_DEFAULT = 5000  # UI limit for rows to avoid freezing


class PacketCaptureTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # backend
        self.capture = TrafficCapture() if TrafficCapture else None

        # reference central arp manager
        self.arp_manager = arp_manager

        # internal storage
        self._packets: Dict[int, Dict[str, Any]] = {}
        self._details: Dict[int, str] = {}
        self._packet_counter = 0

        # UI
        self._build_ui()
        self._connect_signals()

        # populate UI data
        self._refresh_interfaces()
        self._populate_filters()
        self._update_tshark_status()

        # subscribe to arp_manager signals
        try:
            self.arp_manager.log_event.connect(lambda m: self._log(m))
            self.arp_manager.spoof_started.connect(lambda t, g: (self._log(f"[i] Spoof started {t} <-> {g}"), self._set_mitm_status("VERIFYING")))
            self.arp_manager.spoof_verified.connect(self._on_manager_verified)
            self.arp_manager.spoof_failed.connect(self._on_manager_failed)
            self.arp_manager.spoof_stopped.connect(lambda t, g, r: (self._log(f"[i] Spoof stopped {t} <-> {g} restored={r}"), self._set_mitm_status("INACTIVE")))
        except Exception:
            pass

    # -------------------------
    # UI building
    # -------------------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Top controls: interface, presets, custom bpf
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        top_row.addWidget(self.iface_combo)

        top_row.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        top_row.addWidget(self.filter_combo)

        self.custom_bpf = QLineEdit()
        self.custom_bpf.setPlaceholderText("Custom BPF (used when 'Custom BPF' selected)")
        self.custom_bpf.setVisible(False)
        top_row.addWidget(self.custom_bpf)

        layout.addLayout(top_row)

        # MITM inputs row
        mitm_row = QHBoxLayout()
        self.mitm_checkbox = QCheckBox("Start ARP Poison (MITM)")
        mitm_row.addWidget(self.mitm_checkbox)

        mitm_row.addWidget(QLabel("Victim IP:"))
        self.victim_ip_input = QLineEdit()
        self.victim_ip_input.setPlaceholderText("192.168.1.5")
        mitm_row.addWidget(self.victim_ip_input)

        mitm_row.addWidget(QLabel("Gateway IP:"))
        self.gateway_ip_input = QLineEdit()
        self.gateway_ip_input.setPlaceholderText("192.168.1.1")
        mitm_row.addWidget(self.gateway_ip_input)

        # MITM status label and emergency restore
        self.mitm_status_label = QLabel("MITM: INACTIVE")
        mitm_row.addWidget(self.mitm_status_label)
        self.emergency_restore_btn = QPushButton("Emergency Restore")
        self.emergency_restore_btn.setToolTip("Send immediate ARP restore packets (best-effort)")
        mitm_row.addWidget(self.emergency_restore_btn)

        layout.addLayout(mitm_row)

        # Control buttons
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        self.save_btn = QPushButton("Save PCAP...")
        self.save_btn.setToolTip("Save capture to pcap using tshark (if available). Will start capture if not running.")
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.save_btn)

        # Row for max packets and row limit
        config_row = QHBoxLayout()
        config_row.addWidget(QLabel("Max packets (optional):"))
        self.max_packets_spin = QSpinBox()
        self.max_packets_spin.setMinimum(0)
        self.max_packets_spin.setMaximum(10000000)
        self.max_packets_spin.setValue(0)  # 0 -> unlimited
        config_row.addWidget(self.max_packets_spin)

        config_row.addWidget(QLabel("UI row limit:"))
        self.row_limit_spin = QSpinBox()
        self.row_limit_spin.setMinimum(100)
        self.row_limit_spin.setMaximum(20000)
        self.row_limit_spin.setValue(MAX_ROWS_DEFAULT)
        config_row.addWidget(self.row_limit_spin)

        btn_row.addLayout(config_row)
        layout.addLayout(btn_row)

        # Table of captured packets
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Src", "Dst", "Proto", "Info"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(self.table.SelectRows)
        layout.addWidget(self.table)

        # Details area
        details_label = QLabel("Packet Details:")
        layout.addWidget(details_label)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)

        # Small status area
        status_row = QHBoxLayout()
        self.tshark_label = QLabel("")  # shows whether tshark available
        status_row.addWidget(self.tshark_label)
        self.status_log = QTextEdit()
        self.status_log.setReadOnly(True)
        self.status_log.setMaximumHeight(100)
        status_row.addWidget(self.status_log)
        layout.addLayout(status_row)

        self.setLayout(layout)

    # -------------------------
    # Wiring signals
    # -------------------------
    def _connect_signals(self) -> None:
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.save_btn.clicked.connect(self.on_save)
        self.filter_combo.currentTextChanged.connect(self.on_filter_selected)
        self.iface_combo.activated.connect(lambda _: self._update_tshark_status())
        self.table.itemSelectionChanged.connect(self.on_table_selection_changed)
        self.emergency_restore_btn.clicked.connect(self.on_emergency_restore)

        if self.capture:
            self.capture.packet_captured.connect(self._on_packet_captured)
            self.capture.packet_detail.connect(self._on_packet_detail)
            self.capture.started.connect(self._on_capture_started)
            self.capture.stopped.connect(self._on_capture_stopped)
            self.capture.error.connect(self._on_capture_error)

    # -------------------------
    # UI helpers
    # -------------------------
    def _log(self, msg: str) -> None:
        ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
        self.status_log.append(f"{ts} {msg}")

    def _refresh_interfaces(self) -> None:
        self.iface_combo.clear()
        try:
            ifaces = list_interfaces()
            for info in ifaces:
                name = info.get("name")
                ip = info.get("ipv4") or ""
                display = f"{name} {ip}".strip()
                self.iface_combo.addItem(display, userData=name)
            # if none, add a placeholder
            if self.iface_combo.count() == 0:
                self.iface_combo.addItem("no-interface", userData=None)
        except Exception as e:
            self._log(f"Failed to list interfaces: {e}")

    def _populate_filters(self) -> None:
        self.filter_combo.clear()
        for key in supported_filters():
            self.filter_combo.addItem(key)
        # ensure custom BPF visibility according to selection
        self.on_filter_selected(self.filter_combo.currentText())

    def _update_tshark_status(self) -> None:
        iface = self.iface_combo.currentData()
        if check_tshark_installed():
            self.tshark_label.setText("tshark: available")
        else:
            self.tshark_label.setText("tshark: NOT found (pyshark requires tshark)")

    def _set_mitm_status(self, status: str) -> None:
        """
        Update MITM status label. status should be one of:
        INACTIVE, VERIFYING, ACTIVE, FAILED
        """
        self.mitm_status_label.setText(f"MITM: {status}")
        if status == "ACTIVE":
            self.mitm_status_label.setStyleSheet("color: green; font-weight: bold;")
        elif status == "VERIFYING":
            self.mitm_status_label.setStyleSheet("color: orange;")
        elif status == "FAILED":
            self.mitm_status_label.setStyleSheet("color: red;")
        else:
            self.mitm_status_label.setStyleSheet("color: black;")

    # -------------------------
    # Slots / button handlers
    # -------------------------
    @pyqtSlot()
    def on_start(self) -> None:
        iface = self.iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "Interface", "Please select a valid interface.")
            return

        preset = self.filter_combo.currentText()
        victim = self.victim_ip_input.text().strip() or None
        gateway = self.gateway_ip_input.text().strip() or None
        attacker = None  # attacker IP not collected here; could be optional
        bpf, display = map_filter(preset, victim_ip=victim, attacker_ip=attacker, gateway_ip=gateway)

        # handle custom BPF
        if preset == "Custom BPF":
            custom = self.custom_bpf.text().strip()
            if not custom:
                QMessageBox.warning(self, "Custom BPF", "Please enter a custom BPF filter.")
                return
            bpf = custom

        max_packets = self.max_packets_spin.value() or None
        ui_row_limit = self.row_limit_spin.value() or MAX_ROWS_DEFAULT

        # If MITM option selected, validate fields
        start_arp = self.mitm_checkbox.isChecked()
        if start_arp:
            if not victim or not gateway:
                QMessageBox.warning(self, "MITM", "Victim and Gateway IPs are required to start ARP Poison.")
                return
            # ask legal confirmation before doing MITM
            ok = QMessageBox.question(
                self,
                "Confirm MITM",
                "You are about to perform ARP poisoning (MITM). Only do this on networks you own or are authorized to test.\n\nDo you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if ok != QMessageBox.Yes:
                self._log("User cancelled MITM start")
                start_arp = False

        # Clear UI table and counters
        self.table.setRowCount(0)
        self._packets.clear()
        self._details.clear()
        self._packet_counter = 0
        self.details_text.clear()
        self.status_log.clear()
        self._set_mitm_status("INACTIVE")

        # Start ARP spoof via manager if requested (manager handles verification)
        if start_arp:
            if self.arp_manager.is_active():
                self._log("Using existing ARP spoof session for MITM capture")
                self._set_mitm_status("ACTIVE")
                self._start_capture_backend(iface, bpf, display, max_packets)
            else:
                started = self.arp_manager.start_spoof(victim, gateway)
                if started:
                    self._log(f"Requested ARP spoof for {victim} (gateway {gateway}) - verification pending")
                    self._set_mitm_status("VERIFYING")
                    # capture starts automatically when spoof_verified is emitted
                else:
                    QMessageBox.warning(self, "MITM", "Could not start ARP spoof. Starting capture without MITM.")
                    self._start_capture_backend(iface, bpf, display, max_packets)
        else:
            # capture without MITM
            self._start_capture_backend(iface, bpf, display, max_packets)


        # UI state: disable start until capture is running
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def _on_manager_verified(self, target: str, gateway: str, msg: str) -> None:
        """
        Called when arp_manager confirms spoof is active. If capture is not running, start it now.
        """
        self._log(f"[✔] Manager: spoof verified for {target} <-> {gateway}: {msg}")
        self._set_mitm_status("ACTIVE")
        # If capture is not running, start it with current UI choices
        if not (self.capture and self.capture.is_running()):
            iface = self.iface_combo.currentData()
            preset = self.filter_combo.currentText()
            victim = self.victim_ip_input.text().strip() or None
            gateway = self.gateway_ip_input.text().strip() or None
            attacker = None
            bpf, display = map_filter(preset, victim_ip=victim, attacker_ip=attacker, gateway_ip=gateway)
            max_packets = self.max_packets_spin.value() or None
            self._start_capture_backend(iface, bpf, display, max_packets)

    def _on_manager_failed(self, target: str, gateway: str, reason: str) -> None:
        self._log(f"[✖] Manager: spoof verification failed: {reason}")
        self._set_mitm_status("FAILED")
        # Ask user whether to continue without MITM
        choice = QMessageBox.question(self, "MITM verification failed", "MITM verification failed. Start capture without MITM?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if choice == QMessageBox.Yes:
            iface = self.iface_combo.currentData()
            preset = self.filter_combo.currentText()
            victim = self.victim_ip_input.text().strip() or None
            gateway = self.gateway_ip_input.text().strip() or None
            attacker = None
            bpf, display = map_filter(preset, victim_ip=victim, attacker_ip=attacker, gateway_ip=gateway)
            max_packets = self.max_packets_spin.value() or None
            self._start_capture_backend(iface, bpf, display, max_packets)
        else:
            self._log("User aborted capture due to MITM verification failure")

    def _start_capture_backend(self, iface, bpf, display, max_packets) -> None:
        """
        Internal helper to start the capture backend with safe guards.
        """
        if not self.capture:
            QMessageBox.critical(self, "Capture", "Capture backend not available.")
            return
        try:
            self.capture.start_capture(
                interface=iface,
                bpf_filter=bpf,
                display_filter=display,
                save_file=None,
                max_packets=max_packets
            )
            self._log(f"Capture started on {iface}")
        except Exception as e:
            QMessageBox.critical(self, "Capture start failed", str(e))
            # if we had an arp thread running, keep it running for user to manage

    @pyqtSlot()
    def on_stop(self) -> None:
        # stop capture first
        if self.capture and self.capture.is_running():
            try:
                self.capture.stop_capture()
                self._log("Capture stop requested")
            except Exception as e:
                self._log(f"[!] Error requesting capture stop: {e}")

        # then stop spoof via manager (manager will attempt restore)
        try:
            restored = self.arp_manager.stop_spoof(wait_for_restore=True, timeout_ms=4000)
            if restored:
                self._log("[i] ARP spoof stopped and restoration likely successful")
            else:
                self._log("[i] ARP spoof stopped but restoration may have failed")
        except Exception as e:
            self._log(f"[!] Error stopping ARP spoof via manager: {e}")

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._set_mitm_status("INACTIVE")

    @pyqtSlot()
    def on_save(self) -> None:
        # If capture not running, we will start capture with save_file set
        options = QFileDialog.Options()
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        if not path:
            return

        iface = self.iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "Interface", "Please select a valid interface.")
            return

        preset = self.filter_combo.currentText()
        victim = self.victim_ip_input.text().strip() or None
        gateway = self.gateway_ip_input.text().strip() or None
        attacker = None
        bpf, display = map_filter(preset, victim_ip=victim, attacker_ip=attacker, gateway_ip=gateway)
        if preset == "Custom BPF":
            custom = self.custom_bpf.text().strip()
            if not custom:
                QMessageBox.warning(self, "Custom BPF", "Please enter a custom BPF filter.")
                return
            bpf = custom

        # Start capture with save_file (if already running, inform user that save file will not be applied)
        if self.capture and not self.capture.is_running():
            try:
                self.capture.start_capture(interface=iface, bpf_filter=bpf, display_filter=display, save_file=path)
                self._log(f"Saving capture to {path}")
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
            except Exception as e:
                QMessageBox.critical(self, "Save failed", str(e))
        else:
            # Already running: advise user to stop and restart with save option
            QMessageBox.information(self, "Save PCAP", "Capture already running. Stop and restart capture to save to a file.")

    @pyqtSlot(str)
    def on_filter_selected(self, text: str) -> None:
        if text == "Custom BPF":
            self.custom_bpf.setVisible(True)
        else:
            self.custom_bpf.setVisible(False)

    # -------------------------
    # Capture signal handlers
    # -------------------------
    @pyqtSlot(dict)
    def _on_packet_captured(self, summary: Dict[str, Any]) -> None:
        """
        Handle lightweight packet summaries coming from backend.
        """
        try:
            self._packet_counter += 1
            idx = self._packet_counter
            # store summary; details may arrive separately
            self._packets[idx] = summary

            # enforce UI row limit
            row_limit = self.row_limit_spin.value() or MAX_ROWS_DEFAULT
            if self.table.rowCount() >= row_limit:
                # remove oldest row
                self.table.removeRow(0)

            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            time_item = QTableWidgetItem(str(summary.get("time", "")))
            src_item = QTableWidgetItem(str(summary.get("src", "")))
            dst_item = QTableWidgetItem(str(summary.get("dst", "")))
            proto_item = QTableWidgetItem(str(summary.get("proto", "")))
            info_item = QTableWidgetItem(str(summary.get("info", "")[:200]))

            for it in (time_item, src_item, dst_item, proto_item, info_item):
                it.setFlags(it.flags() ^ Qt.ItemIsEditable)

            self.table.setItem(row_pos, 0, time_item)
            self.table.setItem(row_pos, 1, src_item)
            self.table.setItem(row_pos, 2, dst_item)
            self.table.setItem(row_pos, 3, proto_item)
            self.table.setItem(row_pos, 4, info_item)

            # store placeholder detail until real detail arrives
            self._details[idx] = self._details.get(idx, "<details pending>")

            # scroll to bottom
            self.table.scrollToBottom()
        except Exception as e:
            self._log(f"[!] Error handling captured packet: {e}")

    @pyqtSlot(str)
    def _on_packet_detail(self, detail: str) -> None:
        """
        Detailed textual representation of a packet. We store it under the latest packet index.
        """
        try:
            idx = self._packet_counter
            if idx == 0:
                # no packets yet; store in 1
                idx = 1
            self._details[idx] = detail
            # if the last inserted row is selected, update details view
            sel_rows = self.table.selectionModel().selectedRows()
            if sel_rows:
                # if the last row selected corresponds to idx, update
                last_selected_row = sel_rows[-1].row()
                # map table row to packet index: we use insertion order starting at 1
                table_idx = last_selected_row + 1  # because packet_counter starts 1
                if table_idx == idx:
                    self.details_text.setPlainText(detail)
        except Exception as e:
            self._log(f"[!] Error handling packet detail: {e}")

    @pyqtSlot()
    def _on_capture_started(self) -> None:
        self._log("[i] Capture backend reported started")

    @pyqtSlot()
    def _on_capture_stopped(self) -> None:
        self._log("[i] Capture backend reported stopped")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        # ask manager to stop spoof if it is still running
        try:
            self.arp_manager.stop_spoof(wait_for_restore=False)
        except Exception:
            pass

    @pyqtSlot(str)
    def _on_capture_error(self, message: str) -> None:
        self._log(f"[!] Capture error: {message}")
        QMessageBox.warning(self, "Capture error", message)
        # ensure UI is consistent
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    @pyqtSlot()
    def on_table_selection_changed(self) -> None:
        """
        When user selects a row, show corresponding detailed text (if available).
        Mapping logic: row 0 -> packet idx 1, row N -> idx N+1
        """
        try:
            sel = self.table.selectionModel().selectedRows()
            if not sel:
                return
            row = sel[0].row()
            packet_idx = row + 1
            detail = self._details.get(packet_idx, "<no details available>")
            self.details_text.setPlainText(detail)
        except Exception as e:
            self._log(f"[!] Error selecting packet: {e}")

    # -------------------------
    # Emergency restore helper
    # -------------------------
    def on_emergency_restore(self) -> None:
        """
        Best-effort immediate ARP restoration helper. It delegates to arp_manager.emergency_restore.
        """
        victim = self.victim_ip_input.text().strip()
        gateway = self.gateway_ip_input.text().strip()
        if not victim or not gateway:
            QMessageBox.warning(self, "Emergency Restore", "Victim and Gateway IPs are required.")
            return

        ok = False
        try:
            ok = self.arp_manager.emergency_restore(victim, gateway, iface=self.iface_combo.currentData())
        except Exception as e:
            self._log(f"[!] Emergency restore failed: {e}")
        if ok:
            self._log("[i] Emergency restore (manager) succeeded")
        else:
            self._log("[!] Emergency restore (manager) failed")