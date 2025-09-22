import os
import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
    QTextEdit, QMessageBox, QHBoxLayout, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt
from core.scan import AsyncScanner

class NetworkScannerTab(QWidget):
    hosts = []

    def __init__(self):    
        self.scan_completed_callback = lambda hosts, output: None    
        super().__init__()
        self._build_ui()
        self.scanner_thread = None
        self.scan_results = {}  # Dictionary to store results: {host: [ports]}
        self.gateway_ip = None  # Store gateway IP if available

        # Ensure logs directory exists
        os.makedirs("logs", exist_ok=True)

    def _build_ui(self):
        layout = QVBoxLayout()        
        # Input field to IP range
        layout.addWidget(QLabel("Enter the IP range (e.g 192.168.1.0/24):"))
        self.input = QLineEdit()
        self.input.setPlaceholderText("192.168.1.0/24")
        layout.addWidget(self.input)

        layout.addWidget(QLabel("Network Interface (optional):"))
        self.iface_input = QLineEdit()
        self.iface_input.setPlaceholderText("e.g., eth0, en0, wlan0")
        layout.addWidget(self.iface_input)
        
        # Input field to ports
        layout.addWidget(QLabel("Ports to scan (e.g 22,80,443 or 1-1024):"))
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("1-1024")
        self.ports_input.setText("1-1024") 
        layout.addWidget(self.ports_input)

        # Control buttons
        btn_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setObjectName("startButton")
        self.cancel_button = QPushButton("Abort Scan")
        self.cancel_button.setObjectName("stopButton")
        self.cancel_button.setEnabled(False)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.cancel_button)
        layout.addLayout(btn_layout)
        
        # Progressbar
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFormat("Scanning: %p%")
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results area (table)
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["Host", "Open Ports"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.result_table)
        

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)

    def start_scan(self):
        ip_range = self.input.text().strip()        
        ports = self.ports_input.text().strip()        
        
        iface_text = self.iface_input.text().strip()
        iface = iface_text if iface_text else None

        if not ip_range:
            QMessageBox.warning(self, "Error", "Please enter a valid IP range.")
            return
            
        if not ports:
            QMessageBox.warning(self, "Error", "Please enter valid ports to scan.")
            return
            
        self.output_area.clear()
        self.result_table.setRowCount(0)
        self.scan_results = {}
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.output_area.append(f"[*] Starting network scan: {ip_range}")
        self.output_area.append(f"[*] Scanning ports: {ports}")
        if iface:
            self.output_area.append(f"[*] Using network interface: {iface}")
        
        self.scanner_thread = AsyncScanner(ip_range, ports, iface=iface)
        
        self.scanner_thread.result_line.connect(self.output_area.append)
        self.scanner_thread.host_discovered.connect(self.add_host_to_table)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.finished.connect(self.on_scan_finished)
        
        # Start scan
        self.scanner_thread.start()

    def cancel_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.cancel()
            self.scanner_thread.wait()  # Wait for the thread to finish
            self.output_area.append("\n[!] Scan aborted by user\n")
            self.finalize_scan()

    def update_progress(self, completed, total):
        """Update the progress bar with the current scan status."""
        if total > 0:
            percent = int((completed / total) * 100) if total > 0 else 0
            progress_text = f"Scanning: {percent}% ({completed}/{total} hosts)"

            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(completed)
            self.progress_bar.setFormat(progress_text)

            self.progress_bar.repaint()

    def add_host_to_table(self, host, open_ports):
        """Add a discovered host to the results table"""
        # Store results for the callback
        self.scan_results[host] = open_ports
        
        # Add row to table
        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)
        
        # Host
        host_item = QTableWidgetItem(host)
        host_item.setFlags(host_item.flags() ^ Qt.ItemIsEditable)
        self.result_table.setItem(row_position, 0, host_item)
        
        # PORTS OPEN
        ports_str = ", ".join(map(str, open_ports))
        ports_item = QTableWidgetItem(ports_str)
        ports_item.setFlags(ports_item.flags() ^ Qt.ItemIsEditable)
        self.result_table.setItem(row_position, 1, ports_item)
        
        self.result_table.resizeRowsToContents()

    def log_message(self, message: str):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        full_msg = f"{timestamp} {message}"
        self.output_area.append(full_msg)
        with open("logs/network_scan_log.txt", "a") as f:
            f.write(full_msg + "\n")

    def analyze_network(self):
        hosts = self.hosts
        ports_per_host = self.scan_results
        total_hosts = len(hosts)
        total_ports = sum(len(ports) for ports in ports_per_host.values())
        active_subnets = set('.'.join(host.split('.')[:3]) for host in hosts)  # Simple /24 subnet count

        # Find ARP poisoning candidates (same subnet, not gateway)
        gateway = self.gateway_ip
        arp_candidates = [h for h in hosts if h != gateway and self.in_same_subnet(h, gateway)]

        summary = []
        summary.append(f"Network scan summary ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}):")
        summary.append(f"Total hosts discovered: {total_hosts}")
        summary.append(f"Total open ports found: {total_ports}")
        summary.append(f"Active subnets detected: {len(active_subnets)}")
        summary.append(f"ARP poisoning candidates: {', '.join(arp_candidates) if arp_candidates else 'None'}")
        if not arp_candidates:
            summary.append("WARNING: No suitable hosts for ARP poisoning detected.")
        summary.append("Recommended for Wireshark: Capture traffic on the main interface during scan.")
        summary.append("Recommended for Metasploit: Use discovered hosts and open ports for targeted exploits.")

        summary_text = "\n".join(summary)
        self.log_message(summary_text)
        with open("logs/network_analysis_summary.txt", "w") as f:
            f.write(summary_text)

    def export_scan_data(self):
        with open("logs/scan_results_for_tools.txt", "w") as f:
            for host, ports in self.scan_results.items():
                f.write(f"{host}: {','.join(map(str, ports))}\n")

    def in_same_subnet(self, ip1, ip2):
        # Simple /24 subnet check
        return '.'.join(ip1.split('.')[:3]) == '.'.join(ip2.split('.')[:3])
    
    def finalize_scan(self):
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setVisible(False)

    def on_scan_finished(self):
        self.log_message("[+] Scan completed successfully")
        self.finalize_scan()
        self.hosts = list(self.scan_results.keys())
        # Try to get gateway from scan results if available
        if self.hosts:
            self.gateway_ip = self.hosts[0]  # You may want to improve this logic
        if hasattr(self, 'scan_completed_callback'):
            self.scan_completed_callback(self.hosts, self.output_area.toPlainText())
        self.analyze_network()
        self.export_scan_data()