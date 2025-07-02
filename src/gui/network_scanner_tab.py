from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QHBoxLayout
)
from core.scan       import ScanThread

class NetworkScannerTab(QWidget):
    hosts = []

    def __init__(self):
        self.scan_completed_callback = lambda hosts, output: None
        super().__init__()
        self._build_ui()
        self.thread = None

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Ingrese el rango IP (ej. 192.168.1.0/24):"))
        self.input       = QLineEdit()
        layout.addWidget(self.input)

        btn_layout = QHBoxLayout()
        self.scan_button   = QPushButton("Escanear Red")
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setEnabled(False)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.cancel_button)        
        layout.addLayout(btn_layout)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

        # Conexiones
        self.scan_button.clicked.connect(self.scan_network)
        self.cancel_button.clicked.connect(self.cancel_scan)        

    def scan_network(self):
        ip_range = self.input.text().strip()
        if not ip_range:
            QMessageBox.warning(self, "Error", "Por favor ingrese un rango IP válido.")
            return

        self.output_area.clear()
        self.output_area.append(f"Escaneando red: {ip_range}...\n")
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)

        self.thread = ScanThread(ip_range)
        self.thread.result_line.connect(self.output_area.append)
        self.thread.finished.connect(self.on_scan_finished)
        self.thread.start()

    def cancel_scan(self):
        if self.thread:
            self.thread.cancel()
            self.output_area.append("\nEscaneo cancelado.\n")

    def on_scan_finished(self):
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.output_area.append("Proceso finalizado.\n")

        text = self.output_area.toPlainText()
        self.hosts = [
            line.split()[-1]
            for line in text.splitlines()
            if line.startswith("Nmap scan report for ")
        ]
        
        if hasattr(self, 'scan_completed_callback'):
            self.scan_completed_callback(self.hosts, text)
