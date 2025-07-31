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
        self.scan_results = {}  # Diccionario para almacenar resultados: {host: [puertos]}

    def _build_ui(self):
        layout = QVBoxLayout()
        
        # Campo de entrada para rango IP
        layout.addWidget(QLabel("Enter the IP range (e.g 192.168.1.0/24):"))
        self.input = QLineEdit()
        self.input.setPlaceholderText("192.168.1.0/24")
        layout.addWidget(self.input)
        
        # Campo de entrada para puertos
        layout.addWidget(QLabel("Ports to scan (e.g 22,80,443 or 1-1024):"))
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("1-1024")
        self.ports_input.setText("1-1024")  # Valor por defecto
        layout.addWidget(self.ports_input)

        # Botones de control
        btn_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.cancel_button = QPushButton("Abort Scan")
        self.cancel_button.setEnabled(False)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.cancel_button)
        layout.addLayout(btn_layout)
        
        # Barra de progreso
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFormat("Scanning: %p%")
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Área de resultados (tabla)
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["Host", "Open Ports"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.result_table)
        
        # Área de salida de texto
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

        # Conexiones de botones
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)

    def start_scan(self):
        ip_range = self.input.text().strip()
        ports = self.ports_input.text().strip()
        
        if not ip_range:
            QMessageBox.warning(self, "Error", "Please enter a valid IP range.")
            return
            
        if not ports:
            QMessageBox.warning(self, "Error", "Please enter valid ports to scan.")
            return

        # Preparar la interfaz para el escaneo
        self.output_area.clear()
        self.result_table.setRowCount(0)
        self.scan_results = {}
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.output_area.append(f"[*] Starting network scan: {ip_range}")
        self.output_area.append(f"[*] Scanning ports: {ports}")
        
        # Crear y configurar el hilo de escaneo
        self.scanner_thread = AsyncScanner(ip_range, ports)
        
        # Conectar señales
        self.scanner_thread.result_line.connect(self.output_area.append)
        self.scanner_thread.host_discovered.connect(self.add_host_to_table)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.finished.connect(self.on_scan_finished)
        
        # Iniciar el escaneo
        self.scanner_thread.start()

    def cancel_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.cancel()
            self.output_area.append("\n[!] Scan aborted by user\n")
            self.finalize_scan()

    def update_progress(self, completed, total):
        """Actualiza la barra de progreso con el estado del escaneo"""
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(completed)
            percent = int((completed / total) * 100)
            self.progress_bar.setFormat(f"Scanning: {percent}% ({completed}/{total} hosts)")

    def add_host_to_table(self, host, open_ports):
        """Añade un host descubierto a la tabla de resultados"""
        # Almacenar resultados para el callback
        self.scan_results[host] = open_ports
        
        # Añadir fila a la tabla
        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)
        
        # Host
        host_item = QTableWidgetItem(host)
        host_item.setFlags(host_item.flags() ^ Qt.ItemIsEditable)
        self.result_table.setItem(row_position, 0, host_item)
        
        # Puertos abiertos
        ports_str = ", ".join(map(str, open_ports))
        ports_item = QTableWidgetItem(ports_str)
        ports_item.setFlags(ports_item.flags() ^ Qt.ItemIsEditable)
        self.result_table.setItem(row_position, 1, ports_item)
        
        # Auto-ajustar filas
        self.result_table.resizeRowsToContents()

    def on_scan_finished(self):
        """Maneja la finalización del escaneo"""
        self.output_area.append("\n[+] Scan completed successfully\n")
        self.finalize_scan()
        
        # Llamar al callback si existe
        text = self.output_area.toPlainText()
        self.hosts = list(self.scan_results.keys())
        
        if hasattr(self, 'scan_completed_callback'):
            self.scan_completed_callback(self.hosts, text)

    def finalize_scan(self):
        """Restaura el estado de la interfaz después del escaneo"""
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # Limpiar referencia al hilo
        if self.scanner_thread:
            self.scanner_thread.quit()
            self.scanner_thread.wait()
            self.scanner_thread = None