from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, 
    QPushButton, QTextEdit, QMessageBox, QHBoxLayout, QComboBox
)
from PyQt5.QtCore    import QTimer
from core.arp_spoof  import ARPSpoofThread
from utils.net       import in_same_subnet, get_default_gateway
from scapy.all       import get_if_hwaddr, conf

class ARPSpoofTab(QWidget):
    def __init__(self, scanner_tab):
        super().__init__()
        self.scanner_tab   = scanner_tab
        self.thread        = None
        self._build_ui()
        self.check_attempts = 0
        self.max_attempts   = 3

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("IP del objetivo:"))
        self.target_ip_input = QLineEdit()
        layout.addWidget(self.target_ip_input)

        layout.addWidget(QLabel("Puerta de enlace (gateway):"))
        self.gateway_combo = QComboBox()
        layout.addWidget(self.gateway_combo)
        # Carga gateways al inicio:
        for gw in get_default_gateway():
            self.gateway_combo.addItem(gw)

        btn_layout = QHBoxLayout()
        self.start_button = QPushButton("Iniciar ARP Spoof")
        self.stop_button  = QPushButton("Detener")
        self.stop_button.setEnabled(False)
        btn_layout.addWidget(self.start_button)
        btn_layout.addWidget(self.stop_button)
        layout.addLayout(btn_layout)

        layout.addWidget(QLabel("Logs:"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

        self.start_button.clicked.connect(self.start_spoof)
        self.stop_button.clicked.connect(self.stop_spoof)

    def start_spoof(self):
        target_ip = self.target_ip_input.text().strip()
        gateway   = self.gateway_combo.currentText().strip()

        if not target_ip or not gateway:
            QMessageBox.warning(self, "Error", "Debe ingresar IP objetivo y seleccionar gateway.")
            return

        if not in_same_subnet(target_ip, gateway):
            self.log_area.append("[✖] IP y gateway no están en la misma subred.")
            return

        iface = conf.iface
        our_mac = get_if_hwaddr(iface)
        self.thread = ARPSpoofThread(target_ip, gateway)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_area.append(f"[✔] Envenenamiento ARP iniciado contra {target_ip}.")
        self.check_attempts = 0
        QTimer.singleShot(4000, lambda: self.verify_spoof_success(gateway))

    def verify_spoof_success(self, gateway):
        if self.thread.check_success(gateway):
            self.log_area.append("[✔] Envenenamiento ARP funcionando correctamente.")
        else:
            self.check_attempts += 1
            if self.check_attempts < self.max_attempts:
                self.log_area.append("[…] Verificación fallida, reintentando…")
                QTimer.singleShot(3000, lambda: self.verify_spoof_success(gateway))
            else:
                self.log_area.append("[✖] No se detectó envenenamiento tras múltiples intentos.")

    def stop_spoof(self):
        if self.thread:
            self.thread.stop()
            self.thread.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_area.append("[✘] Envenenamiento ARP detenido.")

    def on_thread_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_area.append("[✔] Restauración ARP completada.")
