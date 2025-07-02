from PyQt5.QtCore import QThread, pyqtSignal, QProcess
import re

class ScanThread(QThread):
    result_line = pyqtSignal(str)
    finished    = pyqtSignal()

    def __init__(self, ip_range, parent=None):
        super().__init__(parent)
        self.ip_range = ip_range
        self.proc     = None

    def run(self):
        # 1) Pre-escaneo rápido con Masscan
        masscan_cmd = [
            "masscan",
            "-p1-1024",             # Rango de puertos
            "--rate", "10000",     # Tasa de paquetes por segundo
            self.ip_range,
            "-oG", "-"             # Salida grepable por stdout
        ]
        masscan_proc = QProcess()
        masscan_proc.start(masscan_cmd[0], masscan_cmd[1:])
        masscan_proc.waitForFinished(-1)
        raw = masscan_proc.readAllStandardOutput().data().decode(errors='ignore')
        self.result_line.emit("[Masscan] Pre-scann finished")

        # Parsear puertos abiertos de la salida de Masscan
        open_entries = []  # lista de "IP:puerto"
        for line in raw.splitlines():
            if line.startswith('Host:') and 'Ports:' in line:
                parts = line.split()
                ip = parts[1]
                ports_section = line.split('Ports:')[1]
                for entry in ports_section.split(','):
                    match = re.match(r"\s*(\d+)/open", entry)
                    if match:
                        open_entries.append(f"{ip}:{match.group(1)}")

        # Construir lista de puertos para Nmap
        if open_entries:
            target_list = ','.join(open_entries)
        else:
            # si no hay resultados, escanear puertos comunes
            self.result_line.emit("[Masscan] No ports open, used the range 1-1024")
            target_list = "1-1024"

        # 2) Escaneo refinado con Nmap solo sobre puertos detectados
        nmap_cmd = [
            "nmap",
            "-Pn",
            "-sS",
            "-n",
            "--min-rate", "1000",
            "--max-retries", "1",
            "--open",
            "-T4",
            "-p", target_list,
            self.ip_range
        ]
        self.result_line.emit(f"[Nmap] Executing: {' '.join(nmap_cmd)}")
        self.proc = QProcess()
        self.proc.start(nmap_cmd[0], nmap_cmd[1:])
        self.proc.readyReadStandardOutput.connect(self._stdout)
        self.proc.readyReadStandardError.connect(self._stderr)
        self.proc.waitForFinished(-1)
        self.finished.emit()

    def _stdout(self):
        data = self.proc.readAllStandardOutput().data().decode(errors='ignore')
        self.result_line.emit(data)

    def _stderr(self):
        data = self.proc.readAllStandardError().data().decode(errors='ignore')
        self.result_line.emit(f"<error> {data}")

    def cancel(self):
        if self.proc and self.proc.state():
            self.proc.kill()