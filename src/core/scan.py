from PyQt5.QtCore import QThread, pyqtSignal, QProcess

class ScanThread(QThread):
    result_line = pyqtSignal(str)
    finished    = pyqtSignal()

    def __init__(self, ip_range, parent=None):
        super().__init__(parent)
        self.ip_range = ip_range
        self.proc     = None

    def run(self):
        self.proc = QProcess()
        cmd = ["nmap", "-Pn", "-p", "1-1024", self.ip_range]
        self.proc.start(cmd[0], cmd[1:])
        self.proc.readyReadStandardOutput.connect(self._stdout)
        self.proc.readyReadStandardError.connect(self._stderr)
        self.proc.waitForFinished(-1)
        self.finished.emit()

    def _stdout(self):
        data = self.proc.readAllStandardOutput().data().decode()
        self.result_line.emit(data)

    def _stderr(self):
        data = self.proc.readAllStandardError().data().decode()
        self.result_line.emit(f"<error> {data}")

    def cancel(self):
        if self.proc and self.proc.state():
            self.proc.kill()
