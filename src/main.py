from PyQt5.QtWidgets import QApplication
from gui.main_window import BTMainWindow
import sys

def main():
    app = QApplication(sys.argv)
    window = BTMainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
