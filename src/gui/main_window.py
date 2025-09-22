# src/gui/main_window.py
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QStackedWidget, QSizePolicy, QFrame, QStatusBar
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QPixmap, QFont, QFontDatabase


from gui.network_scanner_tab import NetworkScannerTab
from gui.arp_spoof_tab import ARPSpoofTab
from gui.packet_capture_tab import PacketCaptureTab

class SideButton(QPushButton):
    def __init__(self, text: str, object_name: str = ""):
        super().__init__(text)
        if object_name:
            self.setObjectName(object_name)
        self.setCheckable(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(42)

class BTMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Backstabber - Toolkit")
        self.setMinimumSize(1000, 700)
        self._load_custom_fonts()
        self._setup_ui()
        self.apply_styles()
        self._setup_logo()

    def _load_custom_fonts(self):
        """Load custom fonts (Cinzel Decorative)"""
        try:
            import os
            import urllib.request
            import tempfile
                        
            fonts_dir = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "fonts")
            os.makedirs(fonts_dir, exist_ok=True)
                        
            font_urls = {
                "CinzelDecorative-Regular.ttf": "https://fonts.gstatic.com/s/cinzeldecorative/v14/daaCSScvJGqLYhG8nNt8KPPswUAPni7TTMw.woff2"
            }
            
            for font_name, font_url in font_urls.items():
                font_path = os.path.join(fonts_dir, font_name)
                
                if not os.path.exists(font_path):
                    try:
                        print(f"Downloading font: {font_name}")
                        urllib.request.urlretrieve(font_url, font_path)
                        print(f"✓ Success: {font_name}")
                    except Exception as e:
                        print(f"✗ Error downloading {font_name}: {e}")
                        continue
                                
                if os.path.exists(font_path):
                    font_id = QFontDatabase.addApplicationFont(font_path)
                    if font_id != -1:
                        print(f"✓ Font loaded: {font_name}")
                    else:
                        print(f"✗ Error loading font: {font_name}")
                        
            font_db = QFontDatabase()
            available_fonts = font_db.families()
            cinzel_available = any("Cinzel" in font for font in available_fonts)
            
            if cinzel_available:
                print("✓ Cinzel Decorative available")
            else:
                print("⚠ Cinzel Decorative unavailable, using backup fonts")
                
        except Exception as e:
            print(f"✗ Error loading custom fonts: {e}")
            print("Using system fonts")

    def _setup_ui(self):        
        central = QWidget()
        central_layout = QHBoxLayout()
        central.setLayout(central_layout)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        # Sidebar (navigation)
        side = QWidget()
        side.setObjectName("sideBar")
        side_layout = QVBoxLayout()
        side_layout.setContentsMargins(12, 12, 12, 12)
        side_layout.setSpacing(8)
        side.setLayout(side_layout)
        side.setFixedWidth(220)

        # Logo section - Centered and larger
        logo_container = QWidget()
        logo_container.setObjectName("logoContainer")
        logo_layout = QVBoxLayout()  # Changed to vertical layout
        logo_layout.setContentsMargins(0, 0, 0, 0)
        logo_layout.setSpacing(12)  # Increased spacing
        logo_layout.setAlignment(Qt.AlignCenter)  # Center everything
        
        # Logo image - Larger size
        self.logo_label = QLabel()
        self.logo_label.setObjectName("logo")
        self.logo_label.setFixedSize(64, 64)  # Increased from 32x32 to 64x64
        self.logo_label.setScaledContents(True)
        self.logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(self.logo_label)
        
        # Logo text - Below the logo, bold
        label_logo = QLabel("Backstabber")
        label_logo.setObjectName("logoText")
        label_logo.setAlignment(Qt.AlignCenter)  # Center the text
        label_logo.setStyleSheet("""
            font-family: "Cinzel Decorative", "Cinzel", "Playfair Display", "Times New Roman", serif;
            font-weight: 900;
            font-size: 20px;
            padding: 8px;
            color: #f3e8ff;
            letter-spacing: 2px;
        """)
        logo_layout.addWidget(label_logo)
        
        logo_container.setLayout(logo_layout)
        side_layout.addWidget(logo_container)

        # Navigation buttons
        self.btn_scan = SideButton("Network Scanner", "btn_scan")
        self.btn_arp = SideButton("ARP Spoofing", "btn_arp")
        self.btn_capture = SideButton("Packet Capture", "btn_capture")

        side_layout.addWidget(self.btn_scan)
        side_layout.addWidget(self.btn_arp)
        side_layout.addWidget(self.btn_capture)
        side_layout.addStretch()

        # Top area + main stack
        main_area = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(10)
        main_area.setLayout(main_layout)

        # Top bar
        topbar = QFrame()
        topbar.setObjectName("topBar")
        top_layout = QHBoxLayout()
        top_layout.setContentsMargins(8, 4, 8, 4)
        topbar.setLayout(top_layout)
        self.title_label = QLabel("Backstabber Toolkit")
        self.title_label.setObjectName("mainTitle")
        self.title_label.setStyleSheet("""
            font-family: "Cinzel Decorative", "Cinzel", "Playfair Display", "Times New Roman", serif;
            font-weight: 700;
            font-size: 18px;
            color: #f3e8ff;
            letter-spacing: 1px;
        """)
        top_layout.addWidget(self.title_label)
        top_layout.addStretch()            
        # Stacked pages
        self.stack = QStackedWidget()
        # Instantiate actual tab widgets
        self.network_tab = NetworkScannerTab()
        self.arp_tab = ARPSpoofTab(self.network_tab)
        self.capture_tab = PacketCaptureTab()

        # Push tabs into stack
        self.stack.addWidget(self.network_tab)  # index 0
        self.stack.addWidget(self.arp_tab)      # index 1
        self.stack.addWidget(self.capture_tab)  # index 2

        # Put everything in main layout
        main_layout.addWidget(topbar)
        main_layout.addWidget(self.stack)

        # Assemble central layout
        central_layout.addWidget(side)
        central_layout.addWidget(main_area)

        # Set central widget
        self.setCentralWidget(central)

        # Status bar
        sb = QStatusBar()
        sb.showMessage("Ready")
        self.setStatusBar(sb)

        # Connect navigation windows
        self.btn_scan.clicked.connect(lambda: self.switch_tab(0))
        self.btn_arp.clicked.connect(lambda: self.switch_tab(1))
        self.btn_capture.clicked.connect(lambda: self.switch_tab(2))

        # Set default selected button
        self.btn_scan.setChecked(True)
        self.switch_tab(0)

    def switch_tab(self, index: int):
        # Uncheck all buttons
        for b in (self.btn_scan, self.btn_arp, self.btn_capture):
            b.setChecked(False)
        # Check the selected button
        if index == 0:
            self.btn_scan.setChecked(True)
            self.title_label.setText("Network Scanner")
        elif index == 1:
            self.btn_arp.setChecked(True)
            self.title_label.setText("ARP Spoofing")
        elif index == 2:
            self.btn_capture.setChecked(True)
            self.title_label.setText("Packet Capture")
        self.stack.setCurrentIndex(index)

    def apply_styles(self):
        # Attempt to load QSS theme file from package path
        try:
            import pkgutil, os
            qss_path = os.path.join(os.path.dirname(__file__), "theme.qss")
            if os.path.exists(qss_path):
                with open(qss_path, "r", encoding="utf-8") as fh:
                    self.setStyleSheet(fh.read())
        except Exception:
            pass

    def _setup_logo(self):
        """Setup application logo"""
        try:
            import os            
            logo_paths = [
                os.path.join(os.path.dirname(__file__), "..", "..", "assets", "logoBT.png"),
                os.path.join(os.path.dirname(__file__), "..", "assets", "logoBT.png"),
                os.path.join(os.path.dirname(__file__), "assets", "logoBT.png"),
                "assets/logoBT.png",
                "logoBT.png"
            ]
            
            logo_path = None
            for path in logo_paths:
                if os.path.exists(path):
                    logo_path = path
                    break
            
            if logo_path and os.path.exists(logo_path):                
                pixmap = QPixmap(logo_path)
                if not pixmap.isNull():
                    # Scale logo to 64x64 pixels
                    scaled_pixmap = pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.logo_label.setPixmap(scaled_pixmap)
                    # Set as window icon                    
                    icon = QIcon(pixmap)
                    self.setWindowIcon(icon)
                    
                    print(f"✓ Logo loaded successfully from: {logo_path}")
                else:
                    print("✗ Error: Corrupt logo file")
            else:
                print("✗ Logo not found. Searched in:")
                for path in logo_paths:
                    print(f"  - {path}")
                print("Using text instead")
                
        except Exception as e:
            print(f"✗ Error loading logo: {e}")
            print("Using text instead")