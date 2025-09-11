# Backstabber Toolkit

<img src="assets/logoBT.png" alt="BTTK Logo" width="200">

**Backstabber Toolkit** is a professional, modular network pentesting toolkit written in Python with a PyQt5 graphical interface.  
It is designed for maintainability and extensibility: core functionality (scanning, ARP spoofing, packet capture) is implemented as reusable modules and a central controller so you can safely evolve the project toward more complex workflows.

This repository is intended for authorized security testing, research, and learning in controlled environments only. Use it responsibly and legally.

---

## Key benefits

- Single, consistent control plane for ARP MITM (`ARPManager`) to avoid conflicting spoof sessions.
- Clear separation of concerns in the GUI: `Network Scanner`, `ARP Spoofing`, and `Packet Capture` tabs.
- Modular architecture so you can plug new scanners, capture backends or UI features without large refactors.
- Practical UX safeguards: verification of ARP spoofing, emergency restore helper, and safe stop/restore flows to reduce risk of leaving networks poisoned.

---

## Features

- **Network Scanner**
  - Host discovery (ARP & ICMP).
  - Asynchronous TCP port scan (SYN-style using Scapy).
  - Results exported for later use (logs, simple files to feed other tools).

- **ARP Spoofing (MITM)**
  - Centralized `ARPManager` that wraps `ARPSpoofThread`.
  - Start / stop / verify spoof sessions with retries and sniff-based verification.
  - Emergency restore (gratuitous ARP) helper.

- **Packet Capture**
  - Live capture UI with filters & presets.
  - Optional MITM workflow: starts capture after spoof is verified, or re-uses existing spoof session.
  - Save to PCAP (requires `tshark`).

- **Modular & Extensible**
  - Clean `core/`, `gui/`, `utils/` separation.
  - Adapter pattern for scanner/capture backends so you can swap implementations later (e.g., move from `python3-nmap` to subprocess `nmap` if desired).

---

## Requirements

Recommended Python versions: **Python 3.11 — 3.12** (tested). Some dependencies may work on other 3.x versions.

Example `requirements.txt`:

```bash

markdown-it-py>=3.0.0,<4.0.0
mdurl>=0.1.2,<1.0.0
netifaces>=0.11.0,<1.0.0
Pygments>=2.19.1,<3.0.0
PyQt5>=5.15.9,<6.0.0
python3-nmap>=1.0.0,<2.0.0 # provides nmap3-compatible API (optional)
rich>=14.0.0,<15.0.0
scapy>=2.4.5,<3.0.0
pyshark>=0.4.2 # if you use pyshark-based capture backend

```
---

## Notes:

- `python3-nmap` / `nmap3` is optional: the scanner currently uses Scapy for host discovery and a pluggable adapter to call nmap.  
- For packet capture with PyShark, **`tshark`** (Wireshark CLI) must be installed on the host system.  
- ARP spoofing and raw packet capture require **administrator/root privileges**.  
- On servers or headless setups ensure GUI dependencies are met.

---

## Installation

```bash
git clone https://github.com/IngEsau/Backstabber.git
cd Backstabber

python3 -m venv venv
source venv/bin/activate    # For Linux/macOS
venv\Scripts\activate       # For Windows

pip install -r requirements.txt
```

---

## Usage

Launch the application:

   ```bash
   python src/main.py
   ```

## Main tabs:

Network Scanner — enter IP range and ports then Start Scan.

ARP Spoofing — choose victim and gateway, then Start ARP Spoof.

Packet Capture — select interface and filter. Optionally enable Start ARP Poison (MITM); capture begins after spoof verification.

---

## Contributing

Contributions are welcome. To propose changes or new features:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/YourFeature`.
3. Make your changes and commit with clear messages.
4. Submit a pull request describing the changes.

---

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

**Developed by Esaú Aguilar — Backstabber Toolkit © 2025**

