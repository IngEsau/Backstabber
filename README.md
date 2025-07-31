<<<<<<< IMTEM

=======
# Backstabber Toolkit

**Backstabber Toolkit** is a modular network pentesting solution developed in Python, featuring a graphical user interface built with PyQt5. Its architecture is designed for scalability, allowing for easy integration of additional modules. It currently includes network scanning capabilities and ARP packet interception through spoofing.

---

## Key Features

- **Network Scanning**: Host discovery and open port detection.
- **ARP Spoofing**: Automated ARP poisoning to intercept and analyze traffic.
- **User Interface**: A clean and responsive GUI powered by PyQt5.
- **Modular Design**: Easily extendable architecture for future modules.

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

1. Launch the application:

   ```bash
   python src/main.py
   ```

2. The main interface includes the following sections:

   - **Network Scan**: Configure the IP range and port scanning parameters.
   - **ARP Poisoning**: Specify the target (victim) and gateway IP addresses.

3. Use the corresponding "Stop" buttons to safely terminate ongoing operations.

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

**Developed by Esaú Aguilar — RedEye Toolkit © 2025**
>>>>>>> main
