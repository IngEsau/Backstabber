# RedEye Toolkit

**v1.0** — Herramienta modular de pentesting de redes (Escaneo + ARP Spoof) con GUI en Python + PyQt5.


```bash
src/
  core/        # lógica de escaneo y spoof
  gui/         # clases PyQt5
  utils/       # utilerías comunes
  __main__.py  # entry-point, para poder hacer `python -m redeye_toolkit`


## Instalación

```bash
git clone https://github.com/IngEsau/RedEye-Toolkit.git
cd RedEye-Toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
