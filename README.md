# RedEye Toolkit

&#x20;

**RedEye Toolkit** es una solución modular de pentesting de redes, desarrollada en Python con interfaz gráfica en PyQt5. Su arquitectura permite expandir funcionalidades de forma sencilla, integrando ahora capacidades de captura y análisis de paquetes (ARP Poisoning).

---

## 🔍 Características Principales

- **Escaneo de Redes**: Descubrimiento de hosts y puertos abiertos.
- **ARP Spoofing**: Ejecución automática de envenenamiento ARP para interceptar tráfico.
- **Interfaz Intuitiva**: GUI basada en PyQt5 para una experiencia de usuario fluida.
- **Extensible**: Arquitectura modular que facilita la adición de nuevos módulos.

---

## 🛠 Instalación

```bash
git clone https://github.com/IngEsau/RedEye-Toolkit.git
cd RedEye-Toolkit
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

---

## 🚀 Uso

1. Ejecuta la aplicación:

   ```bash
   python src/main.py
   ```

2. En la ventana principal encontrarás pestañas para:

   - **Network Scan**: Configura rango de IP y puertos.
   - **ARP Poison**: Define IP víctima y gateway.
   - **Packet Capture**: Inicia captura en tiempo real.

3. Para detener operaciones, utiliza los botones "Stop" correspondientes.

---


## 🤝 Contribuciones

Se agradecen sugerencias y mejoras. Para colaborar:

1. Haz un fork de este repositorio.
2. Crea una rama con tu característica: `git checkout -b feature/X`.
3. Realiza tus cambios y haz un commit claro.
4. Envía un pull request describiendo la nueva funcionalidad.

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

*Desarrollado por Esaú Aguilar — RedEye Toolkit © 2025*

