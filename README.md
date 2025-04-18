# Astral-Sniffer

Astral-Sniffer es una herramienta avanzada para capturar y analizar tráfico de red. Es ideal para administradores de redes, desarrolladores y entusiastas de la ciberseguridad que buscan monitorear y depurar el tráfico de red de manera eficiente.

## 📜 Características

- **Filtros avanzados**: Captura tráfico HTTP, DNS, TLS (HTTPS), FTP e IPv6.
- **Exportación de estadísticas**: Guarda reportes en formatos CSV o JSON.
- **Guardado automático**: Almacena capturas en formato PCAP, listo para análisis en herramientas como Wireshark.
- **Interfaz amigable**: Fácil de usar a través de la línea de comandos.
- **Estadísticas en tiempo real**: Proporciona un resumen de protocolos capturados.

---

## ⚙️ Requisitos

- Python 3.7 o superior
- Permisos de administrador (`sudo`)
- Dependencias del proyecto (ver instrucciones de instalación)

---

## 🚀 Instalación

Seguí estos pasos para instalar y configurar **Astral-Sniffer**:

1. Clona este repositorio:
   ```bash
   git clone https://github.com/44Viciius/astral-sniffer.git
   cd astral-sniffer
   ```

2. Instala las dependencias necesarias:
   ```bash
   python3 -m pip install -r requirements.txt
   ```

3. ¡Listo! Ahora podés usar la herramienta.

---

## 📖 Uso

### Mostrar ayuda
```bash
python3 astral.py -h
```

### Ejemplos de uso

1. **Capturar tráfico de red básico**:
   ```bash
   sudo python3 astral.py --interface en0 --count 50
   ```

2. **Filtrar tráfico HTTP**:
   ```bash
   sudo python3 astral.py --interface en0 --count 50 --filter http
   ```

3. **Exportar estadísticas a CSV**:
   ```bash
   sudo python3 astral.py --interface en0 --count 100 --export-csv stats.csv
   ```

4. **Capturar tráfico y guardar automáticamente en PCAP**:
   ```bash
   sudo python3 astral.py --interface en0 --count 100 --save-interval 30 --auto-save-path ./pcap_files
   ```

Para más ejemplos, consulta la [documentación completa](#).

---

## 🛠️ Tecnologías utilizadas

- **[Scapy](https://scapy.net/)**
- **[Colorama](https://pypi.org/project/colorama/)**

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si deseas colaborar, sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una rama nueva:
   ```bash
   git checkout -b mi-nueva-funcionalidad
   ```
3. Realiza tus cambios y haz un commit:
   ```bash
   git commit -m "Añadí una nueva funcionalidad"
   ```
4. Subí tus cambios:
   ```bash
   git push origin mi-nueva-funcionalidad
   ```
5. Crea un Pull Request en este repositorio.

---

## 📜 Licencia

Este proyecto está licenciado bajo la [MIT License](LICENSE).

---

## 📧 Contacto

Si tenes preguntas o sugerencias, no dudes en contactarme!

- **Autor**: 44Viciius
