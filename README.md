# WaxSS 🧪💥 - Pruebas de XSS

**WaxSS** es un script en Python diseñado para detectar y probar vulnerabilidades de Cross-Site Scripting (XSS) en formularios web. El script identifica formularios en un sitio objetivo, prueba varias cargas útiles de XSS, y maneja la presencia de WAFs (Web Application Firewalls). 🚀

## Requisitos 🛠️

- Python 3 🐍
- Las siguientes bibliotecas de Python:
  - `requests` 🌐
  - `requests-html` 🖥️
  - `beautifulsoup4` 🍲
  - `colorama` 🎨
  - `subprocess` (parte de la librería estándar)

Puedes instalar las dependencias con el siguiente comando:

```bash
pip install requests requests-html beautifulsoup4 colorama
```

- **wafw00f** 🦸‍♀️: Esta herramienta es utilizada para detectar la presencia de WAFs. Para instalarla, usa:

```bash
apt install wafw00f
```

## Características ✨

- **Detección de WAF** 🔒: El script utiliza `wafw00f` para identificar si un WAF está presente en el sitio objetivo.
- **Extracción de formularios** 📋: Extrae los formularios de un sitio web, incluso los generados por JavaScript e iframes.
- **Pruebas de XSS** 💣: Realiza pruebas básicas y avanzadas de XSS en los formularios encontrados.
- **Soporte para bypass de WAFs** 🛡️: El script tiene payloads específicos para algunos WAFs conocidos.

## Uso 🚀

1. **Clona el repositorio**:

```bash
git clone https://github.com/theoffsecgirl/waxss.git
cd waxss
```

2. **Ejecuta el script**:

```
python3 waxss.py
```

3. **Ingresa la URL objetivo**:

Cuando se te pida, ingresa la URL del sitio web que deseas probar.

4. **Revisa los resultados**: El script mostrará los formularios encontrados y las pruebas realizadas. Si se encuentra un XSS, se mostrará un mensaje de éxito. 💥
