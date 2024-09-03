import re
import ssl
import warnings
from urllib.parse import urlparse
import socket
import requests
import tldextract

# Suprimir avisos de ResourceWarning e DeprecationWarning
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

def check_https(url):
    """Verifica se a URL utiliza HTTPS."""
    parsed_url = urlparse(url)
    return parsed_url.scheme == "https"

def check_ssl_certificate(url, timeout=5):
    """Verifica se o certificado SSL da URL é válido, com timeout definido."""
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
        return True  # Certificado é válido
    except ssl.SSLError as e:
        print(f"Erro SSL ao verificar certificado: {e}")
    except socket.gaierror as e:
        print(f"Erro ao resolver o hostname: {e}")
    except socket.timeout:
        print(f"Erro: Tempo limite de conexão esgotado para {url}")
    except Exception as e:
        print(f"Erro ao verificar certificado SSL: {e}")
    return False

def check_phishing_patterns(url):
    """Verifica se a URL contém padrões comuns de phishing."""
    phishing_keywords = ["login", "secure", "account", "update", "signin", "banking"]
    extracted = tldextract.extract(url)
    domain = extracted.domain
    for keyword in phishing_keywords:
        if keyword in domain:
            return True
    return False

def is_url_safe(url):
    """Verifica se a URL é segura."""
    if not check_https(url):
        print("URL não é HTTPS")
        return False
    if not check_ssl_certificate(url):
        print("Certificado SSL não é válido ou não pode ser verificado")
        return False
    if check_phishing_patterns(url):
        print("Padrões de phishing detectados na URL")
        return False
    print("URL é segura")
    return True
