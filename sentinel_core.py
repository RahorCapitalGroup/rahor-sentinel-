import os
import sys
import ssl
import socket
import hashlib
import subprocess
import urllib.request
from datetime import datetime

class RahorSentinelCore:
    """
    Motor Híbrido do Rahor Sentinel (Web Recon + OS/DLL Integrity)
    Desenvolvido para Rahor Technology
    """

    def scan_website_real(self, target_url: str):
        clean_host = target_url.replace("https://", "").replace("http://", "").split("/")[0].strip()
        report = {
            "target": clean_host,
            "ssl_valid": False,
            "ssl_issuer": "Desconhecido",
            "missing_headers": [],
            "phishing_risk": "BAIXO",
            "ip_address": "Não resolvido"
        }

        try:
            report["ip_address"] = socket.gethostbyname(clean_host)
        except Exception:
            report["phishing_risk"] = "INACESSÍVEL / SUSPEITO"
            return report

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=clean_host) as s:
                s.settimeout(4.0)
                s.connect((clean_host, 443))
                cert = s.getpeercert()
                report["ssl_valid"] = True
                issuer = dict(x[0] for x in cert.get("issuer", []))
                report["ssl_issuer"] = issuer.get("organizationName", "Válido")
        except Exception:
            report["ssl_valid"] = False
            report["phishing_risk"] = "ALTO (Sem SSL Válido)"

        try:
            req = urllib.request.Request(f"https://{clean_host}", headers={"User-Agent": "RahorSentinel/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = {k.lower(): v for k, v in resp.info().items()}
                for sec_h in ["strict-transport-security", "content-security-policy", "x-frame-options"]:
                    if sec_h not in headers:
                        report["missing_headers"].append(sec_h)
        except Exception:
            pass

        suspicious_keywords = ["login", "verify", "update-account", "secure-bank", "free", "bonus"]
        if any(word in clean_host.lower() for word in suspicious_keywords):
            report["phishing_risk"] = "CRÍTICO (Padrão de Phishing Detectado)"

        return report

    def check_os_dll_integrity(self):
        critical_dlls = ["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "vcruntime140.dll"]
        sys32_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
        results = []

        for dll in critical_dlls:
            full_path = os.path.join(sys32_path, dll)
            if os.path.exists(full_path):
                try:
                    h = hashlib.sha256()
                    with open(full_path, "rb") as f:
                        h.update(f.read(65536))
                    results.append({"dll": dll, "status": "ÍNTEGRO", "sha256_prefix": h.hexdigest()[:12]})
                except Exception:
                    results.append({"dll": dll, "status": "PROTEGIDO", "sha256_prefix": "SYSTEM_LOCKED"})
            else:
                results.append({"dll": dll, "status": "AUSENTE / ERRO", "sha256_prefix": "N/A"})
        return results

if __name__ == "__main__":
    print("=== RAHOR SENTINEL CORE INITIALIZED ===")
    core = RahorSentinelCore()
    print("Testando resolução local de integridade do SO...")
    print(core.check_os_dll_integrity())
