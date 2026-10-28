"""SOC Threat Intelligence & Heuristic Enrichment Modulu.

IP adres turu analizi (Private/Public/Loopback), tarayici araclari ve tehdit gostergelerini degerlendirir.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

KNOWN_ATTACK_TOOLS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "acunetix",
    "dirbuster",
    "gobuster",
    "hydra",
    "wfuzz",
    "zgrab",
    "shodan",
    "censys",
    "burpcollaborator",
    "metasploit",
    "nuclei",
]

SENSITIVE_PATHS = [
    "/filemanagement",
    "web.config",
    "appsettings",
    "/.env",
    "/admin",
    "/swagger",
    "/actuator",
    "/backup",
    "/debug",
    "c:\\inetpub",
    "cmd.exe",
    "powershell",
    "/etc/passwd",
    "../",
    "..\\",
]


def classify_ip(ip_str: str | None) -> dict[str, Any]:
    """IP adresinin turunu belirler (Ozel, Kamusal, Loopback, Bogon)."""
    if not ip_str or ip_str in ("-", "", "null"):
        return {
            "ip": ip_str or "-",
            "kategori": "Bilinmiyor",
            "is_private": False,
            "is_public": False,
            "is_loopback": False,
            "risk_faktoru": 0,
            "aciklama": "Gecersiz veya bos IP",
        }

    clean_ip = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_loopback:
            return {
                "ip": clean_ip,
                "kategori": "Loopback (Yerel)",
                "is_private": True,
                "is_public": False,
                "is_loopback": True,
                "risk_faktoru": 0,
                "aciklama": "Sunucu ici geridonus (127.0.0.1 / ::1)",
            }
        if addr.is_private:
            return {
                "ip": clean_ip,
                "kategori": "Ozel / Dahili Ag (RFC 1918)",
                "is_private": True,
                "is_public": False,
                "is_loopback": False,
                "risk_faktoru": 10,
                "aciklama": "Kurumsal ic ag veya VPN IP adresi",
            }
        if addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return {
                "ip": clean_ip,
                "kategori": "Ayrilmis / Link-Local",
                "is_private": True,
                "is_public": False,
                "is_loopback": False,
                "risk_faktoru": 5,
                "aciklama": "Ayrilmis veya multicast ag trafigi",
            }
        # Public IP
        return {
            "ip": clean_ip,
            "kategori": "Kamusal Ag (Public Internet)",
            "is_private": False,
            "is_public": True,
            "is_loopback": False,
            "risk_faktoru": 30,
            "aciklama": "Dis dunya / internet uzerinden gelen erisim",
        }
    except ValueError:
        return {
            "ip": clean_ip,
            "kategori": "Gecersiz Format",
            "is_private": False,
            "is_public": False,
            "is_loopback": False,
            "risk_faktoru": 15,
            "aciklama": "Standart IPv4/IPv6 formati disinda veri",
        }


def detect_tool_signatures(user_agent: str | None) -> list[str]:
    """User Agent icindeki bilinen saldiri/tarama araclarini yakalar."""
    if not user_agent or user_agent in ("-", "", "null"):
        return []
    ua_lower = user_agent.lower()
    matches = []
    for tool in KNOWN_ATTACK_TOOLS:
        if tool in ua_lower:
            matches.append(tool)
    return matches


def evaluate_endpoint_risk(path: str | None) -> list[str]:
    """Istek yolundaki hassas veya webshell izlerini tespit eder."""
    if not path or path in ("-", "", "null"):
        return []
    path_lower = path.lower()
    flags = []
    for sp in SENSITIVE_PATHS:
        if sp in path_lower:
            flags.append(f"Hassas Yol: {sp}")
    if re.search(r"\.(asp|aspx|php|jsp)(\?|$)", path_lower):
        flags.append("Dinamik Script Calistirma (.asp/.aspx/.php/.jsp)")
    if "c:\\inetpub" in path_lower or "wwwroot" in path_lower:
        flags.append("IIS Web Kok Dizini Taramasi (inetpub/wwwroot)")
    if "web.config" in path_lower or "appsettings" in path_lower:
        flags.append("Kritik Konfigurasyon Dosyasi Hedeflendi")
    return flags
