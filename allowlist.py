"""SOC Allowlist Yonetim Modulu.

Guvenilen IP'ler, CIDR bloklari, sunucular ve servis hesaplarini saklar ve kontrol eder.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

DEFAULT_ALLOWLIST_PATH = Path(__file__).parent / "allowlist.json"

DEFAULT_ALLOWLIST_DATA: dict[str, list[str]] = {
    "ips": [
        "127.0.0.1",
        "::1",
    ],
    "cidrs": [
        "127.0.0.0/8",
    ],
    "service_accounts": [
        "NT AUTHORITY\\SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
    ],
    "trusted_servers": [],
}


class AllowlistManager:
    """Guvenilen varliklari yukler, kaydeder ve kontrol eder."""

    def __init__(self, storage_path: Path | str | None = None) -> None:
        self.storage_path = Path(storage_path) if storage_path else DEFAULT_ALLOWLIST_PATH
        self.data: dict[str, list[str]] = self._load()

    def _load(self) -> dict[str, list[str]]:
        if not self.storage_path.exists():
            self._save_data(DEFAULT_ALLOWLIST_DATA)
            return dict(DEFAULT_ALLOWLIST_DATA)
        try:
            content = self.storage_path.read_text(encoding="utf-8")
            loaded = json.loads(content)
            merged = dict(DEFAULT_ALLOWLIST_DATA)
            for key in ("ips", "cidrs", "service_accounts", "trusted_servers"):
                if key in loaded and isinstance(loaded[key], list):
                    merged[key] = [str(x).strip() for x in loaded[key] if str(x).strip()]
            return merged
        except Exception:
            return dict(DEFAULT_ALLOWLIST_DATA)

    def _save_data(self, data: dict[str, list[str]]) -> None:
        try:
            self.storage_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as err:
            print(f"Allowlist kaydedilemedi: {err}")

    def save(self) -> None:
        self._save_data(self.data)

    def is_ip_allowed(self, ip_str: str | None) -> bool:
        if not ip_str or ip_str in ("-", "", "null"):
            return False
        ip_clean = ip_str.strip()
        if ip_clean in self.data["ips"]:
            return True
        try:
            addr = ipaddress.ip_address(ip_clean)
            for cidr in self.data["cidrs"]:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            return False
        return False

    def is_account_allowed(self, account_str: str | None) -> bool:
        if not account_str or account_str in ("-", "", "null"):
            return False
        acc = account_str.strip().lower()
        return any(acc == trusted.lower() for trusted in self.data["service_accounts"])

    def is_server_allowed(self, server_str: str | None) -> bool:
        if not server_str or server_str in ("-", "", "null"):
            return False
        srv = server_str.strip().lower()
        return any(srv == trusted.lower() for trusted in self.data["trusted_servers"])

    def is_entity_allowed(self, ip: str | None = None, username: str | None = None, server: str | None = None) -> bool:
        """Herhangi bir eslesmede True doner."""
        if ip and self.is_ip_allowed(ip):
            return True
        if username and self.is_account_allowed(username):
            return True
        if server and self.is_server_allowed(server):
            return True
        return False

    def add_entry(self, category: str, value: str) -> bool:
        category = category.strip().lower()
        value = value.strip()
        if not value:
            return False
        if category not in self.data:
            return False
        if value not in self.data[category]:
            self.data[category].append(value)
            self.save()
            return True
        return False

    def remove_entry(self, category: str, value: str) -> bool:
        category = category.strip().lower()
        value = value.strip()
        if category in self.data and value in self.data[category]:
            self.data[category].remove(value)
            self.save()
            return True
        return False
