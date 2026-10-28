"""SOC Olay Yonetimi (Incident Management) Modulu.

Olay durumlari: 'Yeni', 'İnceleniyor', 'Kapatıldı'.
Olaylar 'incidents.json' dosyasinda kalici olarak saklanir.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

DEFAULT_INCIDENTS_PATH = Path(__file__).parent / "incidents.json"

VALID_STATUSES = ["Yeni", "İnceleniyor", "Kapatıldı"]
VALID_SEVERITIES = ["KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"]


class IncidentManager:
    """SOC vaka ve olay takip yoneticisi."""

    def __init__(self, storage_path: Path | str | None = None) -> None:
        self.storage_path = Path(storage_path) if storage_path else DEFAULT_INCIDENTS_PATH
        self.incidents: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not self.storage_path.exists():
            self._save([])
            return []
        try:
            content = self.storage_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if isinstance(data, list):
                return data
            return []
        except Exception:
            return []

    def _save(self, data: list[dict[str, Any]]) -> None:
        try:
            self.storage_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as err:
            print(f"Olaylar kaydedilemedi: {err}")

    def save(self) -> None:
        self._save(self.incidents)

    def list_incidents(self, status_filter: str | None = None) -> list[dict[str, Any]]:
        if not status_filter or status_filter == "Tümü":
            return list(reversed(self.incidents))
        return [inc for inc in reversed(self.incidents) if inc.get("status") == status_filter]

    def create_incident(
        self,
        title: str,
        ip: str = "-",
        server: str = "-",
        username: str = "-",
        severity: str = "YÜKSEK",
        status: str = "Yeni",
        description: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        inc_id = f"INC-{len(self.incidents) + 1001}"
        
        # Check if identical open incident already exists for same IP and title
        for inc in self.incidents:
            if inc.get("ip") == ip and inc.get("title") == title and inc.get("status") != "Kapatıldı":
                if notes:
                    inc["notes"].append({"time": now_str, "text": notes})
                    inc["updated_at"] = now_str
                    self.save()
                return inc

        new_incident: dict[str, Any] = {
            "id": inc_id,
            "title": title,
            "ip": ip,
            "server": server,
            "username": username,
            "severity": severity if severity in VALID_SEVERITIES else "YÜKSEK",
            "status": status if status in VALID_STATUSES else "Yeni",
            "description": description,
            "notes": [{"time": now_str, "text": notes}] if notes else [],
            "created_at": now_str,
            "updated_at": now_str,
        }
        self.incidents.append(new_incident)
        self.save()
        return new_incident

    def update_status(self, incident_id: str, new_status: str, note: str = "") -> bool:
        if new_status not in VALID_STATUSES:
            return False
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for inc in self.incidents:
            if inc["id"] == incident_id:
                inc["status"] = new_status
                inc["updated_at"] = now_str
                if note:
                    inc["notes"].append({
                        "time": now_str,
                        "text": f"[Durum degisikligi: {new_status}] {note}"
                    })
                self.save()
                return True
        return False

    def add_note(self, incident_id: str, note_text: str) -> bool:
        if not note_text.strip():
            return False
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for inc in self.incidents:
            if inc["id"] == incident_id:
                inc["notes"].append({"time": now_str, "text": note_text.strip()})
                inc["updated_at"] = now_str
                self.save()
                return True
        return False

    def delete_incident(self, incident_id: str) -> bool:
        before = len(self.incidents)
        self.incidents = [inc for inc in self.incidents if inc["id"] != incident_id]
        if len(self.incidents) != before:
            self.save()
            return True
        return False
