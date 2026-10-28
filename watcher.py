"""Canli Klasor Izleme (Live Directory Watcher) Modulu.

Belirtilen dizini watchdog ile izler, yeni veya degisen log dosyalarini aninda algilar.
"""

from __future__ import annotations

from collections import deque
import datetime
from pathlib import Path
import threading
from typing import Any, Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

SUPPORTED_EXTENSIONS = {".log", ".csv", ".json", ".jsonl", ".ndjson", ".parquet"}


class LogFileHandler(FileSystemEventHandler):
    """Yeni olusturulan veya degistirilen dosyalari yakalar."""

    def __init__(self, callback: Callable[[Path, str], None]) -> None:
        super().__init__()
        self.callback = callback

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            path = Path(event.src_path)
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                self.callback(path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            path = Path(event.src_path)
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                self.callback(path, "modified")


class DirectoryWatcher:
    """Arka planda klasor izleme servisi."""

    def __init__(self, watch_dir: Path | str, on_new_log: Callable[[Path, str], None] | None = None) -> None:
        self.watch_dir = Path(watch_dir)
        self.on_new_log = on_new_log
        self.observer: Observer | None = None
        self.is_running = False
        self.events_log: deque[dict[str, Any]] = deque(maxlen=50)
        self._lock = threading.Lock()

    def _handle_event(self, path: Path, event_type: str) -> None:
        with self._lock:
            event_entry = {
                "dosya": path.name,
                "yol": str(path),
                "olay": event_type,
                "zaman": datetime.datetime.now().strftime("%H:%M:%S"),
            }
            # Avoid duplicate triggers in quick succession for the same file
            if not self.events_log or self.events_log[0].get("dosya") != path.name or self.events_log[0].get("olay") != event_type:
                self.events_log.appendleft(event_entry)
        if self.on_new_log:
            try:
                self.on_new_log(path, event_type)
            except Exception as err:
                print(f"Watcher callback hatasi: {err}")

    def start(self) -> bool:
        if self.is_running:
            return True
        if not self.watch_dir.exists() or not self.watch_dir.is_dir():
            return False
        try:
            self.observer = Observer()
            handler = LogFileHandler(self._handle_event)
            self.observer.schedule(handler, str(self.watch_dir), recursive=False)
            self.observer.start()
            self.is_running = True
            return True
        except Exception as err:
            print(f"Watcher baslatilamadi: {err}")
            self.is_running = False
            return False

    def stop(self) -> None:
        if self.observer and self.is_running:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.is_running = False
            self.observer = None

    def get_recent_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.events_log)
