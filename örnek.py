"""SOC Tehdit Avi ve Log Analizi Komut Satiri ve Kutuphane Arayuzu.

soc_engine.py motorunu kullanarak tam geriye donuk uyumluluk saglar.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from allowlist import AllowlistManager
from soc_engine import run_hunting_many as core_run_hunting_many


def run_hunting_many(
    log_files: list[Path],
    output_file: Path | None = None,
    exfiltration_bytes: int = 500_000_000,
    failed_attempts: int = 50,
    allowlist_mgr: AllowlistManager | None = None,
    source_names: list[str] | None = None,
) -> dict[str, Any]:
    """Coklu log dosyalarini birlestirerek analiz eder."""
    return core_run_hunting_many(
        log_files=log_files,
        output_file=output_file,
        exfiltration_bytes=exfiltration_bytes,
        failed_attempts=failed_attempts,
        allowlist_mgr=allowlist_mgr,
        source_names=source_names,
    )


def run_hunting(
    log_file: Path,
    output_file: Path | None = None,
    exfiltration_bytes: int = 500_000_000,
    failed_attempts: int = 50,
    allowlist_mgr: AllowlistManager | None = None,
) -> dict[str, Any]:
    """Tek bir log dosyasini analiz eder (geriye donuk uyumluluk)."""
    return run_hunting_many(
        log_files=[log_file],
        output_file=output_file,
        exfiltration_bytes=exfiltration_bytes,
        failed_attempts=failed_attempts,
        allowlist_mgr=allowlist_mgr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC log tehdit avi ve SIEM analizi")
    parser.add_argument("log_files", type=Path, nargs="+", help="Analiz edilecek log dosyalari (W3C, CSV, JSON)")
    parser.add_argument("-o", "--output", type=Path, default=Path("threat_hunting_report.json"), help="Cikti JSON dosyasi")
    parser.add_argument("--exfiltration-bytes", type=int, default=500_000_000, help="Veri sizdirma esigi (varsayilan: 500 MB)")
    parser.add_argument("--failed-attempts", type=int, default=50, help="Basarisiz deneme esigi")
    args = parser.parse_args()

    for path in args.log_files:
        if not path.is_file():
            parser.error(f"Dosya bulunamadi: {path}")

    report = run_hunting_many(
        log_files=args.log_files,
        output_file=args.output,
        exfiltration_bytes=args.exfiltration_bytes,
        failed_attempts=args.failed_attempts,
    )
    print(f"\nRapor basariyla olusturuldu: {args.output}")
    summary = report.get("summary", {})
    print(f"Toplam Olay: {summary.get('toplam_olay', 0):,}")
    print(f"Farkli IP: {summary.get('farkli_ip_sayisi', 0)}")
    print(f"Sunucu Hatasi (5xx): {summary.get('server_error_sayisi', 0)}")
    print(f"Webshell Bulgusu: {len(report.get('webshell_and_file_management', []))}")
    print(f"Gunler Arasi Aktör: {len(report.get('cross_day_correlation', []))}")


if __name__ == "__main__":
    main()
