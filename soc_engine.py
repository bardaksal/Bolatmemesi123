"""SOC Log Lens - Yuksek Performansli Tehdit Avi ve Korelasyon Motoru (DuckDB).

0 Hata Prensibi:
- IIS W3C HTTP & FTP loglari, CSV, JSON, JSONL ve Parquet formatlarini guvenli bicimde normalize eder.
- Coklu dosya / coklu gun birlestirme (Unified Multi-Day Analysis).
- Gunler arasi saldiri iliskilendirme (Cross-Day Attack Correlation).
- Gelismis bot, webshell, veri sizdirma, password spraying ve FTP operasyon tespiti.
- Allowlist ve Threat Intelligence entegrasyonu.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import duckdb

from allowlist import AllowlistManager
from threat_intel import classify_ip, detect_tool_signatures, evaluate_endpoint_risk

FIELD_ALIASES = {
    "tarih": ["tarih", "date", "timestamp", "time"],
    "ip_adresi": ["ip_adresi", "ip", "client_ip", "source_ip", "src_ip", "c_ip", "c-ip"],
    "hedef_ip": ["hedef_ip", "s_ip", "s-ip", "destination_ip", "dst_ip", "server_ip", "dest_ip"],
    "hedef_port": ["hedef_port", "s_port", "s-port", "destination_port", "dst_port", "server_port", "port"],
    "kaynak_port": ["kaynak_port", "c_port", "c-port", "source_port", "src_port", "client_port"],
    "sunucu_ismi": ["sunucu_ismi", "server_name", "server", "host", "hostname", "s_computername", "s-computername", "s_sitename", "s-sitename"],
    "islem_komutu": ["islem_komutu", "command", "request", "url", "endpoint", "path", "cs_uri_stem", "cs-uri-stem", "cs_method", "cs-method"],
    "http_method": ["http_method", "method", "cs_method", "cs-method"],
    "user_agent": ["user_agent", "useragent", "http_user_agent", "cs_user_agent", "cs-user-agent"],
    "byte_degeri": ["byte_degeri", "bytes", "byte", "response_bytes", "bytes_sent", "sc_bytes", "sc-bytes"],
    "istemci_byte": ["istemci_byte", "request_bytes", "cs_bytes", "cs-bytes"],
    "status_code": ["status_code", "status", "http_status", "statuscode", "sc_status", "sc-status"],
    "kullanici_adi": ["kullanici_adi", "username", "user", "user_name", "account", "cs_username", "cs-username"],
    "referer": ["referer", "referrer", "cs_referer", "cs-referer"],
    "response_time_ms": ["response_time_ms", "time_taken", "time-taken", "duration"],
    "session_cookie": ["session_cookie", "cookie", "cs_cookie", "cs-cookie", "x_session", "x-session"],
}


def sql_identifier(value: str) -> str:
    """Kolon adi olarak guvenli SQL tanimlayicisi dondurur."""
    return '"' + value.replace('"', '""') + '"'


def sanitize_column_name(col: str) -> str:
    """W3C tireli isimleri guvenli alt cizgiye cevirir."""
    return col.strip().replace("-", "_").lower()


def log_fields(log_file: Path) -> list[str] | None:
    """W3C log dosyasindaki #Fields satirini okur ve kolon isimlerini dondurur."""
    if log_file.suffix.lower() != ".log":
        return None
    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as stream:
            for _ in range(50):
                line = stream.readline()
                if not line:
                    break
                if line.startswith("#Fields:"):
                    raw_fields = line.removeprefix("#Fields:").strip().split()
                    return [sanitize_column_name(f) for f in raw_fields]
    except Exception:
        pass
    return None


def detect_log_format(log_file: Path) -> str:
    """Log dosyasinin W3C, Checkpoint Firewall veya generic CSV/JSON olup olmadigini sezer."""
    suffix = log_file.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".parquet":
        return "parquet"

    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as stream:
            first_lines = [stream.readline().strip() for _ in range(15)]

        for line in first_lines:
            if line.startswith("#Fields:"):
                return "w3c_iis"

        for line in first_lines:
            if not line or line.startswith("#"):
                continue
            if ("Checkpoint" in line or "Firewall" in line) and "," in line:
                return "checkpoint_firewall"
            if "," in line and any(act in line for act in ["Deny", "Accept", "Drop", "Reject", "Allow"]):
                parts = line.split(",")
                if len(parts) >= 8:
                    return "checkpoint_firewall"
    except Exception:
        pass

    if suffix == ".csv":
        return "csv"
    if suffix == ".log":
        return "w3c_iis"
    return "csv"


def source_expression(log_file: Path, format_type: str | None = None, fields: list[str] | None = None) -> str:
    """Dosya turune gore optimize DuckDB kaynak ifadesini dondurur."""
    suffix = log_file.suffix.lower()
    path = str(log_file.resolve()).replace("'", "''")
    fmt = format_type or detect_log_format(log_file)

    if fmt == "json":
        return f"read_json_auto('{path}', ignore_errors=true)"
    if fmt == "jsonl":
        return f"read_json_auto('{path}', format='newline_delimited', ignore_errors=true)"
    if fmt == "checkpoint_firewall":
        cols = [
            "firewall_event", "sunucu_ismi", "rule_id", "tarih_raw", "firewall_action",
            "ip_adresi", "kaynak_port", "hedef_ip", "hedef_port", "user_agent", "byte_degeri"
        ]
        columns = ", ".join(f"'{c}'" for c in cols)
        return f"read_csv('{path}', header=false, delim=',', quote='\"', names=[{columns}], all_varchar=true, ignore_errors=true)"
    if fmt == "csv":
        return f"read_csv_auto('{path}', header=true, ignore_errors=true)"
    if fmt == "w3c_iis":
        names = fields or [
            "date", "time", "c_ip", "c_port", "cs_username", "s_sitename", "s_computername",
            "cs_host", "s_ip", "s_port", "cs_method", "cs_uri_stem", "sc_status", "sc_win32_status",
            "sc_substatus", "sc_bytes", "cs_bytes", "time_taken", "x_session", "x_fullpath", "x_debug",
        ]
        columns = ", ".join(f"'{name}'" for name in names)
        return f"read_csv_auto('{path}', delim=' ', header=false, comment='#', names=[{columns}], ignore_errors=true, all_varchar=true)"
    if fmt == "parquet":
        return f"read_parquet('{path}')"
    return f"read_csv_auto('{path}', ignore_errors=true)"


def build_normalized_select(source: str, columns: list[str]) -> str:
    """Her kaynaktaki sutunlari standart SOC semasina guvenli TRY_CAST ile donusturur."""
    expressions = []
    lower_columns = {col.lower().replace("-", "_"): col for col in columns}

    # Tarih donusumu
    has_date = "date" in lower_columns
    has_time = "time" in lower_columns
    has_tarih_raw = "tarih_raw" in lower_columns
    if has_tarih_raw:
        col_ref = sql_identifier(lower_columns["tarih_raw"])
        expressions.append(
            f"COALESCE("
            f"TRY_CAST(NULLIF(CAST({col_ref} AS VARCHAR), '-') AS TIMESTAMP), "
            f"TRY_STRPTIME(replace(CAST({col_ref} AS VARCHAR), chr(8239), ' '), '%b %d, %Y, %I:%M:%S %p'), "
            f"TRY_STRPTIME(replace(CAST({col_ref} AS VARCHAR), chr(8239), ' '), '%b %d, %Y, %H:%M:%S'), "
            f"TRY_STRPTIME(CAST({col_ref} AS VARCHAR), '%Y-%m-%d %H:%M:%S')"
            f") AS tarih"
        )
    elif has_date and has_time:
        expressions.append(
            f"TRY_CAST(NULLIF(CAST({sql_identifier(lower_columns['date'])} AS VARCHAR), '-') || ' ' || "
            f"NULLIF(CAST({sql_identifier(lower_columns['time'])} AS VARCHAR), '-') AS TIMESTAMP) AS tarih"
        )
    else:
        match_tarih = next((lower_columns[a] for a in FIELD_ALIASES["tarih"] if a in lower_columns), None)
        if match_tarih:
            col_ref = sql_identifier(match_tarih)
            expressions.append(
                f"COALESCE("
                f"TRY_CAST(NULLIF(CAST({col_ref} AS VARCHAR), '-') AS TIMESTAMP), "
                f"TRY_STRPTIME(replace(CAST({col_ref} AS VARCHAR), chr(8239), ' '), '%b %d, %Y, %I:%M:%S %p'), "
                f"TRY_STRPTIME(replace(CAST({col_ref} AS VARCHAR), chr(8239), ' '), '%b %d, %Y, %H:%M:%S')"
                f") AS tarih"
            )
        else:
            expressions.append("NULL::TIMESTAMP AS tarih")

    # IP Adresi (Kaynak IP)
    match_ip = next((lower_columns[a] for a in FIELD_ALIASES["ip_adresi"] if a in lower_columns), None)
    if match_ip:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_ip)} AS VARCHAR)), '-') AS ip_adresi")
    else:
        expressions.append("NULL::VARCHAR AS ip_adresi")

    # Hedef IP (Destination / Server IP)
    match_dst_ip = next((lower_columns[a] for a in FIELD_ALIASES["hedef_ip"] if a in lower_columns), None)
    if match_dst_ip:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_dst_ip)} AS VARCHAR)), '-') AS hedef_ip")
    else:
        expressions.append("NULL::VARCHAR AS hedef_ip")

    # Hedef Port (Destination Port)
    match_dst_port = next((lower_columns[a] for a in FIELD_ALIASES["hedef_port"] if a in lower_columns), None)
    if match_dst_port:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_dst_port)} AS VARCHAR), '-') AS INTEGER) AS hedef_port")
    else:
        expressions.append("NULL::INTEGER AS hedef_port")

    # Kaynak Port (Client Port)
    match_src_port = next((lower_columns[a] for a in FIELD_ALIASES["kaynak_port"] if a in lower_columns), None)
    if match_src_port:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_src_port)} AS VARCHAR), '-') AS INTEGER) AS kaynak_port")
    else:
        expressions.append("NULL::INTEGER AS kaynak_port")

    # Sunucu Ismi
    match_srv = next((lower_columns[a] for a in FIELD_ALIASES["sunucu_ismi"] if a in lower_columns), None)
    if match_srv:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_srv)} AS VARCHAR)), '-') AS sunucu_ismi")
    else:
        expressions.append("NULL::VARCHAR AS sunucu_ismi")

    # Islem Komutu / URI
    has_stem = "cs_uri_stem" in lower_columns
    has_query = "cs_uri_query" in lower_columns
    has_method = "cs_method" in lower_columns
    has_fullpath = "x_fullpath" in lower_columns
    has_fw_act = "firewall_action" in lower_columns
    has_fw_ev = "firewall_event" in lower_columns

    if has_fw_act or has_fw_ev:
        act_col = sql_identifier(lower_columns.get("firewall_action", lower_columns.get("firewall_event")))
        ev_col = sql_identifier(lower_columns.get("firewall_event", lower_columns.get("firewall_action")))
        expressions.append(
            f"COALESCE(NULLIF(CAST({act_col} AS VARCHAR), '-'), NULLIF(CAST({ev_col} AS VARCHAR), '-'), 'Firewall Event') AS islem_komutu"
        )
    elif has_stem and has_query:
        expressions.append(
            f"COALESCE(NULLIF(CAST({sql_identifier(lower_columns['cs_uri_stem'])} AS VARCHAR), '-'), '') || "
            f"CASE WHEN COALESCE(NULLIF(CAST({sql_identifier(lower_columns['cs_uri_query'])} AS VARCHAR), '-'), '') != '' "
            f"THEN '?' || CAST({sql_identifier(lower_columns['cs_uri_query'])} AS VARCHAR) ELSE '' END AS islem_komutu"
        )
    elif has_stem:
        expressions.append(
            f"CASE WHEN NULLIF(CAST({sql_identifier(lower_columns['cs_uri_stem'])} AS VARCHAR), '-') IS NOT NULL "
            f"THEN CAST({sql_identifier(lower_columns['cs_uri_stem'])} AS VARCHAR) "
            f"ELSE NULLIF(CAST({sql_identifier(lower_columns.get('cs_method', lower_columns['cs_uri_stem']))} AS VARCHAR), '-') "
            f"END AS islem_komutu"
        )
    elif has_method:
        if has_fullpath:
            expressions.append(
                f"CAST({sql_identifier(lower_columns['cs_method'])} AS VARCHAR) || ' ' || "
                f"COALESCE(NULLIF(CAST({sql_identifier(lower_columns['x_fullpath'])} AS VARCHAR), '-'), '') AS islem_komutu"
            )
        else:
            expressions.append(f"NULLIF(CAST({sql_identifier(lower_columns['cs_method'])} AS VARCHAR), '-') AS islem_komutu")
    else:
        match_cmd = next((lower_columns[a] for a in FIELD_ALIASES["islem_komutu"] if a in lower_columns), None)
        if match_cmd:
            expressions.append(f"NULLIF(CAST({sql_identifier(match_cmd)} AS VARCHAR), '-') AS islem_komutu")
        else:
            expressions.append("NULL::VARCHAR AS islem_komutu")

    # HTTP / FTP Method
    if has_method:
        expressions.append(f"NULLIF(UPPER(TRIM(CAST({sql_identifier(lower_columns['cs_method'])} AS VARCHAR))), '-') AS http_method")
    else:
        expressions.append("NULL::VARCHAR AS http_method")

    # User Agent
    match_ua = next((lower_columns[a] for a in FIELD_ALIASES["user_agent"] if a in lower_columns), None)
    if match_ua:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_ua)} AS VARCHAR)), '-') AS user_agent")
    else:
        expressions.append("NULL::VARCHAR AS user_agent")

    # Byte Degeri (Server to Client - Yanit)
    match_bytes = next((lower_columns[a] for a in FIELD_ALIASES["byte_degeri"] if a in lower_columns), None)
    if match_bytes:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_bytes)} AS VARCHAR), '-') AS BIGINT) AS byte_degeri")
    else:
        expressions.append("NULL::BIGINT AS byte_degeri")

    # Istemci Byte (Client to Server - Istek / Upload)
    match_cs_bytes = next((lower_columns[a] for a in FIELD_ALIASES["istemci_byte"] if a in lower_columns), None)
    if match_cs_bytes:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_cs_bytes)} AS VARCHAR), '-') AS BIGINT) AS istemci_byte")
    else:
        expressions.append("NULL::BIGINT AS istemci_byte")

    # Status Code
    match_status = next((lower_columns[a] for a in FIELD_ALIASES["status_code"] if a in lower_columns), None)
    if match_status:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_status)} AS VARCHAR), '-') AS BIGINT) AS status_code")
    elif has_fw_act:
        fw_col = sql_identifier(lower_columns["firewall_action"])
        expressions.append(
            f"CASE "
            f"WHEN UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%DENY%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%DROP%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%BLOCK%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%REJECT%' THEN 403 "
            f"WHEN UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%ACCEPT%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%ALLOW%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%PERMIT%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%PASS%' THEN 200 "
            f"ELSE NULL END AS status_code"
        )
    else:
        expressions.append("NULL::BIGINT AS status_code")

    # Baglanti Karari
    if has_fw_act:
        fw_col = sql_identifier(lower_columns["firewall_action"])
        expressions.append(
            f"CASE "
            f"WHEN UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%DENY%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%DROP%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%BLOCK%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%REJECT%' THEN 'DENY' "
            f"WHEN UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%ACCEPT%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%ALLOW%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%PERMIT%' OR UPPER(CAST({fw_col} AS VARCHAR)) LIKE '%PASS%' THEN 'ACCEPT' "
            f"ELSE 'BILINMIYOR' END AS baglanti_karari"
        )
    elif match_status:
        expressions.append(
            f"CASE "
            f"WHEN TRY_CAST(NULLIF(CAST({sql_identifier(match_status)} AS VARCHAR), '-') AS BIGINT) IN (200, 201, 202, 204, 206, 226, 230, 250, 257, 301, 302, 304) THEN 'ACCEPT' "
            f"WHEN TRY_CAST(NULLIF(CAST({sql_identifier(match_status)} AS VARCHAR), '-') AS BIGINT) IN (401, 403, 530, 550, 553) THEN 'DENY' "
            f"WHEN TRY_CAST(NULLIF(CAST({sql_identifier(match_status)} AS VARCHAR), '-') AS BIGINT) >= 400 THEN 'DENY / HATA' "
            f"WHEN TRY_CAST(NULLIF(CAST({sql_identifier(match_status)} AS VARCHAR), '-') AS BIGINT) IS NOT NULL THEN 'ACCEPT' "
            f"ELSE 'BILINMIYOR' END AS baglanti_karari"
        )
    else:
        expressions.append("'BILINMIYOR' AS baglanti_karari")

    # Kullanici Adi
    match_user = next((lower_columns[a] for a in FIELD_ALIASES["kullanici_adi"] if a in lower_columns), None)
    if match_user:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_user)} AS VARCHAR)), '-') AS kullanici_adi")
    else:
        expressions.append("NULL::VARCHAR AS kullanici_adi")

    # Referer
    match_ref = next((lower_columns[a] for a in FIELD_ALIASES["referer"] if a in lower_columns), None)
    if match_ref:
        expressions.append(f"NULLIF(TRIM(CAST({sql_identifier(match_ref)} AS VARCHAR)), '-') AS referer")
    else:
        expressions.append("NULL::VARCHAR AS referer")

    # Response Time (ms)
    match_time = next((lower_columns[a] for a in FIELD_ALIASES["response_time_ms"] if a in lower_columns), None)
    if match_time:
        expressions.append(f"TRY_CAST(NULLIF(CAST({sql_identifier(match_time)} AS VARCHAR), '-') AS BIGINT) AS response_time_ms")
    else:
        expressions.append("NULL::BIGINT AS response_time_ms")

    # Session / Cookie
    match_sess = next((lower_columns[a] for a in FIELD_ALIASES["session_cookie"] if a in lower_columns), None)
    if match_sess:
        expressions.append(
            f"CASE WHEN NULLIF(TRIM(CAST({sql_identifier(match_sess)} AS VARCHAR)), '-') IS NOT NULL "
            f"THEN md5(CAST({sql_identifier(match_sess)} AS VARCHAR)) ELSE NULL END AS session_cookie"
        )
    else:
        expressions.append("NULL::VARCHAR AS session_cookie")

    return ",\n        ".join(expressions)


def query_records(connection: duckdb.DuckDBPyConnection, query: str) -> list[dict[str, Any]]:
    """Guvenli sorgu calistirici."""
    try:
        result = connection.execute(query)
        column_names = [item[0] for item in result.description]
        return [dict(zip(column_names, row)) for row in result.fetchall()]
    except Exception as err:
        print(f"Sorgu hatasi: {err}\nQuery:\n{query}")
        return []


def run_hunting_many(
    log_files: list[Path],
    output_file: Path | None = None,
    exfiltration_bytes: int = 500_000_000,
    failed_attempts: int = 50,
    allowlist_mgr: AllowlistManager | None = None,
    source_names: list[str] | None = None,
) -> dict[str, Any]:
    """Birden fazla log dosyasini tek bir havuzda birlestirir ve tum SIEM tehdit avini calistirir."""
    if not log_files:
        return {"summary": {}, "error": "Analiz edilecek dosya bulunamadi."}

    connection = duckdb.connect()
    normalized_sources = []

    for file_index, log_file in enumerate(log_files):
        try:
            fmt = detect_log_format(log_file)
            fields = log_fields(log_file) if fmt == "w3c_iis" else None
            source = source_expression(log_file, format_type=fmt, fields=fields)
            columns = [row[0] for row in connection.execute(f"DESCRIBE SELECT * FROM {source}").fetchall()]
            source_name = (source_names or [path.name for path in log_files])[file_index]
            escaped_source_name = source_name.replace("'", "''")

            normalized_sources.append(
                f"SELECT '{escaped_source_name}' AS kaynak_dosya, "
                f"{build_normalized_select(source, columns)} FROM {source}"
            )
        except Exception as err:
            print(f"{log_file.name} normalizasyon hatasi: {err}")

    if not normalized_sources:
        raise ValueError("Hicbir log dosyasi basariyla okunamadi.")

    union_sql = " UNION ALL ".join(normalized_sources)
    connection.execute(f"CREATE OR REPLACE TEMP VIEW logs AS {union_sql}")

    # Allowlist Filtresi (SQL seviyesinde hazirlik)
    allowlist_filter = "1=1"
    # CSV / Log baslik satirlarini (Header rows: 'Source IP', 'Destination IP' vb.) otomatik ele
    allowlist_filter += " AND (ip_adresi IS NULL OR lower(ip_adresi) NOT IN ('source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi'))"
    allowlist_filter += " AND (hedef_ip IS NULL OR lower(hedef_ip) NOT IN ('destination ip', 's-ip', 'dst_ip', 'destination', 'hedef ip', 'hedef_ip'))"

    if allowlist_mgr:
        allowed_ips = [f"'{ip}'" for ip in allowlist_mgr.data["ips"]]
        if allowed_ips:
            allowlist_filter += f" AND (ip_adresi IS NULL OR ip_adresi NOT IN ({','.join(allowed_ips)}))"
        allowed_accs = [f"'{acc.lower()}'" for acc in allowlist_mgr.data["service_accounts"]]
        if allowed_accs:
            allowlist_filter += f" AND (kullanici_adi IS NULL OR lower(kullanici_adi) NOT IN ({','.join(allowed_accs)}))"

    # Core Hunting Queries
    queries: dict[str, str] = {
        # 1. Veri Sizdirma Anomalileri
        "exfiltration_anomalies": f"""
            SELECT ip_adresi, kullanici_adi, sunucu_ismi,
                   COUNT(*) AS toplam_islem,
                   SUM(byte_degeri) AS toplam_transfer_byte,
                   ROUND(SUM(byte_degeri) / 1073741824.0, 2) AS toplam_transfer_gb,
                   ROUND(AVG(byte_degeri), 2) AS ortalama_transfer_byte,
                   MAX(byte_degeri) AS max_tekil_byte,
                   MIN(tarih) AS ilk_transfer, MAX(tarih) AS son_transfer
            FROM logs
            WHERE status_code IN (200, 226) AND byte_degeri IS NOT NULL AND {allowlist_filter}
            GROUP BY ip_adresi, kullanici_adi, sunucu_ismi
            HAVING SUM(byte_degeri) >= {exfiltration_bytes}
            ORDER BY toplam_transfer_byte DESC
        """,

        # 2. Veri Transfer Detaylari (Tekil ve Gruplanmis)
        "data_transfer_details": f"""
            WITH transfers AS (
                SELECT kaynak_dosya, ip_adresi,
                       COALESCE(kullanici_adi, 'Anonim / Belirtilmemis') AS kullanici_adi,
                       COALESCE(sunucu_ismi, 'Bilinmeyen Sunucu') AS sunucu_ismi,
                       COUNT(*) AS basarili_istek_sayisi,
                       SUM(coalesce(byte_degeri, 0)) AS toplam_transfer_byte,
                       AVG(coalesce(byte_degeri, 0)) AS ortalama_transfer_byte,
                       MAX(coalesce(byte_degeri, 0)) AS en_buyuk_tekil_transfer,
                       MIN(tarih) AS ilk_transfer, MAX(tarih) AS son_transfer
                FROM logs
                WHERE status_code IN (200, 226) AND {allowlist_filter}
                GROUP BY kaynak_dosya, ip_adresi, kullanici_adi, sunucu_ismi
            ), totals AS (
                SELECT SUM(toplam_transfer_byte) AS tum_basari_transfer_byte FROM transfers
            )
            SELECT transfers.*,
                   ROUND(toplam_transfer_byte / 1048576.0, 2) AS toplam_transfer_mb,
                   ROUND(toplam_transfer_byte / 1073741824.0, 2) AS toplam_transfer_gb,
                   ROUND(ortalama_transfer_byte, 2) AS ortalama_transfer_byte,
                   ROUND(en_buyuk_tekil_transfer / 1048576.0, 2) AS en_buyuk_tekil_transfer_mb,
                   ROUND(100.0 * toplam_transfer_byte / NULLIF(tum_basari_transfer_byte, 0), 2) AS toplam_transfer_yuzdesi
            FROM transfers CROSS JOIN totals
            ORDER BY toplam_transfer_byte DESC
        """,

        # 3. En Buyuk 100 Tekil Transfer Istegi
        "largest_transfer_requests": f"""
            SELECT kaynak_dosya, tarih, ip_adresi, kullanici_adi, sunucu_ismi, islem_komutu,
                   status_code, byte_degeri,
                   ROUND(byte_degeri / 1048576.0, 2) AS transfer_mb,
                   user_agent
            FROM logs
            WHERE status_code IN (200, 226) AND byte_degeri IS NOT NULL AND {allowlist_filter}
            ORDER BY byte_degeri DESC
            LIMIT 100
        """,

        # 4. Gunler Arasi Tehdit Iliskilendirme (Cross-Day Attack Correlation)
        "cross_day_correlation": f"""
            SELECT ip_adresi,
                   COALESCE(kullanici_adi, '-') AS kullanici_adi,
                   string_agg(DISTINCT sunucu_ismi, ', ') AS sunucular,
                   COUNT(DISTINCT CAST(tarih AS DATE)) AS gun_sayisi,
                   COUNT(DISTINCT kaynak_dosya) AS dosya_sayisi,
                   COUNT(*) AS toplam_istek,
                   COUNT(*) FILTER (WHERE status_code IN (401, 403, 530)) AS basarisiz_auth_sayisi,
                   COUNT(*) FILTER (WHERE status_code >= 500) AS server_hata_sayisi,
                   SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) AS toplam_basarili_byte,
                   MIN(tarih) AS ilk_aktivite, MAX(tarih) AS son_aktivite,
                   CONCAT_WS(' -> ',
                       CASE WHEN COUNT(*) FILTER (WHERE status_code IN (404, 403) OR islem_komutu LIKE '%/admin%' OR islem_komutu LIKE '%/filemanagement%') > 0 THEN 'Kesif' END,
                       CASE WHEN COUNT(*) FILTER (WHERE status_code IN (401, 403, 530) OR lower(islem_komutu) LIKE 'pass %') >= 5 THEN 'Parola Denemesi' END,
                       CASE WHEN COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), 'filemanagement|c:\\\\inetpub|web\\.config|\\.asp|\\.aspx')) > 0 THEN 'Webshell/Dizin Gezintisi' END,
                       CASE WHEN COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'stor %' OR istemci_byte > 100000) > 0 THEN 'Dosya Yukleme' END,
                       CASE WHEN SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) >= 10485760 THEN 'Veri Transferi/Sizdirma' END
                   ) AS asama_izleri
            FROM logs
            WHERE ip_adresi IS NOT NULL AND {allowlist_filter}
            GROUP BY ip_adresi, kullanici_adi
            HAVING COUNT(DISTINCT CAST(tarih AS DATE)) > 1 OR COUNT(DISTINCT kaynak_dosya) > 1 OR COUNT(*) >= 500
            ORDER BY gun_sayisi DESC, toplam_istek DESC
        """,

        # 5. Webshell ve Dosya Yonetimi Tespiti
        "webshell_and_file_management": f"""
            SELECT ip_adresi, sunucu_ismi, user_agent, session_cookie,
                   COUNT(*) AS istek_sayisi,
                   COUNT(*) FILTER (WHERE status_code >= 400) AS hata_sayisi,
                   COUNT(*) FILTER (WHERE status_code >= 500) AS server_hatasi,
                   SUM(coalesce(byte_degeri, 0)) AS toplam_yanit_byte,
                   MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme,
                   string_agg(DISTINCT islem_komutu, ' | ' ORDER BY islem_komutu) AS eylem_ornekleri
            FROM logs
            WHERE (
                regexp_matches(lower(coalesce(islem_komutu, '')), '/filemanagement|c:\\\\inetpub|wwwroot|\\.(asp|aspx|php|jsp)(\\?|$)|browse=|download=.*(web\\.config|appsettings|\\.config|\\.cs|\\.dll)|(\\.\\./|\\.\\.\\\\)')
                OR regexp_matches(lower(coalesce(islem_komutu, '')), 'cmd(\\.exe)?|powershell|whoami|net[[:space:]]+user')
            ) AND {allowlist_filter}
            GROUP BY ip_adresi, sunucu_ismi, user_agent, session_cookie
            ORDER BY son_gorulme DESC
        """,

        # 6. Webshell Eylem Zaman Cizelgesi
        "webshell_activity_timeline": f"""
            SELECT tarih, ip_adresi, sunucu_ismi, http_method, islem_komutu,
                   status_code, byte_degeri, response_time_ms, user_agent, session_cookie, referer
            FROM logs
            WHERE (
                regexp_matches(lower(coalesce(islem_komutu, '')), '/filemanagement|c:\\\\inetpub|wwwroot|\\.(asp|aspx|php|jsp)(\\?|$)|browse=|download=.*(web\\.config|appsettings|\\.config|\\.cs|\\.dll)|(\\.\\./|\\.\\.\\\\)')
                OR regexp_matches(lower(coalesce(islem_komutu, '')), 'cmd(\\.exe)?|powershell|whoami|net[[:space:]]+user')
            ) AND {allowlist_filter}
            ORDER BY tarih ASC
            LIMIT 1000
        """,

        # 7. Gelismis Bot ve Otomatize Tarayici Tespiti
        "scanner_and_bots": f"""
            WITH ip_stats AS (
                SELECT ip_adresi, user_agent,
                       COUNT(*) AS toplam_istek,
                       COUNT(DISTINCT islem_komutu) AS farkli_komut_sayisi,
                       COUNT(DISTINCT sunucu_ismi) AS hedef_sunucu_sayisi,
                       COUNT(*) FILTER (WHERE status_code IN (401, 403, 404)) AS hata_sayisi,
                       COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/admin|/\\.env|/swagger|/backup|/actuator|web\\.config')) AS hassas_sayisi,
                       COUNT(*) FILTER (WHERE http_method IN ('PROPFIND', 'SEARCH', 'TRACK', 'TRACE', 'DEBUG', 'PUT')) AS anormal_method_sayisi
                FROM logs
                WHERE ip_adresi IS NOT NULL AND {allowlist_filter}
                GROUP BY ip_adresi, user_agent
            )
            SELECT ip_stats.*,
                   ROUND(100.0 * hata_sayisi / NULLIF(toplam_istek, 0), 1) AS hata_yuzdesi,
                   CASE
                       WHEN regexp_matches(lower(coalesce(user_agent, '')), 'sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|zgrab|shodan|censys|hydra') THEN 'Acik Arac Imzasi'
                       WHEN farkli_komut_sayisi > 50 AND (100.0 * hata_sayisi / NULLIF(toplam_istek, 0)) >= 50 THEN 'Yuksek Hata & Endpoint Patlamasi'
                       WHEN hassas_sayisi >= 3 THEN 'Hassas Dosya/Dizin Taramasi'
                       WHEN anormal_method_sayisi > 0 THEN 'Anormal HTTP Metodu'
                       WHEN hedef_sunucu_sayisi > 2 THEN 'Coklu Sunucu Yatay Tarama'
                       ELSE 'Supheli Tarayici Davranisi'
                   END AS bot_sebebi
            FROM ip_stats
            WHERE (
                regexp_matches(lower(coalesce(user_agent, '')), 'sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|zgrab|shodan|censys|hydra')
                OR (farkli_komut_sayisi > 30 AND (100.0 * hata_sayisi / NULLIF(toplam_istek, 0)) >= 40)
                OR hassas_sayisi >= 3
                OR anormal_method_sayisi > 0
            )
            ORDER BY toplam_istek DESC
        """,

        # 8. Brute Force Saldirilari
        "brute_force_attempts": f"""
            SELECT ip_adresi, kullanici_adi, sunucu_ismi, status_code,
                   COUNT(*) AS basarisiz_deneme_sayisi,
                   MIN(tarih) AS ilk_deneme, MAX(tarih) AS son_deneme
            FROM logs
            WHERE (status_code IN (401, 403, 530) OR lower(coalesce(islem_komutu, '')) LIKE 'pass %')
              AND {allowlist_filter}
            GROUP BY ip_adresi, kullanici_adi, sunucu_ismi, status_code
            HAVING COUNT(*) >= {failed_attempts}
            ORDER BY basarisiz_deneme_sayisi DESC
        """,

        # 9. Password Spraying
        "password_spraying": f"""
            SELECT ip_adresi,
                   COUNT(DISTINCT kullanici_adi) AS farkli_kullanici_sayisi,
                   COUNT(*) AS basarisiz_deneme_sayisi,
                   COUNT(DISTINCT sunucu_ismi) AS hedef_sunucu_sayisi,
                   string_agg(DISTINCT kullanici_adi, ', ') AS hedeflenen_kullanicilar
            FROM logs
            WHERE (status_code IN (401, 403, 530) OR lower(coalesce(islem_komutu, '')) LIKE 'pass %')
              AND kullanici_adi IS NOT NULL AND kullanici_adi NOT IN ('-', '', 'anonymous')
              AND {allowlist_filter}
            GROUP BY ip_adresi
            HAVING COUNT(DISTINCT kullanici_adi) >= 4 AND COUNT(*) >= 20
            ORDER BY farkli_kullanici_sayisi DESC, basarisiz_deneme_sayisi DESC
        """,

        # 10. FTP Kimlik Dogrulama ve Islemleri
        "ftp_authentication": f"""
            SELECT ip_adresi, kullanici_adi, session_cookie, sunucu_ismi,
                   COUNT(*) AS ftp_istek_sayisi,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'user %') AS user_komutu,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'pass %') AS pass_komutu,
                   COUNT(*) FILTER (WHERE status_code IN (230, 530)) AS auth_sonucu,
                   MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme
            FROM logs
            WHERE (lower(coalesce(islem_komutu, '')) LIKE 'user %'
                OR lower(coalesce(islem_komutu, '')) LIKE 'pass %'
                OR status_code IN (230, 530)) AND {allowlist_filter}
            GROUP BY ip_adresi, kullanici_adi, session_cookie, sunucu_ismi
            ORDER BY son_gorulme DESC
        """,

        # 11. FTP Dosya Islemleri (Upload / Download / Delete)
        "ftp_file_operations": f"""
            SELECT ip_adresi, kullanici_adi, session_cookie, sunucu_ismi,
                   COUNT(*) AS islem_sayisi,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'stor %' OR lower(islem_komutu) LIKE 'appe %') AS yukleme_sayisi,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'retr %') AS indirme_sayisi,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'dele %') AS silme_sayisi,
                   COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'rnfr %' OR lower(islem_komutu) LIKE 'rnto %') AS yeniden_adlandirma_sayisi,
                   SUM(coalesce(byte_degeri, 0)) AS toplam_byte,
                   MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme
            FROM logs
            WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '^(stor|appe|retr|dele|rnfr|rnto|mkd|rmd|cwd|list|nlst)([[:space:]]|$)')
              AND {allowlist_filter}
            GROUP BY ip_adresi, kullanici_adi, session_cookie, sunucu_ismi
            ORDER BY son_gorulme DESC
        """,

        # 12. FTP Supheli Islemler
        "ftp_suspicious_activity": f"""
            SELECT tarih, ip_adresi, kullanici_adi, session_cookie, sunucu_ismi,
                   islem_komutu, status_code, byte_degeri, referer
            FROM logs
            WHERE (
                regexp_matches(lower(coalesce(islem_komutu, '')), '^(stor|appe|dele|rnfr|rnto|mkd|rmd)([[:space:]]|$)')
                OR lower(coalesce(islem_komutu, '')) LIKE 'pass %'
                OR status_code IN (530, 550, 553)
            ) AND {allowlist_filter}
            ORDER BY tarih ASC
            LIMIT 2000
        """,

        # 13. Supheli Komutlar ve RCE / SQLi Enjeksiyon Denemeleri
        "suspicious_commands": f"""
            SELECT sunucu_ismi, islem_komutu, status_code, COUNT(*) AS tekrar_sayisi,
                   COUNT(DISTINCT ip_adresi) AS erisen_farkli_ip_sayisi
            FROM logs
            WHERE (
                status_code >= 500
                OR regexp_matches(lower(coalesce(islem_komutu, '')), '/etc/passwd|/etc/shadow|cmd(\\.exe)?|powershell|union[[:space:]]+select|;[[:space:]]*(cat|curl|wget)')
            ) AND {allowlist_filter}
            GROUP BY sunucu_ismi, islem_komutu, status_code
            ORDER BY tekrar_sayisi DESC
        """,

        # 14. Hassas Endpoint Erisimleri
        "sensitive_endpoints": f"""
            SELECT sunucu_ismi, islem_komutu, status_code, COUNT(*) AS istek_sayisi,
                   COUNT(DISTINCT ip_adresi) AS farkli_ip_sayisi
            FROM logs
            WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/admin|/actuator|/swagger|/\\.env|/config|/backup|/debug|/health|/metrics|password|token|secret')
              AND {allowlist_filter}
            GROUP BY sunucu_ismi, islem_komutu, status_code
            ORDER BY istek_sayisi DESC
        """,

        # 15. Erisim Saglanan Hedef IP'ler ve En Sik Erisilenler
        "destination_ip_analysis": f"""
            SELECT COALESCE(hedef_ip, 'Belirtilmemis') AS hedef_ip,
                   COUNT(*) AS toplam_baglanti,
                   COUNT(DISTINCT ip_adresi) AS erisen_kaynak_ip_sayisi,
                   COUNT(DISTINCT hedef_port) AS kullanilan_port_sayisi,
                   string_agg(DISTINCT CAST(hedef_port AS VARCHAR), ', ') AS portlar,
                   COUNT(*) FILTER (WHERE baglanti_karari = 'ACCEPT') AS accept_sayisi,
                   COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') AS deny_sayisi,
                   ROUND(100.0 * COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') / NULLIF(COUNT(*), 0), 1) AS deny_orani,
                   SUM(coalesce(byte_degeri, 0)) AS toplam_transfer_byte,
                   ROUND(SUM(coalesce(byte_degeri, 0)) / 1048576.0, 2) AS toplam_transfer_mb
            FROM logs
            WHERE {allowlist_filter}
            GROUP BY hedef_ip
            ORDER BY toplam_baglanti DESC
        """,

        # 16. Kullanilan Portlar ve Servis Dagilimi
        "port_analysis": f"""
            SELECT COALESCE(hedef_port, 0) AS port,
                   CASE
                       WHEN hedef_port = 80 THEN 'HTTP'
                       WHEN hedef_port = 443 THEN 'HTTPS'
                       WHEN hedef_port = 21 THEN 'FTP (Control)'
                       WHEN hedef_port = 22 THEN 'SSH'
                       WHEN hedef_port = 53 THEN 'DNS'
                       WHEN hedef_port = 3389 THEN 'RDP'
                       WHEN hedef_port = 445 THEN 'SMB'
                       WHEN hedef_port BETWEEN 50000 AND 60000 THEN 'FTP (Passive Data)'
                       ELSE 'Diger / Ozel'
                   END AS servis_tahmini,
                   COUNT(*) AS baglanti_sayisi,
                   COUNT(*) FILTER (WHERE baglanti_karari = 'ACCEPT') AS accept_sayisi,
                   COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') AS deny_sayisi,
                   COUNT(DISTINCT ip_adresi) AS erisen_istemci_sayisi,
                   SUM(coalesce(byte_degeri, 0)) AS toplam_byte,
                   ROUND(SUM(coalesce(byte_degeri, 0)) / 1048576.0, 2) AS toplam_mb
            FROM logs
            WHERE hedef_port IS NOT NULL AND {allowlist_filter}
            GROUP BY port, servis_tahmini
            ORDER BY baglanti_sayisi DESC
        """,

        # 17. Accept / Deny Baglanti Dagilimi
        "accept_deny_summary": f"""
            SELECT baglanti_karari,
                   COUNT(*) AS baglanti_sayisi,
                   ROUND(100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0), 2) AS oran_yuzde
            FROM logs
            WHERE {allowlist_filter}
            GROUP BY baglanti_karari
            ORDER BY baglanti_sayisi DESC
        """,

        # 18. Saatlik Trafik Dagilimi (Grafikler Icin)
        "hourly_traffic": f"""
            SELECT date_trunc('hour', tarih) AS saatlik_dilim,
                   COUNT(*) AS toplam_istek,
                   COUNT(*) FILTER (WHERE status_code IN (200, 226)) AS basarili_istek,
                   COUNT(*) FILTER (WHERE status_code IN (401, 403, 404)) AS hata_4xx,
                   COUNT(*) FILTER (WHERE status_code >= 500) AS hata_5xx,
                   SUM(coalesce(byte_degeri, 0)) AS saatlik_toplam_byte
            FROM logs
            WHERE tarih IS NOT NULL AND {allowlist_filter}
            GROUP BY saatlik_dilim
            ORDER BY saatlik_dilim ASC
        """,

        # 16. Durum Kodu Dagilimi (Grafikler Icin)
        "status_code_distribution": f"""
            SELECT status_code, COUNT(*) AS adet
            FROM logs
            WHERE status_code IS NOT NULL AND {allowlist_filter}
            GROUP BY status_code
            ORDER BY adet DESC
        """,

        # 17. En Cok Istek Atan IP'ler (Grafikler Icin)
        "top_ips": f"""
            SELECT ip_adresi, COUNT(*) AS istek_sayisi,
                   SUM(coalesce(byte_degeri, 0)) AS toplam_byte,
                   COUNT(DISTINCT sunucu_ismi) AS sunucu_sayisi
            FROM logs
            WHERE ip_adresi IS NOT NULL AND {allowlist_filter}
            GROUP BY ip_adresi
            ORDER BY istek_sayisi DESC
            LIMIT 15
        """,

        # 18. Oncelikli Inceleme Kuyrugu (Entity Risk Queue - 0 ila 100 Puanlama)
        "entity_risk_queue": f"""
            WITH entities AS (
                SELECT ip_adresi,
                       COALESCE(sunucu_ismi, 'Genel') AS sunucu_ismi,
                       COUNT(*) AS toplam_istek,
                       COUNT(DISTINCT islem_komutu) AS farkli_endpoint_sayisi,
                       COUNT(DISTINCT sunucu_ismi) OVER (PARTITION BY ip_adresi) AS farkli_sunucu_sayisi,
                       COUNT(DISTINCT kullanici_adi) FILTER (WHERE kullanici_adi NOT IN ('-', '')) AS farkli_kullanici_sayisi,
                       SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) AS basarili_byte,
                       COUNT(*) FILTER (WHERE status_code IN (401, 403, 530)) AS auth_hatasi,
                       COUNT(*) FILTER (WHERE status_code >= 500) AS server_hatasi,
                       COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/admin|/actuator|/swagger|/\\.env|/config|/backup|/debug|password|token|secret|web\\.config')) AS hassas_endpoint,
                       COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/filemanagement|c:\\\\inetpub|wwwroot|\\.(asp|aspx|php|jsp)(\\?|$)')) AS webshell_sinyali,
                       MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme
                FROM logs
                WHERE ip_adresi IS NOT NULL AND {allowlist_filter}
                GROUP BY ip_adresi, sunucu_ismi
            ), scored AS (
                SELECT entities.*,
                    (CASE WHEN basarili_byte >= {exfiltration_bytes} THEN 35 ELSE 0 END
                     + CASE WHEN auth_hatasi >= {failed_attempts} THEN 25 ELSE 0 END
                     + CASE WHEN webshell_sinyali > 0 THEN 30 ELSE 0 END
                     + CASE WHEN farkli_endpoint_sayisi > 30 THEN 20 ELSE 0 END
                     + CASE WHEN server_hatasi > 0 THEN 15 ELSE 0 END
                     + CASE WHEN hassas_endpoint > 0 THEN 15 ELSE 0 END
                     + CASE WHEN farkli_kullanici_sayisi >= 4 AND auth_hatasi >= 20 THEN 25 ELSE 0 END
                     + CASE WHEN farkli_sunucu_sayisi > 2 THEN 10 ELSE 0 END) AS risk_puani
                FROM entities
            )
            SELECT *,
                CASE WHEN risk_puani >= 60 THEN 'KRİTİK'
                     WHEN risk_puani >= 35 THEN 'YÜKSEK'
                     WHEN risk_puani >= 20 THEN 'ORTA' ELSE 'DÜŞÜK' END AS risk_seviyesi,
                concat_ws('; ',
                    CASE WHEN basarili_byte >= {exfiltration_bytes} THEN 'Yuksek basarili transfer (Sizdirma suphesi)' END,
                    CASE WHEN webshell_sinyali > 0 THEN 'Webshell veya dosya yonetimi erisimi' END,
                    CASE WHEN auth_hatasi >= {failed_attempts} THEN 'Yuksek sayida auth hatasi (401/403/530)' END,
                    CASE WHEN farkli_endpoint_sayisi > 30 THEN 'Cok sayida farkli endpoint (Tarama sinyali)' END,
                    CASE WHEN server_hatasi > 0 THEN '5xx sunucu hatasi (Cokertme/Enjeksiyon)' END,
                    CASE WHEN hassas_endpoint > 0 THEN 'Hassas dosya/yapilandirma erisimi' END,
                    CASE WHEN farkli_kullanici_sayisi >= 4 AND auth_hatasi >= 20 THEN 'Password spraying sinyali' END,
                    CASE WHEN farkli_sunucu_sayisi > 2 THEN 'Coklu sunucu taramasi' END
                ) AS risk_gerekcesi
            FROM scored
            WHERE risk_puani >= 15
            ORDER BY risk_puani DESC, toplam_istek DESC
        """,
    }

    report: dict[str, Any] = {}
    for name, query in queries.items():
        report[name] = query_records(connection, query)

    # Threat Intelligence Zenginlestirmesi (Entity Queue ve Bots uzerine IP siniflandirma ekleme)
    for item in report.get("entity_risk_queue", []):
        ip_info = classify_ip(item.get("ip_adresi"))
        item["ip_kategori"] = ip_info["kategori"]
        item["ip_aciklama"] = ip_info["aciklama"]

    for item in report.get("cross_day_correlation", []):
        ip_info = classify_ip(item.get("ip_adresi"))
        item["ip_kategori"] = ip_info["kategori"]

    # Genel Ozet
    summary_raw = query_records(connection, f"""
        SELECT COUNT(*) AS toplam_olay,
               MIN(tarih) AS ilk_tarih, MAX(tarih) AS son_tarih,
               COUNT(DISTINCT ip_adresi) AS farkli_ip_sayisi,
               COUNT(DISTINCT hedef_ip) AS farkli_hedef_ip_sayisi,
               COUNT(DISTINCT sunucu_ismi) AS farkli_sunucu_sayisi,
               COUNT(DISTINCT islem_komutu) AS farkli_endpoint_sayisi,
               COUNT(*) FILTER (WHERE status_code >= 500) AS server_error_sayisi,
               COUNT(*) FILTER (WHERE status_code IN (401, 403, 530)) AS auth_failure_sayisi,
               COUNT(*) FILTER (WHERE baglanti_karari = 'ACCEPT') AS accept_sayisi,
               COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') AS deny_sayisi,
               SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) AS toplam_transfer_byte
        FROM logs
        WHERE {allowlist_filter}
    """)
    report["summary"] = summary_raw[0] if summary_raw else {}

    if output_file:
        try:
            output_file.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as err:
            print(f"Rapor yazma hatasi: {err}")

    return report
