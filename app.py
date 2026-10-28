"""SOC Log Lens - Advanced Threat Hunting & SIEM Correlation Platform.

0 Hata Prensibi:
- Guvenli DuckDB normalizasyon motoru (soc_engine)
- Coklu dosya / coklu gun birlestirilmis analiz
- Gunler arasi saldiri iliskilendirme (Cross-Day Correlation)
- Olay Yonetimi (Yeni, Inceleniyor, Kapatildi)
- Allowlist Yonetimi
- Threat Intelligence (IP siniflandirma & itibar)
- Otomatik HTML/PDF Raporlama
- Canli Klasor Izleyici (Watchdog)
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import tempfile
from typing import Any

import pandas as pd
import streamlit as st

from allowlist import AllowlistManager
from incident_manager import IncidentManager
from report_generator import generate_html_report
from soc_engine import run_hunting_many
from watcher import DirectoryWatcher

# Sayfa Yapilandirmasi
st.set_page_config(
    page_title="SOC Log Lens | SIEM & Threat Hunting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Modern SOC Arayuz Stili
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    :root {
        --primary: #0f172a;
        --accent: #2563eb;
        --danger: #dc2626;
        --warning: #ea580c;
        --success: #16a34a;
        --card-bg: #ffffff;
        --border-color: #e2e8f0;
    }
    
    .stApp {
        background-color: #f8fafc;
        font-family: 'Inter', sans-serif;
    }
    
    [data-testid="stHeader"] {
        background: transparent;
    }
    
    .soc-header {
        padding: 0.5rem 0 1.5rem 0;
        border-bottom: 1px solid #e2e8f0;
        margin-bottom: 1.5rem;
    }
    
    .soc-badge {
        display: inline-block;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        margin-bottom: 0.5rem;
    }
    
    .soc-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #0f172a;
        margin: 0;
        letter-spacing: -0.02em;
    }
    
    .soc-subtitle {
        color: #64748b;
        font-size: 1rem;
        margin-top: 0.35rem;
    }
    
    [data-testid="stMetric"] {
        background: white;
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 42px;
        border-radius: 8px;
        padding: 0 16px;
        font-weight: 600;
        font-size: 0.9rem;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #ffffff !important;
        box-shadow: 0 2px 5px rgba(0,0,0,0.06);
    }
    
    .risk-badge-kritik {
        background: #fee2e2;
        color: #b91c1c;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
    }
    
    .risk-badge-yuksek {
        background: #ffedd5;
        color: #c2410c;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
    }
    
    .risk-badge-orta {
        background: #fef9c3;
        color: #854d0e;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
    }
    
    .risk-badge-dusuk {
        background: #dcfce7;
        color: #15803d;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Session State Baslatma
if "allowlist_mgr" not in st.session_state:
    st.session_state.allowlist_mgr = AllowlistManager()
if "incident_mgr" not in st.session_state:
    st.session_state.incident_mgr = IncidentManager()
if "report_data" not in st.session_state:
    st.session_state.report_data = None
if "active_log_names" not in st.session_state:
    st.session_state.active_log_names = []
if "watcher_instance" not in st.session_state:
    st.session_state.watcher_instance = None

allowlist_mgr: AllowlistManager = st.session_state.allowlist_mgr
incident_mgr: IncidentManager = st.session_state.incident_mgr

# Header
st.markdown(
    """
    <div class="soc-header">
        <span class="soc-badge">SOC Level 2/3 Threat Hunting & SIEM</span>
        <h1 class="soc-title">SOC Log Lens</h1>
        <div class="soc-subtitle">
            Cok gunluk log birlestirme, gunler arasi saldiri korelasyonu, webshell/veri sizdirma tespiti ve vaka yonetimi.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar Yapilandirmasi
with st.sidebar:
    st.header("⚙️ Analiz Parametreleri")
    exfiltration_mb = st.number_input(
        "Veri Sizdirma Esigi (MB)",
        min_value=1,
        value=50,
        step=25,
        help="Bu esigi asan basarili transferler veri sizdirma anomalisi olarak etiketlenir.",
    )
    failed_attempts = st.number_input(
        "Brute Force Esigi (Basarisiz Deneme)",
        min_value=1,
        value=30,
        step=5,
        help="Ayni IP/kullanicinin bu esikten fazla 401/403/530 hatasi almasi durumunda alarm verilir.",
    )
    enable_allowlist = st.toggle(
        "🛡️ Allowlist Filtresi Uygula",
        value=True,
        help="Bilinen guvenli IP ve servis hesaplarini analizden haric tutarak false-positive'leri onler.",
    )

    st.markdown("---")
    st.markdown("### 📊 Desteklenen Formatlar")
    st.caption("• IIS W3C HTTP (.log)\n• IIS W3C FTP (.log)\n• Checkpoint Firewall (Deny/Drop CSV)\n• Standart CSV (.csv)\n• JSON / JSONL / NDJSON\n• Apache / Parquet (.parquet)")

    st.markdown("---")
    st.caption("v2.5.0 - 0 Hata SIEM Korelasyon Surumu")

# Ana Sekmeler
tab_analysis, tab_incidents, tab_allowlist, tab_watcher = st.tabs([
    "🔍 Tehdit Avı & Analiz",
    "📋 Olay Yönetimi (Incidents)",
    "🛡️ Allowlist (Güvenli Liste)",
    "📡 Canlı Klasör İzleyici",
])

# ==============================================================================
# 1. SEKME: TEHDIT AVI & ANALIZ
# ==============================================================================
with tab_analysis:
    col_upload, col_quick = st.columns([3, 1])

    with col_upload:
        uploads = st.file_uploader(
            "Log dosyalarini surukleyip birakin (Coklu secim yapabilirsiniz)",
            type=["log", "csv", "json", "jsonl", "ndjson", "parquet"],
            accept_multiple_files=True,
            help="Birden fazla gunluk log dosyasini ayni anda secerek tum gunleri tek bir korelasyon havuzunda birlestirebilirsiniz.",
        )

    with col_quick:
        st.markdown("**Hızlı Yerel Analiz:**")
        local_logs = sorted(list(Path(".").glob("*.log")))
        st.caption(f"Calisma dizininde **{len(local_logs)}** log dosyasi bulundu.")
        use_local_files = st.button("Dizindeki Tum Loglari Yukle", use_container_width=True)

    target_files: list[Path] = []
    source_display_names: list[str] = []
    temp_files_to_cleanup: list[Path] = []

    if use_local_files and local_logs:
        target_files = local_logs
        source_display_names = [f.name for f in local_logs]
        st.success(f"Dizindeki {len(local_logs)} dosya secildi: {', '.join(source_display_names)}")
    elif uploads:
        for upload in uploads:
            suffix = Path(upload.name).suffix.lower()
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(upload.getbuffer())
                temp_path = Path(tmp.name)
            target_files.append(temp_path)
            temp_files_to_cleanup.append(temp_path)
            source_display_names.append(upload.name)
        st.info(f"**{len(uploads)} dosya hazir:** {', '.join(source_display_names)}")

    if target_files:
        if st.button("🚀 Birleşik Tehdit Avı Analizini Başlat", type="primary", use_container_width=True):
            with st.spinner(f"{len(target_files)} dosya tek bir korelasyon havuzunda birlestiriliyor ve analiz ediliyor..."):
                try:
                    active_allowlist = allowlist_mgr if enable_allowlist else None
                    report = run_hunting_many(
                        log_files=target_files,
                        exfiltration_bytes=int(exfiltration_mb * 1_000_000),
                        failed_attempts=int(failed_attempts),
                        allowlist_mgr=active_allowlist,
                        source_names=source_display_names,
                    )
                    st.session_state.report_data = report
                    st.session_state.active_log_names = source_display_names
                    st.success("✅ Birlesik Tehdit Avi Analizi Basariyla Tamamlandi!")
                except Exception as err:
                    st.error(f"Analiz sirasinda hata olustu: {err}")
                finally:
                    for tmp in temp_files_to_cleanup:
                        tmp.unlink(missing_ok=True)

    report_data = st.session_state.report_data
    if report_data:
        summary = report_data.get("summary", {})
        total_transfer_gb = (summary.get("toplam_transfer_byte") or 0) / (1024**3)

        st.markdown("### 📌 Yönetici ve SOC Operasyon Özeti")
        kpi_r1_c1, kpi_r1_c2, kpi_r1_c3, kpi_r1_c4 = st.columns(4)
        kpi_r1_c1.metric("Toplam Olay", f"{summary.get('toplam_olay', 0):,}")
        kpi_r1_c2.metric("Farklı Kaynak IP", f"{summary.get('farkli_ip_sayisi', 0):,}")
        kpi_r1_c3.metric("Farklı Hedef IP", f"{summary.get('farkli_hedef_ip_sayisi', 0):,}")
        kpi_r1_c4.metric("Farklı Sunucu", f"{summary.get('farkli_sunucu_sayisi', 0):,}")

        kpi_r2_c1, kpi_r2_c2, kpi_r2_c3, kpi_r2_c4 = st.columns(4)
        kpi_r2_c1.metric("Accept (Kabul)", f"{summary.get('accept_sayisi', 0):,}")
        kpi_r2_c2.metric("Deny (Engellenen)", f"{summary.get('deny_sayisi', 0):,}")
        kpi_r2_c3.metric("Sunucu Hatası (5xx)", f"{summary.get('server_error_sayisi', 0):,}")
        kpi_r2_c4.metric("Başarılı Transfer", f"{total_transfer_gb:,.2f} GB")

        date_range_str = f"{summary.get('ilk_tarih', '-')}  &rarr;  {summary.get('son_tarih', '-')}"
        st.caption(f"🗓️ **Analiz Edilen Zaman Aralığı:** {date_range_str} | **Taranan Dosyalar:** {', '.join(st.session_state.active_log_names)}")

        # Rapor Indirme Butonlari
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            html_report = generate_html_report(report_data, analyst_name="SOC Tehdit Avcisi")
            st.download_button(
                "🖨️ Otomatik HTML/PDF Olay Raporunu İndir",
                data=html_report,
                file_name=f"SOC_Incident_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True,
            )
        with col_btn2:
            st.download_button(
                "💾 Tam JSON Analiz Raporunu İndir",
                data=json.dumps(report_data, ensure_ascii=False, indent=2, default=str),
                file_name="soc_threat_hunting_full.json",
                mime="application/json",
                use_container_width=True,
            )

        # Görsel Grafikler ve Zaman Çizelgesi
        st.markdown("---")
        st.subheader("📈 Görsel Zaman Çizelgesi, Portlar ve Trafik Dağılımı")
        chart_col1, chart_col2, chart_col3 = st.columns([2, 1, 1])

        with chart_col1:
            hourly = report_data.get("hourly_traffic", [])
            if hourly:
                df_hourly = pd.DataFrame(hourly)
                df_hourly["saatlik_dilim"] = pd.to_datetime(df_hourly["saatlik_dilim"])
                df_hourly = df_hourly.set_index("saatlik_dilim")[["toplam_istek", "basarili_istek", "hata_4xx", "hata_5xx"]]
                st.caption("Saatlik İstek ve Hata Dağılımı")
                st.line_chart(df_hourly, use_container_width=True)
            else:
                st.info("Zaman cizelgesi icin yeterli tarih damgasi bulunamadi.")

        with chart_col2:
            port_dist = report_data.get("port_analysis", [])[:10]
            if port_dist:
                df_ports = pd.DataFrame(port_dist)
                df_ports["port_label"] = df_ports["port"].astype(str) + " (" + df_ports["servis_tahmini"] + ")"
                st.caption("En Çok Kullanılan Portlar")
                st.bar_chart(df_ports.set_index("port_label")["baglanti_sayisi"], use_container_width=True)

        with chart_col3:
            ad_summary = report_data.get("accept_deny_summary", [])
            if ad_summary:
                df_ad = pd.DataFrame(ad_summary)
                st.caption("Accept / Deny Bağlantı Dağılımı")
                st.bar_chart(df_ad.set_index("baglanti_karari")["baglanti_sayisi"], use_container_width=True)

        # Detaylı Tehdit Sekmeleri
        st.markdown("---")
        t_risk, t_dest, t_cross, t_transfer, t_webshell, t_bot, t_ftp, t_spray, t_all = st.tabs([
            "🚨 Öncelikli Risk Kuyruğu",
            "🎯 Hedef IP & Port Analizi (Accept/Deny)",
            "📅 Günler Arası Korelasyon",
            "💾 Veri Transfer Kanıtları",
            "🪓 Webshell & Dosya Yönetimi",
            "🤖 Bot & Tarayıcı Tespiti",
            "📁 FTP Operasyonları",
            "🔑 Brute Force & Spraying",
            "⚡ Şüpheli Komutlar & Hassas Yollar",
        ])

        # 1. Risk Kuyrugu
        with t_risk:
            risk_queue = report_data.get("entity_risk_queue", [])
            if risk_queue:
                st.caption(f"Farklı sinyallerin birleştirilmesiyle puanlanan **{len(risk_queue)}** varlık bulundu.")
                df_risk = pd.DataFrame(risk_queue)
                st.dataframe(df_risk, use_container_width=True, hide_index=True)

                st.markdown("#### ⚡ Hızlı Vaka / Olay Oluştur")
                with st.expander("Risk Kuyruğundaki Varlığı Olay Yönetimine Aktar"):
                    chosen_ip = st.selectbox("IP Adresi Seç", options=[r["ip_adresi"] for r in risk_queue])
                    chosen_entity = next((r for r in risk_queue if r["ip_adresi"] == chosen_ip), {})
                    c_title = st.text_input("Vaka Başlığı", value=f"Şüpheli Tehdit Aktivitesi - {chosen_ip}")
                    c_sev = st.selectbox("Ciddiyet", options=["KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"], index=0 if chosen_entity.get("risk_seviyesi") == "KRİTİK" else 1)
                    c_note = st.text_area("Analist İlk İnceleme Notu", value=chosen_entity.get("risk_gerekcesi", ""))
                    if st.button("Vaka Olarak Kaydet"):
                        incident_mgr.create_incident(
                            title=c_title,
                            ip=chosen_ip or "-",
    server=str(chosen_entity.get("sunucu_ismi", "-")),
    severity=c_sev,
    description=str(chosen_entity.get("risk_gerekcesi", "")),
    notes=c_note or "",
                        )
                        st.success(f"{chosen_ip} için vaka başarıyla oluşturuldu!")
            else:
                st.info("Eşiği aşan riskli varlık bulunamadı.")

        # 2. Hedef IP & Port Analizi (Accept / Deny)
        with t_dest:
            st.subheader("🎯 Hedef IP ve Port Trafiği (Accept / Deny Dağılımı)")
            dest_ips = report_data.get("destination_ip_analysis", [])
            ports = report_data.get("port_analysis", [])
            accept_deny = report_data.get("accept_deny_summary", [])

            d_col1, d_col2, d_col3 = st.columns(3)
            tot_accept = sum(int(r.get("accept_sayisi") or 0) for r in dest_ips)
            tot_deny = sum(int(r.get("deny_sayisi") or 0) for r in dest_ips)
            deny_rate = (100.0 * tot_deny / max(tot_accept + tot_deny, 1)) if (tot_accept + tot_deny) > 0 else 0
            d_col1.metric("Toplam Accept (Kabul)", f"{tot_accept:,}")
            d_col2.metric("Toplam Deny (Reddedilen)", f"{tot_deny:,}")
            d_col3.metric("Genel Deny Oranı", f"%{deny_rate:.1f}")

            if dest_ips:
                st.markdown("#### 🌐 En Sık Erişim Sağlanan Hedef IP'ler")
                st.dataframe(pd.DataFrame(dest_ips), use_container_width=True, hide_index=True)

            if ports:
                st.markdown("#### 🔌 Kullanılan Hedef Portlar ve Servis Dağılımı")
                st.dataframe(pd.DataFrame(ports[:50]), use_container_width=True, hide_index=True)

            if accept_deny:
                st.markdown("#### 🛡️ Accept / Deny Karar Özeti")
                st.dataframe(pd.DataFrame(accept_deny), use_container_width=True, hide_index=True)

        # 2. Günler Arası Korelasyon
        with t_cross:
            cross_data = report_data.get("cross_day_correlation", [])
            if cross_data:
                st.warning(
                    "Bu bölüm, aynı saldırgan veya IP'nin farklı log dosyaları veya günlerdeki aktivite zincirini "
                    "(Keşif -> Parola Denemesi -> Webshell/Dizin Gezintisi -> Dosya Yükleme -> Veri Sızdırma) korele eder."
                )
                df_cross = pd.DataFrame(cross_data)
                st.dataframe(df_cross, use_container_width=True, hide_index=True)
            else:
                st.info("Günler arasında eşleşen çoklu aktivite izi bulunamadı.")

        # 3. Veri Transfer Kanitlari
        with t_transfer:
            transfers = report_data.get("data_transfer_details", [])
            largest_100 = report_data.get("largest_transfer_requests", [])
            if transfers:
                st.subheader("Veri Transfer Grupları (IP + Kullanıcı + Sunucu)")
                df_t = pd.DataFrame(transfers)
                st.dataframe(df_t, use_container_width=True, hide_index=True)

            if largest_100:
                st.subheader("En Büyük 100 Tekil Veri Transfer İsteği")
                df_l = pd.DataFrame(largest_100)
                st.dataframe(df_l, use_container_width=True, hide_index=True)

        # 4. Webshell & Dosya Yonetimi
        with t_webshell:
            ws_groups = report_data.get("webshell_and_file_management", [])
            ws_timeline = report_data.get("webshell_activity_timeline", [])
            if ws_groups:
                st.error("🚨 Kritik Webshell / Dosya Yöneticisi / Traversal Bulgusu Tespit Edildi!")
                st.dataframe(pd.DataFrame(ws_groups), use_container_width=True, hide_index=True)
                if ws_timeline:
                    with st.expander("Kronolojik Eylem Akışı (Timeline)"):
                        st.dataframe(pd.DataFrame(ws_timeline), use_container_width=True, hide_index=True)
            else:
                st.success("Webshell veya dosya yöneticisi manipülasyonu tespit edilmedi.")

        # 5. Bot & Tarayici Tespiti
        with t_bot:
            bots = report_data.get("scanner_and_bots", [])
            if bots:
                st.dataframe(pd.DataFrame(bots), use_container_width=True, hide_index=True)
            else:
                st.info("Otomatize bot veya tarayıcı imzası bulunamadı.")

        # 6. FTP Operasyonlari
        with t_ftp:
            ftp_auth = report_data.get("ftp_authentication", [])
            ftp_files = report_data.get("ftp_file_operations", [])
            ftp_susp = report_data.get("ftp_suspicious_activity", [])

            ftp_col1, ftp_col2, ftp_col3 = st.columns(3)
            upload_cnt = sum(int(r.get("yukleme_sayisi") or 0) for r in ftp_files)
            download_cnt = sum(int(r.get("indirme_sayisi") or 0) for r in ftp_files)
            delete_cnt = sum(int(r.get("silme_sayisi") or 0) for r in ftp_files)
            ftp_col1.metric("FTP Dosya Yükleme (STOR)", upload_cnt)
            ftp_col2.metric("FTP Dosya İndirme (RETR)", download_cnt)
            ftp_col3.metric("FTP Dosya Silme (DELE)", delete_cnt)

            if ftp_files:
                st.markdown("#### FTP Dosya Operasyonları")
                st.dataframe(pd.DataFrame(ftp_files[:50]), use_container_width=True, hide_index=True)
            if ftp_auth:
                st.markdown("#### FTP Kimlik Doğrulama Grubu")
                st.dataframe(pd.DataFrame(ftp_auth[:50]), use_container_width=True, hide_index=True)
            if ftp_susp:
                st.markdown("#### FTP Şüpheli İşlemler ve Hatalar (530/550)")
                st.dataframe(pd.DataFrame(ftp_susp[:100]), use_container_width=True, hide_index=True)

        # 7. Brute Force & Password Spraying
        with t_spray:
            brute = report_data.get("brute_force_attempts", [])
            spray = report_data.get("password_spraying", [])
            if spray:
                st.error("🚨 Password Spraying Saldırısı Tespit Edildi!")
                st.dataframe(pd.DataFrame(spray), use_container_width=True, hide_index=True)
            if brute:
                st.warning("Brute Force Parola Denemeleri")
                st.dataframe(pd.DataFrame(brute), use_container_width=True, hide_index=True)
            if not spray and not brute:
                st.info("Brute force veya password spraying alarmı eşiğin altında.")

        # 8. Supheli Komutlar & Hassas Yollar
        with t_all:
            cmds = report_data.get("suspicious_commands", [])
            sens = report_data.get("sensitive_endpoints", [])
            if cmds:
                st.subheader("500 Çökmesi ve Komut Enjeksiyonları")
                st.dataframe(pd.DataFrame(cmds), use_container_width=True, hide_index=True)
            if sens:
                st.subheader("Hassas Dizin ve Yapılandırma Dosyası Erişimleri")
                st.dataframe(pd.DataFrame(sens), use_container_width=True, hide_index=True)
    else:
        st.info("👆 Başlamak için yukarıdan log dosyalarınızı seçin veya 'Dizindeki Tüm Logları Yükle' butonuna tıklayın.")


# ==============================================================================
# 2. SEKME: OLAY YONETIMI (INCIDENT MANAGEMENT)
# ==============================================================================
with tab_incidents:
    st.subheader("📋 SOC Vaka ve Olay Yönetimi (Incident Lifecycle)")
    st.caption("Olayların durumunu takip edin: Yeni, İnceleniyor, Kapatıldı. Veriler kalıcı olarak saklanır.")

    inc_col1, inc_col2 = st.columns([1, 3])
    with inc_col1:
        status_filter = st.selectbox("Duruma Göre Filtrele", ["Tümü", "Yeni", "İnceleniyor", "Kapatıldı"])
        st.markdown("---")
        with st.expander("➕ Manuel Yeni Olay Oluştur"):
            m_title = st.text_input("Vaka Başlığı*", key="m_title")
            m_ip = st.text_input("IP Adresi", key="m_ip")
            m_server = st.text_input("Sunucu", key="m_server")
            m_user = st.text_input("Kullanıcı Adı", key="m_user")
            m_sev = st.selectbox("Ciddiyet", ["KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"], key="m_sev")
            m_desc = st.text_area("Açıklama / Bulgular", key="m_desc")
            if st.button("Olayı Kaydet", key="m_submit"):
                if m_title.strip():
                    incident_mgr.create_incident(
                        title=m_title,
                        ip=m_ip,
                        server=m_server,
                        username=m_user,
                        severity=m_sev,
                        description=m_desc,
                    )
                    st.success("Yeni vaka eklendi!")
                    st.rerun()

    with inc_col2:
        all_incidents = incident_mgr.list_incidents(status_filter)
        if all_incidents:
            for inc in all_incidents:
                with st.container():
                    sev = inc.get("severity", "YÜKSEK")
                    badge_class = "risk-badge-kritik" if sev == "KRİTİK" else "risk-badge-yuksek" if sev == "YÜKSEK" else "risk-badge-orta"
                    st.markdown(
                        f"""
                        <div style="background:white; border:1px solid #e2e8f0; border-radius:8px; padding:1rem; margin-bottom:1rem;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <div>
                                    <span class="{badge_class}">{sev}</span>
                                    <strong style="font-size:1.1rem; margin-left:8px;">{inc['title']}</strong>
                                    <span style="color:#64748b; font-size:0.85rem; margin-left:10px;">({inc['id']})</span>
                                </div>
                                <div>
                                    <span style="font-weight:700; color:#0f172a;">Durum: {inc.get('status', 'Yeni')}</span>
                                </div>
                            </div>
                            <div style="font-size:0.85rem; color:#475569; margin-top:0.5rem;">
                                <strong>IP:</strong> {inc.get('ip')} | <strong>Sunucu:</strong> {inc.get('server')} | <strong>Oluşturulma:</strong> {inc.get('created_at')}
                            </div>
                            <div style="margin-top:0.5rem; font-size:0.9rem;">
                                {inc.get('description', '')}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    # Olay Aksiyonlari
                    act_col1, act_col2, act_col3 = st.columns([1, 2, 1])
                    with act_col1:
                        new_st = st.selectbox("Durumu Güncelle", ["Yeni", "İnceleniyor", "Kapatıldı"], index=["Yeni", "İnceleniyor", "Kapatıldı"].index(inc.get("status", "Yeni")), key=f"st_{inc['id']}")
                        if new_st != inc.get("status"):
                            incident_mgr.update_status(inc["id"], new_st)
                            st.rerun()
                    with act_col2:
                        add_n = st.text_input("Yeni Analist Notu Ekle", key=f"note_{inc['id']}")
                        if st.button("Notu Ekle", key=f"btn_note_{inc['id']}"):
                            if add_n.strip():
                                incident_mgr.add_note(inc["id"], add_n)
                                st.success("Not eklendi!")
                                st.rerun()
                    with act_col3:
                        if st.button("🗑️ Sil", key=f"del_{inc['id']}"):
                            incident_mgr.delete_incident(inc["id"])
                            st.rerun()
                    st.markdown("---")
        else:
            st.info("Filtreye uygun olay bulunamadı.")


# ==============================================================================
# 3. SEKME: ALLOWLIST (GUVENILEN LISTE)
# ==============================================================================
with tab_allowlist:
    st.subheader("🛡️ SOC Allowlist Yönetimi")
    st.caption("Güvenilen varlıkları buraya ekleyerek analiz sonuçlarındaki false-positive alarmları engelleyin.")

    al_col1, al_col2 = st.columns(2)

    with al_col1:
        st.markdown("#### Güvenilen IP ve CIDR Blokları")
        st.write("**Kayıtlı IP'ler:**")
        for ip in allowlist_mgr.data.get("ips", []):
            i_col1, i_col2 = st.columns([3, 1])
            i_col1.code(ip)
            if i_col2.button("Kaldır", key=f"del_ip_{ip}"):
                allowlist_mgr.remove_entry("ips", ip)
                st.rerun()

        new_ip = st.text_input("Yeni Güvenilir IP Ekle (Örn: 10.54.206.10)")
        if st.button("IP Ekle"):
            if new_ip.strip() and allowlist_mgr.add_entry("ips", new_ip.strip()):
                st.success(f"{new_ip} allowlist'e eklendi!")
                st.rerun()

        st.markdown("---")
        st.write("**Kayıtlı CIDR Aralıkları:**")
        for cidr in allowlist_mgr.data.get("cidrs", []):
            c_col1, c_col2 = st.columns([3, 1])
            c_col1.code(cidr)
            if c_col2.button("Kaldır", key=f"del_cidr_{cidr}"):
                allowlist_mgr.remove_entry("cidrs", cidr)
                st.rerun()

        new_cidr = st.text_input("Yeni Güvenilir CIDR Ekle (Örn: 192.168.1.0/24)")
        if st.button("CIDR Ekle"):
            if new_cidr.strip() and allowlist_mgr.add_entry("cidrs", new_cidr.strip()):
                st.success(f"{new_cidr} allowlist'e eklendi!")
                st.rerun()

    with al_col2:
        st.markdown("#### Güvenilen Servis Hesapları & Sunucular")
        st.write("**Kayıtlı Servis Hesapları:**")
        for acc in allowlist_mgr.data.get("service_accounts", []):
            a_col1, a_col2 = st.columns([3, 1])
            a_col1.code(acc)
            if a_col2.button("Kaldır", key=f"del_acc_{acc}"):
                allowlist_mgr.remove_entry("service_accounts", acc)
                st.rerun()

        new_acc = st.text_input("Yeni Güvenilir Servis Hesabı Ekle (Örn: NT AUTHORITY\\SYSTEM)")
        if st.button("Hesap Ekle"):
            if new_acc.strip() and allowlist_mgr.add_entry("service_accounts", new_acc.strip()):
                st.success(f"{new_acc} allowlist'e eklendi!")
                st.rerun()


# ==============================================================================
# 4. SEKME: CANLI KLASOR IZLEYICI (WATCHER)
# ==============================================================================
with tab_watcher:
    st.subheader("📡 Canlı Klasör İzleme Servisi (Live Watcher)")
    st.caption("Hedef log dizinini arka planda izler ve klasöre yeni bir log dosyası düştüğünde anında tespit eder.")

    watcher_col1, watcher_col2 = st.columns([1, 2])

    with watcher_col1:
        watch_path = st.text_input("İzlenecek Klasör Yolu", value=str(Path(".").resolve()))
        w_instance: DirectoryWatcher | None = st.session_state.watcher_instance

        if w_instance and w_instance.is_running:
            st.success("🟢 İzleme Servisi Aktif!")
            if st.button("İzlemeyi Durdur", type="secondary"):
                w_instance.stop()
                st.session_state.watcher_instance = None
                st.rerun()
        else:
            st.warning("⚪ İzleme Servisi Durduruldu.")
            if st.button("İzlemeyi Başlat", type="primary"):
                watcher = DirectoryWatcher(watch_path)
                if watcher.start():
                    st.session_state.watcher_instance = watcher
                    st.success(f"{watch_path} başarıyla izleniyor!")
                    st.rerun()
                else:
                    st.error("Klasör izleme başlatılamadı. Yolu kontrol edin.")

    with watcher_col2:
        st.markdown("#### Yakalanan Son Dosya Hareketleri")
        if w_instance:
            events = w_instance.get_recent_events()
            if events:
                st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
            else:
                st.info("Henüz yeni bir dosya oluşturulmadı veya değiştirilmedi.")
        else:
            st.info("Canlı izleme başlatıldığında yeni log olayları burada listelenecektir.")
