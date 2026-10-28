"""SOC Tehdit Avi ve Olay Raporu Ureteci.

Tamamen bagimsiz, yazdirilabilir (PDF dostu) profesyonel HTML raporu olusturur.
"""

from __future__ import annotations

import datetime
import html
import json
from pathlib import Path
from typing import Any


def generate_html_report(
    report_data: dict[str, Any],
    report_title: str = "SOC Threat Hunting & Incident Investigation Report",
    analyst_name: str = "SOC Tehdit Avcisi (L2/L3)",
) -> str:
    """Rapor verilerini zengin, temiz ve PDF formatina uygun HTML dokumanina donusturur."""
    summary = report_data.get("summary", {})
    now_str = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    def esc(val: Any) -> str:
        if val is None:
            return "-"
        return html.escape(str(val))

    def format_num(val: Any) -> str:
        if val is None:
            return "0"
        try:
            return f"{int(val):,}"
        except (ValueError, TypeError):
            try:
                return f"{float(val):,.2f}"
            except (ValueError, TypeError):
                return esc(val)

    # Tables data
    risk_queue = report_data.get("entity_risk_queue", [])
    transfers = report_data.get("data_transfer_details", [])
    largest_reqs = report_data.get("largest_transfer_requests", [])[:50]
    webshell = report_data.get("webshell_and_file_management", [])
    bots = report_data.get("scanner_and_bots", [])
    cross_day = report_data.get("cross_day_correlation", [])
    ftp_auth = report_data.get("ftp_authentication", [])[:30]
    ftp_files = report_data.get("ftp_file_operations", [])[:30]
    dest_ips = report_data.get("destination_ip_analysis", [])[:25]
    ports = report_data.get("port_analysis", [])[:25]
    accept_deny = report_data.get("accept_deny_summary", [])

    # Calculate overall transfer sum
    total_gb = sum(float(r.get("toplam_transfer_gb") or 0) for r in transfers)

    html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(report_title)}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    
    :root {{
        --primary: #0f172a;
        --secondary: #334155;
        --danger: #dc2626;
        --warning: #ea580c;
        --success: #16a34a;
        --info: #2563eb;
        --border: #e2e8f0;
        --bg: #f8fafc;
    }}
    
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Inter', sans-serif;
        background-color: var(--bg);
        color: var(--primary);
        line-height: 1.5;
        padding: 2.5rem;
    }}
    
    .container {{
        max-width: 1200px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 12px;
        padding: 3rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.05);
        border: 1px solid var(--border);
    }}
    
    header {{
        border-bottom: 2px solid var(--primary);
        padding-bottom: 1.5rem;
        margin-bottom: 2rem;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }}
    
    h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem; }}
    .subtitle {{ color: #64748b; font-size: 0.95rem; }}
    .meta-box {{ text-align: right; font-size: 0.85rem; color: #475569; }}
    .meta-box strong {{ color: var(--primary); }}
    
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1.25rem;
        margin-bottom: 2.5rem;
    }}
    
    .kpi-card {{
        background: #f1f5f9;
        border-radius: 8px;
        padding: 1.25rem;
        border-left: 4px solid var(--info);
    }}
    .kpi-card.danger {{ border-left-color: var(--danger); }}
    .kpi-card.warning {{ border-left-color: var(--warning); }}
    .kpi-card.success {{ border-left-color: var(--success); }}
    
    .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; color: #64748b; font-weight: 600; letter-spacing: 0.05em; }}
    .kpi-val {{ font-size: 1.6rem; font-weight: 700; color: var(--primary); margin-top: 0.25rem; }}
    
    h2 {{
        font-size: 1.25rem;
        font-weight: 700;
        margin: 2.5rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }}
    
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 1.5rem;
        font-size: 0.85rem;
    }}
    
    th, td {{
        padding: 0.65rem 0.75rem;
        text-align: left;
        border-bottom: 1px solid var(--border);
    }}
    
    th {{
        background: #f8fafc;
        font-weight: 600;
        color: #475569;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.04em;
    }}
    
    tr:hover td {{ background: #fdfdfd; }}
    
    .badge {{
        display: inline-block;
        padding: 0.2rem 0.55rem;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }}
    .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
    .badge-warning {{ background: #ffedd5; color: #c2410c; }}
    .badge-info {{ background: #dbeafe; color: #1d4ed8; }}
    .badge-success {{ background: #dcfce7; color: #15803d; }}
    .badge-neutral {{ background: #f1f5f9; color: #475569; }}
    
    .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }}
    
    .callout {{
        background: #eff6ff;
        border-left: 4px solid var(--info);
        padding: 1rem 1.25rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 1.5rem;
        font-size: 0.9rem;
        color: #1e3a8a;
    }}
    .callout-warning {{
        background: #fffbeb;
        border-left-color: var(--warning);
        color: #92400e;
    }}

    .print-btn {{
        display: inline-block;
        background: var(--primary);
        color: white;
        padding: 0.6rem 1.2rem;
        border-radius: 6px;
        text-decoration: none;
        font-weight: 600;
        font-size: 0.9rem;
        cursor: pointer;
        border: none;
        margin-bottom: 1.5rem;
    }}

    @media print {{
        body {{ background: white; padding: 0; }}
        .container {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
        .print-btn {{ display: none; }}
        table {{ page-break-inside: auto; }}
        tr {{ page-break-inside: avoid; page-break-after: auto; }}
        h2 {{ page-break-after: avoid; }}
    }}
</style>
</head>
<body>
<div class="container">
    <button class="print-btn" onclick="window.print()">🖨️ Raporu Yazdır / PDF Kaydet</button>

    <header>
        <div>
            <h1>{esc(report_title)}</h1>
            <div class="subtitle">SOC Tehdit Avcılığı, Güvenlik Olayı ve SIEM Korelasyon İncelemesi</div>
        </div>
        <div class="meta-box">
            <div><strong>Rapor Tarihi:</strong> {now_str}</div>
            <div><strong>Analist:</strong> {esc(analyst_name)}</div>
            <div><strong>Analiz Aralığı:</strong> {esc(summary.get('ilk_tarih', '-'))} &rarr; {esc(summary.get('son_tarih', '-'))}</div>
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">Toplam İncelenen Olay</div>
            <div class="kpi-val">{format_num(summary.get('toplam_olay', 0))}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Farklı Kaynak IP</div>
            <div class="kpi-val">{format_num(summary.get('farkli_ip_sayisi', 0))}</div>
        </div>
        <div class="kpi-card warning">
            <div class="kpi-label">Auth Hataları (401/403)</div>
            <div class="kpi-val">{format_num(summary.get('auth_failure_sayisi', 0))}</div>
        </div>
        <div class="kpi-card danger">
            <div class="kpi-label">Sunucu Hataları (5xx)</div>
            <div class="kpi-val">{format_num(summary.get('server_error_sayisi', 0))}</div>
        </div>
        <div class="kpi-card success">
            <div class="kpi-label">Başarılı Transfer</div>
            <div class="kpi-val">{total_gb:,.2f} GB</div>
        </div>
        <div class="kpi-card success">
            <div class="kpi-label">Accept (Kabul) Bağlantı</div>
            <div class="kpi-val">{format_num(summary.get('accept_sayisi', 0))}</div>
        </div>
        <div class="kpi-card danger">
            <div class="kpi-label">Deny (Engellenen) Bağlantı</div>
            <div class="kpi-val">{format_num(summary.get('deny_sayisi', 0))}</div>
        </div>
    </div>

    <h2>🚨 Öncelikli Tehdit & Risk Kuyruğu (Entity Risk Queue)</h2>
    <div class="callout">
        Birden fazla sinyal (yüksek transfer, 401/403 fırtınası, hassas endpoint erişimleri ve sunucu hataları) birleştirilerek varlık bazında risk puanı hesaplanmıştır.
    </div>
"""

    if risk_queue:
        html_content += """
        <table>
            <thead>
                <tr>
                    <th>IP Adresi</th>
                    <th>Sunucu</th>
                    <th>Risk Seviyesi</th>
                    <th>Risk Puanı</th>
                    <th>İstek Sayısı</th>
                    <th>Endpoint Sayısı</th>
                    <th>Auth Hatası</th>
                    <th>5xx Hata</th>
                    <th>Risk Gerekçeleri</th>
                </tr>
            </thead>
            <tbody>
        """
        for row in risk_queue[:30]:
            sev = row.get("risk_seviyesi", "DÜŞÜK")
            badge_cls = "badge-danger" if sev == "KRİTİK" else "badge-warning" if sev == "YÜKSEK" else "badge-info"
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(row.get('ip_adresi'))}</strong></td>
                    <td>{esc(row.get('sunucu_ismi'))}</td>
                    <td><span class="badge {badge_cls}">{esc(sev)}</span></td>
                    <td><strong>{esc(row.get('risk_puani'))}</strong></td>
                    <td>{format_num(row.get('toplam_istek'))}</td>
                    <td>{format_num(row.get('farkli_endpoint_sayisi'))}</td>
                    <td>{format_num(row.get('auth_hatasi'))}</td>
                    <td>{format_num(row.get('server_hatasi'))}</td>
                    <td><small>{esc(row.get('risk_gerekcesi'))}</small></td>
                </tr>
            """
        html_content += "</tbody></table>"
    else:
        html_content += "<p>Eşiği aşan riskli varlık bulunamadı.</p>"

    # Cross-Day Correlation
    if cross_day:
        html_content += """
        <h2>📅 Günler Arası Tehdit İlişkilendirme (Cross-Day Correlation)</h2>
        <div class="callout callout-warning">
            Aynı aktörün birden fazla log dosyası veya günde gerçekleştirdiği devam eden aktiviteler ve saldırı aşamaları.
        </div>
        <table>
            <thead>
                <tr>
                    <th>IP Adresi</th>
                    <th>Kullanıcı / Hesap</th>
                    <th>Hedef Sunucular</th>
                    <th>Aktif Gün Sayısı</th>
                    <th>İlk Aktivite</th>
                    <th>Son Aktivite</th>
                    <th>Toplam İstek</th>
                    <th>Tespit Edilen Aşama İzleri</th>
                </tr>
            </thead>
            <tbody>
        """
        for c in cross_day[:25]:
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(c.get('ip_adresi'))}</strong></td>
                    <td>{esc(c.get('kullanici_adi'))}</td>
                    <td>{esc(c.get('sunucular'))}</td>
                    <td><span class="badge badge-info">{esc(c.get('gun_sayisi'))} gün</span></td>
                    <td><small>{esc(c.get('ilk_aktivite'))}</small></td>
                    <td><small>{esc(c.get('son_aktivite'))}</small></td>
                    <td>{format_num(c.get('toplam_istek'))}</td>
                    <td><small>{esc(c.get('asama_izleri'))}</small></td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Data Transfer Details
    if transfers:
        html_content += """
        <h2>💾 Veri Transfer Analizi & Sızdırma Kanıtları</h2>
        <table>
            <thead>
                <tr>
                    <th>Kaynak Dosya</th>
                    <th>IP Adresi</th>
                    <th>Kullanıcı Adı</th>
                    <th>Sunucu</th>
                    <th>Başarılı İstek</th>
                    <th>Toplam (GB)</th>
                    <th>Toplam (MB)</th>
                    <th>Ortalama (Byte)</th>
                    <th>En Büyük Tekil (MB)</th>
                    <th>Toplam Payı %</th>
                </tr>
            </thead>
            <tbody>
        """
        for t in transfers[:30]:
            html_content += f"""
                <tr>
                    <td><small>{esc(t.get('kaynak_dosya'))}</small></td>
                    <td class="mono">{esc(t.get('ip_adresi'))}</td>
                    <td>{esc(t.get('kullanici_adi'))}</td>
                    <td>{esc(t.get('sunucu_ismi'))}</td>
                    <td>{format_num(t.get('basarili_istek_sayisi'))}</td>
                    <td><strong>{format_num(t.get('toplam_transfer_gb'))} GB</strong></td>
                    <td>{format_num(t.get('toplam_transfer_mb'))} MB</td>
                    <td>{format_num(t.get('ortalama_transfer_byte'))}</td>
                    <td>{format_num(t.get('en_buyuk_tekil_transfer_mb'))} MB</td>
                    <td>{format_num(t.get('toplam_transfer_yuzdesi'))}%</td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Webshell & File Management
    if webshell:
        html_content += """
        <h2>🪓 Webshell & Dosya Yöneticisi Bulguları</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Adresi</th>
                    <th>Sunucu</th>
                    <th>İstek</th>
                    <th>Hata (4xx)</th>
                    <th>Sunucu Hatası (5xx)</th>
                    <th>Toplam Byte</th>
                    <th>İlk / Son Görülme</th>
                    <th>Örnek Komutlar</th>
                </tr>
            </thead>
            <tbody>
        """
        for w in webshell[:25]:
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(w.get('ip_adresi'))}</strong></td>
                    <td>{esc(w.get('sunucu_ismi'))}</td>
                    <td>{format_num(w.get('istek_sayisi'))}</td>
                    <td>{format_num(w.get('hata_sayisi'))}</td>
                    <td><strong>{format_num(w.get('server_hatasi'))}</strong></td>
                    <td>{format_num(w.get('toplam_yanit_byte'))}</td>
                    <td><small>{esc(w.get('ilk_gorulme'))}<br>{esc(w.get('son_gorulme'))}</small></td>
                    <td class="mono"><small>{esc(w.get('eylem_ornekleri'))[:200]}</small></td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Scanners and Bots
    if bots:
        html_content += """
        <h2>🤖 Otomatize Tarayıcılar ve Botlar (Scanners & Bots)</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Adresi</th>
                    <th>User Agent</th>
                    <th>Farklı İstek / Komut</th>
                    <th>Toplam İstek</th>
                    <th>Tespit Nedeni</th>
                </tr>
            </thead>
            <tbody>
        """
        for b in bots[:25]:
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(b.get('ip_adresi'))}</strong></td>
                    <td><small>{esc(b.get('user_agent'))}</small></td>
                    <td>{format_num(b.get('farkli_komut_sayisi'))}</td>
                    <td>{format_num(b.get('toplam_istek'))}</td>
                    <td><span class="badge badge-warning">{esc(b.get('bot_sebebi', 'Yuksek cesitlilik'))}</span></td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Destination IPs (Erisim Saglanan Hedef IP'ler)
    if dest_ips:
        html_content += """
        <h2>🎯 Erişim Sağlanan Hedef IP'ler (En Sık Erişilenler)</h2>
        <table>
            <thead>
                <tr>
                    <th>Hedef IP (Destination)</th>
                    <th>Toplam Bağlantı</th>
                    <th>Kaynak IP Adedi</th>
                    <th>Kullanılan Portlar</th>
                    <th>Accept (Kabul)</th>
                    <th>Deny (Red)</th>
                    <th>Deny Oranı %</th>
                    <th>Toplam Transfer (MB)</th>
                </tr>
            </thead>
            <tbody>
        """
        for d in dest_ips:
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(d.get('hedef_ip'))}</strong></td>
                    <td>{format_num(d.get('toplam_baglanti'))}</td>
                    <td>{format_num(d.get('erisen_kaynak_ip_sayisi'))}</td>
                    <td class="mono"><small>{esc(d.get('portlar'))[:80]}</small></td>
                    <td><span class="badge badge-success">{format_num(d.get('accept_sayisi'))}</span></td>
                    <td><span class="badge badge-danger">{format_num(d.get('deny_sayisi'))}</span></td>
                    <td>{format_num(d.get('deny_orani'))}%</td>
                    <td>{format_num(d.get('toplam_transfer_mb'))} MB</td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Ports (Kullanilan Portlar)
    if ports:
        html_content += """
        <h2>🔌 Kullanılan Portlar ve Servis Dağılımı</h2>
        <table>
            <thead>
                <tr>
                    <th>Port Numarası</th>
                    <th>Tahmini Protokol / Servis</th>
                    <th>Bağlantı Sayısı</th>
                    <th>Accept Sayısı</th>
                    <th>Deny Sayısı</th>
                    <th>Farklı İstemci Sayısı</th>
                    <th>Toplam Hacim (MB)</th>
                </tr>
            </thead>
            <tbody>
        """
        for p in ports:
            html_content += f"""
                <tr>
                    <td class="mono"><strong>{esc(p.get('port'))}</strong></td>
                    <td><span class="badge badge-info">{esc(p.get('servis_tahmini'))}</span></td>
                    <td>{format_num(p.get('baglanti_sayisi'))}</td>
                    <td><span class="badge badge-success">{format_num(p.get('accept_sayisi'))}</span></td>
                    <td><span class="badge badge-danger">{format_num(p.get('deny_sayisi'))}</span></td>
                    <td>{format_num(p.get('erisen_istemci_sayisi'))}</td>
                    <td>{format_num(p.get('toplam_mb'))} MB</td>
                </tr>
            """
        html_content += "</tbody></table>"

    # Accept / Deny Summary
    if accept_deny:
        html_content += """
        <h2>🛡️ Accept / Deny Bağlantı Kararları Özeti</h2>
        <table>
            <thead>
                <tr>
                    <th>Bağlantı Kararı</th>
                    <th>Bağlantı Sayısı</th>
                    <th>Toplam İçindeki Oran (%)</th>
                </tr>
            </thead>
            <tbody>
        """
        for a in accept_deny:
            karar = a.get('baglanti_karari', '-')
            b_class = "badge-success" if karar == "ACCEPT" else "badge-danger" if karar == "DENY" else "badge-neutral"
            html_content += f"""
                <tr>
                    <td><span class="badge {b_class}">{esc(karar)}</span></td>
                    <td><strong>{format_num(a.get('baglanti_sayisi'))}</strong></td>
                    <td>{format_num(a.get('oran_yuzde'))}%</td>
                </tr>
            """
        html_content += "</tbody></table>"

    html_content += """
    <footer style="margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #e2e8f0; font-size: 0.8rem; color: #94a3b8; text-align: center;">
        Bu rapor SOC Log Lens Tehdit Avcılığı Motoru tarafından otomatik olarak oluşturulmuştur. &bull; Gizli & Kuruma Özel
    </footer>
</div>
</body>
</html>
"""
    return html_content
