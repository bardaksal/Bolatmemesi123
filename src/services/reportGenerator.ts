import { HuntingReport } from '../types';

export function generateHTMLReport(
  report: HuntingReport,
  reportTitle: string = 'SOC Threat Hunting & Incident Investigation Report',
  analystName: string = 'SOC Tehdit Avcısı (L2/L3)'
): string {
  const summary = report.summary || {
    toplam_olay: 0,
    ilk_tarih: '-',
    son_tarih: '-',
    farkli_ip_sayisi: 0,
    farkli_hedef_ip_sayisi: 0,
    farkli_sunucu_sayisi: 0,
    farkli_endpoint_sayisi: 0,
    server_error_sayisi: 0,
    auth_failure_sayisi: 0,
    accept_sayisi: 0,
    deny_sayisi: 0,
    toplam_transfer_byte: 0,
  };
  const nowStr = new Date().toLocaleString('tr-TR');
  const rawTotalGb = report.toplam_gb !== undefined ? report.toplam_gb : ((summary.toplam_transfer_byte || 0) / (1024 * 1024 * 1024));
  const totalGb = isNaN(Number(rawTotalGb)) ? 0 : Number(rawTotalGb);

  const esc = (val: unknown): string => {
    if (val === null || val === undefined) return '-';
    return String(val).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  };

  const formatNum = (val: unknown): string => {
    if (val === null || val === undefined) return '0';
    const num = Number(val);
    if (isNaN(num)) return esc(val);
    return num.toLocaleString('tr-TR');
  };

  const riskQueue = report.entity_risk_queue || [];
  const crossDay = report.cross_day_correlation || [];
  const transfers = report.data_transfer_details || [];
  const webshell = report.webshell_and_file_management || [];
  const bots = report.scanner_and_bots || [];
  const destIps = report.destination_ip_analysis || [];
  const ports = report.port_analysis || [];
  const acceptDeny = report.accept_deny_summary || [];

  let htmlContent = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(reportTitle)}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    
    :root {
        --primary: #0f172a;
        --secondary: #334155;
        --danger: #dc2626;
        --warning: #ea580c;
        --success: #16a34a;
        --info: #2563eb;
        --border: #e2e8f0;
        --bg: #f8fafc;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Inter', sans-serif;
        background-color: var(--bg);
        color: var(--primary);
        line-height: 1.5;
        padding: 2.5rem;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 12px;
        padding: 3rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.05);
        border: 1px solid var(--border);
    }
    
    header {
        border-bottom: 2px solid var(--primary);
        padding-bottom: 1.5rem;
        margin-bottom: 2rem;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }
    
    h1 { font-size: 1.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem; }
    .subtitle { color: #64748b; font-size: 0.95rem; }
    .meta-box { text-align: right; font-size: 0.85rem; color: #475569; }
    .meta-box strong { color: var(--primary); }
    
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 1rem;
        margin-bottom: 2.5rem;
    }
    
    .kpi-card {
        background: #f1f5f9;
        border-radius: 8px;
        padding: 1.1rem;
        border-left: 4px solid var(--info);
    }
    .kpi-card.danger { border-left-color: var(--danger); }
    .kpi-card.warning { border-left-color: var(--warning); }
    .kpi-card.success { border-left-color: var(--success); }
    
    .kpi-label { font-size: 0.75rem; text-transform: uppercase; color: #64748b; font-weight: 600; letter-spacing: 0.05em; }
    .kpi-val { font-size: 1.5rem; font-weight: 700; color: var(--primary); margin-top: 0.25rem; }
    
    h2 {
        font-size: 1.25rem;
        font-weight: 700;
        margin: 2.5rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 1.5rem;
        font-size: 0.85rem;
    }
    
    th, td {
        padding: 0.65rem 0.75rem;
        text-align: left;
        border-bottom: 1px solid var(--border);
    }
    
    th {
        background: #f8fafc;
        font-weight: 600;
        color: #475569;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.04em;
    }
    
    tr:hover td { background: #fdfdfd; }
    
    .badge {
        display: inline-block;
        padding: 0.2rem 0.55rem;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    .badge-danger { background: #fee2e2; color: #b91c1c; }
    .badge-warning { background: #ffedd5; color: #c2410c; }
    .badge-info { background: #dbeafe; color: #1d4ed8; }
    .badge-success { background: #dcfce7; color: #15803d; }
    .badge-neutral { background: #f1f5f9; color: #475569; }
    
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
    
    .callout {
        background: #eff6ff;
        border-left: 4px solid var(--info);
        padding: 1rem 1.25rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 1.5rem;
        font-size: 0.9rem;
        color: #1e3a8a;
    }
    .callout-warning {
        background: #fffbeb;
        border-left-color: var(--warning);
        color: #92400e;
    }

    .print-btn {
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
    }

    @media print {
        body { background: white; padding: 0; }
        .container { border: none; box-shadow: none; padding: 0; max-width: 100%; }
        .print-btn { display: none; }
        table { page-break-inside: auto; }
        tr { page-break-inside: avoid; page-break-after: auto; }
        h2 { page-break-after: avoid; }
    }
</style>
</head>
<body>
<div class="container">
    <button class="print-btn" onclick="window.print()">🖨️ Raporu Yazdır / PDF Kaydet</button>

    <header>
        <div>
            <h1>${esc(reportTitle)}</h1>
            <div class="subtitle">SOC Tehdit Avcılığı, Güvenlik Olayı ve SIEM Korelasyon İncelemesi</div>
        </div>
        <div class="meta-box">
            <div><strong>Rapor Tarihi:</strong> ${nowStr}</div>
            <div><strong>Analist:</strong> ${esc(analystName)}</div>
            <div><strong>Analiz Aralığı:</strong> ${esc(summary.ilk_tarih || '-')} &rarr; ${esc(summary.son_tarih || '-')}</div>
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">Toplam İncelenen Olay</div>
            <div class="kpi-val">${formatNum(summary.toplam_olay)}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Farklı Kaynak IP</div>
            <div class="kpi-val">${formatNum(summary.farkli_ip_sayisi)}</div>
        </div>
        <div class="kpi-card warning">
            <div class="kpi-label">Auth Hataları (401/403)</div>
            <div class="kpi-val">${formatNum(report.auth_hatasi_sayisi || summary.auth_failure_sayisi || 0)}</div>
        </div>
        <div class="kpi-card danger">
            <div class="kpi-label">Sunucu Hataları (5xx)</div>
            <div class="kpi-val">${formatNum(summary.server_error_sayisi)}</div>
        </div>
        <div class="kpi-card success">
            <div class="kpi-label">Başarılı Transfer</div>
            <div class="kpi-val">${totalGb.toFixed(2)} GB</div>
        </div>
        <div class="kpi-card success">
            <div class="kpi-label">Accept (Kabul) Bağlantı</div>
            <div class="kpi-val">${formatNum(report.accept_sayisi || 0)}</div>
        </div>
        <div class="kpi-card danger">
            <div class="kpi-label">Deny (Engellenen) Bağlantı</div>
            <div class="kpi-val">${formatNum(report.deny_sayisi || 0)}</div>
        </div>
    </div>

    ${report.quarantine ? `
    <div class="callout ${report.quarantine.quarantinedCount > 0 ? 'callout-warning' : ''}" style="border-radius: 8px; margin-bottom: 2rem;">
        <div style="font-weight: 700; font-size: 0.95rem; margin-bottom: 0.35rem;">
            ⚖️ Adli Bilişim Bütünlük & Kanıt Dipnotu (Forensic Audit Footnote)
        </div>
        <div style="font-size: 0.9rem; margin-bottom: 0.4rem;">
            <strong>Adli Dipnot:</strong> ${esc(report.quarantine.footnoteText)}
        </div>
        <div style="font-size: 0.8rem; opacity: 0.9; font-family: 'JetBrains Mono', monospace;">
            Toplam Okunan Satır: ${formatNum(report.quarantine.totalLinesRead)} | 
            Standart Olay: ${formatNum(report.quarantine.parsedEventsCount)} | 
            Başlık/Direktif (#): ${formatNum(report.quarantine.headerCommentLinesCount)} | 
            Boş Satır: ${formatNum(report.quarantine.emptyLinesCount)} | 
            Karantina: <strong>${formatNum(report.quarantine.quarantinedCount)}</strong>
        </div>
    </div>
    ` : ''}

    <h2>🚨 Öncelikli Tehdit & Risk Kuyruğu (Entity Risk Queue)</h2>
    <div class="callout">
        Birden fazla sinyal (yüksek transfer, 401/403 fırtınası, hassas endpoint erişimleri ve sunucu hataları) birleştirilerek varlık bazında risk puanı hesaplanmıştır.
    </div>
`;

  if (riskQueue.length > 0) {
    htmlContent += `
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
    `;
    for (const row of riskQueue.slice(0, 30)) {
      const sev = row.risk_seviyesi || 'DÜŞÜK';
      const badgeCls = sev === 'KRİTİK' ? 'badge-danger' : sev === 'YÜKSEK' ? 'badge-warning' : 'badge-info';
      htmlContent += `
                <tr>
                    <td class="mono"><strong>${esc(row.ip_adresi)}</strong></td>
                    <td>${esc(row.sunucu_ismi)}</td>
                    <td><span class="badge ${badgeCls}">${esc(sev)}</span></td>
                    <td><strong>${esc(row.risk_puani)}</strong></td>
                    <td>${formatNum(row.toplam_istek)}</td>
                    <td>${formatNum(row.farkli_endpoint_sayisi)}</td>
                    <td>${formatNum(row.auth_hatasi)}</td>
                    <td>${formatNum(row.server_hatasi)}</td>
                    <td><small>${esc(row.risk_gerekcesi)}</small></td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  } else {
    htmlContent += `<p>Eşiği aşan riskli varlık bulunamadı.</p>`;
  }

  // Cross-Day Correlation
  if (crossDay.length > 0) {
    htmlContent += `
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
    `;
    for (const c of crossDay.slice(0, 25)) {
      htmlContent += `
                <tr>
                    <td class="mono"><strong>${esc(c.ip_adresi)}</strong></td>
                    <td>${esc(c.kullanici_adi)}</td>
                    <td>${esc(c.sunucular)}</td>
                    <td><span class="badge badge-info">${esc(c.gun_sayisi)} gün</span></td>
                    <td><small>${esc(c.ilk_aktivite)}</small></td>
                    <td><small>${esc(c.son_aktivite)}</small></td>
                    <td>${formatNum(c.toplam_istek)}</td>
                    <td><small>${esc(c.asama_izleri)}</small></td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  // Data Transfer Details
  if (transfers.length > 0) {
    htmlContent += `
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
    `;
    for (const t of transfers.slice(0, 30)) {
      htmlContent += `
                <tr>
                    <td><small>${esc(t.kaynak_dosya)}</small></td>
                    <td class="mono">${esc(t.ip_adresi)}</td>
                    <td>${esc(t.kullanici_adi)}</td>
                    <td>${esc(t.sunucu_ismi)}</td>
                    <td>${formatNum(t.basarili_istek)}</td>
                    <td><strong>${formatNum(t.toplam_transfer_gb)} GB</strong></td>
                    <td>${formatNum(t.toplam_transfer_mb)} MB</td>
                    <td>${formatNum(t.ortalama_byte)}</td>
                    <td>${formatNum(t.max_tekil_mb)} MB</td>
                    <td>${formatNum(t.toplam_pay_yuzde)}%</td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  // Destination IPs
  if (destIps.length > 0) {
    htmlContent += `
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
    `;
    for (const d of destIps) {
      const denyOrani = d.deny_orani !== undefined ? d.deny_orani : (d.toplam_baglanti ? Math.round((d.deny_sayisi / d.toplam_baglanti) * 100) : 0);
      const transferMb = d.toplam_transfer_mb !== undefined ? d.toplam_transfer_mb : Math.round((d.toplam_transfer_byte || 0) / (1024 * 1024));
      htmlContent += `
                <tr>
                    <td class="mono"><strong>${esc(d.hedef_ip)}</strong></td>
                    <td>${formatNum(d.toplam_baglanti)}</td>
                    <td>${formatNum(d.erisen_kaynak_ip_sayisi)}</td>
                    <td class="mono"><small>${esc(d.portlar).slice(0, 80)}</small></td>
                    <td><span class="badge badge-success">${formatNum(d.accept_sayisi)}</span></td>
                    <td><span class="badge badge-danger">${formatNum(d.deny_sayisi)}</span></td>
                    <td>${formatNum(denyOrani)}%</td>
                    <td>${formatNum(transferMb)} MB</td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  // Ports
  if (ports.length > 0) {
    htmlContent += `
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
    `;
    for (const p of ports) {
      htmlContent += `
                <tr>
                    <td class="mono"><strong>${esc(p.hedef_port)}</strong></td>
                    <td><span class="badge badge-info">${esc(p.tahmini_servis)}</span></td>
                    <td>${formatNum(p.baglanti_sayisi)}</td>
                    <td><span class="badge badge-success">${formatNum(p.accept_sayisi)}</span></td>
                    <td><span class="badge badge-danger">${formatNum(p.deny_sayisi)}</span></td>
                    <td>${formatNum(p.istemci_sayisi)}</td>
                    <td>${formatNum(p.toplam_transfer_mb)} MB</td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  // Accept / Deny Summary
  if (acceptDeny.length > 0) {
    htmlContent += `
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
    `;
    for (const ad of acceptDeny) {
      const isDeny = ad.baglanti_karari.toUpperCase().includes('DENY') || ad.baglanti_karari.toUpperCase().includes('DROP');
      const badgeCls = isDeny ? 'badge-danger' : 'badge-success';
      htmlContent += `
                <tr>
                    <td><span class="badge ${badgeCls}"><strong>${esc(ad.baglanti_karari)}</strong></span></td>
                    <td>${formatNum(ad.baglanti_sayisi)}</td>
                    <td><strong>%${formatNum(ad.oran_yuzde)}</strong></td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  // Forensic Quarantine Lines Table
  if (report.quarantine && report.quarantine.quarantinedLines && report.quarantine.quarantinedLines.length > 0) {
    htmlContent += `
        <h2>🚫 Ayrıştırılamayan / Bozuk Satırlar Karantinası (${formatNum(report.quarantine.quarantinedCount)} Satır Hariç Tutuldu)</h2>
        <div class="callout callout-warning">
            Aşağıdaki satırlar W3C / Syslog / Firewall standart formatına uymadığı, eksik alan içerdiği veya bozuk karakter barındırdığı için analize dahil edilmemiş ve kanıt niteliğinde karantinaya ayrılmıştır.
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 50px; text-align: center;">#</th>
                    <th>Kaynak Dosya</th>
                    <th style="width: 80px; text-align: center;">Satır</th>
                    <th>Hariç Tutulma Nedeni</th>
                    <th>Orijinal Ham Satır</th>
                </tr>
            </thead>
            <tbody>
    `;
    report.quarantine.quarantinedLines.slice(0, 100).forEach((item, idx) => {
      htmlContent += `
                <tr>
                    <td style="text-align: center; color: #64748b;" class="mono">${idx + 1}</td>
                    <td class="mono"><strong>${esc(item.fileName)}</strong></td>
                    <td style="text-align: center;" class="mono"><span class="badge badge-warning">L${item.lineNumber}</span></td>
                    <td><span class="badge badge-neutral">${esc(item.reason)}</span></td>
                    <td class="mono" style="word-break: break-all; font-size: 0.75rem;">${esc(item.rawText)}</td>
                </tr>
      `;
    });
    if (report.quarantine.quarantinedLines.length > 100) {
      htmlContent += `
                <tr>
                    <td colspan="5" style="text-align: center; color: #64748b; font-style: italic; padding: 1rem;">
                        ... ve ${report.quarantine.quarantinedLines.length - 100} satır daha adli karantina veri tabanında saklanmaktadır.
                    </td>
                </tr>
      `;
    }
    htmlContent += `</tbody></table>`;
  }

  htmlContent += `
</div>
</body>
</html>`;

  return htmlContent;
}
