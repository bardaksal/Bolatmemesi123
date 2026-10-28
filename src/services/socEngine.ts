import {
  NormalizedLog,
  HuntingReport,
  RiskQueueItem,
  DestinationIPItem,
  PortItem,
  AcceptDenyItem,
  CrossDayCorrelationItem,
  TransferDetailItem,
  LargestRequestItem,
  WebshellItem,
  WebshellTimelineItem,
  BotItem,
  BruteForceItem,
  PasswordSprayingItem,
  FtpAuthItem,
  FtpFileItem,
  FtpSuspiciousItem,
  SuspiciousCommandItem,
  SensitiveEndpointItem,
  HourlyTrafficItem,
  StatusCodeItem,
  TopIPItem,
  RiskLevel,
  ConnectionDecision,
  ForensicQuarantineReport,
  QuarantinedLineItem,
  DetectionProfile,
  DetectionSignal,
  DetectionConfidence,
  EntityContext,
} from '../types';
import { AllowlistManager } from './allowlistManager';
import { classifyIP, KNOWN_ATTACK_TOOLS } from './threatIntel';
import { classifyNetworkZone } from './proxyResolver';
import {
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
  getQuarantineReason,
  isDelimitedHeaderLine,
  unpackConcatenatedLines,
} from './streamingParser';

export interface FileInput {
  name: string;
  content: string;
}

export const DUCKDB_QUERIES: Record<string, string> = {
  exfiltration_anomalies: `SELECT ip_adresi, kullanici_adi, sunucu_ismi,
       COUNT(*) AS toplam_islem,
       SUM(byte_degeri) AS toplam_transfer_byte,
       ROUND(SUM(byte_degeri) / 1073741824.0, 2) AS toplam_transfer_gb,
       ROUND(AVG(byte_degeri), 2) AS ortalama_transfer_byte,
       MAX(byte_degeri) AS max_tekil_byte,
       MIN(tarih) AS ilk_transfer, MAX(tarih) AS son_transfer
FROM logs
WHERE status_code IN (200, 226) AND byte_degeri IS NOT NULL
GROUP BY ip_adresi, kullanici_adi, sunucu_ismi
HAVING SUM(byte_degeri) >= :exfiltration_bytes
ORDER BY toplam_transfer_byte DESC;`,

  cross_day_correlation: `SELECT ip_adresi,
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
           CASE WHEN COUNT(*) FILTER (WHERE status_code IN (404, 403) OR islem_komutu LIKE '%/admin%') > 0 THEN 'Kesif' END,
           CASE WHEN COUNT(*) FILTER (WHERE status_code IN (401, 403, 530) OR lower(islem_komutu) LIKE 'pass %') >= 5 THEN 'Parola Denemesi' END,
           CASE WHEN COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), 'filemanagement|c:\\\\inetpub|web\\.config|\\.asp|\\.aspx')) > 0 THEN 'Webshell/Dizin Gezintisi' END,
           CASE WHEN COUNT(*) FILTER (WHERE lower(islem_komutu) LIKE 'stor %' OR istemci_byte > 100000) > 0 THEN 'Dosya Yukleme' END,
           CASE WHEN SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) >= 10485760 THEN 'Veri Transferi/Sizdirma' END
       ) AS asama_izleri
FROM logs
GROUP BY ip_adresi, kullanici_adi
HAVING COUNT(DISTINCT CAST(tarih AS DATE)) > 1 OR COUNT(DISTINCT kaynak_dosya) > 1 OR COUNT(*) >= 500
ORDER BY gun_sayisi DESC, toplam_istek DESC;`,

  webshell_and_file_management: `SELECT ip_adresi, sunucu_ismi, user_agent, session_cookie,
       COUNT(*) AS istek_sayisi,
       COUNT(*) FILTER (WHERE status_code >= 400) AS hata_sayisi,
       COUNT(*) FILTER (WHERE status_code >= 500) AS server_hatasi,
       SUM(coalesce(byte_degeri, 0)) AS toplam_yanit_byte,
       MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme,
       string_agg(DISTINCT islem_komutu, ' | ' ORDER BY islem_komutu) AS eylem_ornekleri
FROM logs
WHERE (
    regexp_matches(lower(coalesce(islem_komutu, '')), '/filemanagement|c:\\\\inetpub|wwwroot|/(?:c99|r57|wso|b374k|alfa|shell|cmd|root|backdoor|eval|hack)\\.(?:asp|aspx|php|jsp)|browse=|download=.*(web\\.config|appsettings|\\.config|\\.cs|\\.dll)|(\\.\\./|\\.\\.\\\\)')
    OR regexp_matches(lower(coalesce(islem_komutu, '')), 'cmd(\\.exe)?|powershell|whoami|net[[:space:]]+user|actuator/(?:env|restart|heapdump)')
)
GROUP BY ip_adresi, sunucu_ismi, user_agent, session_cookie
ORDER BY son_gorulme DESC;`,

  entity_risk_queue: `WITH entities AS (
    SELECT ip_adresi,
           COALESCE(sunucu_ismi, 'Genel') AS sunucu_ismi,
           COUNT(*) AS toplam_istek,
           COUNT(DISTINCT islem_komutu) AS farkli_endpoint_sayisi,
           COUNT(DISTINCT sunucu_ismi) OVER (PARTITION BY ip_adresi) AS farkli_sunucu_sayisi,
           COUNT(DISTINCT kullanici_adi) FILTER (WHERE kullanici_adi NOT IN ('-', '')) AS farkli_kullanici_sayisi,
           SUM(CASE WHEN status_code IN (200, 226) THEN coalesce(byte_degeri, 0) ELSE 0 END) AS basarili_byte,
           COUNT(*) FILTER (WHERE status_code IN (401, 403, 530)) AS auth_hatasi,
           COUNT(*) FILTER (WHERE status_code >= 500) AS server_hatasi,
           COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/admin|/actuator/(?!health)|/swagger|/\\.env|/config|/backup|/debug|password|token|secret|web\\.config')) AS hassas_endpoint,
           COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/filemanagement|c:\\\\inetpub|wwwroot|/(?:c99|r57|wso|b374k|alfa|shell|cmd|root|backdoor)\\.(?:asp|aspx|php|jsp)')) AS webshell_sinyali,
           MIN(tarih) AS ilk_gorulme, MAX(tarih) AS son_gorulme
    FROM logs
    GROUP BY ip_adresi, sunucu_ismi
), scored AS (
    SELECT entities.*,
        (CASE WHEN basarili_byte >= :exfiltration_bytes AND (webshell_sinyali > 0 OR auth_hatasi >= 5) THEN 35
              WHEN basarili_byte >= :exfiltration_bytes THEN 15 ELSE 0 END
         + CASE WHEN auth_hatasi >= :failed_attempts THEN 25 ELSE 0 END
         + CASE WHEN webshell_sinyali > 0 THEN 35 ELSE 0 END
         + CASE WHEN farkli_endpoint_sayisi > 40 THEN 15 ELSE 0 END
         + CASE WHEN server_hatasi > 0 AND (webshell_sinyali > 0 OR hassas_endpoint > 0) THEN 20
                WHEN server_hatasi >= 5 THEN 5 ELSE 0 END
         + CASE WHEN hassas_endpoint > 0 THEN 15 ELSE 0 END
         + CASE WHEN farkli_kullanici_sayisi >= 4 AND auth_hatasi >= 15 THEN 25 ELSE 0 END
         + CASE WHEN farkli_sunucu_sayisi > 2 THEN 10 ELSE 0 END) AS risk_puani
    FROM entities
)
SELECT *,
    CASE WHEN risk_puani >= 60 THEN 'KRİTİK'
         WHEN risk_puani >= 35 THEN 'YÜKSEK'
         WHEN risk_puani >= 20 THEN 'ORTA' ELSE 'DÜŞÜK' END AS risk_seviyesi
FROM scored
WHERE risk_puani >= 15
ORDER BY risk_puani DESC;`,

  scanner_and_bots: `WITH ip_stats AS (
    SELECT ip_adresi, user_agent,
           COUNT(*) AS toplam_istek,
           COUNT(DISTINCT islem_komutu) AS farkli_komut_sayisi,
           COUNT(DISTINCT sunucu_ismi) AS hedef_sunucu_sayisi,
           COUNT(*) FILTER (WHERE status_code IN (401, 403, 404)) AS hata_sayisi,
           COUNT(*) FILTER (WHERE regexp_matches(lower(coalesce(islem_komutu, '')), '/admin|/\\.env|/swagger|/backup|/actuator|web\\.config')) AS hassas_sayisi,
           COUNT(*) FILTER (WHERE http_method IN ('PROPFIND', 'SEARCH', 'TRACK', 'TRACE', 'DEBUG')) AS anormal_method_sayisi
    FROM logs
    GROUP BY ip_adresi, user_agent
)
SELECT ip_stats.*,
       ROUND(100.0 * hata_sayisi / NULLIF(toplam_istek, 0), 1) AS hata_yuzdesi
FROM ip_stats
WHERE regexp_matches(lower(coalesce(user_agent, '')), 'sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|zgrab|shodan|censys|hydra')
   OR (farkli_komut_sayisi > 30 AND (100.0 * hata_sayisi / NULLIF(toplam_istek, 0)) >= 40)
   OR hassas_sayisi >= 3;`,

  destination_ip_analysis: `SELECT COALESCE(hedef_ip, 'Belirtilmemis') AS hedef_ip,
       COUNT(*) AS toplam_baglanti,
       COUNT(DISTINCT ip_adresi) AS erisen_kaynak_ip_sayisi,
       COUNT(DISTINCT hedef_port) AS kullanilan_port_sayisi,
       string_agg(DISTINCT CAST(hedef_port AS VARCHAR), ', ' ORDER BY CAST(hedef_port AS INTEGER)) AS portlar,
       COUNT(*) FILTER (WHERE baglanti_karari = 'ACCEPT') AS accept_sayisi,
       COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') AS deny_sayisi,
       ROUND(100.0 * COUNT(*) FILTER (WHERE baglanti_karari = 'DENY') / NULLIF(COUNT(*), 0), 1) AS deny_orani,
       SUM(coalesce(byte_degeri, 0)) AS toplam_transfer_byte
FROM logs
GROUP BY hedef_ip
ORDER BY toplam_baglanti DESC;`,
};

export function createEmptyReport(): HuntingReport {
  return {
    summary: {
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
    },
    entity_risk_queue: [],
    destination_ip_analysis: [],
    port_analysis: [],
    accept_deny_summary: [],
    cross_day_correlation: [],
    data_transfer_details: [],
    largest_transfer_requests: [],
    webshell_and_file_management: [],
    webshell_activity_timeline: [],
    scanner_and_bots: [],
    brute_force_attempts: [],
    password_spraying: [],
    ftp_authentication: [],
    ftp_file_operations: [],
    ftp_suspicious_activity: [],
    suspicious_commands: [],
    sensitive_endpoints: [],
    hourly_traffic: [],
    status_code_distribution: [],
    top_ips: [],
  };
}

export function parseLogs(
  files: FileInput[],
  options: {
    exfiltrationBytes: number;
    failedAttempts: number;
    allowlistMgr?: AllowlistManager | null;
    detectionProfile?: DetectionProfile;
  }
): HuntingReport {
  if (!files || files.length === 0) {
    return createEmptyReport();
  }

  const allLogs: NormalizedLog[] = [];
  const detectedFormats: { fileName: string; format: string; formatDisplayName: string; lineCount: number }[] = [];
  const quarantinedLines: QuarantinedLineItem[] = [];
  let totalLinesRead = 0;
  let totalHeaderLines = 0;
  let totalEmptyLines = 0;
  let totalQuarantined = 0;

  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    const formatState = initializeFormatState(file.name);
    let validLines = 0;

    for (let i = 0; i < lines.length; i++) {
      totalLinesRead++;
      const rawLine = lines[i];
      const subLines = unpackConcatenatedLines(rawLine);

      for (const singleLine of subLines) {
        const trimmed = singleLine.replace(/^\uFEFF/, '').trim();
        if (!trimmed) {
          totalEmptyLines++;
          continue;
        }

        if (trimmed.startsWith('#')) {
          totalHeaderLines++;
          if (trimmed.toLowerCase().startsWith('#fields:')) {
            formatState.isW3C = true;
            formatState.format = 'W3C_IIS';
            formatState.w3cFields = trimmed
              .replace(/^#fields:\s*/i, '')
              .trim()
              .split(/\s+/)
              .map(f => f.toLowerCase().replace(/[()]/g, '_').replace(/-+/g, '_').replace(/^_+|_+$/g, '').trim());
            formatState.detected = true;
          }
          continue;
        }

        if (!formatState.detected) {
          feedSampleLine(formatState, trimmed);
        }

        if (isDelimitedHeaderLine(trimmed, formatState)) {
          totalHeaderLines++;
          continue;
        }

        const parsed = parseLineToNormalizedLog(trimmed, formatState);
        if (parsed) {
          allLogs.push(parsed);
          validLines++;
        } else {
          totalQuarantined++;
          if (quarantinedLines.length < 500) {
            quarantinedLines.push({
              fileName: file.name,
              lineNumber: i + 1,
              rawText: trimmed.length > 300 ? trimmed.slice(0, 300) + '... (kırpıldı)' : trimmed,
              reason: getQuarantineReason(trimmed, formatState),
            });
          }
        }
      }
    }

    detectedFormats.push({
      fileName: file.name,
      format: formatState.format,
      formatDisplayName: formatState.formatDisplayName,
      lineCount: validLines,
    });
  }

  // Filter with Allowlist
  const allowlistMgr = options.allowlistMgr;
  const filteredLogs = allLogs.filter(log => {
    if (allowlistMgr) {
      if (allowlistMgr.isAllowed(log.ip_adresi, log.kullanici_adi, log.sunucu_ismi)) {
        return false;
      }
    }
    // Filter out obvious header row artifacts
    const ip = (log.ip_adresi || '').toLowerCase();
    if (['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi'].includes(ip)) return false;
    return true;
  });

  const report = runAnalytics(
    filteredLogs,
    options.exfiltrationBytes,
    options.failedAttempts,
    options.detectionProfile || 'BALANCED'
  );
  report.detected_formats = detectedFormats;

  const footnoteText = totalQuarantined > 0
    ? `${totalQuarantined.toLocaleString('tr-TR')} satır ayrıştırılamadı (karantinaya alındı).`
    : 'Ayrıştırılan %100, sorun yok.';

  report.quarantine = {
    totalLinesRead,
    parsedEventsCount: allLogs.length,
    headerCommentLinesCount: totalHeaderLines,
    emptyLinesCount: totalEmptyLines,
    quarantinedCount: totalQuarantined,
    quarantinedLines,
    footnoteText,
  };

  return report;
}

export function isSuccessfulTransferLog(l: NormalizedLog): boolean {
  // 1. Timeouts and errors can never be considered successful transfers
  if (l.status_code === 408 || l.status_code === 504) {
    return false;
  }
  if (l.baglanti_karari && (l.baglanti_karari.startsWith('DENY') || l.baglanti_karari === 'BILINMIYOR')) {
    return false;
  }

  const cmd = (l.islem_komutu || '').toLowerCase();
  const isTimeout = /time[-_\s]?out|zaman[-_\s]?a[sş][ıi]m[ıi]|aged[-_\s]?out/i.test(cmd);
  if (isTimeout && (!l.byte_degeri || l.byte_degeri < 100)) {
    return false;
  }

  // 2. HTTP Status Code Check
  if (l.status_code) {
    // 2xx HTTP Success (200, 201, 202, 204, 206 Partial Content, 226) or 304 Not Modified
    return (l.status_code >= 200 && l.status_code < 300) || l.status_code === 304;
  }

  // 3. For firewalls/proxies without HTTP status code: ACCEPT decision (provided no timeout was reported)
  return l.baglanti_karari === 'ACCEPT' && !isTimeout;
}

export function runAnalytics(
  logs: NormalizedLog[],
  exfiltrationBytes: number,
  failedAttemptsThreshold: number,
  detectionProfile: DetectionProfile = 'BALANCED'
): HuntingReport {
  // 1. Summary KPIs
  const uniqueIps = new Set<string>();
  const uniqueDestIps = new Set<string>();
  const uniqueServers = new Set<string>();
  const uniqueEndpoints = new Set<string>();
  let serverErrors = 0;
  let authFailures = 0;
  let acceptCount = 0;
  let denyCount = 0;
  let totalTransferBytes = 0;
  let minDate = '';
  let maxDate = '';

  logs.forEach(l => {
    if (l.ip_adresi) uniqueIps.add(l.ip_adresi);
    if (l.hedef_ip) uniqueDestIps.add(l.hedef_ip);
    if (l.sunucu_ismi) uniqueServers.add(l.sunucu_ismi);
    if (l.islem_komutu) uniqueEndpoints.add(l.islem_komutu);

    if (l.status_code && l.status_code >= 500) serverErrors++;
    if (l.status_code && [401, 403, 530].includes(l.status_code)) authFailures++;
    if (l.baglanti_karari === 'ACCEPT') acceptCount++;
    if (l.baglanti_karari && l.baglanti_karari.startsWith('DENY')) denyCount++;
    if (isSuccessfulTransferLog(l)) {
      const b = l.byte_degeri || l.istemci_byte || 0;
      if (b > 0) totalTransferBytes += b;
    }

    if (l.tarih) {
      if (!minDate || l.tarih < minDate) minDate = l.tarih;
      if (!maxDate || l.tarih > maxDate) maxDate = l.tarih;
    }
  });

  // 2. Destination IP Analysis
  const destIpMap = new Map<string, {
    total: number;
    sourceIps: Set<string>;
    ports: Set<number>;
    accepts: number;
    denies: number;
    bytes: number;
  }>();

  logs.forEach(l => {
    const dst = l.hedef_ip || 'Belirtilmemiş';
    if (!destIpMap.has(dst)) {
      destIpMap.set(dst, {
        total: 0,
        sourceIps: new Set(),
        ports: new Set(),
        accepts: 0,
        denies: 0,
        bytes: 0,
      });
    }
    const d = destIpMap.get(dst)!;
    d.total++;
    if (l.ip_adresi) d.sourceIps.add(l.ip_adresi);
    if (l.hedef_port) d.ports.add(l.hedef_port);
    if (l.baglanti_karari === 'ACCEPT') d.accepts++;
    if (l.baglanti_karari && l.baglanti_karari.startsWith('DENY')) d.denies++;
    if (l.byte_degeri) d.bytes += l.byte_degeri;
  });

  const destination_ip_analysis: DestinationIPItem[] = Array.from(destIpMap.entries())
    .map(([hedef_ip, d]) => ({
      hedef_ip,
      toplam_baglanti: d.total,
      erisen_kaynak_ip_sayisi: d.sourceIps.size,
      kullanilan_port_sayisi: d.ports.size,
      portlar: Array.from(d.ports).sort((a, b) => a - b).join(', ') || '-',
      accept_sayisi: d.accepts,
      deny_sayisi: d.denies,
      deny_orani: parseFloat(((100 * d.denies) / Math.max(d.total, 1)).toFixed(1)),
      toplam_transfer_byte: d.bytes,
      toplam_transfer_mb: parseFloat((d.bytes / (1024 * 1024)).toFixed(2)),
    }))
    .sort((a, b) => b.toplam_baglanti - a.toplam_baglanti);

  // 3. Port Analysis
  const portMap = new Map<number, {
    service: string;
    total: number;
    accepts: number;
    denies: number;
    clients: Set<string>;
    bytes: number;
  }>();

  logs.forEach(l => {
    if (l.hedef_port) {
      const p = l.hedef_port;
      if (!portMap.has(p)) {
        let s = 'Diğer / Özel';
        if (p === 80) s = 'HTTP';
        else if (p === 443) s = 'HTTPS';
        else if (p === 21) s = 'FTP (Control)';
        else if (p === 22) s = 'SSH';
        else if (p === 53) s = 'DNS';
        else if (p === 3389) s = 'RDP';
        else if (p === 445) s = 'SMB';
        else if (p >= 50000 && p <= 60000) s = 'FTP (Passive Data)';

        portMap.set(p, {
          service: s,
          total: 0,
          accepts: 0,
          denies: 0,
          clients: new Set(),
          bytes: 0,
        });
      }
      const item = portMap.get(p)!;
      item.total++;
      if (l.baglanti_karari === 'ACCEPT') item.accepts++;
      if (l.baglanti_karari && l.baglanti_karari.startsWith('DENY')) item.denies++;
      if (l.ip_adresi) item.clients.add(l.ip_adresi);
      if (l.byte_degeri) item.bytes += l.byte_degeri;
    }
  });

  const port_analysis: PortItem[] = Array.from(portMap.entries())
    .map(([port, p]) => ({
      port,
      servis_tahmini: p.service,
      baglanti_sayisi: p.total,
      accept_sayisi: p.accepts,
      deny_sayisi: p.denies,
      erisen_istemci_sayisi: p.clients.size,
      toplam_byte: p.bytes,
      toplam_mb: parseFloat((p.bytes / (1024 * 1024)).toFixed(2)),
    }))
    .sort((a, b) => b.baglanti_sayisi - a.baglanti_sayisi);

  // 4. Accept / Deny Summary
  const accept_deny_summary: AcceptDenyItem[] = [
    {
      baglanti_karari: 'ACCEPT',
      baglanti_sayisi: acceptCount,
      oran_yuzde: logs.length ? parseFloat(((100 * acceptCount) / logs.length).toFixed(2)) : 0,
    },
    {
      baglanti_karari: 'DENY',
      baglanti_sayisi: denyCount,
      oran_yuzde: logs.length ? parseFloat(((100 * denyCount) / logs.length).toFixed(2)) : 0,
    },
  ];

  // 5. Data Transfer Details (IP + User + Server)
  const transferMap = new Map<string, {
    kaynak_dosya: string;
    ip_adresi: string;
    kullanici_adi: string;
    sunucu_ismi: string;
    basarili_istek_sayisi: number;
    toplam_transfer_byte: number;
    en_buyuk_tekil_transfer: number;
    ilk_transfer: string;
    son_transfer: string;
  }>();

  logs.forEach(l => {
    if (isSuccessfulTransferLog(l)) {
      const b = l.byte_degeri || l.istemci_byte || 0;
      if (b <= 0) return;
      const key = `${l.kaynak_dosya}|${l.ip_adresi || '-'}|${l.kullanici_adi || 'Anonim'}|${l.sunucu_ismi || 'Bilinmeyen'}`;
      if (!transferMap.has(key)) {
        transferMap.set(key, {
          kaynak_dosya: l.kaynak_dosya,
          ip_adresi: l.ip_adresi || '-',
          kullanici_adi: l.kullanici_adi || 'Anonim / Belirtilmemiş',
          sunucu_ismi: l.sunucu_ismi || 'Bilinmeyen Sunucu',
          basarili_istek_sayisi: 0,
          toplam_transfer_byte: 0,
          en_buyuk_tekil_transfer: 0,
          ilk_transfer: l.tarih || '-',
          son_transfer: l.tarih || '-',
        });
      }
      const t = transferMap.get(key)!;
      t.basarili_istek_sayisi++;
      t.toplam_transfer_byte += b;
      if (b > t.en_buyuk_tekil_transfer) t.en_buyuk_tekil_transfer = b;
      if (l.tarih && l.tarih < t.ilk_transfer) t.ilk_transfer = l.tarih;
      if (l.tarih && l.tarih > t.son_transfer) t.son_transfer = l.tarih;
    }
  });

  const allSuccessBytes = totalTransferBytes || 1;
  const data_transfer_details: TransferDetailItem[] = Array.from(transferMap.values())
    .map(t => ({
      kaynak_dosya: t.kaynak_dosya,
      ip_adresi: t.ip_adresi,
      kullanici_adi: t.kullanici_adi,
      sunucu_ismi: t.sunucu_ismi,
      basarili_istek_sayisi: t.basarili_istek_sayisi,
      toplam_transfer_byte: t.toplam_transfer_byte,
      toplam_transfer_mb: parseFloat((t.toplam_transfer_byte / (1024 * 1024)).toFixed(2)),
      toplam_transfer_gb: parseFloat((t.toplam_transfer_byte / (1024 * 1024 * 1024)).toFixed(2)),
      ortalama_transfer_byte: Math.round(t.toplam_transfer_byte / Math.max(t.basarili_istek_sayisi, 1)),
      en_buyuk_tekil_transfer: t.en_buyuk_tekil_transfer,
      en_buyuk_tekil_transfer_mb: parseFloat((t.en_buyuk_tekil_transfer / (1024 * 1024)).toFixed(2)),
      toplam_transfer_yuzdesi: parseFloat(((100 * t.toplam_transfer_byte) / allSuccessBytes).toFixed(2)),
      ilk_transfer: t.ilk_transfer,
      son_transfer: t.son_transfer,
    }))
    .sort((a, b) => b.toplam_transfer_byte - a.toplam_transfer_byte);

  // 6. Largest 100 Transfer Requests
  const largest_transfer_requests: LargestRequestItem[] = logs
    .filter(l => isSuccessfulTransferLog(l) && (l.byte_degeri || l.istemci_byte))
    .sort((a, b) => ((b.byte_degeri || b.istemci_byte || 0) - (a.byte_degeri || a.istemci_byte || 0)))
    .slice(0, 100)
    .map(l => {
      const bytes = l.byte_degeri || l.istemci_byte || 0;
      return {
        kaynak_dosya: l.kaynak_dosya,
        tarih: l.tarih || '-',
        ip_adresi: l.ip_adresi || '-',
        kullanici_adi: l.kullanici_adi || '-',
        sunucu_ismi: l.sunucu_ismi || '-',
        islem_komutu: l.islem_komutu || '-',
        status_code: l.status_code !== undefined && l.status_code !== null ? l.status_code : null,
        byte_degeri: bytes,
        transfer_mb: parseFloat((bytes / (1024 * 1024)).toFixed(2)),
        user_agent: l.user_agent || '-',
      };
    });

  // 7. Webshell & File Management / Exploitation Detection
  const webshellRegex =
    /(?:\/(?:c99|r57|wso|b374k|alfa|cmdasp|shell|backdoor|root|hack|upload_shell)\.(?:asp|aspx|php|jsp|cgi|pl)\b|\/(?:uploads?|avatars?|images?|media|temp|tmp|writable|attachments?|files?)\/[^?#\s]+\.(?:php|asp|aspx|jsp|cgi|pl|sh|py)\b|(?:\b(?:powershell(?:\.exe)?|whoami|net\s+user|cat%20|\/bin\/(?:sh|bash)|\/etc\/(?:passwd|shadow)|druid\/indexer)\b|actuator\/(?:env|restart|heapdump|gateway)|(?:eval|system|passthru|shell_exec|assert)\s*\(|concat\(0x|extractvalue|\$\{jndi|jndi:(?:ldap|rmi|dns|corba|iiop))|[?&](?:cmd|exec|command|shell|eval|system|passthru|powershell)=(?:powershell|whoami|dir|ls|cat|id|net|ipconfig|ping|curl|wget|[a-zA-Z0-9_./\\-]{3,})|download=.*(?:web\.config|appsettings|\.config|\.cs|\.dll)|\b(?:c:\\inetpub\\wwwroot|\/var\/www\/html)\b|\/filemanagement\.(?:asp|aspx|php))/i;
  const webshellLogs = logs.filter(l => l.islem_komutu && webshellRegex.test(l.islem_komutu));

  const wsGroupMap = new Map<string, {
    ip_adresi: string;
    sunucu_ismi: string;
    user_agent: string;
    session_cookie: string;
    istek_sayisi: number;
    hata_sayisi: number;
    server_hatasi: number;
    toplam_yanit_byte: number;
    ilk_gorulme: string;
    son_gorulme: string;
    actions: Set<string>;
  }>();

  webshellLogs.forEach(l => {
    const key = `${l.ip_adresi || '-'}|${l.sunucu_ismi || '-'}|${l.user_agent || '-'}|${l.session_cookie || '-'}`;
    if (!wsGroupMap.has(key)) {
      wsGroupMap.set(key, {
        ip_adresi: l.ip_adresi || '-',
        sunucu_ismi: l.sunucu_ismi || '-',
        user_agent: l.user_agent || '-',
        session_cookie: l.session_cookie || '-',
        istek_sayisi: 0,
        hata_sayisi: 0,
        server_hatasi: 0,
        toplam_yanit_byte: 0,
        ilk_gorulme: l.tarih || '-',
        son_gorulme: l.tarih || '-',
        actions: new Set(),
      });
    }
    const g = wsGroupMap.get(key)!;
    g.istek_sayisi++;
    if (l.status_code && l.status_code >= 400) g.hata_sayisi++;
    if (l.status_code && l.status_code >= 500) g.server_hatasi++;
    if (l.byte_degeri) g.toplam_yanit_byte += l.byte_degeri;
    if (l.tarih && l.tarih < g.ilk_gorulme) g.ilk_gorulme = l.tarih;
    if (l.tarih && l.tarih > g.son_gorulme) g.son_gorulme = l.tarih;
    if (l.islem_komutu) g.actions.add(l.islem_komutu);
  });

  const webshell_and_file_management: WebshellItem[] = Array.from(wsGroupMap.values())
    .map(g => ({
      ip_adresi: g.ip_adresi,
      sunucu_ismi: g.sunucu_ismi,
      user_agent: g.user_agent,
      session_cookie: g.session_cookie,
      istek_sayisi: g.istek_sayisi,
      hata_sayisi: g.hata_sayisi,
      server_hatasi: g.server_hatasi,
      toplam_yanit_byte: g.toplam_yanit_byte,
      ilk_gorulme: g.ilk_gorulme,
      son_gorulme: g.son_gorulme,
      eylem_ornekleri: Array.from(g.actions).slice(0, 5).join(' | '),
    }))
    .sort((a, b) => b.istek_sayisi - a.istek_sayisi);

  const webshell_activity_timeline: WebshellTimelineItem[] = webshellLogs
    .slice(0, 1000)
    .sort((a, b) => (a.tarih || '').localeCompare(b.tarih || ''))
    .map(l => ({
      tarih: l.tarih || '-',
      ip_adresi: l.ip_adresi || '-',
      sunucu_ismi: l.sunucu_ismi || '-',
      http_method: l.http_method || '-',
      islem_komutu: l.islem_komutu || '-',
      status_code: l.status_code || 0,
      byte_degeri: l.byte_degeri || 0,
      response_time_ms: l.response_time_ms || 0,
      user_agent: l.user_agent || '-',
      session_cookie: l.session_cookie || '-',
      referer: l.referer || '-',
    }));

  // 8. Bot & Scanner Detection
  const botIpMap = new Map<string, {
    ip: string;
    ua: string;
    total: number;
    endpoints: Set<string>;
    servers: Set<string>;
    errors: number;
    sensitive: number;
    abnormalMethods: number;
  }>();

  const toolRegex = new RegExp(KNOWN_ATTACK_TOOLS.join('|'), 'i');
  const sensitiveRegex = /\/admin|\/\.env|\/swagger|\/backup|\/actuator\/(?!health)|web\.config/i;
  const abnormalMethodList = ['PROPFIND', 'SEARCH', 'TRACK', 'TRACE', 'DEBUG', 'CONNECT'];

  logs.forEach(l => {
    if (!l.ip_adresi) return;
    const key = `${l.ip_adresi}|${l.user_agent || '-'}`;
    if (!botIpMap.has(key)) {
      botIpMap.set(key, {
        ip: l.ip_adresi,
        ua: l.user_agent || '-',
        total: 0,
        endpoints: new Set(),
        servers: new Set(),
        errors: 0,
        sensitive: 0,
        abnormalMethods: 0,
      });
    }
    const b = botIpMap.get(key)!;
    b.total++;
    if (l.islem_komutu) {
      b.endpoints.add(l.islem_komutu);
      if (sensitiveRegex.test(l.islem_komutu)) b.sensitive++;
    }
    if (l.sunucu_ismi) b.servers.add(l.sunucu_ismi);
    if (l.status_code && [401, 403, 404].includes(l.status_code)) b.errors++;
    if (l.http_method && abnormalMethodList.includes(l.http_method)) b.abnormalMethods++;
  });

  const scanner_and_bots: BotItem[] = [];
  botIpMap.forEach(b => {
    const errorPct = parseFloat(((100 * b.errors) / Math.max(b.total, 1)).toFixed(1));
    const isTool = toolRegex.test(b.ua);
    const isEndpointBurst = b.endpoints.size > 30 && errorPct >= 40;
    const isSensitive = b.sensitive >= 3;
    const isAbnormal = b.abnormalMethods > 0;

    if (isTool || isEndpointBurst || isSensitive || isAbnormal) {
      let reason = 'Şüpheli Tarayıcı Davranışı';
      if (isTool) reason = 'Açık Araç İmzası (Known Tool Signature)';
      else if (isEndpointBurst) reason = 'Yüksek Hata & Endpoint Patlaması';
      else if (isSensitive) reason = 'Hassas Dosya/Dizin Taraması';
      else if (isAbnormal) reason = 'Anormal HTTP Metodu';
      else if (b.servers.size > 2) reason = 'Çoklu Sunucu Yatay Tarama';

      scanner_and_bots.push({
        ip_adresi: b.ip,
        user_agent: b.ua,
        toplam_istek: b.total,
        farkli_komut_sayisi: b.endpoints.size,
        hedef_sunucu_sayisi: b.servers.size,
        hata_sayisi: b.errors,
        hata_yuzdesi: errorPct,
        hassas_sayisi: b.sensitive,
        anormal_method_sayisi: b.abnormalMethods,
        bot_sebebi: reason,
      });
    }
  });
  scanner_and_bots.sort((a, b) => b.toplam_istek - a.toplam_istek);

  // 9. Brute Force Attempts
  const bruteMap = new Map<string, {
    ip: string;
    user: string;
    server: string;
    status: number;
    count: number;
    first: string;
    last: string;
  }>();

  logs.forEach(l => {
    const isAuthFailure = (l.status_code && [401, 403, 530].includes(l.status_code)) ||
      (l.islem_komutu && l.islem_komutu.toLowerCase().startsWith('pass '));
    if (isAuthFailure && l.ip_adresi) {
      const key = `${l.ip_adresi}|${l.kullanici_adi || '-'}|${l.sunucu_ismi || '-'}|${l.status_code || 0}`;
      if (!bruteMap.has(key)) {
        bruteMap.set(key, {
          ip: l.ip_adresi,
          user: l.kullanici_adi || '-',
          server: l.sunucu_ismi || '-',
          status: l.status_code || 401,
          count: 0,
          first: l.tarih || '-',
          last: l.tarih || '-',
        });
      }
      const b = bruteMap.get(key)!;
      b.count++;
      if (l.tarih && l.tarih < b.first) b.first = l.tarih;
      if (l.tarih && l.tarih > b.last) b.last = l.tarih;
    }
  });

  const brute_force_attempts: BruteForceItem[] = Array.from(bruteMap.values())
    .filter(b => b.count >= failedAttemptsThreshold)
    .map(b => ({
      ip_adresi: b.ip,
      kullanici_adi: b.user,
      sunucu_ismi: b.server,
      status_code: b.status,
      basarisiz_deneme_sayisi: b.count,
      ilk_deneme: b.first,
      son_deneme: b.last,
    }))
    .sort((a, b) => b.basarisiz_deneme_sayisi - a.basarisiz_deneme_sayisi);

  // 10. Password Spraying
  const sprayMap = new Map<string, {
    ip: string;
    users: Set<string>;
    failures: number;
    servers: Set<string>;
  }>();

  logs.forEach(l => {
    const isAuthFailure = (l.status_code && [401, 403, 530].includes(l.status_code)) ||
      (l.islem_komutu && l.islem_komutu.toLowerCase().startsWith('pass '));
    if (isAuthFailure && l.ip_adresi && l.kullanici_adi && !['-', '', 'anonymous'].includes(l.kullanici_adi)) {
      if (!sprayMap.has(l.ip_adresi)) {
        sprayMap.set(l.ip_adresi, {
          ip: l.ip_adresi,
          users: new Set(),
          failures: 0,
          servers: new Set(),
        });
      }
      const s = sprayMap.get(l.ip_adresi)!;
      s.failures++;
      s.users.add(l.kullanici_adi);
      if (l.sunucu_ismi) s.servers.add(l.sunucu_ismi);
    }
  });

  const password_spraying: PasswordSprayingItem[] = Array.from(sprayMap.values())
    .filter(s => s.users.size >= 3 || (s.users.size >= 2 && s.failures >= 5))
    .map(s => ({
      ip_adresi: s.ip,
      farkli_kullanici_sayisi: s.users.size,
      basarisiz_deneme_sayisi: s.failures,
      hedef_sunucu_sayisi: s.servers.size,
      hedeflenen_kullanicilar: Array.from(s.users).slice(0, 10).join(', '),
    }))
    .sort((a, b) => b.farkli_kullanici_sayisi - a.farkli_kullanici_sayisi);

  // 11. FTP Operations
  const ftpLogs = logs.filter(l =>
    (l.islem_komutu && /^(user|pass|stor|appe|retr|dele|rnfr|rnto|mkd|rmd|cwd|list|nlst)(\s|$)/i.test(l.islem_komutu)) ||
    (l.status_code && [230, 530, 550, 553].includes(l.status_code))
  );

  const ftpAuthMap = new Map<string, {
    ip: string;
    user: string;
    session: string;
    server: string;
    total: number;
    userCmd: number;
    passCmd: number;
    authRes: number;
    first: string;
    last: string;
  }>();

  const ftpFileMap = new Map<string, {
    ip: string;
    user: string;
    session: string;
    server: string;
    total: number;
    uploads: number;
    downloads: number;
    deletes: number;
    renames: number;
    bytes: number;
    first: string;
    last: string;
  }>();

  const ftp_suspicious_activity: FtpSuspiciousItem[] = [];

  ftpLogs.forEach(l => {
    const cmd = (l.islem_komutu || '').toLowerCase();
    const keyAuth = `${l.ip_adresi || '-'}|${l.kullanici_adi || '-'}|${l.sunucu_ismi || '-'}`;

    if (!ftpAuthMap.has(keyAuth)) {
      ftpAuthMap.set(keyAuth, {
        ip: l.ip_adresi || '-',
        user: l.kullanici_adi || '-',
        session: l.session_cookie || '-',
        server: l.sunucu_ismi || '-',
        total: 0,
        userCmd: 0,
        passCmd: 0,
        authRes: 0,
        first: l.tarih || '-',
        last: l.tarih || '-',
      });
    }
    const fa = ftpAuthMap.get(keyAuth)!;
    fa.total++;
    if (cmd.startsWith('user ')) fa.userCmd++;
    if (cmd.startsWith('pass ')) fa.passCmd++;
    if (l.status_code && [230, 530].includes(l.status_code)) fa.authRes++;
    if (l.tarih && l.tarih < fa.first) fa.first = l.tarih;
    if (l.tarih && l.tarih > fa.last) fa.last = l.tarih;

    if (/^(stor|appe|retr|dele|rnfr|rnto|mkd|rmd|cwd|list|nlst)(\s|$)/i.test(cmd)) {
      const keyFile = `${l.ip_adresi || '-'}|${l.kullanici_adi || '-'}|${l.sunucu_ismi || '-'}`;
      if (!ftpFileMap.has(keyFile)) {
        ftpFileMap.set(keyFile, {
          ip: l.ip_adresi || '-',
          user: l.kullanici_adi || '-',
          session: l.session_cookie || '-',
          server: l.sunucu_ismi || '-',
          total: 0,
          uploads: 0,
          downloads: 0,
          deletes: 0,
          renames: 0,
          bytes: 0,
          first: l.tarih || '-',
          last: l.tarih || '-',
        });
      }
      const ff = ftpFileMap.get(keyFile)!;
      ff.total++;
      if (cmd.startsWith('stor ') || cmd.startsWith('appe ')) ff.uploads++;
      if (cmd.startsWith('retr ')) ff.downloads++;
      if (cmd.startsWith('dele ')) ff.deletes++;
      if (cmd.startsWith('rnfr ') || cmd.startsWith('rnto ')) ff.renames++;
      if (l.byte_degeri) ff.bytes += l.byte_degeri;
      if (l.tarih && l.tarih < ff.first) ff.first = l.tarih;
      if (l.tarih && l.tarih > ff.last) ff.last = l.tarih;
    }

    if (
      /^(stor|appe|dele|rnfr|rnto)(\s|$)/i.test(cmd) ||
      cmd.startsWith('pass ') ||
      (l.status_code && [530, 550, 553].includes(l.status_code))
    ) {
      ftp_suspicious_activity.push({
        tarih: l.tarih || '-',
        ip_adresi: l.ip_adresi || '-',
        kullanici_adi: l.kullanici_adi || '-',
        session_cookie: l.session_cookie || '-',
        sunucu_ismi: l.sunucu_ismi || '-',
        islem_komutu: l.islem_komutu || '-',
        status_code: l.status_code || 0,
        byte_degeri: l.byte_degeri || 0,
        referer: l.referer || '-',
      });
    }
  });

  const ftp_authentication: FtpAuthItem[] = Array.from(ftpAuthMap.values())
    .map(fa => ({
      ip_adresi: fa.ip,
      kullanici_adi: fa.user,
      session_cookie: fa.session,
      sunucu_ismi: fa.server,
      ftp_istek_sayisi: fa.total,
      user_komutu: fa.userCmd,
      pass_komutu: fa.passCmd,
      auth_sonucu: fa.authRes,
      ilk_gorulme: fa.first,
      son_gorulme: fa.last,
    }))
    .sort((a, b) => b.ftp_istek_sayisi - a.ftp_istek_sayisi);

  const ftp_file_operations: FtpFileItem[] = Array.from(ftpFileMap.values())
    .map(ff => ({
      ip_adresi: ff.ip,
      kullanici_adi: ff.user,
      session_cookie: ff.session,
      sunucu_ismi: ff.server,
      islem_sayisi: ff.total,
      yukleme_sayisi: ff.uploads,
      indirme_sayisi: ff.downloads,
      silme_sayisi: ff.deletes,
      yeniden_adlandirma_sayisi: ff.renames,
      toplam_byte: ff.bytes,
      ilk_gorulme: ff.first,
      son_gorulme: ff.last,
    }))
    .sort((a, b) => b.islem_sayisi - a.islem_sayisi);

  // 12. Suspicious Commands & 500 Crashes (RCE, SQLi, /etc/passwd)
  const sqliOrRce = /(?:\/etc\/(?:passwd|shadow)|\bcmd(?:\.exe)?\b|powershell|union\s+select|;\s*(?:cat|curl|wget)|concat\(0x|extractvalue|\$\{jndi|jndi:(?:ldap|rmi|dns)|whoami)/i;
  const suspCmdMap = new Map<string, {
    server: string;
    cmd: string;
    status: number;
    count: number;
    ips: Set<string>;
  }>();

  logs.forEach(l => {
    // Only flag as suspicious command if actual exploit payload is present OR status >= 500 is accompanied by injection characters
    const hasExploitPayload = l.islem_komutu && sqliOrRce.test(l.islem_komutu);
    const hasCrashWithProbe = (l.status_code && l.status_code >= 500) && (l.islem_komutu && (sqliOrRce.test(l.islem_komutu) || l.islem_komutu.includes("'") || l.islem_komutu.includes('..')));
    
    if (hasExploitPayload || hasCrashWithProbe) {
      const key = `${l.sunucu_ismi || '-'}|${l.islem_komutu || '-'}|${l.status_code !== undefined && l.status_code !== null ? l.status_code : 'none'}`;
      if (!suspCmdMap.has(key)) {
        suspCmdMap.set(key, {
          server: l.sunucu_ismi || '-',
          cmd: l.islem_komutu || '-',
          status: l.status_code !== undefined && l.status_code !== null ? l.status_code : null,
          count: 0,
          ips: new Set(),
        });
      }
      const s = suspCmdMap.get(key)!;
      s.count++;
      if (l.ip_adresi) s.ips.add(l.ip_adresi);
    }
  });

  const suspicious_commands: SuspiciousCommandItem[] = Array.from(suspCmdMap.values())
    .map(s => ({
      sunucu_ismi: s.server,
      islem_komutu: s.cmd,
      status_code: s.status,
      tekrar_sayisi: s.count,
      erisen_farkli_ip_sayisi: s.ips.size,
    }))
    .sort((a, b) => b.tekrar_sayisi - a.tekrar_sayisi);

  // 13. Sensitive Endpoints
  const sensEndpointRegex = /(?:\/\.env|\/web\.config|\/swagger(?:-ui)?|\/actuator\/(?!health|info|metrics)|\/backup|\/dump|\/debug\/vars|\/(?:appsettings|database)\.(?:json|yml|xml|config)|[?&](?:password|token|secret)=[^&\s]{12,}|\/admin\/(?:config|backup|restore|eval|exec)|(?:\/|^)admin(?:\/|$))/i;
  const sensMap = new Map<string, {
    server: string;
    cmd: string;
    status: number | null;
    count: number;
    ips: Set<string>;
  }>();

  logs.forEach(l => {
    if (l.islem_komutu && sensEndpointRegex.test(l.islem_komutu)) {
      const key = `${l.sunucu_ismi || '-'}|${l.islem_komutu || '-'}|${l.status_code !== undefined && l.status_code !== null ? l.status_code : 'none'}`;
      if (!sensMap.has(key)) {
        sensMap.set(key, {
          server: l.sunucu_ismi || '-',
          cmd: l.islem_komutu || '-',
          status: l.status_code !== undefined && l.status_code !== null ? l.status_code : null,
          count: 0,
          ips: new Set(),
        });
      }
      const s = sensMap.get(key)!;
      s.count++;
      if (l.ip_adresi) s.ips.add(l.ip_adresi);
    }
  });

  const sensitive_endpoints: SensitiveEndpointItem[] = Array.from(sensMap.values())
    .map(s => ({
      sunucu_ismi: s.server,
      islem_komutu: s.cmd,
      status_code: s.status,
      istek_sayisi: s.count,
      farkli_ip_sayisi: s.ips.size,
    }))
    .sort((a, b) => b.istek_sayisi - a.istek_sayisi);

  // 14. Hourly Traffic & Distribution (Recharts)
  const hourlyMap = new Map<string, {
    total: number;
    success: number;
    err4xx: number;
    err5xx: number;
    bytes: number;
  }>();

  logs.forEach(l => {
    if (l.tarih) {
      const hour = l.tarih.substring(0, 13) + ':00';
      if (!hourlyMap.has(hour)) {
        hourlyMap.set(hour, { total: 0, success: 0, err4xx: 0, err5xx: 0, bytes: 0 });
      }
      const h = hourlyMap.get(hour)!;
      h.total++;
      if (l.status_code && [200, 226].includes(l.status_code)) h.success++;
      if (l.status_code && [401, 403, 404].includes(l.status_code)) h.err4xx++;
      if (l.status_code && l.status_code >= 500) h.err5xx++;
      if (l.byte_degeri) h.bytes += l.byte_degeri;
    }
  });

  const hourly_traffic: HourlyTrafficItem[] = Array.from(hourlyMap.entries())
    .map(([saatlik_dilim, h]) => ({
      saatlik_dilim,
      toplam_istek: h.total,
      basarili_istek: h.success,
      hata_4xx: h.err4xx,
      hata_5xx: h.err5xx,
      saatlik_toplam_byte: h.bytes,
    }))
    .sort((a, b) => a.saatlik_dilim.localeCompare(b.saatlik_dilim));

  // Status code distribution
  const statusMap = new Map<number, number>();
  logs.forEach(l => {
    if (l.status_code) {
      statusMap.set(l.status_code, (statusMap.get(l.status_code) || 0) + 1);
    }
  });
  const status_code_distribution: StatusCodeItem[] = Array.from(statusMap.entries())
    .map(([status_code, adet]) => ({ status_code, adet }))
    .sort((a, b) => b.adet - a.adet);

  // Top IPs
  const ipCountMap = new Map<string, { count: number; bytes: number; servers: Set<string> }>();
  logs.forEach(l => {
    if (l.ip_adresi) {
      if (!ipCountMap.has(l.ip_adresi)) {
        ipCountMap.set(l.ip_adresi, { count: 0, bytes: 0, servers: new Set() });
      }
      const entry = ipCountMap.get(l.ip_adresi)!;
      entry.count++;
      if (l.byte_degeri) entry.bytes += l.byte_degeri;
      if (l.sunucu_ismi) entry.servers.add(l.sunucu_ismi);
    }
  });
  const top_ips: TopIPItem[] = Array.from(ipCountMap.entries())
    .map(([ip_adresi, val]) => ({
      ip_adresi,
      istek_sayisi: val.count,
      toplam_byte: val.bytes,
      sunucu_sayisi: val.servers.size,
    }))
    .sort((a, b) => b.istek_sayisi - a.istek_sayisi)
    .slice(0, 15);

  // 15. Cross-Day Correlation
  const crossIpMap = new Map<string, {
    ip: string;
    users: Set<string>;
    servers: Set<string>;
    dates: Set<string>;
    files: Set<string>;
    total: number;
    authFails: number;
    serverFails: number;
    successBytes: number;
    first: string;
    last: string;
    hasRecon: boolean;
    hasBrute: boolean;
    hasWebshell: boolean;
    hasUpload: boolean;
  }>();

  logs.forEach(l => {
    if (!l.ip_adresi) return;
    if (!crossIpMap.has(l.ip_adresi)) {
      crossIpMap.set(l.ip_adresi, {
        ip: l.ip_adresi,
        users: new Set(),
        servers: new Set(),
        dates: new Set(),
        files: new Set(),
        total: 0,
        authFails: 0,
        serverFails: 0,
        successBytes: 0,
        first: l.tarih || '-',
        last: l.tarih || '-',
        hasRecon: false,
        hasBrute: false,
        hasWebshell: false,
        hasUpload: false,
      });
    }
    const c = crossIpMap.get(l.ip_adresi)!;
    c.total++;
    if (l.kullanici_adi && l.kullanici_adi !== '-') c.users.add(l.kullanici_adi);
    if (l.sunucu_ismi) c.servers.add(l.sunucu_ismi);
    if (l.tarih) {
      c.dates.add(l.tarih.substring(0, 10));
      if (l.tarih < c.first) c.first = l.tarih;
      if (l.tarih > c.last) c.last = l.tarih;
    }
    c.files.add(l.kaynak_dosya);

    if (l.status_code && [401, 403, 530].includes(l.status_code)) c.authFails++;
    if (l.status_code && l.status_code >= 500) c.serverFails++;
    if (isSuccessfulTransferLog(l)) {
      const b = l.byte_degeri || l.istemci_byte || 0;
      if (b > 0) c.successBytes += b;
    }

    const cmd = (l.islem_komutu || '').toLowerCase();
    if ((l.status_code && [404, 403].includes(l.status_code)) || cmd.includes('/admin') || cmd.includes('/filemanagement')) {
      c.hasRecon = true;
    }
    if ((l.status_code && [401, 403, 530].includes(l.status_code)) || cmd.startsWith('pass ')) {
      c.hasBrute = true;
    }
    if (webshellRegex.test(cmd)) {
      c.hasWebshell = true;
    }
    if (cmd.startsWith('stor ') || (l.istemci_byte && l.istemci_byte > 100000)) {
      c.hasUpload = true;
    }
  });

  const cross_day_correlation: CrossDayCorrelationItem[] = Array.from(crossIpMap.values())
    .filter(c => c.dates.size > 1 || c.files.size > 1 || c.total >= 8)
    .map(c => {
      const stages: string[] = [];
      if (c.hasRecon) stages.push('Keşif');
      if (c.hasBrute) stages.push('Parola Denemesi');
      if (c.hasWebshell) stages.push('Webshell / Dizin Gezintisi');
      if (c.hasUpload) stages.push('Dosya Yükleme');
      if (c.successBytes >= 10485760) stages.push('Veri Transferi / Sızdırma');

      const ipInfo = classifyIP(c.ip);

      return {
        ip_adresi: c.ip,
        kullanici_adi: Array.from(c.users).join(', ') || '-',
        sunucular: Array.from(c.servers).join(', ') || '-',
        gun_sayisi: c.dates.size || 1,
        dosya_sayisi: c.files.size,
        toplam_istek: c.total,
        basarisiz_auth_sayisi: c.authFails,
        server_hata_sayisi: c.serverFails,
        toplam_basarili_byte: c.successBytes,
        ilk_aktivite: c.first,
        son_aktivite: c.last,
        asama_izleri: stages.join(' -> ') || 'Standart Trafik',
        ip_kategori: ipInfo.kategori,
      };
    })
    .sort((a, b) => b.gun_sayisi - a.gun_sayisi || b.toplam_istek - a.toplam_istek);

  // 16. Entity Risk Queue (Multi-Signal, Correlated & Explainable Risk Scoring Engine)
  interface EntityAccumulator {
    ip: string;
    server: string;
    servers: Set<string>;
    devices: Set<string>;
    total: number;
    endpoints: Set<string>;
    users: Set<string>;
    successBytes: number;
    authFails: number;
    serverErrors: number;
    notFound404: number;
    sensitiveCount: number;
    webshellCount: number;
    traversalCount: number;
    abnormalMethodCount: number;
    scannerToolDetected: boolean;
    scannerToolName?: string;
    networkZone: 'internal' | 'external' | 'loopback';
    ipSource: 'direct-peer' | 'trusted-proxy-forwarded' | 'untrusted-spoofed-ignored' | 'parsed-client';
    forwardedChain?: string | null;
    first: string;
    last: string;
    samplePayloads: Set<string>;
    sampleUsers: Set<string>;
  }

  const entityMap = new Map<string, EntityAccumulator>();
  const ipServerCounts = new Map<string, Set<string>>();

  const traversalRegex = /(\.\.\/|\.\.\\|\.%2e|%2e\.|%2e%2e)/i;

  logs.forEach(l => {
    if (!l.ip_adresi) return;
    const ip = l.ip_adresi;
    const srv = l.sunucu_ismi || 'Genel';
    const key = `${ip}|${srv}`;

    if (!ipServerCounts.has(ip)) ipServerCounts.set(ip, new Set());
    ipServerCounts.get(ip)!.add(srv);

    if (!entityMap.has(key)) {
      const zone = l.network_zone || classifyNetworkZone(ip);
      const source = l.ip_source || (l.forwarded_client_ip ? 'trusted-proxy-forwarded' : 'direct-peer');

      entityMap.set(key, {
        ip,
        server: srv,
        servers: new Set([srv]),
        devices: new Set(l.device ? [l.device] : []),
        total: 0,
        endpoints: new Set(),
        users: new Set(),
        successBytes: 0,
        authFails: 0,
        serverErrors: 0,
        notFound404: 0,
        sensitiveCount: 0,
        webshellCount: 0,
        traversalCount: 0,
        abnormalMethodCount: 0,
        scannerToolDetected: false,
        networkZone: zone,
        ipSource: source,
        forwardedChain: l.forwarded_chain || null,
        first: l.tarih || '-',
        last: l.tarih || '-',
        samplePayloads: new Set(),
        sampleUsers: new Set(),
      });
    }

    const e = entityMap.get(key)!;
    e.total++;
    e.servers.add(srv);
    if (l.device) e.devices.add(l.device);

    if (l.islem_komutu) {
      e.endpoints.add(l.islem_komutu);
      if (sensEndpointRegex.test(l.islem_komutu)) {
        e.sensitiveCount++;
        if (e.samplePayloads.size < 4) e.samplePayloads.add(l.islem_komutu);
      }
      if (webshellRegex.test(l.islem_komutu)) {
        e.webshellCount++;
        if (e.samplePayloads.size < 4) e.samplePayloads.add(l.islem_komutu);
      }
      if (traversalRegex.test(l.islem_komutu)) {
        e.traversalCount++;
        if (e.samplePayloads.size < 4) e.samplePayloads.add(l.islem_komutu);
      }
    }

    if (l.http_method && abnormalMethodList.includes(l.http_method)) {
      e.abnormalMethodCount++;
    }

    if (l.user_agent) {
      const matchedTool = KNOWN_ATTACK_TOOLS.find(tool => l.user_agent!.toLowerCase().includes(tool));
      if (matchedTool) {
        e.scannerToolDetected = true;
        e.scannerToolName = matchedTool;
      }
    }

    if (l.kullanici_adi && l.kullanici_adi !== '-' && l.kullanici_adi.trim() !== '') {
      e.users.add(l.kullanici_adi);
      if (e.sampleUsers.size < 5) e.sampleUsers.add(l.kullanici_adi);
    }

    if (isSuccessfulTransferLog(l)) {
      const b = l.byte_degeri || l.istemci_byte || 0;
      if (b > 0) e.successBytes += b;
    }

    if (l.status_code && [401, 403, 530].includes(l.status_code)) {
      e.authFails++;
    }

    if (l.status_code && l.status_code >= 500) {
      e.serverErrors++;
    }

    if (l.status_code === 404) {
      e.notFound404++;
    }

    if (l.tarih) {
      if (e.first === '-' || l.tarih < e.first) e.first = l.tarih;
      if (e.last === '-' || l.tarih > e.last) e.last = l.tarih;
    }
  });

  const entity_risk_queue: RiskQueueItem[] = [];

  entityMap.forEach(e => {
    const srvCount = ipServerCounts.get(e.ip)?.size || e.servers.size || 1;
    const signals: DetectionSignal[] = [];
    const scoring_breakdown: Array<{ item: string; points: number; note: string }> = [];
    const correlations: string[] = [];

    // --- 1. SİNYAL ÜRETİMİ (Bağımsız Tespit Katmanları) ---

    // A) Webshell & RCE Girişimi
    if (e.webshellCount > 0) {
      // Logarithmic scaling for repetition to prevent runaway score
      const pts = Math.min(40, 25 + Math.round(Math.log2(e.webshellCount + 1) * 4));
      signals.push({
        code: 'SIG_WEBSHELL_RCE',
        points: pts,
        label: 'Webshell / RCE Payload İstismarı',
        confidence: 'YÜKSEK',
        category: 'WEBSHELL',
        description: `${e.webshellCount} adet zararlı webshell/komut enjeksiyonu deseni eşleşti.`,
      });
      scoring_breakdown.push({
        item: 'Webshell / RCE Tespiti',
        points: pts,
        note: `${e.webshellCount} adet istek (Örnek: ${Array.from(e.samplePayloads)[0] || 'webshell'})`,
      });
    }

    // B) Dizin Atlama / LFI
    if (e.traversalCount > 0 && e.webshellCount === 0) {
      const pts = Math.min(25, 15 + Math.round(Math.log2(e.traversalCount + 1) * 3));
      signals.push({
        code: 'SIG_DIR_TRAVERSAL',
        points: pts,
        label: 'Dizin Atlama (Path Traversal / LFI)',
        confidence: 'YÜKSEK',
        category: 'EXPLOIT',
        description: `${e.traversalCount} adet dizin geçişi (../) paterni tespit edildi.`,
      });
      scoring_breakdown.push({
        item: 'Path Traversal / LFI',
        points: pts,
        note: `${e.traversalCount} adet dizin atlama isteği`,
      });
    }

    // C) Kimlik Doğrulama / Brute Force
    if (e.authFails >= failedAttemptsThreshold) {
      const pts = Math.min(30, 20 + Math.round(Math.log2(e.authFails - failedAttemptsThreshold + 2) * 3));
      signals.push({
        code: 'SIG_AUTH_BRUTE_FORCE',
        points: pts,
        label: 'Kritik Sayıda Auth Hatası (Brute Force)',
        confidence: 'YÜKSEK',
        category: 'BRUTE_FORCE',
        description: `${e.authFails} adet başarısız kimlik doğrulama eşiği aştı.`,
      });
      scoring_breakdown.push({
        item: 'Brute Force Saldırısı',
        points: pts,
        note: `${e.authFails} auth hatası (Eşik: ${failedAttemptsThreshold})`,
      });
    } else if (e.authFails >= 5) {
      signals.push({
        code: 'SIG_AUTH_REPEATED_FAILS',
        points: 10,
        label: 'Tekrarlayan Kimlik Doğrulama Hatası',
        confidence: 'ORTA',
        category: 'BRUTE_FORCE',
        description: `${e.authFails} adet 401/403/530 hata kaydı.`,
      });
      scoring_breakdown.push({
        item: 'Tekrarlayan Auth Hataları',
        points: 10,
        note: `${e.authFails} adet auth hatası`,
      });
    }

    // D) Password Spraying (Çoklu hesap denenmesi)
    if (e.users.size >= 4 && e.authFails >= 10) {
      signals.push({
        code: 'SIG_PASSWORD_SPRAYING',
        points: 25,
        label: 'Çoklu Hesap Parola Püskürtme (Password Spraying)',
        confidence: 'YÜKSEK',
        category: 'BRUTE_FORCE',
        description: `${e.users.size} farklı kullanıcı adına yönelik tekrarlayan oturum denemesi.`,
      });
      scoring_breakdown.push({
        item: 'Password Spraying',
        points: 25,
        note: `${e.users.size} farklı kullanıcı hesabı: ${Array.from(e.sampleUsers).slice(0, 3).join(', ')}`,
      });
    }

    // E) Tarayıcı & Otomasyon Araçları (Scanner)
    if (e.scannerToolDetected) {
      signals.push({
        code: 'SIG_SCANNER_TOOL',
        points: 25,
        label: `Bilinen Saldırı / Tarama Aracı (${e.scannerToolName || 'Security Scanner'})`,
        confidence: 'YÜKSEK',
        category: 'SCANNER',
        description: `İstemci User-Agent başlığında bilinen tarama aracı tespit edildi.`,
      });
      scoring_breakdown.push({
        item: 'Saldırı / Tarama Aracı Tespiti',
        points: 25,
        note: `User-Agent: ${e.scannerToolName}`,
      });
    } else if (e.endpoints.size > 25 && (((e.authFails + e.serverErrors + e.notFound404) / Math.max(e.total, 1) > 0.35) || e.total >= 80 || e.notFound404 >= 20)) {
      signals.push({
        code: 'SIG_FUZZING_RECON',
        points: 15,
        label: 'Geniş Kapsamlı Endpoint Fuzzing / Keşif',
        confidence: 'ORTA',
        category: 'SCANNER',
        description: `${e.endpoints.size} farklı uç nokta tarandı, ${e.notFound404} adet 404 hata yanıtı tespit edildi.`,
      });
      scoring_breakdown.push({
        item: 'Dizin Keşfi / Fuzzing',
        points: 15,
        note: `${e.endpoints.size} farklı URI, ${e.notFound404} adet 404 hatası`,
      });
    }

    // F) Hassas Uç Noktalar ve Yapılandırma Dosyaları
    if (e.sensitiveCount > 0) {
      const isPersistent = e.sensitiveCount >= 3 || e.endpoints.size > 5;
      const pts = isPersistent ? 15 : 8;
      signals.push({
        code: 'SIG_SENSITIVE_PROBE',
        points: pts,
        label: `Hassas Dosya / Yapılandırma Erişimi (${e.sensitiveCount} istek)`,
        confidence: isPersistent ? 'ORTA' : 'DÜŞÜK',
        category: 'EXPLOIT',
        description: `${e.sensitiveCount} adet .env, swagger, config, admin veya yedek dosyası sorgulandı.`,
      });
      scoring_breakdown.push({
        item: 'Hassas Dosya Erişimi',
        points: pts,
        note: `${e.sensitiveCount} istek (Örnek: ${Array.from(e.samplePayloads)[0] || 'admin/config'})`,
      });
    }

    // G) 5xx Sunucu Hataları (Payload Korelasyonu ile)
    if (e.serverErrors > 0) {
      const hasExploitSignal = e.webshellCount > 0 || e.sensitiveCount > 0 || e.traversalCount > 0 || e.scannerToolDetected;
      if (hasExploitSignal) {
        // Enjeksiyon / istismar payload'ı sunucuyu çökertti (Kritik korelasyon)
        signals.push({
          code: 'SIG_EXPLOIT_CRASH_5XX',
          points: 20,
          label: 'Payload Kaynaklı 5xx Sunucu Hatası (İstismar Çökmesi)',
          confidence: 'YÜKSEK',
          category: 'EXPLOIT',
          description: `İstismar veya enjeksiyon payload'ı sunucuda ${e.serverErrors} kez 5xx kritik hata tetikledi.`,
        });
        scoring_breakdown.push({
          item: 'İstismar Kaynaklı Sunucu Çökmesi (5xx)',
          points: 20,
          note: `${e.serverErrors} hata, şüpheli payload ile korele`,
        });
      } else if (e.serverErrors >= 10) {
        // Saldırı payload'ı olmadan sadece 500 hatası -> yazılım/altyapı hatası
        signals.push({
          code: 'SIG_SERVER_ERROR_ANOMALY',
          points: 6,
          label: 'Yüksek 5xx Hacmi (Uygulama veya Altyapı Hatası Olasılığı)',
          confidence: 'DÜŞÜK',
          category: 'ANOMALY',
          description: `${e.serverErrors} kez 5xx hatası oluştu, saldırı payload'ı görülmedi.`,
        });
        scoring_breakdown.push({
          item: '5xx Sunucu Hatası (Bağımsız)',
          points: 6,
          note: `${e.serverErrors} adet 5xx hatası (Yazılım bug'ı olabilir)`,
        });
      } else {
        // 1-9 tekil 500 hatası tek başına saldırı sayılamaz
        signals.push({
          code: 'SIG_MINOR_5XX',
          points: 2,
          label: 'Düşük Frekanslı 5xx Hatası',
          confidence: 'DÜŞÜK',
          category: 'ANOMALY',
          description: `${e.serverErrors} adet 5xx hata kaydı.`,
        });
        scoring_breakdown.push({
          item: 'Tekil 5xx Hatası',
          points: 2,
          note: `${e.serverErrors} adet hata`,
        });
      }
    }

    // H) Veri Sızdırma (Data Exfiltration)
    if (e.successBytes >= exfiltrationBytes) {
      const hasPrecursor = e.webshellCount > 0 || e.authFails >= 5 || e.sensitiveCount > 0;
      if (hasPrecursor) {
        signals.push({
          code: 'SIG_EXFILTRATION_CORRELATED',
          points: 35,
          label: 'Kritik Veri Sızdırma (İstismar / Auth ile Bağlantılı Transfer)',
          confidence: 'YÜKSEK',
          category: 'EXPLOIT',
          description: `${(e.successBytes / (1024 * 1024)).toFixed(1)} MB veri transferi güvenlik anomalisi ile korele.`,
        });
        scoring_breakdown.push({
          item: 'Korele Veri Sızdırma',
          points: 35,
          note: `${(e.successBytes / (1024 * 1024)).toFixed(1)} MB transfer, saldırı sinyali ile ilişkili`,
        });
      } else {
        // Meşru dosya indirmesi / yedekleme olabilir
        signals.push({
          code: 'SIG_HIGH_TRANSFER_ALONE',
          points: 12,
          label: 'Yüksek Hacimli Veri Transferi (Meşru İndirme Olasılığı)',
          confidence: 'DÜŞÜK',
          category: 'EXFILTRATION',
          description: `${(e.successBytes / (1024 * 1024)).toFixed(1)} MB transfer gerçekleşti.`,
        });
        scoring_breakdown.push({
          item: 'Yüksek Transfer Hacmi',
          points: 12,
          note: `${(e.successBytes / (1024 * 1024)).toFixed(1)} MB transfer (Saldırı sinyali bulunmadı)`,
        });
      }
    }

    // I) Anormal HTTP Metotları
    if (e.abnormalMethodCount > 0) {
      signals.push({
        code: 'SIG_ABNORMAL_METHOD',
        points: 10,
        label: 'Anormal HTTP Metodu Kullanımı (DEBUG/TRACE/PROPFIND)',
        confidence: 'ORTA',
        category: 'ANOMALY',
        description: `${e.abnormalMethodCount} istek standart dışı HTTP metotlarıyla yapıldı.`,
      });
      scoring_breakdown.push({
        item: 'Anormal HTTP Metodu',
        points: 10,
        note: `${e.abnormalMethodCount} anormal istek (PUT hariç tutuldu)`,
      });
    }

    // J) Çoklu Sunucu Taraması (Pivot)
    if (srvCount > 2) {
      signals.push({
        code: 'SIG_MULTI_SERVER_PIVOT',
        points: 12,
        label: 'Çoklu Sunucuya Erişim (Ağ İçi Pivot / Keşif)',
        confidence: 'ORTA',
        category: 'INTERNAL_LATERAL',
        description: `İstemci ${srvCount} farklı sunucuya aynı anda istek gönderdi.`,
      });
      scoring_breakdown.push({
        item: 'Çoklu Sunucu Erişimi (Pivot)',
        points: 12,
        note: `${srvCount} hedef sunucu: ${Array.from(e.servers).slice(0, 3).join(', ')}`,
      });
    }

    // --- 2. BİLEŞİK KORELASYON KURALLARI (Compound Boosts) ---
    let correlationBonus = 0;
    let contextModifier = 1.0;

    const hasWebshell = signals.some(s => s.code === 'SIG_WEBSHELL_RCE');
    const hasRecon = signals.some(s => s.code === 'SIG_SCANNER_TOOL' || s.code === 'SIG_FUZZING_RECON');
    const hasAuth = signals.some(s => s.code === 'SIG_AUTH_BRUTE_FORCE' || s.code === 'SIG_PASSWORD_SPRAYING');

    // Kural 1: Keşif + İstismar Korelasyonu (Recon -> Exploit)
    if (hasRecon && hasWebshell) {
      correlationBonus += 20;
      correlations.push('Aşamalı Saldırı: Otomatize keşif/fuzzing ardından webshell veya komut çalıştırma istismarı gerçekleşti (Recon -> Exploit)');
      scoring_breakdown.push({
        item: 'Korelasyon: Keşif -> İstismar',
        points: 20,
        note: 'Bağımsız keşif ve sömürü zinciri doğrulandı',
      });
    }

    // Kural 2: İstismar + Veri Sızdırma (Exploit -> Exfiltration)
    if (hasWebshell && e.successBytes >= 500000) {
      correlationBonus += 25;
      correlations.push('Veri Hırsızlığı: Webshell/Komut çalıştırma sonrasında yüksek hacimli başarılı transfer (Exploit -> Exfiltration)');
      scoring_breakdown.push({
        item: 'Korelasyon: İstismar -> Sızdırma',
        points: 25,
        note: `${(e.successBytes / (1024 * 1024)).toFixed(1)} MB veri sızdırıldı`,
      });
    }

    // Kural 3: Kimlik Avı + Başarılı Erişim (Brute Force -> Compromise)
    if (hasAuth && e.successBytes >= 500000) {
      correlationBonus += 20;
      correlations.push('Hesap Ele Geçirme: Başarısız parola denemeleri sonrası başarılı oturum ve veri akışı');
      scoring_breakdown.push({
        item: 'Korelasyon: Kaba Kuvvet -> Başarılı Oturum',
        points: 20,
        note: 'Parola denemeleri sonrası veri transferi',
      });
    }

    // Kural 4: İç Ağ Tehdidi / Cihaz Ele Geçirilmesi (Insider Threat / Lateral Movement)
    if (e.networkZone === 'internal') {
      if (srvCount >= 2 && (e.users.size >= 3 || e.authFails >= 10)) {
        correlationBonus += 25;
        correlations.push('İç Ağ Tehdidi: Kurum içi kaynaktan çoklu sunucu ve hesap taraması (Lateral Movement / Ele Geçirilmiş Cihaz)');
        scoring_breakdown.push({
          item: 'İç Ağ Tehdidi (Lateral Movement)',
          points: 25,
          note: 'İç IP üzerinden çoklu sunucu ve hesap hedef alındı',
        });
      } else if (signals.length === 1 && (signals[0].code === 'SIG_HIGH_TRANSFER_ALONE' || signals[0].code === 'SIG_SERVER_ERROR_ANOMALY')) {
        // Kurum içi meşru transfer veya tekil yazılım hatası false-positive azaltma
        contextModifier *= 0.65;
        scoring_breakdown.push({
          item: 'İç Ağ İndirimi',
          points: -5,
          note: 'Saldırı sinyali bulunmayan tekil iç ağ trafiği zayıflatıldı',
        });
      }
    }

    // --- 3. ZAYIF SİNYAL KORUMASI (False Positive Prevention) ---
    // Yalnızca tek bir zayıf sinyali olan varlıklar yüksek risk alamaz
    const onlyWeakSignal = signals.length === 1 && (signals[0].confidence === 'DÜŞÜK' || signals[0].points <= 12);
    if (onlyWeakSignal && correlationBonus === 0) {
      contextModifier *= 0.7;
      scoring_breakdown.push({
        item: 'Zayıf Sinyal Koruması',
        points: -3,
        note: 'Tek bir zayıf sinyal nedeniyle yüksek risk oluşturulması engellendi',
      });
    }

    // Proxy / WAF XFF Bilgilendirmesi
    if (e.ipSource === 'untrusted-spoofed-ignored') {
      scoring_breakdown.push({
        item: 'Proxy Güvenlik Uyarısı',
        points: 0,
        note: 'Güvenilmeyen XFF başlığı yok sayıldı, gerçek peer IP analiz edildi',
      });
    }

    // --- 4. PROFİL AYARI VE NİHAİ SKOR HESAPLAMASI ---
    const basePointsSum = signals.reduce((acc, s) => acc + s.points, 0);
    let profileFactor = 1.0;
    let minScoreThreshold = 15;

    if (detectionProfile === 'RELAXED') {
      profileFactor = 0.85;
      minScoreThreshold = 25;
    } else if (detectionProfile === 'STRICT') {
      profileFactor = 1.15;
      minScoreThreshold = 10;
    }

    let calculatedScore = Math.round((basePointsSum * contextModifier + correlationBonus) * profileFactor);
    if (onlyWeakSignal) {
      calculatedScore = Math.min(calculatedScore, 14); // Eşiğin altında kalır
    }

    const finalScore = Math.min(100, Math.max(0, calculatedScore));

    // Skor eşiğini geçenleri veya korelasyonu olanları kuyruğa ekle
    if (finalScore >= minScoreThreshold && signals.length > 0) {
      let sev: RiskLevel = 'DÜŞÜK';
      if (finalScore >= 65) sev = 'KRİTİK';
      else if (finalScore >= 40) sev = 'YÜKSEK';
      else if (finalScore >= 20) sev = 'ORTA';

      // Güven Seviyesi Tayini
      let confidence: DetectionConfidence = 'DÜŞÜK';
      if (signals.some(s => s.confidence === 'YÜKSEK') && (signals.length >= 2 || correlationBonus > 0)) {
        confidence = 'YÜKSEK';
      } else if (signals.some(s => s.confidence === 'ORTA') || signals.length >= 2) {
        confidence = 'ORTA';
      }

      const ipInfo = classifyIP(e.ip);
      const zoneLabel = e.networkZone === 'internal' ? 'İç Ağ' : e.networkZone === 'loopback' ? 'Yerel' : 'Dış Kaynak';
      const proxyNote = e.ipSource === 'trusted-proxy-forwarded' ? ' (WAF/Proxy Arkası Gerçek İstemci)' : '';

      const reasonParts: string[] = [];
      if (correlations.length > 0) {
        reasonParts.push(correlations.join(' | '));
      } else {
        reasonParts.push(...signals.map(s => s.label));
      }

      const explainability_summary = `${zoneLabel}${proxyNote} ${e.ip} üzerinden ${e.total} istek incelendi. ` +
        `Tespit edilen ${signals.length} bağımsız sinyal (${signals.map(s => s.label).slice(0, 3).join(', ')}) değerlendirildi. ` +
        `${correlations.length > 0 ? 'Korelasyon: ' + correlations[0] + '. ' : ''}` +
        `Hesaplanan Risk Skoru: ${finalScore}/100 (${sev}). Güven Seviyesi: ${confidence}.`;

      entity_risk_queue.push({
        ip_adresi: e.ip,
        sunucu_ismi: e.server,
        toplam_istek: e.total,
        farkli_endpoint_sayisi: e.endpoints.size,
        farkli_sunucu_sayisi: srvCount,
        farkli_kullanici_sayisi: e.users.size,
        basarili_byte: e.successBytes,
        auth_hatasi: e.authFails,
        server_hatasi: e.serverErrors,
        hassas_endpoint: e.sensitiveCount,
        webshell_sinyali: e.webshellCount,
        ilk_gorulme: e.first,
        son_gorulme: e.last,
        risk_puani: finalScore,
        risk_seviyesi: sev,
        risk_gerekcesi: reasonParts.join('; ') || 'Şüpheli aktivite korelasyonu',
        ip_kategori: ipInfo.kategori,
        ip_aciklama: ipInfo.aciklama,
        confidence,
        signals,
        scoring_breakdown,
        explainability_summary,
        device: Array.from(e.devices)[0] || null,
        kullanici_adi: Array.from(e.users)[0] || null,
        network_zone: e.networkZone,
        ip_source: e.ipSource,
        context: {
          network_zone: e.networkZone,
          device: Array.from(e.devices)[0] || null,
          user: Array.from(e.users)[0] || null,
          ip_source: e.ipSource,
          forwarded_chain: e.forwardedChain,
        },
      });
    }
  });

  entity_risk_queue.sort((a, b) => b.risk_puani - a.risk_puani || b.toplam_istek - a.toplam_istek);

  return {
    summary: {
      toplam_olay: logs.length,
      ilk_tarih: minDate || '-',
      son_tarih: maxDate || '-',
      farkli_ip_sayisi: uniqueIps.size,
      farkli_hedef_ip_sayisi: uniqueDestIps.size,
      farkli_sunucu_sayisi: uniqueServers.size,
      farkli_endpoint_sayisi: uniqueEndpoints.size,
      server_error_sayisi: serverErrors,
      auth_failure_sayisi: authFailures,
      accept_sayisi: acceptCount,
      deny_sayisi: denyCount,
      toplam_transfer_byte: totalTransferBytes,
    },
    entity_risk_queue,
    risk_queue: entity_risk_queue,
    detection_profile: detectionProfile,
    destination_ip_analysis,
    port_analysis,
    accept_deny_summary,
    cross_day_correlation,
    data_transfer_details,
    largest_transfer_requests,
    webshell_and_file_management,
    webshell_activity_timeline,
    scanner_and_bots,
    brute_force_attempts,
    password_spraying,
    ftp_authentication,
    ftp_file_operations,
    ftp_suspicious_activity,
    suspicious_commands,
    sensitive_endpoints,
    hourly_traffic,
    status_code_distribution,
    top_ips,
  };
}
