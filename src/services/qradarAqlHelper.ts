/**
 * IBM QRadar AQL (Ariel Query Language) Generator & Custom Property Regex Engine
 *
 * Provides SOC L2/L3 Threat Hunters with:
 * 1. Event-specific AQL Threat Hunting Queries (matching normalized/raw fields)
 * 2. Specialized AQL correlation queries (Time-window aggregations, IP investigation, Brute force, Exfiltration)
 * 3. QRadar Custom Event Property (CEP) Regex Generator:
 *    - Generates QRadar-compatible capture groups / regex for any arbitrary substring or key-value
 *    - Verifies match validity and shows capture group (e.g. $1)
 */

export type DetectedLogCategory = 'WINDOWS' | 'WEB' | 'FIREWALL' | 'GENERIC';

export interface QradarAqlQueryItem {
  id: string;
  title: string;
  category: 'INVESTIGATION' | 'CORRELATION' | 'AGGREGATION' | 'HUNTING';
  logType: DetectedLogCategory;
  description: string;
  aql: string;
  recommendedTimeWindow: string;
}

export interface QradarCustomRuleDefinition {
  id: string;
  ruleName: string;
  ruleType: 'CRE_EVENT_RULE' | 'CRE_OFFENSE_RULE' | 'AQL_RULE';
  severity: number; // 1 - 10
  credibility: number; // 1 - 10
  relevance: number; // 1 - 10
  category: string;
  mitreTechnique: string;
  mitreTactic: string;
  summary: string;
  logSourceFilter: string;
  ruleTestConditions: string[];
  ruleActionDescription: string;
  qradarCREExpression: string;
  qradarAqlRuleCondition?: string;
  qradarRuleConfigSteps: string[];
}

export interface RegexExtractionCandidate {
  fieldName: string;
  value: string;
  regexPattern: string;
  captureGroup: string;
  qradarPropertyType: 'Text' | 'IP' | 'Port' | 'Number' | 'Date';
  explanation: string;
}

/**
 * Escapes regex special characters in a literal string.
 */
function escapeRegex(text: string): string {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}

/**
 * Analyzes raw log line and extracted context to accurately determine log nature.
 */
export function detectLogNature(params: {
  rawLog?: string;
  eventId?: number | string;
  method?: string;
  url?: string;
  statusCode?: number | string;
}): {
  category: DetectedLogCategory;
  displayName: string;
  details: string;
  confidence: number;
} {
  const raw = (params.rawLog || '').toLowerCase();
  const eid = params.eventId ? String(params.eventId) : '';
  const method = (params.method || '').toUpperCase();
  const url = (params.url || '').toLowerCase();

  // 1. Windows Security & Sysmon Detection
  const hasWinEventId = eid && ['4624', '4625', '4688', '4672', '4720', '4728', '4732', '1102', '104', '7045', '4697', '4768', '4769', '4776', '4648'].includes(eid);
  const winKeywords = [
    'microsoft-windows-security-auditing',
    'eventid',
    'event id',
    'subjectusername',
    'targetusername',
    'logontype',
    'substatus',
    'status: 0x',
    'workstation name',
    'process command line',
    'newprocessname',
    'parentprocessname',
    'kerberos',
    'service name: win',
    'powershell.exe',
    'cmd.exe /c',
    'audit success',
    'audit failure',
    'an account was successfully logged on',
    'an account failed to log on',
    'a new process has been created',
    'the audit log was cleared',
  ];
  const winMatches = winKeywords.filter(k => raw.includes(k)).length;

  if (hasWinEventId || winMatches >= 2 || (winMatches >= 1 && (raw.includes('microsoft') || raw.includes('windows')))) {
    return {
      category: 'WINDOWS',
      displayName: 'Windows Güvenlik Olayı (Endpoint & AD)',
      details: eid ? `Windows Event ID: ${eid}` : 'Windows İşletim Sistemi / Active Directory Günlüğü',
      confidence: 95,
    };
  }

  // 2. Web Application / WAF / Proxy Detection
  const webKeywords = [
    'http/1.0',
    'http/1.1',
    'http/2',
    'fortiweb',
    'modsecurity',
    'waf',
    'nginx',
    'apache',
    'iis',
    'user-agent',
    'referer',
    'cookie',
    'uri_path',
    'request_uri',
    'http_host',
    'status_code',
    'sqli',
    'xss',
    'webshell',
    'rce',
    'owasp',
  ];
  const webMatches = webKeywords.filter(k => raw.includes(k)).length;
  const hasHttpMethod = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'].includes(method) ||
    /\b(GET|POST|PUT|DELETE)\s+\/[^\s]*/i.test(raw);

  if (hasHttpMethod || webMatches >= 2 || (url && url.startsWith('/')) || (params.statusCode && [200, 301, 302, 400, 401, 403, 404, 500, 502].includes(Number(params.statusCode)))) {
    return {
      category: 'WEB',
      displayName: 'Web Uygulama / WAF / Proxy Günlüğü',
      details: method ? `HTTP Metodu: ${method}` : 'HTTP İsteği & Web Sunucu Logu',
      confidence: 90,
    };
  }

  // 3. Firewall / UTM / Network Traffic Detection
  const fwKeywords = ['fortigate', 'paloalto', 'checkpoint', 'firewall', 'drop', 'deny', 'accept', 'traffic', 'session', 'dstport', 'srcport', 'proto=6', 'proto=17'];
  const fwMatches = fwKeywords.filter(k => raw.includes(k)).length;
  if (fwMatches >= 2) {
    return {
      category: 'FIREWALL',
      displayName: 'Güvenlik Duvarı / Ağ Trafiği (Firewall/UTM)',
      details: 'Ağ Bağlantısı ve Paket Engelleme/İzin Logu',
      confidence: 85,
    };
  }

  return {
    category: 'GENERIC',
    displayName: 'Genel Syslog / Güvenlik Olayı',
    details: 'Ağ ve Kimlik Doğrulama Olayı',
    confidence: 60,
  };
}

/**
 * Generates tailored QRadar AQL Threat Hunting Queries based on parsed event fields
 */
export function generateQradarAqlQueries(params: {
  rawLog?: string;
  ip?: string;
  destIp?: string;
  user?: string;
  port?: number | string;
  method?: string;
  url?: string;
  statusCode?: number | string;
  eventId?: number | string;
  processName?: string;
  logSourceName?: string;
  hostname?: string;
}): QradarAqlQueryItem[] {
  const queries: QradarAqlQueryItem[] = [];
  const raw = params.rawLog || '';
  const rawLow = raw.toLowerCase();

  // Extract or auto-detect values from rawLog if parameters are empty
  let detectedEventId = params.eventId ? String(params.eventId) : '';
  if (!detectedEventId) {
    const eidMatch = raw.match(/\b(?:EventID|Event ID|EventCode|Signature ID)\s*[:=]\s*(\d{3,5})\b/i) ||
                     raw.match(/\b(4624|4625|4688|4672|4720|4728|4732|1102|104|7045|4697|4768|4769|4776|4648)\b/);
    if (eidMatch) detectedEventId = eidMatch[1];
  }

  let detectedUser = params.user && params.user !== '-' && params.user !== 'Bilinmiyor' ? params.user : '';
  if (!detectedUser) {
    const usrMatch = raw.match(/\b(?:TargetUserName|Account Name|User Name|user|usr|username)\s*[:=]\s*["']?([a-zA-Z0-9._-]+)["']?/i);
    if (usrMatch && !['system', 'anonymous', '-'].includes(usrMatch[1].toLowerCase())) {
      detectedUser = usrMatch[1];
    }
  }

  let detectedSrcIp = params.ip && params.ip !== '-' && params.ip !== 'Bilinmiyor' ? params.ip : '';
  if (!detectedSrcIp) {
    const ipMatch = raw.match(/\b(?:Source Network Address|IpAddress|src|srcip|sourceip|client_ip)\s*[:=]\s*["']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']?/i);
    if (ipMatch) detectedSrcIp = ipMatch[1];
  }

  let detectedDstIp = params.destIp && params.destIp !== '-' && params.destIp !== 'Bilinmiyor' ? params.destIp : '';
  if (!detectedDstIp) {
    const dstMatch = raw.match(/\b(?:Destination Network Address|dst|dstip|destinationip)\s*[:=]\s*["']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']?/i);
    if (dstMatch) detectedDstIp = dstMatch[1];
  }

  let detectedProcess = params.processName || '';
  if (!detectedProcess) {
    const procMatch = raw.match(/\b(?:NewProcessName|Process Name|Image|CommandLine|islem_komutu)\s*[:=]\s*["']?([^\r\n"';]+)["']?/i);
    if (procMatch) detectedProcess = procMatch[1].trim();
  }

  let detectedHost = params.hostname && params.hostname !== '-' ? params.hostname : '';
  if (!detectedHost) {
    const hostMatch = raw.match(/\b(?:WorkstationName|ComputerName|Computer|host|hostname)\s*[:=]\s*["']?([a-zA-Z0-9._-]+)["']?/i);
    if (hostMatch) detectedHost = hostMatch[1];
  }

  // Detect Log Nature
  const nature = detectLogNature({
    rawLog: raw,
    eventId: detectedEventId,
    method: params.method,
    url: params.url,
    statusCode: params.statusCode,
  });

  const isWindows = nature.category === 'WINDOWS';
  const isWeb = nature.category === 'WEB';

  const srcIp = detectedSrcIp || null;
  const dstIp = detectedDstIp || null;
  const username = detectedUser || null;
  const eventId = detectedEventId || null;
  const urlOrCmd = params.url || '';
  const proc = detectedProcess || '';
  const port = params.port ? String(params.port) : null;

  // 1. Point Investigation (Olay Bazlı Derin İnceleme)
  const whereClauses: string[] = [];
  if (srcIp) whereClauses.push(`sourceip = '${srcIp}'`);
  if (dstIp) whereClauses.push(`destinationip = '${dstIp}'`);
  if (username) whereClauses.push(`username ILIKE '${username}'`);
  if (eventId) whereClauses.push(`eventid = '${eventId}'`);
  if (port) whereClauses.push(`destinationport = ${port}`);

  const mainWhere = whereClauses.length > 0 ? whereClauses.join(' AND ') : "eventcount > 0";

  queries.push({
    id: 'aql_target_event',
    title: isWindows 
      ? '🎯 Windows Olayı & Host Odaklı Ariel Taraması (Host & Event Investigation)' 
      : '🎯 Nokta Hedefli Olay & Akış Taraması (Point Investigation)',
    category: 'INVESTIGATION',
    logType: isWindows ? 'WINDOWS' : isWeb ? 'WEB' : 'GENERIC',
    description: isWindows
      ? `Windows olayına ait Host (${detectedHost || 'Endpoint'}), Olay ID (${eventId || 'Tümü'}) ve hesap (${username || 'Tümü'}) kayıtlarını döker.`
      : 'Şüpheli olaya ait kaynak, hedef, kullanıcı ve port parametreleri ile Ariel veri tabanında eşleşen tüm ham olayları listeler.',
    recommendedTimeWindow: 'LAST 24 HOURS',
    aql: `SELECT QIDNAME(qid) AS "Olay_Adi",
       DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Baslangic_Zamani",
       sourceip AS "Kaynak_IP",
       sourceport AS "Kaynak_Port",
       destinationip AS "Hedef_IP",
       destinationport AS "Hedef_Port",
       username AS "Kullanici",
       eventcount AS "Olay_Adedi",
       LOGSOURCENAME(logsourceid) AS "Log_Kaynagi"
FROM events
WHERE ${mainWhere}
ORDER BY starttime DESC
LAST 24 HOURS`,
  });

  // -------------------------------------------------------------
  // WINDOWS-SPECIFIC THREAT HUNTING QUERIES
  // -------------------------------------------------------------
  if (isWindows) {
    // A. Windows Event 4625: Account Lockout & Spraying
    if (eventId === '4625' || (!eventId && rawLow.includes('4625'))) {
      queries.push({
        id: 'aql_win_4625_spray',
        title: '🔑 Windows Event 4625: Parola Püskürtme ve Hedeflenen Hesaplar (Password Spraying)',
        category: 'HUNTING',
        logType: 'WINDOWS',
        description: 'Windows Active Directory / DC üzerinde ardışık başarısız oturum denemelerini, hata alt kodlarını (0xC000006A, 0xC0000064 vb.) ve kaynak IP dağılımını gruplar.',
        recommendedTimeWindow: 'LAST 12 HOURS',
        aql: `SELECT sourceip AS "Kaynak_IP",
       username AS "Hedef_Hesap",
       "SubStatus" AS "Hata_Kodu_0xC000006A",
       "WorkstationName" AS "Istemci_Makine",
       COUNT(*) AS "Basarisiz_Giris_Sayisi",
       DATEFORMAT(MIN(starttime), 'yyyy-MM-dd HH:mm:ss') AS "Ilk_Deneme",
       DATEFORMAT(MAX(starttime), 'yyyy-MM-dd HH:mm:ss') AS "Son_Deneme"
FROM events
WHERE "EventID" = '4625' ${srcIp ? `AND sourceip = '${srcIp}'` : ''} ${username ? `AND username ILIKE '${username}'` : ''}
GROUP BY sourceip, username, "SubStatus", "WorkstationName"
ORDER BY "Basarisiz_Giris_Sayisi" DESC
LAST 12 HOURS`,
      });

      queries.push({
        id: 'aql_win_4625_lateral',
        title: '⚡ Windows Event 4625: Tek Kaynaktan Çoklu DC / Host Oturum Başarısızlıkları',
        category: 'HUNTING',
        logType: 'WINDOWS',
        description: 'Tek bir kaynak IP veya iş istasyonundan etki alanındaki birden fazla sunucuya başarısız NTLM/Kerberos denemesi yapılıp yapılmadığını denetler (Lateral Movement göstergesi).',
        recommendedTimeWindow: 'LAST 24 HOURS',
        aql: `SELECT sourceip AS "Saldirgan_IP",
       UNIQUECOUNT(destinationip) AS "Hedef_Sunucu_Sayisi",
       UNIQUECOUNT(username) AS "Denenen_Kullanici_Sayisi",
       COUNT(*) AS "Toplam_Basarisiz_Giris",
       DATEFORMAT(MAX(starttime), 'yyyy-MM-dd HH:mm:ss') AS "Son_Aktivite"
FROM events
WHERE "EventID" = '4625'
GROUP BY sourceip
HAVING "Toplam_Basarisiz_Giris" >= 5 OR "Hedef_Sunucu_Sayisi" >= 2
ORDER BY "Toplam_Basarisiz_Giris" DESC
LAST 24 HOURS`,
      });
    }

    // B. Windows Event 4624: Successful Logon & Lateral Movement
    if (eventId === '4624' || (!eventId && rawLow.includes('4624')) || (!eventId && eventId === '4625')) {
      queries.push({
        id: 'aql_win_4624_rdp_psexec',
        title: '🖥️ Windows Event 4624: Uzak Masaüstü (RDP Type 10) ve Ağ Oturumları (Type 3)',
        category: 'HUNTING',
        logType: 'WINDOWS',
        description: 'İlgili hesap veya IP ile açılan başarılı uzak oturumları (Type 10 RDP, Type 3 Ağ Paylaşımı/SMB/PsExec) listeler.',
        recommendedTimeWindow: 'LAST 24 HOURS',
        aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Oturum_Zamani",
       username AS "Oturum_Acan_Hesap",
       sourceip AS "Giris_Yapilan_IP",
       "LogonType" AS "Oturum_Turu",
       "WorkstationName" AS "Kaynak_Host",
       LOGSOURCENAME(logsourceid) AS "Hedef_Sistem"
FROM events
WHERE "EventID" = '4624' 
  AND ("LogonType" = '10' OR "LogonType" = '3')
  ${username ? `AND username ILIKE '${username}'` : ''}
  ${srcIp ? `AND sourceip = '${srcIp}'` : ''}
ORDER BY starttime DESC
LAST 24 HOURS`,
      });
    }

    // C. Windows Event 4688 / Sysmon: Process Creation & Living-off-the-Land (LotL)
    queries.push({
      id: 'aql_win_4688_lotl',
      title: '⚡ Windows Event 4688: Şüpheli Komut Satırı ve Living-off-the-Land (LotL)',
      category: 'HUNTING',
      logType: 'WINDOWS',
      description: 'PowerShell -enc, cmd /c, certutil, whoami, vssadmin delete, bitsadmin, rundll32 yürütmelerini arar.',
      recommendedTimeWindow: 'LAST 24 HOURS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       "Process Name" AS "Baslatilan_Surec",
       "Process Command Line" AS "Komut_Satiri",
       username AS "Calistiran_Hesap",
       LOGSOURCENAME(logsourceid) AS "Host_Adi"
FROM events
WHERE ("EventID" = '4688' OR "EventID" = '1')
  AND ("Process Command Line" ILIKE '%powershell%' 
    OR "Process Command Line" ILIKE '%cmd.exe%' 
    OR "Process Command Line" ILIKE '%certutil%' 
    OR "Process Command Line" ILIKE '%whoami%' 
    OR "Process Command Line" ILIKE '%vssadmin%' 
    OR "Process Command Line" ILIKE '%rundll32%'
    OR "Process Command Line" ILIKE '%encodedcommand%')
  ${detectedHost ? `AND LOGSOURCENAME(logsourceid) ILIKE '%${detectedHost}%'` : ''}
ORDER BY starttime DESC
LAST 24 HOURS`,
    });

    // D. Windows Event 4672 / 4720 / 4732: Privilege Escalation & Domain Admin Addition
    queries.push({
      id: 'aql_win_priv_escalation',
      title: '🛡️ Windows Yetki Yükseltme & Grup Değişikliği (Event 4672 / 4720 / 4728 / 4732)',
      category: 'HUNTING',
      logType: 'WINDOWS',
      description: 'Özel yetki atanması (Special Privileges Assigned - 4672), yeni yerel/domain kullanıcı açılması (4720) ve Administrators grubuna üye eklenmesi (4732 / 4728) olaylarını tarar.',
      recommendedTimeWindow: 'LAST 48 HOURS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       QIDNAME(qid) AS "Yetki_Olayi",
       username AS "Etkilenen_Veya_Acan_Hesap",
       "EventID" AS "Olay_ID",
       LOGSOURCENAME(logsourceid) AS "Domain_Controller"
FROM events
WHERE "EventID" IN ('4672', '4720', '4728', '4732', '4738')
ORDER BY starttime DESC
LAST 48 HOURS`,
    });

    // E. Windows Event 1102 / 104: Security Log Cleared (Savunmayı Devre Dışı Bırakma)
    queries.push({
      id: 'aql_win_log_cleared',
      title: '🚨 Windows Olay Günlüğü Sıfırlama Tespiti (Audit Log Cleared - 1102 / 104)',
      category: 'HUNTING',
      logType: 'WINDOWS',
      description: 'Saldırganların izlerini silmek amacıyla Security.evtx veya System günlüğünü temizlemesi (T1070.001 - Clear Windows Event Logs).',
      recommendedTimeWindow: 'LAST 7 DAYS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       username AS "Gunlugu_Silen_Hesap",
       "EventID" AS "Olay_ID",
       LOGSOURCENAME(logsourceid) AS "Hedef_Sunucu"
FROM events
WHERE "EventID" = '1102' OR "EventID" = '104'
ORDER BY starttime DESC
LAST 7 DAYS`,
    });
  }

  // -------------------------------------------------------------
  // WEB APPLICATION & WAF THREAT HUNTING QUERIES
  // -------------------------------------------------------------
  if (isWeb) {
    const cleanUri = urlOrCmd.split('?')[0].trim();
    const uriMatch = cleanUri ? `(UTF8(payload) ILIKE '%${cleanUri}%')` : `sourceip = '${srcIp || '0.0.0.0'}'`;

    queries.push({
      id: 'aql_web_threat_hunting',
      title: '🌐 Web Uygulama Saldırısı & Payload İncelemesi (Web Attack & Payload)',
      category: 'HUNTING',
      logType: 'WEB',
      description: 'WAF veya Web Sunucu loglarında benzer URI / Payload desenini arar ve HTTP durum kodlarını listeler.',
      recommendedTimeWindow: 'LAST 24 HOURS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       sourceip AS "Saldirgan_IP",
       destinationip AS "Hedef_Web_Sunucu",
       "URL" AS "Istek_Adresi",
       "ResponseCode" AS "HTTP_Durum",
       UTF8(payload) AS "Ham_Payload"
FROM events
WHERE ${uriMatch}
ORDER BY starttime DESC
LAST 24 HOURS`,
    });

    queries.push({
      id: 'aql_web_sqli_xss_rce',
      title: '💉 Web Enjeksiyon ve Webshell Taraması (SQLi, RCE, Webshell Hunting)',
      category: 'HUNTING',
      logType: 'WEB',
      description: 'Ariel payload içerisinde SELECT, UNION, cmd=, /etc/passwd, <script>, eval(), phpinfo() veya .jsp desenlerini tarar.',
      recommendedTimeWindow: 'LAST 24 HOURS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       sourceip AS "Kaynak_IP",
       destinationip AS "Hedef_Sunucu",
       "URL" AS "Saldırı_Yolu",
       "ResponseCode" AS "HTTP_Cevap",
       UTF8(payload) AS "Payload_Icerigi"
FROM events
WHERE (UTF8(payload) ILIKE '%union%select%'
    OR UTF8(payload) ILIKE '%/etc/passwd%'
    OR UTF8(payload) ILIKE '%cmd=%'
    OR UTF8(payload) ILIKE '%.php?%'
    OR UTF8(payload) ILIKE '%<script>%'
    OR UTF8(payload) ILIKE '%..%2f%')
  ${srcIp ? `AND sourceip = '${srcIp}'` : ''}
ORDER BY starttime DESC
LAST 24 HOURS`,
    });

    queries.push({
      id: 'aql_web_path_traversal',
      title: '📂 Dizin Dolaşımı ve Yetkisiz Erişim Denemeleri (Path Traversal & 403 Spike)',
      category: 'HUNTING',
      logType: 'WEB',
      description: 'Hedef sunucuya yapılan 401, 403 ve 404 hatalarını tekil kaynak IP bazında toplayarak dizin tarama yazılımlarını (Dirbuster, Gobuster vb.) tespit eder.',
      recommendedTimeWindow: 'LAST 12 HOURS',
      aql: `SELECT sourceip AS "Kaynak_IP",
       COUNT(*) AS "Hata_Sayisi_4xx",
       UNIQUECOUNT("URL") AS "Denenen_Farkli_Yollar",
       DATEFORMAT(MIN(starttime), 'yyyy-MM-dd HH:mm:ss') AS "Ilk_Istek",
       DATEFORMAT(MAX(starttime), 'yyyy-MM-dd HH:mm:ss') AS "Son_Istek"
FROM events
WHERE "ResponseCode" IN (401, 403, 404)
GROUP BY sourceip
HAVING COUNT(*) >= 20
ORDER BY "Hata_Sayisi_4xx" DESC
LAST 12 HOURS`,
    });
  }

  // -------------------------------------------------------------
  // NETWORK & FIREWALL QUERIES
  // -------------------------------------------------------------
  if (nature.category === 'FIREWALL' || (!isWindows && !isWeb)) {
    queries.push({
      id: 'aql_fw_deny_spike',
      title: '🧱 Güvenlik Duvarı Engellenen Bağlantı Anomalisi (Firewall Deny / Drop Spike)',
      category: 'HUNTING',
      logType: 'FIREWALL',
      description: 'Güvenlik duvarı üzerinde aynı kaynak IP tarafından hedeflenen portları ve engellenen paket sayısını gruplar.',
      recommendedTimeWindow: 'LAST 24 HOURS',
      aql: `SELECT sourceip AS "Kaynak_IP",
       destinationip AS "Hedef_IP",
       destinationport AS "Hedef_Port",
       QIDNAME(qid) AS "Kural_Adi",
       COUNT(*) AS "Engelleme_Sayisi"
FROM events
WHERE (QIDNAME(qid) ILIKE '%Drop%' OR QIDNAME(qid) ILIKE '%Deny%' OR QIDNAME(qid) ILIKE '%Blocked%')
  ${srcIp ? `AND sourceip = '${srcIp}'` : ''}
GROUP BY sourceip, destinationip, destinationport, QIDNAME(qid)
ORDER BY "Engelleme_Sayisi" DESC
LAST 24 HOURS`,
    });
  }

  // 2. IP Pivot / Horizontal Expansion (Ağ Geneli Yayılma & Pivot)
  if (srcIp) {
    queries.push({
      id: 'aql_ip_pivot',
      title: '🌐 Kaynak IP Ağ Geneli Yayılma & Hedefler (Lateral Movement Pivot)',
      category: 'HUNTING',
      logType: isWindows ? 'WINDOWS' : isWeb ? 'WEB' : 'GENERIC',
      description: `Kaynak IP (${srcIp}) tarafından ağdaki diğer sunuculara veya servislere yöneltilen tüm istekleri ve hedef portları gruplar.`,
      recommendedTimeWindow: 'LAST 48 HOURS',
      aql: `SELECT destinationip AS "Hedef_IP",
       destinationport AS "Hedef_Port",
       QIDNAME(qid) AS "Tetiklenen_Kural",
       COUNT(*) AS "Istek_Sayisi",
       UNIQUECOUNT(username) AS "Farkli_Hesap_Sayisi"
FROM events
WHERE sourceip = '${srcIp}'
GROUP BY destinationip, destinationport, QIDNAME(qid)
ORDER BY "Istek_Sayisi" DESC
LAST 48 HOURS`,
    });
  }

  // 3. User Behavior / Account Activity (Kullanıcı Hesabı Taraması)
  if (username) {
    queries.push({
      id: 'aql_user_timeline',
      title: `👤 Hesap Etkinlik Zaman Çizelgesi (${username})`,
      category: 'INVESTIGATION',
      logType: isWindows ? 'WINDOWS' : 'GENERIC',
      description: `Kullanıcı hesabının (${username}) son 7 gün içinde giriş yaptığı IP adreslerini, makine adlarını ve oturum sonuçlarını döker.`,
      recommendedTimeWindow: 'LAST 7 DAYS',
      aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Zaman",
       sourceip AS "Giris_Yapilan_IP",
       LOGSOURCENAME(logsourceid) AS "Sistem",
       QIDNAME(qid) AS "Olay",
       COUNT(*) AS "Deneme_Sayisi"
FROM events
WHERE username ILIKE '${username}'
GROUP BY starttime, sourceip, logsourceid, qid
ORDER BY starttime DESC
LAST 7 DAYS`,
    });
  }

  // 7. General Aggregation (Zaman Penceresi Trendi)
  queries.push({
    id: 'aql_hourly_spike',
    title: '📈 Saatlik Olay Dağılımı ve Tepe Noktaları (Hourly Spike Trend)',
    category: 'AGGREGATION',
    logType: isWindows ? 'WINDOWS' : isWeb ? 'WEB' : 'GENERIC',
    description: 'Saatlik bazda olay yoğunluğunu özetleyerek anormal aktivite artışlarını tespit eder.',
    recommendedTimeWindow: 'LAST 24 HOURS',
    aql: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:00') AS "Saat_Dilimi",
       COUNT(*) AS "Olay_Adedi",
       UNIQUECOUNT(sourceip) AS "Tekil_Kaynak_IP",
       UNIQUECOUNT(destinationip) AS "Tekil_Hedef_IP"
FROM events
WHERE ${mainWhere}
GROUP BY "Saat_Dilimi"
ORDER BY "Saat_Dilimi" ASC
LAST 24 HOURS`,
  });

  return queries;
}

/**
 * Analyzes the parsed log line and context parameters to generate production-ready,
 * exact IBM QRadar CRE (Custom Rule Engine) Detection Rules and Offense definitions.
 */
export function generateQradarCustomRules(params: {
  rawLog?: string;
  ip?: string;
  destIp?: string;
  user?: string;
  port?: number | string;
  method?: string;
  url?: string;
  statusCode?: number | string;
  eventId?: number | string;
  processName?: string;
  hostname?: string;
}): QradarCustomRuleDefinition[] {
  const rules: QradarCustomRuleDefinition[] = [];
  const raw = params.rawLog || '';
  const rawLow = raw.toLowerCase();

  // Extract / auto-detect parameters
  let detectedEventId = params.eventId ? String(params.eventId) : '';
  if (!detectedEventId) {
    const eidMatch = raw.match(/\b(?:EventID|Event ID|EventCode|Signature ID)\s*[:=]\s*(\d{3,5})\b/i) ||
                     raw.match(/\b(4624|4625|4688|4672|4720|4728|4732|1102|104|7045|4697|4768|4769|4776|4648)\b/);
    if (eidMatch) detectedEventId = eidMatch[1];
  }

  let detectedUser = params.user && params.user !== '-' && params.user !== 'Bilinmiyor' ? params.user : '';
  if (!detectedUser) {
    const usrMatch = raw.match(/\b(?:TargetUserName|Account Name|User Name|user|usr|username)\s*[:=]\s*["']?([a-zA-Z0-9._-]+)["']?/i);
    if (usrMatch && !['system', 'anonymous', '-'].includes(usrMatch[1].toLowerCase())) {
      detectedUser = usrMatch[1];
    }
  }

  let detectedSrcIp = params.ip && params.ip !== '-' && params.ip !== 'Bilinmiyor' ? params.ip : '';
  if (!detectedSrcIp) {
    const ipMatch = raw.match(/\b(?:Source Network Address|IpAddress|src|srcip|sourceip|client_ip)\s*[:=]\s*["']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']?/i);
    if (ipMatch) detectedSrcIp = ipMatch[1];
  }

  let detectedProcess = params.processName || '';
  if (!detectedProcess) {
    const procMatch = raw.match(/\b(?:NewProcessName|Process Name|Image|CommandLine|islem_komutu)\s*[:=]\s*["']?([^\r\n"';]+)["']?/i);
    if (procMatch) detectedProcess = procMatch[1].trim();
  }

  let detectedHost = params.hostname && params.hostname !== '-' ? params.hostname : '';
  if (!detectedHost) {
    const hostMatch = raw.match(/\b(?:WorkstationName|ComputerName|Computer|host|hostname)\s*[:=]\s*["']?([a-zA-Z0-9._-]+)["']?/i);
    if (hostMatch) detectedHost = hostMatch[1];
  }

  const nature = detectLogNature({
    rawLog: raw,
    eventId: detectedEventId,
    method: params.method,
    url: params.url,
    statusCode: params.statusCode,
  });

  const isWindows = nature.category === 'WINDOWS';
  const isWeb = nature.category === 'WEB';

  // -------------------------------------------------------------------------
  // 1. WINDOWS EVENT RULES (Specific & Real)
  // -------------------------------------------------------------------------
  if (isWindows) {
    // 1.A. Windows 4625 - Password Spraying & Brute Force Rule
    if (detectedEventId === '4625' || rawLow.includes('4625') || (!detectedEventId && rawLow.includes('an account failed to log on'))) {
      const subStatus = raw.includes('0xC000006A') ? '0xC000006A (Bad Password)' : raw.includes('0xC0000064') ? '0xC0000064 (User Does Not Exist)' : '0xC000006A / 0xC000006D';

      rules.push({
        id: 'cre_win_4625_spray',
        ruleName: 'SOC-RULE-WIN: Ardışık Başarısız Oturum ve Parola Püskürtme (Event 4625)',
        ruleType: 'CRE_OFFENSE_RULE',
        severity: 7,
        credibility: 8,
        relevance: 9,
        category: 'Authentication.Failed Authentication',
        mitreTactic: 'Credential Access (TA0006)',
        mitreTechnique: 'Brute Force: Password Spraying (T1110.003)',
        summary: `Aynı kaynak IP'den (${detectedSrcIp || 'Source IP'}) veya makinadan (${detectedHost || 'Workstation'}) Windows DC/Endpoint sistemlerine kısa sürede (5-10 dk) çok sayıda başarısız oturum (Event 4625) gerçekleştiğinde Offense tetikler.`,
        logSourceFilter: 'Microsoft Windows Security Event Log / DSM',
        ruleTestConditions: [
          `and when an event matches any of the following: QID is "4625: An account failed to log on" OR EventID is "4625"`,
          `and when the event category is "Authentication.Failed Authentication"`,
          `and when at least 5 events are seen with the same Source IP in 5 minutes`,
          `and when the event(s) have not been marked as False Positive in Reference Data`,
        ],
        ruleActionDescription: `CRE Eylemi: Yeni bir Offense (Olay Kaydı) oluştur, "Indexed by Source IP". Offense Başlığı: "SOC Alert: Parola Püskürtme Şüphesi (Event 4625) - " + Source IP. Severity: 7. SOC Bildirim e-postası tetikle.`,
        qradarCREExpression: `Apply "SOC-RULE-WIN: Ardışık Başarısız Oturum ve Parola Püskürtme" on events which are detected by the Local system
and when the event QID is one of the following (4625) An account failed to log on
and when at least 5 events are seen with the same Source IP in 5 minutes
and when "SubStatus" matches any of ("0xC000006A", "0xC000006D", "0xC0000064")`,
        qradarAqlRuleCondition: `SELECT sourceip, username, "SubStatus", COUNT(*) 
FROM events 
WHERE "EventID" = '4625' ${detectedSrcIp ? `AND sourceip = '${detectedSrcIp}'` : ''}
GROUP BY sourceip, username, "SubStatus" 
HAVING COUNT(*) >= 5 
LAST 5 MINUTES`,
        qradarRuleConfigSteps: [
          `1. QRadar -> Offenses -> Rules -> Actions -> New Event Rule seçin.`,
          `2. Kural Adı: "SOC-RULE-WIN: Ardışık Başarısız Oturum ve Parola Püskürtme (Event 4625)" girin.`,
          `3. Rule Wizard'da Test Filtresi: "when an event matches QID = 4625" ekleyin.`,
          `4. İkinci Filtre: "and when at least 5 events are seen with the same Source IP in 5 minutes" koşulunu bağlayın.`,
          `5. Rule Response: "Dispatch New Event" ve "Ensure the detected event is part of an offense, indexed by: Source IP" kutusunu işaretleyin.`,
        ],
      });

      // 1.B. Lateral Movement via Failed Logons (Multiple Destination Hosts)
      rules.push({
        id: 'cre_win_4625_lateral',
        ruleName: 'SOC-RULE-WIN: Tek Kaynaktan Çoklu Sunucuya Başarısız NTLM/SMB Denemesi (Lateral Movement)',
        ruleType: 'CRE_OFFENSE_RULE',
        severity: 8,
        credibility: 9,
        relevance: 9,
        category: 'Lateral Movement.Exploitation of Remote Services',
        mitreTactic: 'Lateral Movement (TA0008)',
        mitreTechnique: 'Remote Services: SMB/Windows Admin Shares (T1021.002)',
        summary: `Tek bir iç IP veya hosttan 10 dakika içerisinde en az 3 farklı sunucuya (DC, File Server vb.) başarısız 4625 oturumu açıldığında saldırganın ağda yanal hareket ettiğini tespit eder.`,
        logSourceFilter: 'Microsoft Windows Security Event Log',
        ruleTestConditions: [
          `and when an event matches QID is "4625: An account failed to log on"`,
          `and when the number of distinct Destination IP is at least 3 with the same Source IP in 10 minutes`,
          `and when LogonType is one of the following: 3 (Network) OR 10 (RemoteInteractive/RDP)`,
        ],
        ruleActionDescription: `Yüksek Öncelikli Offense Aç: "Lateral Movement Detected: " + Source IP + " -> Multi Target Servers". SOC Ekibine anında Slack/Teams/Syslog bildirimi gönder.`,
        qradarCREExpression: `Apply "SOC-RULE-WIN: Tek Kaynaktan Çoklu Sunucuya Başarısız Deneme" on events
and when EventID is '4625'
and when LogonType in ('3', '10')
and when the count of unique Destination IP exceeds 3 with the same Source IP in 10 minutes`,
        qradarAqlRuleCondition: `SELECT sourceip, UNIQUECOUNT(destinationip) AS Targets, COUNT(*) AS Attempts 
FROM events 
WHERE "EventID" = '4625' AND "LogonType" IN ('3', '10') 
GROUP BY sourceip 
HAVING Targets >= 3 
LAST 10 MINUTES`,
        qradarRuleConfigSteps: [
          `1. QRadar CRE -> New Rule -> Event Rule.`,
          `2. Filtre: "when the number of distinct Destination IP is at least 3 with the same Source IP in 10 minutes".`,
          `3. İkincil Filtre: "and when LogonType equals 3 or 10".`,
          `4. Action: Severity 8, Credibility 9, Offense Index: Source IP.`,
        ],
      });
    }

    // 1.C. Windows 4688 / Sysmon - Suspicious LotL Process Execution
    if (detectedEventId === '4688' || rawLow.includes('4688') || rawLow.includes('newprocessname') || rawLow.includes('powershell')) {
      rules.push({
        id: 'cre_win_4688_lotl',
        ruleName: 'SOC-RULE-WIN: Şüpheli Komut Satırı ve Living-off-the-Land (LotL) Yürütmesi',
        ruleType: 'CRE_EVENT_RULE',
        severity: 8,
        credibility: 9,
        relevance: 10,
        category: 'Execution.Command and Scripting Interpreter',
        mitreTactic: 'Execution (TA0002) / Defense Evasion (TA0005)',
        mitreTechnique: 'PowerShell (T1059.001) / Living off the Land (T1218)',
        summary: `Uç noktada PowerShell (-enc, -w hidden, downloadstring, iex), cmd.exe /c, certutil, whoami veya vssadmin komutları çalıştırıldığında anında tetiklenir.`,
        logSourceFilter: 'Microsoft Windows Security Event Log (QID: 4688) OR Sysmon (Event ID: 1)',
        ruleTestConditions: [
          `and when an event matches any of: EventID is "4688" OR EventID is "1"`,
          `and when "Process Command Line" matches any of: [powershell.*-enc.*, .*downloadstring.*, .*certutil.*-decode.*, .*vssadmin.*delete.*, .*whoami.*, .*cmd\\.exe.*\\/c.*]`,
          `and when the username is NOT in "SOC-Whitelisted-Admins" Reference Set`,
        ],
        ruleActionDescription: `CRE Eylemi: Anında Kritik Olay (Severity 8) oluştur. Offense Başlığı: "Şüpheli LotL Komut Yürütmesi - " + HostName + " (" + UserName + ")".`,
        qradarCREExpression: `Apply "SOC-RULE-WIN: Şüpheli Komut Satırı LotL" on events
and when EventID in ('4688', '1')
and when "Process Command Line" matches regex '(?i)(powershell.*(-enc|-w\\s+hidden|iex|downloadstring)|certutil.*(-urlcache|-decode)|vssadmin.*delete.*shadows)'`,
        qradarAqlRuleCondition: `SELECT LOGSOURCENAME(logsourceid) AS Host, username, "Process Command Line" 
FROM events 
WHERE ("EventID" = '4688' OR "EventID" = '1') 
  AND ("Process Command Line" ILIKE '%-enc%' 
    OR "Process Command Line" ILIKE '%downloadstring%' 
    OR "Process Command Line" ILIKE '%vssadmin%delete%'
    OR "Process Command Line" ILIKE '%certutil%')
ORDER BY starttime DESC 
LAST 15 MINUTES`,
        qradarRuleConfigSteps: [
          `1. QRadar -> Rules -> Add Rule -> Event Rule.`,
          `2. Rule Filter: "when any of Process Command Line match regular expression: (?i)(powershell.*-enc|certutil.*-decode|vssadmin.*delete)".`,
          `3. Rule Action: Generate New Event -> Event Name: "Suspicious Living-off-the-Land Tool Execution".`,
          `4. Create Offense indexed by: Hostname (Log Source) and Username.`,
        ],
      });
    }

    // 1.D. Windows 1102 / 104 - Event Log Cleared Rule
    rules.push({
      id: 'cre_win_1102_log_cleared',
      ruleName: 'SOC-RULE-WIN: Windows Güvenlik Olay Günlüğü Sıfırlandı (Audit Log Cleared)',
      ruleType: 'CRE_OFFENSE_RULE',
      severity: 10,
      credibility: 10,
      relevance: 10,
      category: 'Defense Evasion.Indicator Removal on Host',
      mitreTactic: 'Defense Evasion (TA0005)',
      mitreTechnique: 'Clear Windows Event Logs (T1070.001)',
      summary: `Windows Security.evtx veya System olay günlüğünün (Event ID 1102 veya 104) silinmesi veya wevtutil cl komutu ile sıfırlanması durumunda anında en yüksek öncelikli (Severity 10) Offense oluşturur.`,
      logSourceFilter: 'Microsoft Windows Security Event Log',
      ruleTestConditions: [
        `and when an event matches any of: EventID is "1102" OR EventID is "104" OR QID is "The audit log was cleared"`,
        `and when the event is detected by any Log Source`,
      ],
      ruleActionDescription: `Kritik Offense Başlat (Severity 10). Offense Index: HostName ve Kullanıcı. SOC L3 nöbetçisine SMS/Pager/Webhook çağrısı yap.`,
      qradarCREExpression: `Apply "SOC-RULE-WIN: Windows Olay Günlüğü Sıfırlandı" on events
and when EventID in ('1102', '104')`,
      qradarAqlRuleCondition: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS Zaman, LOGSOURCENAME(logsourceid) AS Host, username, "EventID" 
FROM events 
WHERE "EventID" IN ('1102', '104') 
LAST 24 HOURS`,
      qradarRuleConfigSteps: [
        `1. QRadar CRE -> New Rule -> Event Rule.`,
        `2. Test: "when an event matches QID: The audit log was cleared (EventID 1102, 104)".`,
        `3. Severity: 10 (Maximum), Credibility: 10.`,
        `4. Response: Ensure Offense is opened and email alert sent immediately to soc-alerts@company.com.`,
      ],
    });
  }

  // -------------------------------------------------------------------------
  // 2. WEB APPLICATION / WAF RULES (Specific & Real)
  // -------------------------------------------------------------------------
  if (isWeb) {
    rules.push({
      id: 'cre_web_sqli_rce',
      ruleName: 'SOC-RULE-WEB: Web Uygulama Enjeksiyonu ve Payload Saldırısı (SQLi / RCE / XSS)',
      ruleType: 'CRE_OFFENSE_RULE',
      severity: 8,
      credibility: 8,
      relevance: 9,
      category: 'Web Application.SQL Injection / Remote Command',
      mitreTactic: 'Initial Access (TA0001) / Exploitation for Client Execution (TA0002)',
      mitreTechnique: 'Exploit Public-Facing Application (T1190)',
      summary: `WAF veya web sunucu isteklerinde SQLi (UNION, SELECT, ORDER BY), RCE (/etc/passwd, cmd=, eval), Webshell veya XSS desenleri görüldüğünde kaynak IP bazında Offense açar.`,
      logSourceFilter: 'FortiWeb / ModSecurity / Nginx / IIS / F5 BIG-IP ASM',
      ruleTestConditions: [
        `and when an event matches any of: UTF8(payload) contains any of ["union select", "select * from", "/etc/passwd", "cmd.exe", "eval(", "<script>"]`,
        `and when the HTTP Response Code is NOT 400`,
        `and when at least 3 events occur with the same Source IP in 10 minutes`,
      ],
      ruleActionDescription: `Offense Index: Source IP. Offense Başlığı: "Web Saldırısı / Enjeksiyon Şüphesi: " + Source IP + " -> " + Destination IP. Otomatik Firewall engelleme scriptini tetikle.`,
      qradarCREExpression: `Apply "SOC-RULE-WEB: Web Uygulama Enjeksiyonu" on events
and when UTF8(payload) matches regex '(?i)(union.*select|/etc/passwd|cmd=\\w+|eval\\(|<script>)'
and when at least 3 events occur with the same Source IP in 10 minutes`,
      qradarAqlRuleCondition: `SELECT sourceip, destinationip, "URL", "ResponseCode", COUNT(*) AS Istek_Sayisi 
FROM events 
WHERE UTF8(payload) ILIKE '%union%select%' 
   OR UTF8(payload) ILIKE '%/etc/passwd%' 
   OR UTF8(payload) ILIKE '%cmd=%' 
GROUP BY sourceip, destinationip, "URL", "ResponseCode" 
HAVING COUNT(*) >= 3 
LAST 10 MINUTES`,
      qradarRuleConfigSteps: [
        `1. QRadar -> Rules -> New Event Rule.`,
        `2. Test: "when the event payload contains any of: union select, /etc/passwd, cmd=".`,
        `3. Threshold: "and when at least 3 events are seen with the same Source IP in 10 minutes".`,
        `4. Action: Create Offense indexed by Source IP. Severity: 8.`,
      ],
    });

    rules.push({
      id: 'cre_web_403_scanner',
      ruleName: 'SOC-RULE-WEB: Otomatik Dizin Tarama ve 4xx Hata Patlaması (Directory Brute-force)',
      ruleType: 'CRE_OFFENSE_RULE',
      severity: 6,
      credibility: 7,
      relevance: 8,
      category: 'Reconnaissance.Active Scanning',
      mitreTactic: 'Reconnaissance (TA0043)',
      mitreTechnique: 'Active Scanning: Wordlist Scanning (T1595.002)',
      summary: `Tek bir IP adresinden web sunucusuna kısa sürede (5 dakika) 25'ten fazla 401/403/404 cevabı döndüğünde dizin tarama yazılımlarını (Dirbuster/Gobuster/Nikto) tespit eder.`,
      logSourceFilter: 'Web Application / Reverse Proxy Log Sources',
      ruleTestConditions: [
        `and when the HTTP Response Code is one of: 401, 403, 404`,
        `and when at least 25 events are seen with the same Source IP in 5 minutes`,
        `and when Source IP is NOT in "Internal-Vulnerability-Scanners" Reference Set`,
      ],
      ruleActionDescription: `Offense Index: Source IP. Offense Başlığı: "Web Dizin Tarayıcı Tespiti: " + Source IP.`,
      qradarCREExpression: `Apply "SOC-RULE-WEB: Otomatik Dizin Tarama" on events
and when "ResponseCode" in (401, 403, 404)
and when at least 25 events are seen with the same Source IP in 5 minutes`,
      qradarAqlRuleCondition: `SELECT sourceip, COUNT(*) AS Hatalar, UNIQUECOUNT("URL") AS Farkli_Adresler 
FROM events 
WHERE "ResponseCode" IN (401, 403, 404) 
GROUP BY sourceip 
HAVING COUNT(*) >= 25 
LAST 5 MINUTES`,
      qradarRuleConfigSteps: [
        `1. QRadar CRE -> New Rule -> Event Rule.`,
        `2. Test: "when ResponseCode is in (401, 403, 404)".`,
        `3. Threshold: "at least 25 events with the same Source IP in 5 minutes".`,
        `4. Exclude: "and when Source IP is not in Reference Set: Authorized-Scanners".`,
      ],
    });
  }

  // -------------------------------------------------------------------------
  // 3. GENERIC / FIREWALL IP PIVOT RULE
  // -------------------------------------------------------------------------
  if (detectedSrcIp) {
    const isInternalIp =
      detectedSrcIp === '127.0.0.1' ||
      detectedSrcIp === '::1' ||
      detectedSrcIp === 'localhost' ||
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(detectedSrcIp) ||
      /^192\.168\.\d{1,3}\.\d{1,3}$/.test(detectedSrcIp) ||
      /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(detectedSrcIp) ||
      /^169\.254\.\d{1,3}\.\d{1,3}$/.test(detectedSrcIp);

    rules.push({
      id: 'cre_fw_port_scan_spike',
      ruleName: isInternalIp
        ? `SOC-RULE-NET: Dahili Kaynak IP (${detectedSrcIp}) Port Taraması ve Yatay Yayılma Şüphesi`
        : `SOC-RULE-NET: Dış Kaynak IP (${detectedSrcIp}) Port Taraması ve Engellenen Trafik`,
      ruleType: 'CRE_OFFENSE_RULE',
      severity: 7,
      credibility: 7,
      relevance: 8,
      category: isInternalIp ? 'Internal.Lateral Movement / Internal Port Scan' : 'Network.Port Scan / Denied Traffic',
      mitreTactic: isInternalIp ? 'Lateral Movement (TA0008) / Reconnaissance (TA0043)' : 'Reconnaissance (TA0043)',
      mitreTechnique: 'Network Service Discovery (T1046)',
      summary: isInternalIp
        ? `Dahili IP adresinden (${detectedSrcIp}) diğer iç sistemlere doğru anormal port taraması veya reddedilen bağlantı patlaması görüldüğünde tetiklenir.`
        : `Dış kaynak IP'den (${detectedSrcIp}) iç ağa doğru çok sayıda farklı hedef porta kısa sürede erişim denemesi yapıldığında veya firewall tarafından drop/deny edildiğinde tetiklenir.`,
      logSourceFilter: isInternalIp
        ? 'İç Güvenlik Duvarı / EDR / Switch Syslog / İç Segmentasyon'
        : 'Sınır Güvenlik Duvarı (Perimeter FW) / UTM / Edge Sensor',
      ruleTestConditions: [
        `and when an event matches any of: QID is "Firewall Deny" OR "Packet Drop"`,
        `and when the number of distinct Destination Port is at least 10 with the same Source IP in 5 minutes`,
      ],
      ruleActionDescription: isInternalIp
        ? `Dahili Kaynak IP (${detectedSrcIp}): Sınır firewall yerine EDR uç nokta ağ izolasyonu (Host Network Isolation) veya 802.1X karantina VLAN yönlendirmesi uygulanmalıdır.`
        : `Offense Index: Source IP. Offense Başlığı: "Ağ Port Taraması Tespiti - " + Source IP. Otomatik Sınır Güvenlik Duvarı IP Engelleme (Firewall Drop) kuralını tetikle.`,
      qradarCREExpression: `Apply "SOC-RULE-NET: Port Taraması" on events
and when (QIDNAME(qid) ILIKE '%Deny%' OR QIDNAME(qid) ILIKE '%Drop%')
and when the count of distinct Destination Port exceeds 10 with the same Source IP in 5 minutes`,
      qradarAqlRuleCondition: `SELECT sourceip, UNIQUECOUNT(destinationport) AS Portlar, COUNT(*) AS Engelleme 
FROM events 
WHERE (QIDNAME(qid) ILIKE '%Deny%' OR QIDNAME(qid) ILIKE '%Drop%') ${detectedSrcIp ? `AND sourceip = '${detectedSrcIp}'` : ''}
GROUP BY sourceip 
HAVING Portlar >= 10 
LAST 5 MINUTES`,
      qradarRuleConfigSteps: isInternalIp
        ? [
            `1. QRadar CRE -> New Rule -> Event Rule.`,
            `2. Test: "when number of distinct Destination Port is at least 10 with the same Source IP in 5 minutes".`,
            `3. Severity: 7, Offense Index: Source IP.`,
            `4. Aksiyon: Dış firewall engellemesi YERİNE Dahili EDR karantina ve Incident yanıt ekibine bildirim gönder.`,
          ]
        : [
            `1. QRadar CRE -> New Rule.`,
            `2. Test: "when number of distinct Destination Port is at least 10 with the same Source IP in 5 minutes".`,
            `3. Severity: 7, Offense Index: Source IP.`,
            `4. Aksiyon: Dış Sınır Güvenlik Duvarında (Perimeter FW) IP kara listeye alınsın.`,
          ],
    });
  }

  return rules;
}

/**
 * Generates QRadar Custom Event Property (CEP) Regex patterns for arbitrary text or target fields.
 */
export function generateQradarRegexForField(
  fullLogLine: string,
  targetValue: string,
  suggestedFieldName?: string
): {
  fieldName: string;
  regexPattern: string;
  captureGroup: string;
  qradarFormatType: 'Text' | 'IP' | 'Port' | 'Number' | 'Date';
  sampleMatch: string;
  qradarCepGuide: string;
  alternativeRegexes: string[];
} {
  const trimmedLog = fullLogLine.trim();
  const trimmedTarget = targetValue.trim();
  const fieldName = suggestedFieldName ? suggestedFieldName.replace(/[^a-zA-Z0-9_]/g, '_') : 'Custom_Field';

  // 1. Detect if target is in key-value form in the log (e.g. key="val" or key=val or key: val)
  const escapedTarget = escapeRegex(trimmedTarget);
  const kvSearchRegex = new RegExp(`([a-zA-Z0-9_.-]+)\\s*[:=]\\s*["']?(${escapedTarget})["']?`, 'i');
  const kvMatch = trimmedLog.match(kvSearchRegex);

  let primaryRegex = '';
  let formatType: 'Text' | 'IP' | 'Port' | 'Number' | 'Date' = 'Text';
  const alternativeRegexes: string[] = [];

  // Determine property type based on target value
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmedTarget)) {
    formatType = 'IP';
  } else if (/^\d{1,5}$/.test(trimmedTarget) && parseInt(trimmedTarget, 10) <= 65535) {
    formatType = 'Port';
  } else if (/^\d+$/.test(trimmedTarget)) {
    formatType = 'Number';
  } else if (/^\d{4}-\d{2}-\d{2}/.test(trimmedTarget) || /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}/.test(trimmedTarget)) {
    formatType = 'Date';
  }

  if (kvMatch && kvMatch[1]) {
    const keyName = kvMatch[1];
    // Pattern A: key="value" or key=value
    primaryRegex = `${escapeRegex(keyName)}=["']?([^"';\\s,]+)["']?`;
    alternativeRegexes.push(`${escapeRegex(keyName)}[:=]\\s*["']?([^"';\\r\\n]+)["']?`);
    alternativeRegexes.push(`${escapeRegex(keyName)}="([^"]+)"`);
  } else {
    // Context-based capture (look at surrounding 15 chars before target)
    const idx = trimmedLog.indexOf(trimmedTarget);
    if (idx !== -1) {
      const prefix = trimmedLog.slice(Math.max(0, idx - 15), idx);
      // Clean prefix to create a robust anchor
      const anchor = prefix.split(/\s+/).pop() || '';
      if (anchor) {
        primaryRegex = `${escapeRegex(anchor)}\\s*([^\\s,;"'<>]+)`;
      } else {
        primaryRegex = `(${escapedTarget})`;
      }
    } else {
      primaryRegex = `(${escapedTarget})`;
    }
    alternativeRegexes.push(`(?:${escapedTarget})`);
    alternativeRegexes.push(`\\b(${escapedTarget})\\b`);
  }

  // Validate match
  let sampleMatch = '';
  try {
    const tester = new RegExp(primaryRegex, 'i');
    const res = trimmedLog.match(tester);
    if (res && res[1]) {
      sampleMatch = res[1];
    } else if (res && res[0]) {
      sampleMatch = res[0];
    }
  } catch {
    sampleMatch = trimmedTarget;
  }

  const qradarCepGuide = `QRadar Custom Event Property (CEP) Yapılandırma Adımları:
1. QRadar Konsolu -> Admin sekmesine gidin.
2. 'Data Sources' altından 'Custom Event Properties' (Özel Olay Özellikleri) seçeneğine tıklayın.
3. 'Add' butonuna tıklayarak Özellik Adı (Name) alanına "${fieldName}" yazın.
4. Alan Tipi (Field Type): '${formatType}' olarak seçin.
5. 'Extraction Expression' (Çıkarım İfadesi) alanına oluşturulan Regex'i yapıştırın:
   ${primaryRegex}
6. Capture Group (Yakalama Grubu): $1
7. 'Optimize parsing for rules, reports, and searches' kutucuğunu işaretleyerek kaydedin.`;

  return {
    fieldName,
    regexPattern: primaryRegex,
    captureGroup: '$1',
    qradarFormatType: formatType,
    sampleMatch: sampleMatch || trimmedTarget,
    qradarCepGuide,
    alternativeRegexes,
  };
}

/**
 * Scans a raw log line and automatically extracts all parseable candidate fields
 * (IPs, usernames, status codes, ports, domains, URIs, key-value pairs) with ready-to-use QRadar regex.
 */
export function extractCandidateFieldsForQradar(logLine: string): RegexExtractionCandidate[] {
  const candidates: RegexExtractionCandidate[] = [];
  const trimmed = logLine.trim();
  if (!trimmed) return candidates;

  const addedKeys = new Set<string>();

  // 1. Key-Value pairs (key=val or key="val" or key: val)
  const kvRegex = /([a-zA-Z0-9_.-]+)\s*[:=]\s*(".*?"|'.*?'|[^\s,;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = kvRegex.exec(trimmed)) !== null) {
    const rawKey = m[1];
    let val = m[2].trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    const cleanKey = rawKey.replace(/[^a-zA-Z0-9_]/g, '_');

    if (!addedKeys.has(cleanKey) && val.length > 0 && val.length < 150) {
      addedKeys.add(cleanKey);
      let propType: 'Text' | 'IP' | 'Port' | 'Number' | 'Date' = 'Text';
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) propType = 'IP';
      else if (/^\d{1,5}$/.test(val) && parseInt(val, 10) <= 65535) propType = 'Port';
      else if (/^\d+$/.test(val)) propType = 'Number';

      candidates.push({
        fieldName: cleanKey,
        value: val,
        regexPattern: `${escapeRegex(rawKey)}[:=]\\s*["']?([^"';\\s,]+)["']?`,
        captureGroup: '$1',
        qradarPropertyType: propType,
        explanation: `Ham logda '${rawKey}' anahtarından çıkarılan değer.`,
      });
    }
  }

  // 2. Standalone IP Addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  let ipMatch: RegExpExecArray | null;
  let ipIndex = 1;
  while ((ipMatch = ipRegex.exec(trimmed)) !== null) {
    const ip = ipMatch[0];
    const key = `Detected_IP_${ipIndex++}`;
    if (!addedKeys.has(ip)) {
      addedKeys.add(ip);
      candidates.push({
        fieldName: key,
        value: ip,
        regexPattern: `\\b(${escapeRegex(ip)})\\b`,
        captureGroup: '$1',
        qradarPropertyType: 'IP',
        explanation: 'Ham log içerisinde yakalanan bağımsız IP adresi.',
      });
    }
  }

  // 3. Windows Specific Forensic Fields
  // 3.1 Event ID
  const eventIdMatch = trimmed.match(/\b(?:EventID|Event ID|EventCode)\s*[:=]\s*(\d{3,5})\b/i);
  if (eventIdMatch && !addedKeys.has('EventID')) {
    addedKeys.add('EventID');
    candidates.push({
      fieldName: 'Windows_EventID',
      value: eventIdMatch[1],
      regexPattern: '(?:EventID|Event ID|EventCode)\\s*[:=]\\s*(\\d+)',
      captureGroup: '$1',
      qradarPropertyType: 'Number',
      explanation: 'Windows Güvenlik Olay Kimliği (4625, 4624, 4688 vb.)',
    });
  }

  // 3.2 TargetUserName / SubjectUserName
  const targetUserMatch = trimmed.match(/\b(?:TargetUserName|Target User Name)\s*[:=]\s*["']?([^\s"';\r\n,]+)["']?/i);
  if (targetUserMatch && !addedKeys.has('TargetUserName')) {
    addedKeys.add('TargetUserName');
    candidates.push({
      fieldName: 'TargetUserName',
      value: targetUserMatch[1],
      regexPattern: 'TargetUserName\\s*[:=]\\s*["\']?([^\\s"\';\\r\\n]+)["\']?',
      captureGroup: '$1',
      qradarPropertyType: 'Text',
      explanation: 'Hedef Kullanıcı Hesabı (Oturum Açılmaya Çalışılan Hesap)',
    });
  }

  // 3.3 SubStatus / Failure Status Code (0xC000006A etc.)
  const subStatusMatch = trimmed.match(/\b(?:SubStatus|Sub-Status|Status)\s*[:=]\s*["']?(0x[0-9a-fA-F]{4,8})["']?/i);
  if (subStatusMatch && !addedKeys.has('Windows_SubStatus')) {
    addedKeys.add('Windows_SubStatus');
    candidates.push({
      fieldName: 'Windows_SubStatus',
      value: subStatusMatch[1],
      regexPattern: '(?:SubStatus|Sub-Status)\\s*[:=]\\s*["\']?(0x[0-9a-fA-F]+)["\']?',
      captureGroup: '$1',
      qradarPropertyType: 'Text',
      explanation: 'Windows Oturum Hata Kodu (0xC000006A: Hatalı Şifre, 0xC0000064: Geçersiz Kullanıcı vb.)',
    });
  }

  // 3.4 WorkstationName / Computer
  const wsMatch = trimmed.match(/\b(?:WorkstationName|Workstation Name|ComputerName|Computer)\s*[:=]\s*["']?([^\s"';\r\n,]+)["']?/i);
  if (wsMatch && !addedKeys.has('WorkstationName')) {
    addedKeys.add('WorkstationName');
    candidates.push({
      fieldName: 'WorkstationName',
      value: wsMatch[1],
      regexPattern: '(?:WorkstationName|Workstation Name|Computer)\\s*[:=]\\s*["\']?([^\\s"\';\\r\\n]+)["\']?',
      captureGroup: '$1',
      qradarPropertyType: 'Text',
      explanation: 'İstemci veya Hedef Bilgisayar / Host Adı',
    });
  }

  // 3.5 Process CommandLine
  const cmdMatch = trimmed.match(/\b(?:Process Command Line|CommandLine|ProcessCommandLine)\s*[:=]\s*["']?([^"'\r\n;]+)["']?/i);
  if (cmdMatch && !addedKeys.has('Process_CommandLine')) {
    addedKeys.add('Process_CommandLine');
    candidates.push({
      fieldName: 'Process_CommandLine',
      value: cmdMatch[1].slice(0, 100),
      regexPattern: '(?:Process Command Line|CommandLine)\\s*[:=]\\s*["\']?([^"\'\\r\\n]+)["\']?',
      captureGroup: '$1',
      qradarPropertyType: 'Text',
      explanation: 'Yürütülen Sürecin Tam Komut Satırı Argümanları',
    });
  }

  // 4. HTTP Methods & Status
  const methodMatch = trimmed.match(/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/);
  if (methodMatch && !addedKeys.has('HTTP_Method')) {
    addedKeys.add('HTTP_Method');
    candidates.push({
      fieldName: 'HTTP_Method',
      value: methodMatch[1],
      regexPattern: '\\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\b',
      captureGroup: '$1',
      qradarPropertyType: 'Text',
      explanation: 'HTTP Metodu (GET, POST, PUT, DELETE vb.)',
    });
  }

  // 5. HTTP Status Code (200, 401, 403, 404, 500 etc.)
  const statusMatch = trimmed.match(/\b(200|201|204|301|302|400|401|403|404|405|408|500|502|503|504)\b/);
  if (statusMatch && !addedKeys.has('HTTP_Status')) {
    addedKeys.add('HTTP_Status');
    candidates.push({
      fieldName: 'HTTP_Status',
      value: statusMatch[1],
      regexPattern: '\\b([1-5]\\d{2})\\b',
      captureGroup: '$1',
      qradarPropertyType: 'Number',
      explanation: 'HTTP Yanıt Durum Kodu (Status Code)',
    });
  }

  return candidates;
}
