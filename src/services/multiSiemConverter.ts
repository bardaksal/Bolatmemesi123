/**
 * Multi-SIEM & EDR Threat Hunting Query & Detection Rule Generator
 * 
 * Supports:
 * 1. Splunk (SPL)
 * 2. Microsoft Sentinel (KQL)
 * 3. Elasticsearch (KQL, Lucene & EQL)
 * 4. Sigma Rule (YAML)
 * 5. IBM QRadar (AQL - referenced from qradarAqlHelper)
 */

export type SiemPlatform = 'SPLUNK' | 'SENTINEL' | 'ELASTIC' | 'SIGMA' | 'QRADAR';

export interface MultiSiemQueryItem {
  id: string;
  title: string;
  platform: SiemPlatform;
  category: 'INVESTIGATION' | 'CORRELATION' | 'AGGREGATION' | 'HUNTING' | 'DETECTION';
  description: string;
  query: string;
  syntaxHighlightLanguage: 'spl' | 'kql' | 'yaml' | 'sql' | 'text';
  timeWindow: string;
  targetLogSource: string;
  mitreTechnique?: string;
  mitreTactic?: string;
}

export interface MultiSiemContext {
  rawLog?: string;
  ip?: string;
  destIp?: string;
  user?: string;
  port?: number | string;
  method?: string;
  url?: string;
  statusCode?: number | string;
  eventId?: number | string;
  subStatus?: string;
  processName?: string;
  commandLine?: string;
  hostname?: string;
}

/**
 * Escapes values for safe insertion into SIEM queries
 */
export function cleanVal(v?: string | number, fallback: string = ''): string {
  if (v === undefined || v === null) return fallback;
  const s = String(v).trim();
  const lower = s.toLowerCase();
  if (
    s === '' ||
    s === '-' ||
    lower === 'bilinmiyor' ||
    lower === 'unknown' ||
    lower === 'n/a' ||
    lower === 'null' ||
    lower === 'none' ||
    lower === 'undefined'
  ) {
    return fallback;
  }
  return s;
}

export function escapeSpl(v: string): string {
  if (!v) return '';
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function escapeKql(v: string): string {
  if (!v) return '';
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function escapeElastic(v: string): string {
  if (!v) return '';
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function escapeYaml(v: string): string {
  if (!v) return '';
  return v.replace(/'/g, "''");
}

/**
 * Generates tailored Splunk Search Processing Language (SPL) hunting queries
 */
export function generateSplunkQueries(ctx: MultiSiemContext): MultiSiemQueryItem[] {
  const queries: MultiSiemQueryItem[] = [];
  const srcIp = cleanVal(ctx.ip);
  const destIp = cleanVal(ctx.destIp);
  const user = cleanVal(ctx.user);
  const port = cleanVal(ctx.port);
  const eid = cleanVal(ctx.eventId);
  const proc = cleanVal(ctx.processName);
  const raw = cleanVal(ctx.rawLog).toLowerCase();

  // 1. Splunk: Windows Event Log Hunting
  if (eid || raw.includes('eventid') || raw.includes('4625') || raw.includes('4688')) {
    const targetEid = eid || (raw.includes('4625') ? '4625' : raw.includes('4688') ? '4688' : '4624');
    
    if (targetEid === '4625') {
      queries.push({
        id: 'splunk_win_4625_spray',
        title: 'Splunk SPL: Başarısız Oturumlar ve Parola Püskürtme Analizi (Event 4625)',
        platform: 'SPLUNK',
        category: 'CORRELATION',
        description: 'Belirtilen kullanıcı veya IP üzerinden gelen Event 4625 loglarını zaman aralığında gruplar ve hedef hesapları listeler.',
        timeWindow: 'Son 24 Saat (earliest=-24h)',
        targetLogSource: 'wineventlog:security / XmlWinEventLog:Security',
        syntaxHighlightLanguage: 'spl',
        mitreTechnique: 'T1110.003 (Password Spraying)',
        mitreTactic: 'Credential Access (TA0006)',
        query: `index=* (sourcetype="*wineventlog:security" OR sourcetype="*XmlWinEventLog*") EventCode=4625 ${srcIp ? `(Source_Network_Address="${escapeSpl(srcIp)}" OR IpAddress="${escapeSpl(srcIp)}")` : ''} ${user ? `TargetUserName="${escapeSpl(user)}"` : ''}
| stats count as Basarisiz_Giris, dc(TargetUserName) as Hedef_Kullanici_Sayisi, values(TargetUserName) as Kullanicilar, values(SubStatus) as Hata_Kodlari, values(Workstation_Name) as Istemciler by Source_Network_Address
| where Basarisiz_Giris >= 3
| sort - Basarisiz_Giris`,
      });

      queries.push({
        id: 'splunk_win_4625_timeline',
        title: 'Splunk SPL: Dakikalık Başarısız Giriş Zaman Çizelgesi (Timechart Spike)',
        platform: 'SPLUNK',
        category: 'AGGREGATION',
        description: 'Dakikalık bazda başarısız giriş anomalilerini ve zirve noktalarını görselleştirmek için zaman grafiği üretir.',
        timeWindow: 'Son 6 Saat (earliest=-6h)',
        targetLogSource: 'wineventlog:security',
        syntaxHighlightLanguage: 'spl',
        query: `index=* sourcetype="*wineventlog*" EventCode=4625 ${srcIp ? `Source_Network_Address="${escapeSpl(srcIp)}"` : ''}
| timechart span=5m count as Hatali_Giris_Sayisi by TargetUserName`,
      });
    }

    if (targetEid === '4688' || proc || raw.includes('process command line') || raw.includes('newprocessname')) {
      queries.push({
        id: 'splunk_win_4688_process',
        title: 'Splunk SPL: Şüpheli Süreç ve Komut Satırı Yürütme (Event 4688 / Sysmon 1)',
        platform: 'SPLUNK',
        category: 'HUNTING',
        description: 'PowerShell, cmd, certutil, vssadmin veya şüpheli komut parametrelerini ana süreç-alt süreç hiyerarşisiyle listeler.',
        timeWindow: 'Son 24 Saat (earliest=-24h)',
        targetLogSource: 'wineventlog:security / Sysmon',
        syntaxHighlightLanguage: 'spl',
        mitreTechnique: 'T1059 (Command and Scripting Interpreter)',
        mitreTactic: 'Execution (TA0002)',
        query: `index=* (EventCode=4688 OR (sourcetype="*sysmon*" EventCode=1)) ${proc ? `(NewProcessName="*${escapeSpl(proc)}*" OR CommandLine="*${escapeSpl(proc)}*")` : ''}
| search CommandLine="*powershell*" OR CommandLine="*-enc*" OR CommandLine="*vssadmin*" OR CommandLine="*certutil*" OR CommandLine="*whoami*"
| table _time, host, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| sort - _time`,
      });
    }
  }

  // 2. Splunk: Web Application & WAF Hunting
  if (ctx.method || ctx.url || ctx.statusCode || raw.includes('http') || raw.includes('waf') || raw.includes('get /') || raw.includes('post /')) {
    queries.push({
      id: 'splunk_web_sqli_rce',
      title: 'Splunk SPL: Web Uygulama Enjeksiyonu & Saldırı Payload Taraması (SQLi / RCE)',
      platform: 'SPLUNK',
      category: 'HUNTING',
      description: 'Web erişim ve WAF kayıtlarında UNION, SELECT, /etc/passwd, cmd=, eval veya XSS desenlerini arar.',
      timeWindow: 'Son 12 Saat (earliest=-12h)',
      targetLogSource: 'access_combined / nginx:access / iis / waf:*',
      syntaxHighlightLanguage: 'spl',
      mitreTechnique: 'T1190 (Exploit Public-Facing Application)',
      mitreTactic: 'Initial Access (TA0001)',
      query: `index=* (sourcetype="*access*" OR sourcetype="*waf*" OR sourcetype="*iis*") ${srcIp ? `(clientip="${escapeSpl(srcIp)}" OR src_ip="${escapeSpl(srcIp)}" OR c_ip="${escapeSpl(srcIp)}")` : ''}
| search uri="*union*select*" OR uri="*information_schema*" OR uri="*/etc/passwd*" OR uri="*cmd=*" OR uri="*<script>*" OR uri="*\${jndi:*"
| stats count as Istek_Sayisi, values(status) as Donen_Kodlar, values(useragent) as Ajanlar by clientip, uri
| sort - Istek_Sayisi`,
    });

    queries.push({
      id: 'splunk_web_scanner_4xx',
      title: 'Splunk SPL: Otomatize Web Dizin Tarayıcıları (401/403/404 Burst)',
      platform: 'SPLUNK',
      category: 'CORRELATION',
      description: 'Tek bir istemci IP adresinden kısa sürede gelen çok sayıda 4xx hatasını tespit eder (Dirbuster/Nikto).',
      timeWindow: 'Son 4 Saat (earliest=-4h)',
      targetLogSource: 'web / proxy / access_combined',
      syntaxHighlightLanguage: 'spl',
      mitreTechnique: 'T1595.002 (Wordlist Scanning)',
      mitreTactic: 'Reconnaissance (TA0043)',
      query: `index=* (status=401 OR status=403 OR status=404)
| stats count as Toplam_Hata, dc(uri) as Farkli_Adres_Sayisi, values(status) as Kodlar by clientip
| where Toplam_Hata >= 20 AND Farkli_Adres_Sayisi >= 10
| sort - Toplam_Hata`,
    });
  }

  // 3. Splunk: Firewall & Network Traffic Hunting
  if (srcIp || port || raw.includes('deny') || raw.includes('drop') || raw.includes('firewall')) {
    queries.push({
      id: 'splunk_fw_denied_traffic',
      title: 'Splunk SPL: Güvenlik Duvarı Engellenen Bağlantı & Port Taraması (Deny Spike)',
      platform: 'SPLUNK',
      category: 'INVESTIGATION',
      description: 'Engellenen bağlantıları kaynak ve hedef port çeşitliliğine göre gruplar.',
      timeWindow: 'Son 2 Saat (earliest=-2h)',
      targetLogSource: 'pan:traffic / cisco:asa / fgt_traffic / firewall',
      syntaxHighlightLanguage: 'spl',
      mitreTechnique: 'T1046 (Network Service Discovery)',
      mitreTactic: 'Discovery (TA0007)',
      query: `index=* (action="blocked" OR action="denied" OR action="drop" OR action="deny") ${srcIp ? `src_ip="${escapeSpl(srcIp)}"` : ''} ${destIp ? `dest_ip="${escapeSpl(destIp)}"` : ''}
| stats count as Engelleme_Sayisi, dc(dest_port) as Farkli_Port_Sayisi, values(dest_port) as Hedef_Portlar by src_ip, dest_ip
| where Farkli_Port_Sayisi >= 5 OR Engelleme_Sayisi >= 20
| sort - Engelleme_Sayisi`,
    });
  }

  return queries;
}

/**
 * Generates Microsoft Sentinel (Azure Monitor / Log Analytics) KQL queries
 */
export function generateSentinelKqlQueries(ctx: MultiSiemContext): MultiSiemQueryItem[] {
  const queries: MultiSiemQueryItem[] = [];
  const srcIp = cleanVal(ctx.ip);
  const destIp = cleanVal(ctx.destIp);
  const user = cleanVal(ctx.user);
  const port = cleanVal(ctx.port);
  const eid = cleanVal(ctx.eventId);
  const proc = cleanVal(ctx.processName);
  const raw = cleanVal(ctx.rawLog).toLowerCase();

  // 1. Sentinel: Windows Security Events
  if (eid || raw.includes('eventid') || raw.includes('4625') || raw.includes('4688')) {
    const targetEid = eid || (raw.includes('4625') ? '4625' : raw.includes('4688') ? '4688' : '4624');

    if (targetEid === '4625') {
      queries.push({
        id: 'kql_win_4625_spray',
        title: 'Sentinel KQL: Ardışık Başarısız Girişler ve Parola Püskürtme (Event 4625)',
        platform: 'SENTINEL',
        category: 'CORRELATION',
        description: 'Azure Sentinel SecurityEvent tablosunda ardışık başarısız oturumları analiz eder.',
        timeWindow: 'Son 24 Saat (ago(24h))',
        targetLogSource: 'SecurityEvent / WindowsEvent',
        syntaxHighlightLanguage: 'kql',
        mitreTechnique: 'T1110.003 (Password Spraying)',
        mitreTactic: 'Credential Access (TA0006)',
        query: `SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
${srcIp ? `| where IpAddress == "${escapeKql(srcIp)}"` : ''}
${user ? `| where TargetAccount has "${escapeKql(user)}"` : ''}
| summarize 
    Basarisiz_Giris_Sayisi = count(),
    Farkli_Kullanicilar = dcount(TargetAccount),
    Kullanici_Listesi = make_set(TargetAccount, 10),
    Hata_Kodlari = make_set(SubStatus, 5),
    Istemci_Makineler = make_set(WorkstationName, 5)
    by IpAddress, Computer
| where Basarisiz_Giris_Sayisi >= 3
| sort by Basarisiz_Giris_Sayisi desc`,
      });

      queries.push({
        id: 'kql_win_4625_timechart',
        title: 'Sentinel KQL: Zamansal Anomali Dağılımı (5 Dakikalık Dilimler)',
        platform: 'SENTINEL',
        category: 'AGGREGATION',
        description: 'Zaman çizelgesi üzerinde başarısız giriş anomalilerini görselleştirir.',
        timeWindow: 'Son 12 Saat',
        targetLogSource: 'SecurityEvent',
        syntaxHighlightLanguage: 'kql',
        query: `SecurityEvent
| where TimeGenerated >= ago(12h)
| where EventID == 4625
${srcIp ? `| where IpAddress == "${escapeKql(srcIp)}"` : ''}
| summarize Hatali_Denemeler = count() by bin(TimeGenerated, 5m), TargetAccount
| render timechart`,
      });
    }

    if (targetEid === '4688' || proc || raw.includes('commandline') || raw.includes('sysmon')) {
      queries.push({
        id: 'kql_win_4688_process',
        title: 'Sentinel KQL: Süreç Oluşturma & LOLBAS Komut Tespiti (SecurityEvent 4688 / Sysmon)',
        platform: 'SENTINEL',
        category: 'HUNTING',
        description: 'Uç noktalarda çalıştırılan PowerShell, cmd, certutil, vssadmin gibi şüpheli komutları haritalandırır.',
        timeWindow: 'Son 24 Saat',
        targetLogSource: 'SecurityEvent / DeviceProcessEvents',
        syntaxHighlightLanguage: 'kql',
        mitreTechnique: 'T1059 (Command and Scripting Interpreter)',
        mitreTactic: 'Execution (TA0002)',
        query: `SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
${proc ? `| where NewProcessName has "${escapeKql(proc)}" or CommandLine has "${escapeKql(proc)}"` : ''}
| where CommandLine has_any ("powershell", "-enc", "vssadmin", "certutil", "whoami", "mimikatz", "bitsadmin", "/dev/tcp")
| project TimeGenerated, Computer, SubjectAccount, ParentProcessName, NewProcessName, CommandLine
| sort by TimeGenerated desc`,
      });
    }
  }

  // 2. Sentinel: WAF & Web Application Security
  if (ctx.method || ctx.url || ctx.statusCode || raw.includes('http') || raw.includes('waf')) {
    queries.push({
      id: 'kql_web_sqli_rce',
      title: 'Sentinel KQL: Azure WAF / IIS İstismar Payload Taraması (SQLi / RCE / Log4j)',
      platform: 'SENTINEL',
      category: 'HUNTING',
      description: 'Azure Application Gateway WAF veya CommonSecurityLog üzerinden gelen enjeksiyon saldırılarını arar.',
      timeWindow: 'Son 24 Saat',
      targetLogSource: 'AzureDiagnostics (Azure Application Gateway WAF) / CommonSecurityLog',
      syntaxHighlightLanguage: 'kql',
      mitreTechnique: 'T1190 (Exploit Public-Facing Application)',
      mitreTactic: 'Initial Access (TA0001)',
      query: `AzureDiagnostics
| where TimeGenerated >= ago(24h)
| where Category == "ApplicationGatewayFirewallLog"
${srcIp ? `| where clientIp_s == "${escapeKql(srcIp)}"` : ''}
| where requestUri_s has_any ("union", "select", "/etc/passwd", "cmd.exe", "eval(", "\${jndi:") or details_message_s has_any ("SQLI", "RCE", "XSS")
| summarize Istek_Sayisi = count(), Aksiyonlar = make_set(action_s) by clientIp_s, requestUri_s, ruleId_s
| sort by Istek_Sayisi desc`,
    });
  }

  // 3. Sentinel: CommonSecurityLog (Firewall & Network Sensor)
  if (srcIp || port || raw.includes('deny') || raw.includes('firewall')) {
    queries.push({
      id: 'kql_fw_denied_traffic',
      title: 'Sentinel KQL: Güvenlik Duvarı Engellenen Trafik & Port Taraması (CommonSecurityLog)',
      platform: 'SENTINEL',
      category: 'INVESTIGATION',
      description: 'Palo Alto, FortiGate, Checkpoint gibi CEF entegrasyonlu güvenlik duvarı loglarında engellemeleri analiz eder.',
      timeWindow: 'Son 6 Saat',
      targetLogSource: 'CommonSecurityLog (CEF Syslog)',
      syntaxHighlightLanguage: 'kql',
      mitreTechnique: 'T1046 (Network Service Discovery)',
      mitreTactic: 'Discovery (TA0007)',
      query: `CommonSecurityLog
| where TimeGenerated >= ago(6h)
| where DeviceAction in ("deny", "drop", "blocked", "reset")
${srcIp ? `| where SourceIP == "${escapeKql(srcIp)}"` : ''}
${destIp ? `| where DestinationIP == "${escapeKql(destIp)}"` : ''}
| summarize 
    Engelleme_Sayisi = count(),
    Hedef_Port_Cesidi = dcount(DestinationPort),
    Port_Listesi = make_set(DestinationPort, 15)
    by SourceIP, DestinationIP, DeviceVendor, DeviceProduct
| where Hedef_Port_Cesidi >= 5 or Engelleme_Sayisi >= 20
| sort by Engelleme_Sayisi desc`,
    });
  }

  return queries;
}

/**
 * Generates Elasticsearch / Kibana / Elastic SIEM (KQL & Lucene & EQL) queries
 */
export function generateElasticQueries(ctx: MultiSiemContext): MultiSiemQueryItem[] {
  const queries: MultiSiemQueryItem[] = [];
  const srcIp = cleanVal(ctx.ip);
  const destIp = cleanVal(ctx.destIp);
  const user = cleanVal(ctx.user);
  const port = cleanVal(ctx.port);
  const eid = cleanVal(ctx.eventId);
  const proc = cleanVal(ctx.processName);
  const raw = cleanVal(ctx.rawLog).toLowerCase();

  // 1. Elastic: Windows Security / Winlogbeat (ECS Schema)
  if (eid || raw.includes('eventid') || raw.includes('4625') || raw.includes('4688')) {
    const targetEid = eid || (raw.includes('4625') ? '4625' : raw.includes('4688') ? '4688' : '4624');

    if (targetEid === '4625') {
      queries.push({
        id: 'elastic_win_4625_kql',
        title: 'Elastic KQL: Başarısız Oturum Açma (Event 4625 - ECS Standardı)',
        platform: 'ELASTIC',
        category: 'INVESTIGATION',
        description: 'Elasticsearch Kibana Discover arama çubuğuna doğrudan yapıştırılabilen KQL sorgusu.',
        timeWindow: 'Son 24 Saat',
        targetLogSource: 'winlogbeat-* / logs-endpoint.events.*',
        syntaxHighlightLanguage: 'kql',
        mitreTechnique: 'T1110.003 (Password Spraying)',
        mitreTactic: 'Credential Access (TA0006)',
        query: `winlog.channel: "Security" and winlog.event_id: 4625 ${srcIp ? `and source.ip: "${escapeElastic(srcIp)}"` : ''} ${user ? `and user.name: "${escapeElastic(user)}"` : ''}`,
      });

      queries.push({
        id: 'elastic_win_4625_eql',
        title: 'Elastic EQL: 5 Dakikada 5+ Başarısız Giriş Korelasyon Kuralı',
        platform: 'ELASTIC',
        category: 'CORRELATION',
        description: 'Elastic Detection Engine için Event Query Language (EQL) korelasyon dizisi.',
        timeWindow: '5 Dakikalık Pencere (maxspan=5m)',
        targetLogSource: 'winlogbeat-* / logs-endpoint.events.*',
        syntaxHighlightLanguage: 'kql',
        query: `sequence by winlog.computer_name, source.ip with maxspan=5m
  [authentication where winlog.event_id == 4625]
  [authentication where winlog.event_id == 4625]
  [authentication where winlog.event_id == 4625]
  [authentication where winlog.event_id == 4625]
  [authentication where winlog.event_id == 4625]`,
      });
    }

    if (targetEid === '4688' || proc || raw.includes('commandline')) {
      queries.push({
        id: 'elastic_win_4688_kql',
        title: 'Elastic KQL: Şüpheli Süreç ve Gizlenmiş Komut Yürütme (Event 4688 / Sysmon 1)',
        platform: 'ELASTIC',
        category: 'HUNTING',
        description: 'PowerShell Base64, vssadmin veya certutil çağıran süreçleri ECS şemasında arar.',
        timeWindow: 'Son 24 Saat',
        targetLogSource: 'winlogbeat-* / logs-endpoint.events.*',
        syntaxHighlightLanguage: 'kql',
        mitreTechnique: 'T1059.001 (PowerShell)',
        mitreTactic: 'Execution (TA0002)',
        query: `event.category: "process" and event.type: "start" and (process.command_line: (*powershell* and *-enc*) or process.command_line: (*vssadmin* and *delete*) or process.command_line: (*certutil* and *-urlcache*)) ${srcIp ? `and source.ip: "${escapeElastic(srcIp)}"` : ''}`,
      });
    }
  }

  // 2. Elastic: Web & Network Logs (Filebeat / Packetbeat)
  if (ctx.method || ctx.url || ctx.statusCode || raw.includes('http') || raw.includes('deny')) {
    queries.push({
      id: 'elastic_web_kql',
      title: 'Elastic KQL: Web Uygulama Enjeksiyonu & Saldırı İstismarı',
      platform: 'ELASTIC',
      category: 'HUNTING',
      description: 'Web erişim veya WAF loglarında SQLi, RCE ve XSS göstergelerini arar.',
      timeWindow: 'Son 24 Saat',
      targetLogSource: 'filebeat-* / packetbeat-* / logs-nginx.* / logs-apache.*',
      syntaxHighlightLanguage: 'kql',
      mitreTechnique: 'T1190 (Exploit Public-Facing Application)',
      mitreTactic: 'Initial Access (TA0001)',
      query: `event.dataset: ("nginx.access" or "apache.access" or "iis.access") and (url.original: (*union*select* or *information_schema* or */etc/passwd* or *cmd.exe* or *jndi:*)) ${srcIp ? `and source.ip: "${escapeElastic(srcIp)}"` : ''}`,
    });

    queries.push({
      id: 'elastic_fw_deny_kql',
      title: 'Elastic KQL: Güvenlik Duvarı Engellenen Bağlantılar (Drop/Deny)',
      platform: 'ELASTIC',
      category: 'INVESTIGATION',
      description: 'Ağ trafiği ve güvenlik duvarı cihazlarından gelen reddedilmiş oturumları filtreler.',
      timeWindow: 'Son 4 Saat',
      targetLogSource: 'filebeat-* / logs-panw.* / logs-fortinet.* / logs-checkpoint.*',
      syntaxHighlightLanguage: 'kql',
      query: `event.category: "network" and event.action: ("deny" or "drop" or "blocked") ${srcIp ? `and source.ip: "${escapeElastic(srcIp)}"` : ''} ${destIp ? `and destination.ip: "${escapeElastic(destIp)}"` : ''}`,
    });
  }

  return queries;
}

/**
 * Generates Universal Vendor-Agnostic Sigma Rules (YAML)
 */
export function generateSigmaRule(ctx: MultiSiemContext): MultiSiemQueryItem[] {
  const rules: MultiSiemQueryItem[] = [];
  const srcIp = cleanVal(ctx.ip);
  const destIp = cleanVal(ctx.destIp);
  const user = cleanVal(ctx.user);
  const eid = cleanVal(ctx.eventId);
  const proc = cleanVal(ctx.processName);
  const raw = cleanVal(ctx.rawLog).toLowerCase();

  const isWindows = !!eid || raw.includes('eventid') || raw.includes('4625') || raw.includes('4688');
  const isWeb = !!ctx.method || !!ctx.url || !!ctx.statusCode || raw.includes('http') || raw.includes('get /');

  if (isWindows) {
    if (eid === '4625' || raw.includes('4625') || (!eid && !isWeb)) {
      const yaml = `title: Windows Ardışık Başarısız Oturum ve Parola Püskürtme (Event 4625)
id: f48b8c91-2a13-4c91-b3e1-d0a4c28f1109
status: test
description: Tek bir kaynak IP veya iş istasyonundan Windows Active Directory / Endpoint sistemlerine doğru kısa sürede ardışık başarısız oturum denemelerini tespit eder.
references:
    - https://attack.mitre.org/techniques/T1110/003/
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
author: SOC Threat Hunting Engine
date: 2026/09/23
tags:
    - attack.credential_access
    - attack.t1110.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
${srcIp ? `        SourceNetworkAddress: '${escapeYaml(srcIp)}'\n` : ''}${user ? `        TargetUserName: '${escapeYaml(user)}'\n` : ''}    timeframe: 5m
    condition: selection | count() by SourceNetworkAddress > 4
falsepositives:
    - Parolası yakın zamanda değişmiş ancak arka planda oturum açmaya çalışan meşru servis hesapları veya eşlenmiş ağ sürücüleri (SMB).
    - Yanlış yapılandırılmış otomatik izleme araçları (Monitoring Agent).
level: high`;

      rules.push({
        id: 'sigma_win_4625',
        title: 'Sigma Kuralı: Windows Event 4625 Parola Püskürtme (Universal YAML)',
        platform: 'SIGMA',
        category: 'DETECTION',
        description: 'Tüm SIEM ve EDR platformlarına (Splunk, QRadar, Sentinel, Elastic) çevrilebilir resmi Sigma kuralı.',
        timeWindow: '5 Dakika (timeframe: 5m)',
        targetLogSource: 'Windows Security Event Log',
        syntaxHighlightLanguage: 'yaml',
        mitreTechnique: 'T1110.003 (Password Spraying)',
        mitreTactic: 'Credential Access (TA0006)',
        query: yaml,
      });
    }

    if (eid === '4688' || proc || raw.includes('commandline') || raw.includes('powershell')) {
      const yaml = `title: Şüpheli Komut Satırı ve LOLBAS Betik Yürütme
id: c718a230-e341-482a-9f50-32df9c91b102
status: test
description: PowerShell Base64 gizleme (-enc), vssadmin gölge kopya silme veya certutil dosya indirme komut satırlarını tespit eder.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://lolbas-project.github.io/
author: SOC Threat Hunting Engine
date: 2026/09/23
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - 'vssadmin delete shadows'
            - 'certutil -urlcache'
            - 'certutil.exe -urlcache'
            - '/dev/tcp/'
    condition: selection_cmd
falsepositives:
    - Kurumsal yönetim otomasyonları ve yama dağıtım yazılımları (SCCM / Intune).
level: critical`;

      rules.push({
        id: 'sigma_win_process_lolbas',
        title: 'Sigma Kuralı: LOLBAS & Gizlenmiş Komut Yürütme (Universal YAML)',
        platform: 'SIGMA',
        category: 'DETECTION',
        description: 'Saldırganların sistem içi araçları kötüye kullanma (LOLBAS) girişimlerini yakalayan Sigma kuralı.',
        timeWindow: 'Gerçek Zamanlı (Realtime)',
        targetLogSource: 'Windows Process Creation (Event 4688 / Sysmon 1)',
        syntaxHighlightLanguage: 'yaml',
        mitreTechnique: 'T1059.001 (PowerShell) / T1490',
        mitreTactic: 'Execution (TA0002) / Defense Evasion (TA0005)',
        query: yaml,
      });
    }
  }

  if (isWeb) {
    const yaml = `title: Web Uygulama İstismar Payloadı ve Enjeksiyon Saldırısı
id: b92a105f-7128-4e3a-9694-814a6e35cf82
status: test
description: Web sunucusu URI veya istek gövdesinde SQL Injection, Path Traversal veya Log4j JNDI saldırı kalıplarını tespit eder.
references:
    - https://attack.mitre.org/techniques/T1190/
    - https://owasp.org/www-project-top-ten/
author: SOC Threat Hunting Engine
date: 2026/09/23
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_payload:
        c-uri|contains:
            - 'union select'
            - 'information_schema'
            - '/etc/passwd'
            - 'cmd.exe'
            - '\${jndi:'
            - '<script>'
${srcIp ? `    selection_ip:\n        c-ip: '${escapeYaml(srcIp)}'\n` : ''}    condition: selection_payload
falsepositives:
    - Yetkili iç güvenlik zafiyet taramaları veya penetrasyon testleri.
level: high`;

    rules.push({
      id: 'sigma_web_exploit',
      title: 'Sigma Kuralı: Web Enjeksiyonu & RCE Saldırısı (Universal YAML)',
      platform: 'SIGMA',
      category: 'DETECTION',
      description: 'Web sunucu ve ters vekil (Nginx/IIS/Apache) logları için evrensel Sigma kuralı.',
      timeWindow: 'Gerçek Zamanlı',
      targetLogSource: 'Web Sunucu / Reverse Proxy / WAF',
      syntaxHighlightLanguage: 'yaml',
      mitreTechnique: 'T1190 (Exploit Public-Facing Application)',
      mitreTactic: 'Initial Access (TA0001)',
      query: yaml,
    });
  }

  return rules;
}

/**
 * Aggregates all queries across all platforms
 */
export function generateAllSiemQueries(ctx: MultiSiemContext): Record<SiemPlatform, MultiSiemQueryItem[]> {
  return {
    SPLUNK: generateSplunkQueries(ctx),
    SENTINEL: generateSentinelKqlQueries(ctx),
    ELASTIC: generateElasticQueries(ctx),
    SIGMA: generateSigmaRule(ctx),
    QRADAR: [], // QRadar handled via qradarAqlHelper
  };
}
