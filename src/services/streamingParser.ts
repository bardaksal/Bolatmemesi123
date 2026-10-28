import { NormalizedLog, ConnectionDecision, AllowlistData } from '../types';
import { isItemAllowed, isLogAllowedByAllowlist } from './allowlistManager';
import { resolveClientIp, classifyNetworkZone } from './proxyResolver';

export interface StreamEventSample {
  time: string;
  ip: string;
  method: string;
  uri: string;
  status: number;
  server: string;
  bytes: number;
  threatDetected?: string;
  format?: string;
}

export type DetectedFormat =
  | 'W3C_IIS'
  | 'APACHE_NGINX'
  | 'SURICATA_EVE'
  | 'JSON_GENERIC'
  | 'AWS_VPC_FLOW'
  | 'FORTINET_KV'
  | 'PALO_ALTO_CSV'
  | 'PFSENSE_CSV'
  | 'CEF_LEEF'
  | 'SYSLOG_RFC'
  | 'CHECKPOINT_CSV'
  | 'VPN_GATEWAY_CSV'
  | 'F5_BIGIP_CSV'
  | 'WINDOWS_EVENT_LOG'
  | 'GENERIC_DELIMITED'
  | 'UNIVERSAL_AUTO'
  | 'UNKNOWN';

export interface FileFormatState {
  fileName: string;
  format: DetectedFormat;
  formatDisplayName: string;
  isW3C: boolean;
  w3cFields: string[];
  delimiter: string;
  delimiterHeaders: string[];
  isCheckpoint: boolean;
  isPaloAlto: boolean;
  isPfSense: boolean;
  isVpcFlow: boolean;
  isFortinet: boolean;
  isCefLeef: boolean;
  isApacheNginx: boolean;
  isSuricata: boolean;
  isJson: boolean;
  isSyslog: boolean;
  isVpn?: boolean;
  isF5?: boolean;
  isWindowsEvent?: boolean;
  headerLine?: string;
  sampleLinesCount: number;
  detected: boolean;
}

export interface FormatDescription {
  id: DetectedFormat;
  name: string;
  category: string;
  description: string;
  example: string;
}

export const SUPPORTED_LOG_FORMATS: FormatDescription[] = [
  {
    id: 'W3C_IIS',
    name: 'Microsoft IIS (W3C Extended)',
    category: 'Web & FTP Server',
    description: 'IIS 6/7/8/10 W3C logları (#Fields: headerlı veya standart 16 sütunlu).',
    example: '2026-03-01 10:14:22 10.0.0.5 GET /admin/login.aspx - 80 - 192.168.1.50 Mozilla/5.0 - 200 0 0 120',
  },
  {
    id: 'APACHE_NGINX',
    name: 'Apache / Nginx (Combined & Common)',
    category: 'Web Server & Reverse Proxy',
    description: 'Standart Combined/Common log formatı ve Apache/Nginx hata logları.',
    example: '192.168.1.50 - frank [10/Oct/2026:13:55:36 +0300] "GET /api/v1/auth HTTP/1.1" 200 2326 "https://ref.com" "Mozilla/5.0"',
  },
  {
    id: 'SURICATA_EVE',
    name: 'Suricata EVE JSON (IDS/IPS)',
    category: 'Network Security / NIDS',
    description: 'Suricata EVE JSON alarm, HTTP, DNS, TLS ve akış (flow) telemetri kayıtları.',
    example: '{"timestamp":"2026-03-01T10:14:22.123Z","event_type":"alert","src_ip":"192.168.1.50","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SPECIFIC_APPS Webshell Command Execution","action":"allowed"},"http":{"url":"/cmd.aspx?c=whoami","http_method":"GET","status":200}}',
  },
  {
    id: 'JSON_GENERIC',
    name: 'JSON / CloudWatch / K8s / GCP / Azure',
    category: 'Cloud & Container Logs',
    description: 'AWS CloudWatch JSON, Google Cloud Logging (httpRequest), Azure Diagnostics ve Kubernetes/Docker NDJSON.',
    example: '{"timestamp":"2026-03-01T10:14:22Z","remote_addr":"192.168.1.50","request_method":"POST","request_uri":"/login","status":401,"body_bytes_sent":532}',
  },
  {
    id: 'AWS_VPC_FLOW',
    name: 'AWS VPC Flow Logs',
    category: 'Cloud Network Security',
    description: 'Amazon AWS VPC Flow Log standart 14 alanlı metin formatı.',
    example: '2 123456789010 eni-1235b8ca123456789 192.168.1.50 10.0.0.5 54321 443 6 20 4249 1618530010 1618530070 ACCEPT OK',
  },
  {
    id: 'FORTINET_KV',
    name: 'Fortigate / FortiOS Key-Value',
    category: 'Firewall / UTM',
    description: 'Fortinet Fortigate anahtar=değer (key=value) trafik, güvenlik ve UTM logları.',
    example: 'date=2026-03-01 time=10:14:22 devname="FGT-CORP" srcip=192.168.1.50 dstip=10.0.0.5 srcport=54321 dstport=443 action="deny" msg="traffic:denied"',
  },
  {
    id: 'PALO_ALTO_CSV',
    name: 'Palo Alto Networks (PAN-OS CSV)',
    category: 'Next-Gen Firewall',
    description: 'Palo Alto PAN-OS trafik ve tehdit analiz CSV/Syslog formatları.',
    example: '1,2026/03/01 10:14:22,001234567,TRAFFIC,drop,2304,2026/03/01 10:14:22,192.168.1.50,10.0.0.5,0.0.0.0,0.0.0.0,Rule-Deny,,,ssl,vsys1,trust,untrust,,,1,2026/03/01 10:14:22,0,1,54321,443,0,0,0x0,tcp,deny,1234,1234',
  },
  {
    id: 'PFSENSE_CSV',
    name: 'pfSense / OPNsense Filterlog',
    category: 'Open Source Firewall',
    description: 'pfSense ve OPNsense paket filtreleme CSV logları.',
    example: '100,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.50,10.0.0.5,54321,443,0,S,12345678,,65535,,',
  },
  {
    id: 'CEF_LEEF',
    name: 'ArcSight CEF / IBM QRadar LEEF',
    category: 'SIEM Standard Formats',
    description: 'CEF (Common Event Format) ve LEEF (Log Event Extended Format) kurumsal güvenlik kayıtları.',
    example: 'CEF:0|Vendor|SecurityGateway|1.0|100|Unauthorized Access|8|src=192.168.1.50 dst=10.0.0.5 spt=54321 dpt=443 act=deny request=/admin msg="Brute force block"',
  },
  {
    id: 'SYSLOG_RFC',
    name: 'Linux Syslog / Auth / SSH (RFC 3164/5424)',
    category: 'OS & Endpoint Security',
    description: 'Linux auth.log, secure, sshd, sudo, iptables ve standart syslog protokolleri.',
    example: '<13>Mar  1 10:14:22 srv-core sshd[12345]: Failed password for invalid user root from 192.168.1.50 port 54321 ssh2',
  },
  {
    id: 'CHECKPOINT_CSV',
    name: 'Checkpoint Firewall SmartConsole CSV',
    category: 'Firewall',
    description: 'Checkpoint SmartLog ve SmartConsole dışa aktarma CSV kayıtları.',
    example: '"1","Drop","10:14:22","01-Mar-2026","eth0","192.168.1.50","54321","10.0.0.5","443","TCP","Standard Drop Rule"',
  },
  {
    id: 'VPN_GATEWAY_CSV',
    name: 'VPN Oturum & Kimlik Doğrulama CSV',
    category: 'VPN & Remote Access',
    description: 'GlobalProtect, Pulse Secure, FortiClient, SSL-VPN ve kurumsal VPN oturum/giriş CSV telemetrisi.',
    example: 'Username,Realm (custom),Event_Name,VPN_Baglanti_Zamani,VPN_Cikis_Zamani,IP_Adresi,Basarili_Giris,Basarisiz_Giris',
  },
  {
    id: 'F5_BIGIP_CSV',
    name: 'F5 BIG-IP / ASM / WAF (Excel & CSV)',
    category: 'Web Application Firewall',
    description: 'F5 BIG-IP ASM/Advanced WAF engelleme (blocked/alerted), URI, saldırı ve istek dökümü Excel/CSV kayıtları.',
    example: 'F5 Host (custom),F5 Request Status (custom),F5 Full Request (custom),F5 Request URI (custom)',
  },
  {
    id: 'WINDOWS_EVENT_LOG',
    name: 'Windows Güvenlik Olay Günlüğü',
    category: 'Endpoint & Kimlik Güvenliği',
    description: 'Windows Security Event Log (Olay Kimlikleri 4624, 4625, 4688, 4720, 1102, 7045 vb.) oturum ve süreç olayları.',
    example: '<13>Sep 18 10:14:22 dc01 Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: tekin, Workstation: PC01, Source Network Address: 10.0.0.5, Logon Type: 10, SubStatus: 0xC000006A',
  },
  {
    id: 'GENERIC_DELIMITED',
    name: 'Yapılandırılmış CSV / TSV / Semicolon / Pipe',
    category: 'Tabular Logs',
    description: 'Virgül, noktalı virgül, tab veya pipe (|) ile ayrılmış başlıklı özel tablolar.',
    example: 'timestamp,source_ip,dest_ip,port,method,uri,status,bytes',
  },
  {
    id: 'UNIVERSAL_AUTO',
    name: 'Evrensel Adaptif Algılama (Heuristic Engine)',
    category: 'Her Türlü Özel / Düzensiz Log',
    description: 'Formatı bilinmeyen veya karmaşık loglarda IP, tarih, metot, URL, durum kodu ve portları otomatik çıkaran adaptif yapay analiz motoru.',
    example: '[WARN] [ConnectionManager] Client connection 192.168.1.50 -> 10.0.0.5:443 rejected (403) for /restricted/config.json',
  },
];

export function getFormatDisplayName(format: DetectedFormat): string {
  switch (format) {
    case 'W3C_IIS':
      return 'Microsoft IIS (W3C)';
    case 'APACHE_NGINX':
      return 'Apache / Nginx Combined';
    case 'SURICATA_EVE':
      return 'Suricata EVE JSON';
    case 'JSON_GENERIC':
      return 'JSON / CloudWatch / K8s';
    case 'AWS_VPC_FLOW':
      return 'AWS VPC Flow Logs';
    case 'FORTINET_KV':
      return 'Fortigate / Key-Value';
    case 'PALO_ALTO_CSV':
      return 'Palo Alto Networks CSV';
    case 'PFSENSE_CSV':
      return 'pfSense / OPNsense Log';
    case 'CEF_LEEF':
      return 'ArcSight CEF / LEEF';
    case 'SYSLOG_RFC':
      return 'Linux Syslog / Auth (RFC)';
    case 'CHECKPOINT_CSV':
      return 'Checkpoint Firewall CSV';
    case 'VPN_GATEWAY_CSV':
      return 'VPN Oturum & Kimlik Doğrulama CSV';
    case 'F5_BIGIP_CSV':
      return 'F5 BIG-IP / WAF (Excel/CSV)';
    case 'WINDOWS_EVENT_LOG':
      return 'Windows Güvenlik Olay Günlüğü';
    case 'GENERIC_DELIMITED':
      return 'Yapılandırılmış CSV / TSV';
    case 'UNIVERSAL_AUTO':
      return 'Evrensel Otomatik Algılama';
    default:
      return 'Otomatik Taranıyor';
  }
}

// Standard modern IIS fields (IIS 7.0 / 8.0 / 8.5 / 10.0 / Windows Server default)
export const MODERN_IIS_22_FIELDS = [
  'date',
  'time',
  's_sitename',
  's_computername',
  's_ip',
  'cs_method',
  'cs_uri_stem',
  'cs_uri_query',
  's_port',
  'cs_username',
  'c_ip',
  'cs_version',
  'cs_user_agent',
  'cs_cookie',
  'cs_referer',
  'cs_host',
  'sc_status',
  'sc_substatus',
  'sc_win32_status',
  'sc_bytes',
  'cs_bytes',
  'time_taken',
];

// Classic IIS fields (17 fields with bytes)
export const CLASSIC_IIS_17_FIELDS = [
  'date',
  'time',
  's_ip',
  'cs_method',
  'cs_uri_stem',
  'cs_uri_query',
  's_port',
  'cs_username',
  'c_ip',
  'cs_user_agent',
  'cs_referer',
  'sc_status',
  'sc_substatus',
  'sc_win32_status',
  'sc_bytes',
  'cs_bytes',
  'time_taken',
];

// Classic IIS fields (15 fields minimal)
export const CLASSIC_IIS_15_FIELDS = [
  'date',
  'time',
  's_ip',
  'cs_method',
  'cs_uri_stem',
  'cs_uri_query',
  's_port',
  'cs_username',
  'c_ip',
  'cs_user_agent',
  'cs_referer',
  'sc_status',
  'sc_substatus',
  'sc_win32_status',
  'time_taken',
];

export const DEFAULT_IIS_FIELDS = MODERN_IIS_22_FIELDS;

// Common web methods
const HTTP_METHODS_REGEX = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|PROPFIND|SEARCH|TRACK|TRACE|CONNECT)$/i;

// Apache / Nginx Combined/Common Regex
// e.g. 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://referer.com" "Mozilla/5.0"
const APACHE_NGINX_COMBINED_REGEX =
  /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]*?)(?:\s+HTTP\/[\d.]+)?\"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/i;

// Apache / Nginx Common Log Format (without referer / user-agent)
const APACHE_COMMON_REGEX =
  /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]*?)(?:\s+HTTP\/[\d.]+)?\"\s+(\d{3})\s+(\S+)/i;

// Nginx Error Log Regex
// e.g. 2026/03/01 10:14:22 [error] 1234#0: *1 open() "/var/www/shell.php" failed, client: 192.168.1.5, server: example.com, request: "GET /shell.php HTTP/1.1"
const NGINX_ERROR_REGEX =
  /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(\w+)\]\s+.*client:\s+([^,]+).*?(?:request:\s+"(\S+)\s+([^"]+)")?/i;

// Apache Error Log Regex
// e.g. [Wed Oct 11 14:32:52 2026] [error] [client 192.168.1.5:54321] File does not exist: /var/www/cmd.exe
const APACHE_ERROR_REGEX =
  /^\[([^\]]+)\]\s+\[(\w+)\]\s+(?:\[client\s+([^\s:]+)(?::\d+)?\])?\s+(.*)/i;

// AWS VPC Flow Logs Standard 14 fields
// e.g. 2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK
const AWS_VPC_FLOW_REGEX =
  /^\d+\s+\S+\s+eni-\w+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT|NODATA|SKIPDATA)\s+(\S+)/i;

// Linux Syslog RFC 3164 (e.g. <13>Mar  1 10:14:22 host sshd[1234]: Failed password for root from 1.2.3.4 port 55212 ssh2)
const SYSLOG_RFC3164_REGEX =
  /^(?:<(\d+)>)?([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)/i;

// Linux Syslog RFC 5424 (e.g. <165>1 2026-03-01T10:14:22.123Z host app 1234 ID47 [exampleSDID@32473] message)
const SYSLOG_RFC5424_REGEX =
  /^<(\d+)>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[[^\]]+\]\s+)?(.*)/i;

// General IPv4 Regex
const IPV4_REGEX = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/;

/**
 * Robust RFC-4180 compliant CSV / Delimited tokenizer.
 * Handles quoted strings, commas inside quotes, escaped double quotes ("").
 */
export function splitCsvRow(row: string, delimiter: string = ','): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < row.length; i++) {
    const char = row[i];
    if (char === '"') {
      if (inQuotes && row[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === delimiter && !inQuotes) {
      result.push(current.trim().replace(/^"|"$/g, ''));
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim().replace(/^"|"$/g, ''));
  return result;
}

/**
 * Unpacks lines where multiple CSV/log records were concatenated onto a single line
 * without newlines (e.g. ..."0.0"   "ACBDDOM\ali.gul"...).
 * Returns array of individual raw lines so not a single log entry is lost.
 */
export function unpackConcatenatedLines(line: string): string[] {
  if (!line || !line.includes('"')) return [line];

  // If a line has a closing quote followed by whitespace (without delimiter) and an opening quote:
  if (/"\s{1,}(?=")/.test(line)) {
    const rows: string[] = [];
    let currentRow = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        if (inQuotes && line[i + 1] === '"') {
          currentRow += '""';
          i++;
          continue;
        }
        inQuotes = !inQuotes;
        currentRow += char;

        // If we just closed a quote, look ahead for whitespace then another quote (without delimiter)
        if (!inQuotes) {
          let j = i + 1;
          while (j < line.length && (line[j] === ' ' || line[j] === '\t')) {
            j++;
          }
          if (j > i + 1 && j < line.length && line[j] === '"') {
            rows.push(currentRow.trim());
            currentRow = '';
            i = j - 1;
          }
        }
      } else {
        currentRow += char;
      }
    }
    if (currentRow.trim()) {
      rows.push(currentRow.trim());
    }
    return rows.length > 0 ? rows : [line];
  }
  return [line];
}

/**
 * Checks if a line is the column header line of a delimited file (should not be quarantined).
 */
export function isDelimitedHeaderLine(line: string, state: FileFormatState): boolean {
  const trimmed = line.trim().toLowerCase();
  if (state.headerLine && trimmed === state.headerLine) return true;
  if (state.delimiterHeaders && state.delimiterHeaders.length > 0) {
    const parts = splitCsvRow(line, state.delimiter).map(p =>
      p.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
    );
    const matches = parts.filter(p => state.delimiterHeaders.includes(p));
    if (matches.length >= Math.min(2, state.delimiterHeaders.length)) {
      return true;
    }
  }
  const low = trimmed.toLowerCase();
  if (
    low.includes('f5 host') ||
    low.includes('f5 request') ||
    low.includes('f5 full request') ||
    (low.includes('username') && (low.includes('ip_adresi') || low.includes('vpn_')))
  ) {
    return true;
  }
  return false;
}

export function initializeFormatState(fileName: string): FileFormatState {
  return {
    fileName,
    format: 'UNKNOWN',
    formatDisplayName: 'Otomatik Taranıyor',
    isW3C: false,
    w3cFields: [],
    delimiter: ',',
    delimiterHeaders: [],
    isCheckpoint: false,
    isPaloAlto: false,
    isPfSense: false,
    isVpcFlow: false,
    isFortinet: false,
    isCefLeef: false,
    isApacheNginx: false,
    isSuricata: false,
    isJson: false,
    isSyslog: false,
    isVpn: false,
    isF5: false,
    isWindowsEvent: false,
    headerLine: '',
    sampleLinesCount: 0,
    detected: false,
  };
}

export function feedSampleLine(state: FileFormatState, line: string): void {
  if (state.detected) return;
  const trimmed = line.replace(/^\uFEFF/, '').trim();
  if (!trimmed) return;

  // Header comment lines in W3C
  if (trimmed.toLowerCase().startsWith('#fields:')) {
    state.isW3C = true;
    state.format = 'W3C_IIS';
    state.formatDisplayName = getFormatDisplayName('W3C_IIS');
    state.w3cFields = trimmed
      .replace(/^#fields:\s*/i, '')
      .trim()
      .split(/\s+/)
      .map(f => f.toLowerCase().replace(/[()]/g, '_').replace(/-+/g, '_').replace(/^_+|_+$/g, '').trim());
    state.detected = true;
    return;
  }

  // Windows Event Log detection (Syslog, Key-Value or EventID pattern)
  if (
    trimmed.includes('Microsoft-Windows-Security-Auditing') ||
    trimmed.includes('MSWinEventLog') ||
    /\bEventID=\d+/i.test(trimmed) ||
    /\bEvent ID:\s*\d+/i.test(trimmed) ||
    /\bEventCode=\d+/i.test(trimmed)
  ) {
    state.isWindowsEvent = true;
    state.format = 'WINDOWS_EVENT_LOG';
    state.formatDisplayName = getFormatDisplayName('WINDOWS_EVENT_LOG');
    state.detected = true;
    return;
  }

  // Skip other comments (#Software, #Version, #Date) without incrementing sample count
  if (trimmed.startsWith('#')) {
    return;
  }

  state.sampleLinesCount++;

  // 1. JSON / NDJSON format (Suricata EVE, CloudWatch, GCP, Azure, K8s, custom JSON)
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (typeof parsed === 'object' && parsed !== null) {
        state.isJson = true;

        // Check if Suricata EVE
        if (
          parsed.event_type ||
          parsed.alert ||
          (parsed.src_ip && parsed.dest_ip && (parsed.proto || parsed.app_proto || parsed.flow_id))
        ) {
          state.isSuricata = true;
          state.format = 'SURICATA_EVE';
          state.formatDisplayName = getFormatDisplayName('SURICATA_EVE');
        } else {
          state.format = 'JSON_GENERIC';
          state.formatDisplayName = getFormatDisplayName('JSON_GENERIC');
        }
        state.detected = true;
        return;
      }
    } catch {
      // Not valid JSON, continue checks
    }
  }

  // 2. ArcSight CEF / LEEF format
  if (trimmed.startsWith('CEF:') || trimmed.startsWith('LEEF:')) {
    state.isCefLeef = true;
    state.format = 'CEF_LEEF';
    state.formatDisplayName = getFormatDisplayName('CEF_LEEF');
    state.detected = true;
    return;
  }

  // 3. AWS VPC Flow Logs (starts with version number + eni-...)
  if (AWS_VPC_FLOW_REGEX.test(trimmed)) {
    state.isVpcFlow = true;
    state.format = 'AWS_VPC_FLOW';
    state.formatDisplayName = getFormatDisplayName('AWS_VPC_FLOW');
    state.detected = true;
    return;
  }

  // 4. Fortigate / FortiWeb / Key-Value pair logs
  if (
    (/\b(?:srcip|src_ip|src)=\S+/i.test(trimmed) && /\b(?:dstip|dst_ip|dst)=\S+/i.test(trimmed)) ||
    (trimmed.includes('devname=') && trimmed.includes('action=')) ||
    (trimmed.includes('device_id=FV-') || trimmed.includes('device_id=FG-') || (trimmed.includes('log_id=') && trimmed.includes('type=')))
  ) {
    state.isFortinet = true;
    state.format = 'FORTINET_KV';
    state.formatDisplayName = getFormatDisplayName('FORTINET_KV');
    state.detected = true;
    return;
  }

  // 5. Apache / Nginx Combined or Common Format
  if (APACHE_NGINX_COMBINED_REGEX.test(trimmed) || APACHE_COMMON_REGEX.test(trimmed)) {
    state.isApacheNginx = true;
    state.format = 'APACHE_NGINX';
    state.formatDisplayName = getFormatDisplayName('APACHE_NGINX');
    state.detected = true;
    return;
  }

  // 6. Nginx / Apache Error logs
  if (NGINX_ERROR_REGEX.test(trimmed) || APACHE_ERROR_REGEX.test(trimmed)) {
    state.isApacheNginx = true;
    state.format = 'APACHE_NGINX';
    state.formatDisplayName = 'Apache / Nginx Hata Logu';
    state.detected = true;
    return;
  }

  // 7. W3C IIS without #Fields: header (starts with YYYY-MM-DD HH:MM:SS)
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+/.test(trimmed) && !/nginx|systemd|sshd|postfix|kernel/i.test(trimmed)) {
    const sampleParts = trimmed.split(/\s+/);
    state.isW3C = true;
    state.format = 'W3C_IIS';
    state.formatDisplayName = getFormatDisplayName('W3C_IIS');

    if (sampleParts.length >= 20 && HTTP_METHODS_REGEX.test(sampleParts[5])) {
      state.w3cFields = [...MODERN_IIS_22_FIELDS];
    } else if (sampleParts.length >= 16 && HTTP_METHODS_REGEX.test(sampleParts[3])) {
      state.w3cFields = [...CLASSIC_IIS_17_FIELDS];
    } else if (HTTP_METHODS_REGEX.test(sampleParts[3])) {
      state.w3cFields = [...CLASSIC_IIS_15_FIELDS];
    } else {
      const methodIndex = sampleParts.findIndex(p => HTTP_METHODS_REGEX.test(p));
      if (methodIndex === 5) {
        state.w3cFields = [...MODERN_IIS_22_FIELDS];
      } else if (methodIndex === 3) {
        state.w3cFields = sampleParts.length >= 16 ? [...CLASSIC_IIS_17_FIELDS] : [...CLASSIC_IIS_15_FIELDS];
      } else {
        state.w3cFields = [...MODERN_IIS_22_FIELDS];
      }
    }
    state.detected = true;
    return;
  }

  // 8. Palo Alto Networks PAN-OS CSV
  if (
    trimmed.includes(',TRAFFIC,') ||
    trimmed.includes(',THREAT,') ||
    trimmed.includes(',SYSTEM,') ||
    (trimmed.startsWith('1,') && trimmed.includes('/'))
  ) {
    state.isPaloAlto = true;
    state.format = 'PALO_ALTO_CSV';
    state.formatDisplayName = getFormatDisplayName('PALO_ALTO_CSV');
    state.detected = true;
    return;
  }

  // 9. pfSense / OPNsense filterlog
  if (/^\d+,,,.*?,\w+,(?:match|pass|block),/i.test(trimmed)) {
    state.isPfSense = true;
    state.format = 'PFSENSE_CSV';
    state.formatDisplayName = getFormatDisplayName('PFSENSE_CSV');
    state.detected = true;
    return;
  }

  // 10. Checkpoint Firewall format
  if (
    trimmed.includes('firewall_event') ||
    trimmed.includes('Checkpoint') ||
    (trimmed.includes('Drop') && trimmed.includes(',')) ||
    (trimmed.includes('Accept') && trimmed.includes(',') && trimmed.includes('TCP'))
  ) {
    state.isCheckpoint = true;
    state.format = 'CHECKPOINT_CSV';
    state.formatDisplayName = getFormatDisplayName('CHECKPOINT_CSV');
    state.detected = true;
    return;
  }

  // 11. Linux Syslog (RFC 3164 / RFC 5424 / auth.log / sshd)
  if (SYSLOG_RFC3164_REGEX.test(trimmed) || SYSLOG_RFC5424_REGEX.test(trimmed) || /sshd\[\d+\]:/.test(trimmed)) {
    state.isSyslog = true;
    state.format = 'SYSLOG_RFC';
    state.formatDisplayName = getFormatDisplayName('SYSLOG_RFC');
    state.detected = true;
    return;
  }

  // 12. Delimited file header check (Comma, Semicolon, Tab, Pipe) & VPN / F5 CSV
  if (state.sampleLinesCount <= 5) {
    const delimiters = [',', ';', '\t', '|'];
    for (const d of delimiters) {
      if (trimmed.includes(d)) {
        const rawParts = splitCsvRow(trimmed, d);
        const parts = rawParts.map(s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, ''));
        const hasIpHeader = parts.some(p =>
          ['ip', 'c_ip', 's_ip', 'src_ip', 'dst_ip', 'source', 'client', 'remote_addr', 'ip_adresi', 'hedef_ip', 'host', 'f5_host'].some(t => p.includes(t))
        );
        const hasVpnIndicators =
          parts.some(p => p.includes('vpn') || p.includes('realm')) ||
          (parts.includes('event_name') && (parts.includes('basarili_giris') || parts.includes('basarisiz_giris')));
        const hasF5Indicators =
          parts.some(p => p.includes('f5') || p.includes('bigip') || p.includes('asm')) ||
          parts.some(p =>
            p.includes('request_status') ||
            p.includes('request_uri') ||
            p.includes('full_request') ||
            p.includes('attack_type') ||
            p.includes('virtual_server') ||
            p.includes('threat_type') ||
            p.includes('policy_name') ||
            p.includes('destination_port') ||
            (p === 'response' && parts.some(x => x.includes('policy') || x.includes('threat') || x.includes('destination')))
          );

        if (hasIpHeader || hasVpnIndicators || hasF5Indicators) {
          state.delimiter = d;
          state.delimiterHeaders = parts;
          state.headerLine = trimmed.toLowerCase();
          if (hasF5Indicators) {
            state.isF5 = true;
            state.format = 'F5_BIGIP_CSV';
            state.formatDisplayName = getFormatDisplayName('F5_BIGIP_CSV');
          } else if (hasVpnIndicators) {
            state.isVpn = true;
            state.format = 'VPN_GATEWAY_CSV';
            state.formatDisplayName = getFormatDisplayName('VPN_GATEWAY_CSV');
          } else {
            state.format = 'GENERIC_DELIMITED';
            state.formatDisplayName = getFormatDisplayName('GENERIC_DELIMITED');
          }
          state.detected = true;
          return;
        }
      }
    }
  }

  // If sample reaches threshold, mark detected as UNIVERSAL_AUTO fallback
  if (state.sampleLinesCount >= 8) {
    state.format = 'UNIVERSAL_AUTO';
    state.formatDisplayName = getFormatDisplayName('UNIVERSAL_AUTO');
    state.detected = true;
  }
}

// -------------------------------------------------------------
function finalizeLog(log: NormalizedLog | null): NormalizedLog | null {
  if (!log) return null;
  if (!log.network_zone && log.ip_adresi) {
    log.network_zone = classifyNetworkZone(log.ip_adresi);
  }
  if (!log.immediate_peer_ip && log.ip_adresi) {
    log.immediate_peer_ip = log.ip_adresi;
  }
  if (!log.ip_source) {
    log.ip_source = log.forwarded_client_ip ? 'trusted-proxy-forwarded' : 'direct-peer';
  }
  if (!log.device && log.sunucu_ismi) {
    log.device = log.sunucu_ismi;
  }
  return log;
}

// -------------------------------------------------------------
// MAIN UNIVERSAL LOG NORMALIZATION DISPATCHER
// -------------------------------------------------------------
export function parseLineToNormalizedLog(
  rawLine: string,
  state: FileFormatState
): NormalizedLog | null {
  const line = rawLine.replace(/^\uFEFF/, '').trim();
  if (!line) return null;

  // Handle mid-stream #Fields: directive if IIS server restarted or multiple days joined
  if (line.toLowerCase().startsWith('#fields:')) {
    state.isW3C = true;
    state.format = 'W3C_IIS';
    state.formatDisplayName = getFormatDisplayName('W3C_IIS');
    state.w3cFields = line
      .replace(/^#fields:\s*/i, '')
      .trim()
      .split(/\s+/)
      .map(f => f.toLowerCase().replace(/[()]/g, '_').replace(/-+/g, '_').replace(/^_+|_+$/g, '').trim());
    state.detected = true;
    return null;
  }

  if (line.startsWith('#')) return null;

  let parsed: NormalizedLog | null = null;

  // 1. SURICATA EVE JSON (IDS/IPS) & GENERIC JSON
  if (line.startsWith('{') && line.endsWith('}')) {
    parsed = parseJsonLog(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 2. W3C IIS FORMAT
  if (state.isW3C || /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+/.test(line)) {
    parsed = parseW3cLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 3. APACHE / NGINX COMBINED, COMMON & ERROR LOGS
  if (
    state.isApacheNginx ||
    APACHE_NGINX_COMBINED_REGEX.test(line) ||
    APACHE_COMMON_REGEX.test(line) ||
    NGINX_ERROR_REGEX.test(line) ||
    APACHE_ERROR_REGEX.test(line)
  ) {
    parsed = parseApacheNginxLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 4. AWS VPC FLOW LOGS
  if (state.isVpcFlow || AWS_VPC_FLOW_REGEX.test(line)) {
    parsed = parseAwsVpcFlowLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 5. FORTINET / KEY-VALUE PAIR LOGS
  if (
    state.isFortinet ||
    /\b(?:srcip|src_ip)=\S+/i.test(line) ||
    (line.includes('devname=') && line.includes('action='))
  ) {
    parsed = parseKeyValueLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 6. ARCSIGHT CEF & IBM QRADAR LEEF
  if (state.isCefLeef || line.startsWith('CEF:') || line.startsWith('LEEF:')) {
    parsed = parseCefLeefLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 7. PALO ALTO NETWORKS CSV
  if (
    state.isPaloAlto ||
    line.includes(',TRAFFIC,') ||
    line.includes(',THREAT,') ||
    (line.startsWith('1,') && line.includes('/') && line.includes(','))
  ) {
    parsed = parsePaloAltoLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 8. PFSENSE / OPNSENSE FILTERLOG
  if (state.isPfSense || /^\d+,,,.*?,\w+,(?:match|pass|block),/i.test(line)) {
    parsed = parsePfSenseLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 9. CHECKPOINT FIREWALL CSV
  if (
    state.isCheckpoint ||
    (line.includes(',') && (line.includes('Drop') || line.includes('Accept')) && line.includes('TCP'))
  ) {
    parsed = parseCheckpointLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 10. WINDOWS SECURITY EVENT LOG (Event ID / Syslog / Text / Key-Value)
  if (
    state.isWindowsEvent ||
    state.format === 'WINDOWS_EVENT_LOG' ||
    line.includes('Microsoft-Windows-Security-Auditing') ||
    line.includes('MSWinEventLog') ||
    /\bEventID=\d+/i.test(line) ||
    /\bEvent ID:\s*\d+/i.test(line) ||
    /\bEventCode=\d+/i.test(line)
  ) {
    parsed = parseWindowsEventLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 10.B. LINUX SYSLOG / AUTH / SSH (RFC 3164/5424)
  if (state.isSyslog || SYSLOG_RFC3164_REGEX.test(line) || SYSLOG_RFC5424_REGEX.test(line) || /sshd\[\d+\]:/.test(line)) {
    parsed = parseSyslogLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 11. GENERIC DELIMITED (CSV, TSV, SEMICOLON, PIPE) & VPN CSV
  if (
    (state.isVpn || state.format === 'VPN_GATEWAY_CSV' || (state.delimiterHeaders && state.delimiterHeaders.length > 0)) &&
    line.includes(state.delimiter)
  ) {
    parsed = parseDelimitedLine(line, state);
    if (parsed) return finalizeLog(parsed);
  }

  // 12. UNIVERSAL ADAPTIVE HEURISTIC ENGINE (Last-resort intelligent regex extractor)
  return finalizeLog(parseUniversalAdaptiveLine(line, state));
}

// -------------------------------------------------------------
// 1. JSON / SURICATA / CLOUDWATCH / GCP / AZURE / K8S PARSER
// -------------------------------------------------------------
function parseJsonLog(line: string, state: FileFormatState): NormalizedLog | null {
  try {
    const obj = JSON.parse(line);
    if (typeof obj !== 'object' || obj === null) return null;

    // A. Handle Kubernetes / Docker container wrapped logs: { "log": "...", "time": "..." }
    if (typeof obj.log === 'string' && obj.log.trim()) {
      const innerLine = obj.log.trim();
      const innerParsed = parseLineToNormalizedLog(innerLine, { ...state, isJson: false });
      if (innerParsed) {
        if (!innerParsed.tarih && obj.time) innerParsed.tarih = String(obj.time);
        return innerParsed;
      }
    }

    // B. Handle AWS CloudWatch Log Event wrapped: { "message": "...", "timestamp": 123456 }
    if (typeof obj.message === 'string' && obj.message.trim()) {
      const innerLine = obj.message.trim();
      if (innerLine.startsWith('{') && innerLine.endsWith('}')) {
        const innerJson = parseJsonLog(innerLine, state);
        if (innerJson) return innerJson;
      } else {
        const innerParsed = parseLineToNormalizedLog(innerLine, { ...state, isJson: false });
        if (innerParsed) return innerParsed;
      }
    }

    // C. SURICATA EVE JSON
    if (obj.event_type || obj.alert || obj.http || obj.dns || obj.flow) {
      return parseSuricataEveJson(obj, state);
    }

    // D. GOOGLE CLOUD LOGGING JSON (with httpRequest object)
    if (obj.httpRequest && typeof obj.httpRequest === 'object') {
      const hr = obj.httpRequest;
      const clientIp = hr.remoteIp || obj.client_ip || null;
      const status = hr.status ? parseInt(hr.status, 10) || null : null;
      const bytes = hr.responseSize ? parseInt(hr.responseSize, 10) || null : null;
      const method = hr.requestMethod ? hr.requestMethod.toUpperCase() : null;
      const uri = hr.requestUrl || null;
      const dateStr = obj.timestamp || obj.time || null;
      const ua = hr.userAgent || null;
      const ref = hr.referer || null;
      const server = obj.resource?.labels?.instance_id || obj.resource?.labels?.service_name || null;

      let decision: ConnectionDecision = 'BILINMIYOR';
      if (status && status >= 400) decision = 'DENY / HATA';
      else if (status) decision = 'ACCEPT';

      return {
        kaynak_dosya: state.fileName,
        tarih: dateStr,
        tarih_obj: null,
        ip_adresi: clientIp,
        hedef_ip: hr.serverIp || null,
        hedef_port: null,
        kaynak_port: null,
        sunucu_ismi: server,
        islem_komutu: uri,
        http_method: method,
        user_agent: ua,
        byte_degeri: bytes,
        istemci_byte: hr.requestSize ? parseInt(hr.requestSize, 10) || null : null,
        status_code: status,
        baglanti_karari: decision,
        kullanici_adi: obj.principalEmail || null,
        referer: ref,
        response_time_ms: hr.latency ? Math.round(parseFloat(hr.latency) * 1000) : null,
        session_cookie: null,
      };
    }

    // E. AZURE DIAGNOSTIC / ACTIVITY JSON
    if (obj.category || obj.properties || obj.operationName) {
      const props = obj.properties || {};
      const clientIp = props.sourceIp || props.clientIP || props.sourceIP || obj.caller || null;
      const serverIp = props.destinationIp || props.serverIP || props.destinationIP || null;
      const destPort = parseInt(props.destinationPort || props.destPort || '0', 10) || null;
      const srcPort = parseInt(props.sourcePort || props.srcPort || '0', 10) || null;
      const isDeny =
        props.access === 'Deny' ||
        props.action === 'Deny' ||
        props.action === 'Drop' ||
        obj.resultType === 'Failure';
      const decision: ConnectionDecision = isDeny ? 'DENY' : 'ACCEPT';

      return {
        kaynak_dosya: state.fileName,
        tarih: obj.time || obj.timestamp || null,
        tarih_obj: null,
        ip_adresi: clientIp,
        hedef_ip: serverIp,
        hedef_port: destPort,
        kaynak_port: srcPort,
        sunucu_ismi: obj.resourceId ? obj.resourceId.split('/').pop() || null : null,
        islem_komutu: obj.operationName || props.rule || null,
        http_method: null,
        user_agent: null,
        byte_degeri: parseInt(props.bytesSent || props.bytes || '0', 10) || null,
        istemci_byte: parseInt(props.bytesReceived || '0', 10) || null,
        status_code: props.statusCode ? (parseInt(props.statusCode, 10) || null) : (props.status ? (parseInt(props.status, 10) || null) : null),
        baglanti_karari: decision,
        kullanici_adi: obj.identity?.claims?.name || props.user || null,
        referer: null,
        response_time_ms: null,
        session_cookie: null,
      };
    }

    // F. GENERIC JSON (Keys lookups across all standard industry naming conventions)
    const clientIp =
      obj.client_ip ||
      obj.c_ip ||
      obj.ip ||
      obj.src_ip ||
      obj.source_ip ||
      obj.remote_addr ||
      obj.src ||
      obj.srcaddr ||
      obj.client ||
      obj.caller_ip ||
      null;

    const serverIp =
      obj.server_ip ||
      obj.s_ip ||
      obj.dst_ip ||
      obj.destination_ip ||
      obj.dest_ip ||
      obj.dst ||
      obj.dstaddr ||
      obj.host ||
      null;

    const rawStatus = obj.status || obj.status_code || obj.sc_status || obj.code || obj.response_code;
    const status = rawStatus !== undefined && rawStatus !== null && rawStatus !== '' ? parseInt(String(rawStatus), 10) || null : null;

    const rawBytes = obj.bytes || obj.body_bytes_sent || obj.sc_bytes || obj.bytes_sent || obj.size || obj.length;
    const bytes = rawBytes !== undefined && rawBytes !== null && rawBytes !== '' ? parseInt(String(rawBytes), 10) || null : null;

    const rawMethod = obj.method || obj.http_method || obj.verb;
    const method = rawMethod ? String(rawMethod).toUpperCase() : null;
    const rawUri = obj.uri || obj.url || obj.path || obj.request || obj.request_uri || obj.islem_komutu;
    const uri = rawUri && rawUri !== '-' ? String(rawUri) : null;
    const dateStr = obj.timestamp || obj['@timestamp'] || obj.time || obj.date || obj.datetime || obj.time_local || null;
    const srvName = obj.server_name || obj.server || obj.hostname || obj.host || null;
    const ua = obj.user_agent || obj.agent || obj.http_user_agent || obj.cs_user_agent || null;
    const user = obj.username || obj.user || obj.user_id || obj.cs_username || null;
    const destPort = parseInt(obj.port || obj.dst_port || obj.dest_port || obj.dport || obj.dpt || '0', 10) || null;
    const srcPort = parseInt(obj.src_port || obj.sport || obj.spt || '0', 10) || null;

    let decision: ConnectionDecision = 'BILINMIYOR';
    if (obj.action && /deny|drop|block|reject/i.test(String(obj.action))) {
      decision = 'DENY';
    } else if (obj.action && /allow|permit|pass|accept/i.test(String(obj.action))) {
      decision = 'ACCEPT';
    } else if (status && status >= 400) {
      decision = 'DENY / HATA';
    } else if (status) {
      decision = 'ACCEPT';
    }

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr ? String(dateStr) : null,
      tarih_obj: null,
      ip_adresi: clientIp ? String(clientIp) : null,
      hedef_ip: serverIp ? String(serverIp) : null,
      hedef_port: destPort,
      kaynak_port: srcPort,
      sunucu_ismi: srvName ? String(srvName) : null,
      islem_komutu: uri,
      http_method: method,
      user_agent: ua ? String(ua) : null,
      byte_degeri: bytes,
      istemci_byte: parseInt(obj.cs_bytes || obj.bytes_received || '0', 10) || null,
      status_code: status,
      baglanti_karari: decision,
      kullanici_adi: user ? String(user) : null,
      referer: obj.referer || obj.http_referer || null,
      response_time_ms: parseInt(obj.duration || obj.response_time_ms || obj.time_taken || '0', 10) || null,
      session_cookie: obj.session_cookie || obj.cookie || null,
    };
  } catch {
    return null;
  }
}

// Suricata EVE JSON parser helper
function parseSuricataEveJson(obj: Record<string, any>, state: FileFormatState): NormalizedLog {
  const clientIp = obj.src_ip || null;
  const serverIp = obj.dest_ip || null;
  const srcPort = parseInt(obj.src_port || '0', 10) || null;
  const destPort = parseInt(obj.dest_port || '0', 10) || null;

  let uri = '-';
  let method = obj.event_type ? String(obj.event_type).toUpperCase() : 'SURICATA';
  let status: number | null = null;
  let ua: string | null = null;
  let ref: string | null = null;
  let srvName: string | null = obj.dest_ip || null;
  let isDeny = false;
  let bytes = 0;

  if (obj.http && typeof obj.http === 'object') {
    uri = obj.http.url || '/';
    if (obj.http.http_method) method = String(obj.http.http_method).toUpperCase();
    if (obj.http.status) status = parseInt(obj.http.status, 10);
    if (obj.http.http_user_agent) ua = obj.http.http_user_agent;
    if (obj.http.http_refer) ref = obj.http.http_refer;
    if (obj.http.hostname) srvName = obj.http.hostname;
    if (obj.http.length) bytes = parseInt(obj.http.length, 10) || 0;
  } else if (obj.alert && typeof obj.alert === 'object') {
    uri = `[ALARM] ${obj.alert.signature || 'Tehdit Tespiti'}`;
    if (obj.alert.category) srvName = obj.alert.category;
    if (obj.alert.action === 'blocked' || obj.drop) isDeny = true;
  } else if (obj.dns && typeof obj.dns === 'object') {
    uri = `DNS: ${obj.dns.rrname || obj.dns.type || 'Sorgu'}`;
  } else if (obj.tls && typeof obj.tls === 'object') {
    uri = `TLS: ${obj.tls.sni || obj.tls.subject || 'Handshake'}`;
  }

  if (obj.flow && typeof obj.flow === 'object') {
    bytes = (obj.flow.bytes_toclient || 0) + (obj.flow.bytes_toserver || 0);
  }

  if (status && (status === 401 || status === 403 || status >= 500)) isDeny = true;
  const decision: ConnectionDecision = isDeny ? 'DENY' : 'ACCEPT';

  return {
    kaynak_dosya: state.fileName,
    tarih: obj.timestamp || null,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: serverIp,
    hedef_port: destPort,
    kaynak_port: srcPort,
    sunucu_ismi: srvName,
    islem_komutu: uri,
    http_method: method,
    user_agent: ua,
    byte_degeri: bytes,
    istemci_byte: obj.flow?.bytes_toserver || null,
    status_code: status,
    baglanti_karari: decision,
    kullanici_adi: null,
    referer: ref,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 2. W3C IIS PARSER
// -------------------------------------------------------------
function parseW3cLine(line: string, state: FileFormatState): NormalizedLog | null {
  const parts = line.split(/\s+/);
  if (parts.length < 4) return null;

  // Dynamically resolve fields if state.w3cFields is not specifically customized
  let fields = state.w3cFields;
  if (!fields || fields.length === 0) {
    if (parts.length >= 20 && HTTP_METHODS_REGEX.test(parts[5])) {
      fields = MODERN_IIS_22_FIELDS;
      state.w3cFields = [...MODERN_IIS_22_FIELDS];
    } else if (parts.length >= 16 && HTTP_METHODS_REGEX.test(parts[3])) {
      fields = CLASSIC_IIS_17_FIELDS;
      state.w3cFields = [...CLASSIC_IIS_17_FIELDS];
    } else if (HTTP_METHODS_REGEX.test(parts[3])) {
      fields = CLASSIC_IIS_15_FIELDS;
      state.w3cFields = [...CLASSIC_IIS_15_FIELDS];
    } else {
      fields = MODERN_IIS_22_FIELDS;
    }
  } else if (fields.length !== parts.length) {
    // If field count mismatch, check if line is modern 22-field
    if (parts.length >= 20 && HTTP_METHODS_REGEX.test(parts[5])) {
      fields = MODERN_IIS_22_FIELDS;
      state.w3cFields = [...MODERN_IIS_22_FIELDS];
    } else if (parts.length >= 16 && HTTP_METHODS_REGEX.test(parts[3])) {
      fields = CLASSIC_IIS_17_FIELDS;
      state.w3cFields = [...CLASSIC_IIS_17_FIELDS];
    }
  }

  const record: Record<string, string> = {};
  fields.forEach((field, idx) => {
    record[field] = parts[idx] || '-';
  });

  const d = record.date && record.date !== '-' ? record.date : '';
  const t = record.time && record.time !== '-' ? record.time : '';
  const fullDate = d && t ? `${d} ${t}` : (record.timestamp || null);

  let clientIp = record.c_ip || record.client_ip || record.ip || null;
  let serverIp = record.s_ip || record.destination_ip || null;

  // Positional fallback if clientIp is not valid
  if (!clientIp || clientIp === '-' || !/\d/.test(clientIp)) {
    if (parts.length >= 11 && IPV4_REGEX.test(parts[10])) {
      clientIp = parts[10];
    } else {
      for (let p = 0; p < parts.length; p++) {
        if (IPV4_REGEX.test(parts[p])) {
          if (!serverIp) {
            serverIp = parts[p];
          } else if (!clientIp || clientIp === '-') {
            clientIp = parts[p];
          }
        }
      }
    }
  }
  if ((!serverIp || serverIp === '-') && parts.length >= 5 && IPV4_REGEX.test(parts[4])) {
    serverIp = parts[4];
  }

  const destPort = parseInt(record.s_port || record.port || '0', 10) || null;
  const srcPort = parseInt(record.c_port || '0', 10) || null;
  const rawSrvName = record.s_computername || record.s_sitename || record.cs_host || null;
  const srvName = rawSrvName && rawSrvName !== '-' ? rawSrvName : null;

  let uri = record.cs_uri_stem || record.path || record.request || '-';
  if (record.cs_uri_query && record.cs_uri_query !== '-') {
    uri = `${uri}?${record.cs_uri_query}`;
  }

  let method = record.cs_method ? record.cs_method.toUpperCase() : null;
  if (!method || !HTTP_METHODS_REGEX.test(method)) {
    const foundMethod = parts.find(p => HTTP_METHODS_REGEX.test(p));
    if (foundMethod) method = foundMethod.toUpperCase();
  }

  let rawUa = record.cs_user_agent || record.cs_user_agent_ || record.user_agent || record['cs(user-agent)'] || null;
  if (rawUa === '-') rawUa = null;
  const ua = rawUa ? rawUa.replace(/\+/g, ' ') : null;

  let scBytes = parseInt(record.sc_bytes || '0', 10) || null;
  let csBytes = parseInt(record.cs_bytes || '0', 10) || null;

  // Positional check for sc_bytes and cs_bytes if missing from record
  if (!scBytes && parts.length >= 20 && /^\d+$/.test(parts[19])) {
    scBytes = parseInt(parts[19], 10);
  }
  if (!csBytes && parts.length >= 21 && /^\d+$/.test(parts[20])) {
    csBytes = parseInt(parts[20], 10);
  }

  let status = parseInt(record.sc_status || record.status || '0', 10) || null;
  if (!status && parts.length >= 17 && /^[1-5]\d{2}$/.test(parts[16])) {
    status = parseInt(parts[16], 10);
  }
  if (!status) {
    const foundStatus = parts.find(p => /^[1-5]\d{2}$/.test(p));
    if (foundStatus) status = parseInt(foundStatus, 10);
  }

  const user = (record.cs_username && record.cs_username !== '-')
    ? record.cs_username
    : (record.username && record.username !== '-' ? record.username : null);

  const rawRef = record.cs_referer || record.cs_referer_ || record.referer || record['cs(referer)'] || null;
  const ref = (rawRef && rawRef !== '-') ? rawRef : null;

  let timeTaken = parseInt(record.time_taken || record.timetaken || record.time_ms || '0', 10) || null;
  if (!timeTaken && parts.length >= 22 && /^\d+$/.test(parts[21])) {
    timeTaken = parseInt(parts[21], 10);
  }

  const rawSession = record.cs_cookie || record.cs_cookie_ || record.cookie || record['cs(cookie)'] || record.x_session || null;
  const session = (rawSession && rawSession !== '-') ? rawSession : null;

  let decision: ConnectionDecision = 'ACCEPT';
  if (status && status >= 400) {
    decision = 'DENY / HATA';
  }

  const ip = clientIp === '-' ? null : clientIp;
  if (ip) {
    const lowIp = ip.toLowerCase();
    if (['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi'].includes(lowIp)) return null;
  }

  // Forensic integrity check: Must have at least one valid IP address OR a valid date + recognized HTTP method
  const hasValidClientIp = Boolean(ip && (IPV4_REGEX.test(ip) || ip.includes('.')));
  const hasValidServerIp = Boolean(serverIp && serverIp !== '-' && (IPV4_REGEX.test(serverIp) || serverIp.includes('.')));
  const hasValidDate = Boolean(fullDate && /^\d{4}[-/.]\d{2}[-/.]\d{2}/.test(fullDate));
  const hasValidMethod = Boolean(method && HTTP_METHODS_REGEX.test(method));

  if (!hasValidClientIp && !hasValidServerIp && (!hasValidDate || !hasValidMethod)) {
    return null;
  }

  const rawXff = record.x_forwarded_for || record.x_forwarded_for_ || record['cs(x-forwarded-for)'] || record.forwarded_for || null;
  const forwardedHeader = rawXff && rawXff !== '-' ? rawXff : null;
  const resolved = resolveClientIp(ip, forwardedHeader);
  const networkZone = classifyNetworkZone(resolved.clientIp);

  return {
    kaynak_dosya: state.fileName,
    tarih: fullDate,
    tarih_obj: null,
    ip_adresi: resolved.clientIp,
    immediate_peer_ip: resolved.immediatePeer,
    forwarded_client_ip: resolved.forwardedClientIp,
    ip_source: resolved.ipSource,
    forwarded_chain: resolved.forwardedChain,
    network_zone: networkZone,
    device: srvName === '-' ? null : srvName,
    hedef_ip: serverIp === '-' ? null : serverIp,
    hedef_port: destPort,
    kaynak_port: srcPort,
    sunucu_ismi: srvName === '-' ? null : srvName,
    islem_komutu: uri === '-' ? null : uri,
    http_method: method === '-' ? null : method,
    user_agent: ua === '-' ? null : ua,
    byte_degeri: scBytes,
    istemci_byte: csBytes,
    status_code: status,
    baglanti_karari: decision,
    kullanici_adi: user,
    referer: ref,
    response_time_ms: timeTaken,
    session_cookie: session === '-' ? null : session,
  };
}

// -------------------------------------------------------------
// 3. APACHE / NGINX COMBINED, COMMON & ERROR PARSER
// -------------------------------------------------------------
function parseApacheNginxLine(line: string, state: FileFormatState): NormalizedLog | null {
  // A. Combined Log Format
  const combinedMatch = line.match(APACHE_NGINX_COMBINED_REGEX);
  if (combinedMatch) {
    const clientIp = combinedMatch[1];
    const username = combinedMatch[2] !== '-' ? combinedMatch[2] : null;
    const dateStr = combinedMatch[3];
    const method = combinedMatch[4].toUpperCase();
    const uri = combinedMatch[5];
    const status = parseInt(combinedMatch[6], 10);
    const bytes = combinedMatch[7] !== '-' ? parseInt(combinedMatch[7], 10) : 0;
    const referer = combinedMatch[8] && combinedMatch[8] !== '-' ? combinedMatch[8] : null;
    const ua = combinedMatch[9] && combinedMatch[9] !== '-' ? combinedMatch[9] : null;

    let decision: ConnectionDecision = 'ACCEPT';
    if (status >= 400) decision = 'DENY / HATA';

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: clientIp,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: null,
      sunucu_ismi: null,
      islem_komutu: uri,
      http_method: method,
      user_agent: ua,
      byte_degeri: bytes,
      istemci_byte: null,
      status_code: status,
      baglanti_karari: decision,
      kullanici_adi: username,
      referer,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  // B. Common Log Format
  const commonMatch = line.match(APACHE_COMMON_REGEX);
  if (commonMatch) {
    const clientIp = commonMatch[1];
    const username = commonMatch[2] !== '-' ? commonMatch[2] : null;
    const dateStr = commonMatch[3];
    const method = commonMatch[4].toUpperCase();
    const uri = commonMatch[5];
    const status = parseInt(commonMatch[6], 10);
    const bytes = commonMatch[7] !== '-' ? parseInt(commonMatch[7], 10) : 0;

    let decision: ConnectionDecision = 'ACCEPT';
    if (status >= 400) decision = 'DENY / HATA';

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: clientIp,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: null,
      sunucu_ismi: null,
      islem_komutu: uri,
      http_method: method,
      user_agent: null,
      byte_degeri: bytes,
      istemci_byte: null,
      status_code: status,
      baglanti_karari: decision,
      kullanici_adi: username,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  // C. Nginx Error Log
  const nginxErrMatch = line.match(NGINX_ERROR_REGEX);
  if (nginxErrMatch) {
    const clientIp = nginxErrMatch[2];
    const method = nginxErrMatch[3] ? nginxErrMatch[3].toUpperCase() : 'NGINX_ERR';
    const uri = nginxErrMatch[4] || line;

    return {
      kaynak_dosya: state.fileName,
      tarih: line.slice(0, 19),
      tarih_obj: null,
      ip_adresi: clientIp,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: null,
      sunucu_ismi: null,
      islem_komutu: uri,
      http_method: method,
      user_agent: null,
      byte_degeri: 0,
      istemci_byte: null,
      status_code: null,
      baglanti_karari: 'DENY / HATA',
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  // D. Apache Error Log
  const apacheErrMatch = line.match(APACHE_ERROR_REGEX);
  if (apacheErrMatch) {
    const dateStr = apacheErrMatch[1];
    const clientIp = apacheErrMatch[3] || null;
    const msg = apacheErrMatch[4];

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: clientIp,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: null,
      sunucu_ismi: null,
      islem_komutu: msg,
      http_method: 'APACHE_ERR',
      user_agent: null,
      byte_degeri: 0,
      istemci_byte: null,
      status_code: null,
      baglanti_karari: 'DENY / HATA',
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  return null;
}

// -------------------------------------------------------------
// 4. AWS VPC FLOW LOGS PARSER
// -------------------------------------------------------------
function parseAwsVpcFlowLine(line: string, state: FileFormatState): NormalizedLog | null {
  const match = line.match(AWS_VPC_FLOW_REGEX);
  if (!match) return null;

  const srcAddr = match[1];
  const dstAddr = match[2];
  const srcPort = parseInt(match[3], 10) || null;
  const dstPort = parseInt(match[4], 10) || null;
  const protoNum = match[5];
  const packets = parseInt(match[6], 10) || 0;
  const bytes = parseInt(match[7], 10) || 0;
  const startTime = parseInt(match[8], 10);
  const action = match[10].toUpperCase();

  const isReject = action === 'REJECT';
  const decision: ConnectionDecision = isReject ? 'DENY' : 'ACCEPT';

  let dateStr: string | null = null;
  if (startTime > 0) {
    try {
      dateStr = new Date(startTime * 1000).toISOString().replace('T', ' ').replace('Z', '');
    } catch {
      dateStr = null;
    }
  }

  const protoName = protoNum === '6' ? 'TCP' : protoNum === '17' ? 'UDP' : `PROTO-${protoNum}`;

  return {
    kaynak_dosya: state.fileName,
    tarih: dateStr,
    tarih_obj: null,
    ip_adresi: srcAddr,
    hedef_ip: dstAddr,
    hedef_port: dstPort,
    kaynak_port: srcPort,
    sunucu_ismi: null,
    islem_komutu: `${protoName} ${srcAddr}:${srcPort || 0} -> ${dstAddr}:${dstPort || 0} [${packets} pkts]`,
    http_method: null,
    user_agent: null,
    byte_degeri: bytes,
    istemci_byte: null,
    status_code: null,
    baglanti_karari: decision,
    kullanici_adi: null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 5. FORTINET / KEY-VALUE PAIR PARSER
// -------------------------------------------------------------
function parseKeyValueLine(line: string, state: FileFormatState): NormalizedLog | null {
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=(".*?"|\S+)/g;
  const dict: Record<string, string> = {};
  let match: RegExpExecArray | null;

  while ((match = kvRegex.exec(line)) !== null) {
    const key = match[1].toLowerCase();
    let val = match[2];
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    dict[key] = val;
  }

  const clientIp = dict.srcip || dict.src_ip || dict.src || dict.source || dict.c_ip || null;
  const serverIp = dict.dstip || dict.dst_ip || dict.dst || dict.dest || dict.destination || dict.s_ip || null;

  if (!clientIp && !serverIp) return null;

  const srcPort = parseInt(dict.srcport || dict.src_port || dict.spt || '0', 10) || null;
  const destPort = parseInt(dict.dstport || dict.dst_port || dict.dpt || dict.port || '0', 10) || null;
  const isNumericStatus = dict.status && /^\d{3}$/.test(dict.status.trim());
  const action = (dict.action || dict.act || (!isNumericStatus && dict.status ? dict.status : '') || 'alert').toUpperCase();
  const rawStatusCode = parseInt(dict.http_status || dict.status_code || dict.response_code || (isNumericStatus ? dict.status : '') || '0', 10);

  const isTimeout = /time[-_\s]?out|zaman[-_\s]?a[sş][ıi]m[ıi]|aged[-_\s]?out/i.test(
    action + ' ' + (dict.reason || '') + ' ' + (dict.msg || '')
  );
  const isDeny = isTimeout || /deny|drop|block|reject|close|failure/i.test(action);

  const bytesSent = parseInt(dict.sentbyte || dict.sent_bytes || dict.bytes || '0', 10) || 0;
  const bytesRcvd = parseInt(dict.rcvdbyte || dict.rcvd_bytes || '0', 10) || 0;
  const totalBytes = bytesSent + bytesRcvd;

  const date = dict.date || '';
  const time = dict.time || '';
  const fullDate = date && time ? `${date} ${time}` : (dict.timestamp || null);
  const srvName = dict.http_host || dict.host || dict.server_pool_name || dict.devname || dict.devid || dict.device_id || 'Fortinet-WAF';
  const user = dict.user || dict.username || dict.user_name || dict.srcuser || null;
  
  // High-fidelity HTTP command/URL extraction
  const httpUrl = dict.http_url || dict.url || dict.uri || dict.path || null;
  const msg = httpUrl || dict.msg || dict.attack || dict.signature_subclass || dict.reason || `Action: ${action}`;

  // HTTP Method extraction
  const rawMethod = (dict.http_method || dict.method || (dict.proto ? dict.proto.toUpperCase() : 'FW_KV')).toUpperCase();
  const method = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'].includes(rawMethod)
    ? rawMethod
    : 'FW_KV';

  // User-Agent and Referer
  const userAgent = dict.http_agent || dict.user_agent || dict.agent || null;
  const referer = dict.http_refer || dict.referer || dict.ref || null;

  return {
    kaynak_dosya: state.fileName,
    tarih: fullDate,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: serverIp,
    hedef_port: destPort,
    kaynak_port: srcPort,
    sunucu_ismi: srvName,
    islem_komutu: msg,
    http_method: method,
    user_agent: userAgent,
    byte_degeri: totalBytes > 0 ? totalBytes : null,
    istemci_byte: bytesSent > 0 ? bytesSent : null,
    status_code: isTimeout ? 408 : rawStatusCode > 0 ? rawStatusCode : null,
    baglanti_karari: isTimeout ? 'DENY / HATA' : isDeny ? 'DENY' : (rawStatusCode >= 400 ? 'DENY / HATA' : 'ACCEPT'),
    kullanici_adi: user && user !== 'Unknown' && user !== 'none' ? user : null,
    referer: referer,
    response_time_ms: parseInt(dict.duration || '0', 10) || null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 6. ARCSIGHT CEF & IBM QRADAR LEEF PARSER
// -------------------------------------------------------------
function parseCefLeefLine(line: string, state: FileFormatState): NormalizedLog | null {
  const dict: Record<string, string> = {};

  // CEF:0|Vendor|Product|Version|ID|Name|Severity|Extension
  if (line.startsWith('CEF:')) {
    const pipeParts = line.split('|');
    if (pipeParts.length >= 7) {
      const vendor = pipeParts[1];
      const product = pipeParts[2];
      const eventName = pipeParts[5];
      const extStr = pipeParts.slice(7).join('|');

      const kvRegex = /([a-zA-Z0-9_]+)=(".*?"|\S+)/g;
      let m: RegExpExecArray | null;
      while ((m = kvRegex.exec(extStr)) !== null) {
        let v = m[2];
        if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
        dict[m[1].toLowerCase()] = v;
      }

      const clientIp = dict.src || dict.source || dict.sourceaddress || null;
      const serverIp = dict.dst || dict.destination || dict.destaddress || null;
      const srcPort = parseInt(dict.spt || dict.sourceport || '0', 10) || null;
      const destPort = parseInt(dict.dpt || dict.destport || '0', 10) || null;
      const action = (dict.act || dict.action || 'permit').toUpperCase();
      const isTimeout = /time[-_\s]?out|zaman[-_\s]?a[sş][ıi]m[ıi]|aged[-_\s]?out/i.test(
        eventName + ' ' + (dict.reason || '') + ' ' + (dict.msg || '') + ' ' + action
      );
      const isDeny = isTimeout || /deny|drop|block|reject|fail/i.test(action);
      const user = dict.suser || dict.duser || dict.user || null;
      const bytes = parseInt(dict.bytesout || dict.out || '0', 10) || null;
      const request = dict.request || dict.msg || eventName;

      return {
        kaynak_dosya: state.fileName,
        tarih: dict.start || dict.end || null,
        tarih_obj: null,
        ip_adresi: clientIp,
        hedef_ip: serverIp,
        hedef_port: destPort,
        kaynak_port: srcPort,
        sunucu_ismi: `${vendor}-${product}`,
        islem_komutu: request,
        http_method: (dict.requestmethod || dict.method || '').toUpperCase() || null,
        user_agent: dict.useragent || null,
        byte_degeri: bytes,
        istemci_byte: parseInt(dict.bytesin || '0', 10) || null,
        status_code: parseInt(dict.status || dict.outcome || dict.sc_status || '0', 10) || null,
        baglanti_karari: isTimeout ? 'DENY / HATA' : isDeny ? 'DENY' : 'ACCEPT',
        kullanici_adi: user,
        referer: null,
        response_time_ms: null,
        session_cookie: null,
      };
    }
  }

  return null;
}

// -------------------------------------------------------------
// 7. PALO ALTO NETWORKS PAN-OS CSV PARSER
// -------------------------------------------------------------
function parsePaloAltoLine(line: string, state: FileFormatState): NormalizedLog | null {
  const parts = line.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
  if (parts.length < 15) return null;

  // PAN-OS Traffic standard positions:
  // 1: Date/Time, 3: TRAFFIC/THREAT, 6: Start Time, 7: Source IP, 8: Dest IP, 24: Source Port, 25: Dest Port, 30: Action, 31: Bytes
  let clientIp: string | null = null;
  let serverIp: string | null = null;
  let srcPort: number | null = null;
  let destPort: number | null = null;
  let action = 'allow';
  let bytes = 0;
  let srvName = 'PaloAlto-NGFW';
  let dateStr: string | null = parts[1] || parts[6] || null;

  // Search for IP addresses in columns 5 to 12
  for (let i = 5; i < Math.min(12, parts.length); i++) {
    if (IPV4_REGEX.test(parts[i])) {
      if (!clientIp) clientIp = parts[i];
      else if (!serverIp) serverIp = parts[i];
    }
  }

  // Action search
  const foundAction = parts.find(p => /^(allow|deny|drop|reset-both|reset-client|reset-server)$/i.test(p));
  if (foundAction) action = foundAction.toLowerCase();

  const isDeny = /deny|drop|reset/i.test(action);

  // Search ports
  for (let i = 20; i < Math.min(30, parts.length); i++) {
    const n = parseInt(parts[i], 10);
    if (n > 0 && n <= 65535) {
      if (!srcPort) srcPort = n;
      else if (!destPort) destPort = n;
    }
  }

  return {
    kaynak_dosya: state.fileName,
    tarih: dateStr,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: serverIp,
    hedef_port: destPort,
    kaynak_port: srcPort,
    sunucu_ismi: srvName,
    islem_komutu: `Rule: ${parts[11] || action}`,
    http_method: null,
    user_agent: null,
    byte_degeri: bytes > 0 ? bytes : null,
    istemci_byte: null,
    status_code: null,
    baglanti_karari: isDeny ? 'DENY' : 'ACCEPT',
    kullanici_adi: parts[12] && parts[12] !== '-' ? parts[12] : null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 8. PFSENSE / OPNSENSE FILTERLOG PARSER
// -------------------------------------------------------------
function parsePfSenseLine(line: string, state: FileFormatState): NormalizedLog | null {
  const parts = line.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
  if (parts.length < 15) return null;

  const action = (parts[6] || '').toLowerCase(); // pass or block
  const isDeny = action === 'block';

  // IPv4 is usually indicated in parts[8] === '4'
  let clientIp: string | null = null;
  let serverIp: string | null = null;
  let srcPort: number | null = null;
  let destPort: number | null = null;

  for (let i = 15; i < parts.length; i++) {
    if (IPV4_REGEX.test(parts[i])) {
      if (!clientIp) clientIp = parts[i];
      else if (!serverIp) serverIp = parts[i];
    }
  }

  if (parts.length > 20) {
    srcPort = parseInt(parts[20] || '0', 10) || null;
    destPort = parseInt(parts[21] || '0', 10) || null;
  }

  return {
    kaynak_dosya: state.fileName,
    tarih: null,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: serverIp,
    hedef_port: destPort,
    kaynak_port: srcPort,
    sunucu_ismi: `pfSense-${parts[4] || 'Interface'}`,
    islem_komutu: `Filter: ${action.toUpperCase()}`,
    http_method: null,
    user_agent: null,
    byte_degeri: null,
    istemci_byte: null,
    status_code: null,
    baglanti_karari: isDeny ? 'DENY' : 'ACCEPT',
    kullanici_adi: null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 9. CHECKPOINT FIREWALL CSV PARSER
// -------------------------------------------------------------
function parseCheckpointLine(line: string, state: FileFormatState): NormalizedLog | null {
  const parts = line.split(',').map(s => s.trim().replace(/"/g, ''));
  if (parts.length < 5) return null;

  const action = (parts[4] || parts[1] || '').toUpperCase();
  const isDeny = /DROP|DENY|BLOCK|REJECT/.test(action);
  const decision: ConnectionDecision = isDeny ? 'DENY' : 'ACCEPT';

  let clientIp: string | null = null;
  let serverIp: string | null = null;

  const ips = parts.filter(p => IPV4_REGEX.test(p));
  if (ips.length >= 2) {
    clientIp = ips[0];
    serverIp = ips[1];
  } else if (ips.length === 1) {
    clientIp = ips[0];
  }

  const bytes = parseInt(parts[10] || parts[8] || '0', 10) || 0;

  return {
    kaynak_dosya: state.fileName,
    tarih: parts[3] || parts[0] || null,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: serverIp,
    hedef_port: parseInt(parts[8] || '0', 10) || null,
    kaynak_port: parseInt(parts[6] || '0', 10) || null,
    sunucu_ismi: parts[1] || null,
    islem_komutu: parts[4] || 'Firewall Action',
    http_method: null,
    user_agent: null,
    byte_degeri: bytes > 0 ? bytes : null,
    istemci_byte: null,
    status_code: null,
    baglanti_karari: decision,
    kullanici_adi: null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 10. LINUX SYSLOG / AUTH / SSH (RFC 3164/5424) PARSER
// -------------------------------------------------------------
function parseSyslogLine(line: string, state: FileFormatState): NormalizedLog | null {
  let dateStr: string | null = null;
  let host = 'Linux-Host';
  let app = 'syslog';
  let message = line;

  const match3164 = line.match(SYSLOG_RFC3164_REGEX);
  if (match3164) {
    dateStr = match3164[2];
    host = match3164[3];
    app = match3164[4];
    message = match3164[6];
  } else {
    const match5424 = line.match(SYSLOG_RFC5424_REGEX);
    if (match5424) {
      dateStr = match5424[3];
      host = match5424[4];
      app = match5424[5];
      message = match5424[8];
    }
  }

  // Detect SSH Brute-force pattern: "Failed password for (invalid user )?(\S+) from (\S+) port (\d+)"
  const sshFailMatch = message.match(/Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)/i);
  if (sshFailMatch) {
    const user = sshFailMatch[1];
    const ip = sshFailMatch[2];
    const clientPort = parseInt(sshFailMatch[3], 10) || null;

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: ip,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: clientPort,
      sunucu_ismi: host,
      islem_komutu: `SSH Failed Password (User: ${user})`,
      http_method: null,
      user_agent: null,
      byte_degeri: 0,
      istemci_byte: null,
      status_code: null,
      baglanti_karari: 'DENY / HATA',
      kullanici_adi: user,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  // Detect SSH Accepted pattern: "Accepted password|publickey for (\S+) from (\S+) port (\d+)"
  const sshAcceptMatch = message.match(/Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)/i);
  if (sshAcceptMatch) {
    const user = sshAcceptMatch[1];
    const ip = sshAcceptMatch[2];
    const clientPort = parseInt(sshAcceptMatch[3], 10) || null;

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: ip,
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: clientPort,
      sunucu_ismi: host,
      islem_komutu: `SSH Accepted (User: ${user})`,
      http_method: null,
      user_agent: null,
      byte_degeri: 0,
      istemci_byte: null,
      status_code: null,
      baglanti_karari: 'ACCEPT',
      kullanici_adi: user,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  // Generic syslog with IP address
  const ipMatch = message.match(IPV4_REGEX);
  if (ipMatch) {
    const isDaemon = /sshd|postfix|systemd|cron|kernel/i.test(app);
    const isFailure = /fail|error|invalid|attack/i.test(message);
    const isFirewallDeny = !isDaemon && /drop|deny|reject|block/i.test(message);
    const decision: ConnectionDecision = isFirewallDeny ? 'DENY' : (isFailure ? 'DENY / HATA' : 'ACCEPT');

    return {
      kaynak_dosya: state.fileName,
      tarih: dateStr,
      tarih_obj: null,
      ip_adresi: ipMatch[0],
      hedef_ip: null,
      hedef_port: null,
      kaynak_port: null,
      sunucu_ismi: `${host} (${app})`,
      islem_komutu: message.slice(0, 100),
      http_method: null,
      user_agent: null,
      byte_degeri: null,
      istemci_byte: null,
      status_code: null,
      baglanti_karari: decision,
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    };
  }

  return null;
}

// -------------------------------------------------------------
// 10.B. WINDOWS SECURITY EVENT LOG PARSER
// -------------------------------------------------------------
function parseWindowsEventLine(line: string, state: FileFormatState): NormalizedLog | null {
  // Extract Event ID (e.g. EventID=4625 or [4625] or Event ID: 4625)
  const eventIdMatch =
    line.match(/(?:EventID|Event\s*ID|EventCode|Olay\s*ID)[:=\s]+(\d{3,5})/i) ||
    line.match(/\[(\d{4})\]/) ||
    line.match(/Security-Auditing:\s*(\d{4})/i);
  const eventId = eventIdMatch ? parseInt(eventIdMatch[1], 10) : null;

  // Extract IP (Source Network Address, IpAddress, src, etc.) - not applicable to local process (4688), service (7045), log clear (1102)
  const ipMatch =
    line.match(/(?:Source\s*(?:Network\s*)?Address|IpAddress|SourceAddress|src)[:=\s]+["']?([0-9a-fA-F\.:]+)["']?/i) ||
    line.match(IPV4_REGEX);
  const rawIp = ipMatch ? (ipMatch[1] || ipMatch[0]) : null;
  const clientIp =
    eventId === 4688 || eventId === 7045 || eventId === 1102
      ? null
      : rawIp && rawIp !== '-' && rawIp !== '::1' && rawIp !== '127.0.0.1'
      ? rawIp
      : rawIp || null;

  // Extract User (For 4688/1102 prioritize SubjectUserName / suser, else TargetUserName / Account Name)
  const userMatch =
    eventId === 4688 || eventId === 1102
      ? line.match(/(?:SubjectUserName|Subject\s*User\s*Name|SubjectUser|suser|TargetUserName|TargetUser|Account\s*Name|duser|user)[:=\s]+["']?([^\s"',;]+)/i)
      : line.match(/(?:TargetUserName|TargetUser|SubjectUserName|SubjectUser|Account\s*Name|duser|user)[:=\s]+["']?([^\s"',;]+)/i);
  const username = userMatch && userMatch[1] !== '-' ? userMatch[1] : null;

  // Extract Workstation / Host (Prioritize ComputerName/Computer for endpoint host)
  const hostMatch =
    line.match(/(?:Computer\s*Name|ComputerName|Computer|Workstation\s*Name|WorkstationName|host)[:=\s]+["']?([^\s"',;]+)/i);
  const server = hostMatch ? hostMatch[1] : 'Windows-Endpoint';

  // Extract Process / Command
  const cmdMatch =
    line.match(/(?:Process\s*Command\s*Line|CommandLine|New\s*Process\s*Name|NewProcessName)[:=\s]+["']?([^"';\n]+)/i);
  const command = cmdMatch
    ? cmdMatch[1]
    : eventId
    ? `Windows Event ${eventId}`
    : 'Windows Security Event';

  // Status & Decision
  let decision: ConnectionDecision = 'ACCEPT';
  if (eventId === 4625 || eventId === 1102 || eventId === 104) {
    decision = 'DENY';
  } else if (line.toLowerCase().includes('failure') || line.toLowerCase().includes('failed')) {
    decision = 'DENY';
  }

  // Date extraction
  const dateMatch =
    line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/) ||
    line.match(/([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);
  const dateStr = dateMatch ? dateMatch[1] : null;

  return {
    kaynak_dosya: state.fileName,
    tarih: dateStr,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: null,
    hedef_port: null,
    kaynak_port: null,
    sunucu_ismi: server,
    islem_komutu: command,
    http_method: eventId ? `EVENT-${eventId}` : 'WIN-EVENT',
    user_agent: null,
    byte_degeri: 0,
    istemci_byte: null,
    status_code: null,
    baglanti_karari: decision,
    kullanici_adi: username,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// 11. GENERIC DELIMITED (CSV, TSV, SEMICOLON, PIPE) & VPN PARSER
// -------------------------------------------------------------
function parseDelimitedLine(line: string, state: FileFormatState): NormalizedLog | null {
  const parts = splitCsvRow(line, state.delimiter);
  const record: Record<string, string> = {};

  state.delimiterHeaders.forEach((h, idx) => {
    record[h] = (parts[idx] || '').trim();
  });

  let clientIp =
    record.f5_host_custom ||
    record.f5_host ||
    record.f5_client_ip_custom ||
    record.f5_client_ip ||
    record.f5_ip ||
    record.client_ip_custom ||
    record.source_ip_custom ||
    record.ip_adresi ||
    record.ip ||
    record.c_ip ||
    record.source_ip ||
    record.source_address ||
    record.source ||
    record.src_ip ||
    record.src ||
    record.client_ip ||
    record.client ||
    record.client_address ||
    record.remote_ip ||
    record.remote_addr ||
    record.destination ||
    record.dest ||
    record.log_source ||
    record.host ||
    null;

  // Fallback scan: If no designated IP column, find any cell containing a valid IPv4
  if (!clientIp) {
    for (const val of Object.values(record)) {
      if (val && IPV4_REGEX.test(val)) {
        clientIp = val;
        break;
      }
    }
  }

  if (!clientIp && (record.policy_name_custom || record.threat_type_custom || record.response)) {
    clientIp = null;
  }

  if (clientIp) {
    const lowIp = clientIp.toLowerCase();
    if (['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi', 'client', 'f5 host', 'host'].includes(lowIp)) return null;
    const portMatch = clientIp.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
    if (portMatch) {
      clientIp = portMatch[1];
    }
  }

  // User
  let user =
    record.f5_username_custom ||
    record.f5_username ||
    record.username ||
    record.kullanici_adi ||
    record.user ||
    record.account ||
    record.user_name ||
    record.ad_user ||
    null;

  // Event / Action / Command / F5 Full Request & URI
  const fullReq =
    record.f5_full_request_custom ||
    record.f5_full_request ||
    record.full_request ||
    record.request ||
    null;

  const f5Uri =
    record.f5_request_uri_custom ||
    record.f5_request_uri ||
    record.request_uri ||
    null;

  let method = record.http_method || record.method || null;

  let eventName =
    record.event_name ||
    record.event ||
    record.action ||
    record.islem_komutu ||
    f5Uri ||
    record.url ||
    record.path ||
    record.uri ||
    record.mesaj ||
    record.message ||
    null;

  if (fullReq) {
    const reqMatch = fullReq.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\S+))?/i);
    if (reqMatch) {
      if (!method) method = reqMatch[1].toUpperCase();
      eventName = reqMatch[2];
    } else if (!eventName) {
      eventName = fullReq;
    }
  }

  if (!user && eventName) {
    const userMatch = eventName.match(/[?&](?:user(?:name)?|login|account)=([^&#\s]+)/i);
    if (userMatch) {
      try {
        user = decodeURIComponent(userMatch[1]);
      } catch {
        user = userMatch[1];
      }
    }
  }

  // Session / Realm
  const session =
    record.realm_custom ||
    record.realm ||
    record.session_cookie ||
    record.session ||
    record.session_id ||
    record.sid ||
    null;

  // Date / Time (VPN connection time, connection date, F5 timestamp or standard timestamp)
  let dateStr =
    record.vpn_baglanti_zamani ||
    record.baglanti_zamani ||
    record.f5_timestamp_custom ||
    record.f5_timestamp ||
    record.f5_date ||
    record.tarih ||
    record.date ||
    record.timestamp ||
    record.time ||
    record.event_time ||
    record.zaman ||
    record.datetime ||
    record.created_at ||
    record.vpn_cikis_zamani ||
    record.cikis_zamani ||
    null;

  if (dateStr === '-' || !dateStr) {
    dateStr = null;
  }

  // Session Duration (ms between connection and disconnection if both available)
  let durationMs: number | null = parseInt(record.response_time_ms || record.duration || '0', 10) || null;
  if (!durationMs && record.vpn_baglanti_zamani && record.vpn_cikis_zamani) {
    const start = new Date(record.vpn_baglanti_zamani.replace(' ', 'T')).getTime();
    const end = new Date(record.vpn_cikis_zamani.replace(' ', 'T')).getTime();
    if (!isNaN(start) && !isNaN(end) && end >= start) {
      durationMs = end - start;
    }
  }

  // Authentication Status & Decision
  const basarisiz = parseFloat(record.basarisiz_giris || '0');
  const basarili = parseFloat(record.basarili_giris || '0');
  const eventLower = (eventName || '').toLowerCase();

  // F5 WAF & Status override inspection
  const f5Status = (
    record.response ||
    record.f5_response ||
    record.f5_request_status_custom ||
    record.f5_request_status ||
    record.request_status ||
    record.request_status_custom ||
    record.f5_status ||
    record.status ||
    record.action ||
    record.f5_action ||
    record.event ||
    record.karar ||
    record.durum ||
    ''
  ).toLowerCase();

  const reasonLower = (
    record.reason ||
    record.close_reason ||
    record.session_end_reason ||
    record.disconnect_reason ||
    record.error ||
    record.message ||
    ''
  ).toLowerCase();

  const isTimeout = /time[-_\s]?out|zaman[-_\s]?a[sş][ıi]m[ıi]|aged[-_\s]?out/i.test(
    eventLower + ' ' + f5Status + ' ' + reasonLower
  );

  const isAuthFailure =
    basarisiz > 0 ||
    eventLower.includes('failed') ||
    eventLower.includes('failure') ||
    eventLower.includes('basarisiz') ||
    eventLower.includes('denied') ||
    eventLower.includes('reject');

  const isAuthSuccess =
    !isTimeout &&
    (basarili > 0 ||
      eventLower.includes('success') ||
      eventLower.includes('basarili') ||
      eventLower.includes('ended') ||
      eventLower.includes('connected') ||
      eventLower.includes('login') ||
      eventLower.includes('logout'));

  const rawStatus = record.status_code || record.status || record.sc_status;
  let status: number | null = rawStatus !== undefined && rawStatus !== null && rawStatus !== '' ? parseInt(String(rawStatus), 10) || null : null;
  if (!status && isTimeout) {
    status = 408;
  }

  let decision: ConnectionDecision = 'BILINMIYOR';
  if (isTimeout) {
    decision = 'DENY / HATA';
  } else if (f5Status) {
    if (
      f5Status.includes('block') ||
      f5Status.includes('drop') ||
      f5Status.includes('reject') ||
      f5Status.includes('deny') ||
      f5Status.includes('abort')
    ) {
      decision = 'DENY';
    } else if (
      f5Status.includes('allow') ||
      f5Status.includes('pass') ||
      f5Status.includes('legal') ||
      f5Status.includes('permit') ||
      f5Status.includes('accept')
    ) {
      decision = 'ACCEPT';
    } else if (
      f5Status.includes('alarm') ||
      f5Status.includes('alert') ||
      f5Status.includes('log') ||
      f5Status.includes('notice') ||
      f5Status.includes('learning') ||
      f5Status.includes('monitor')
    ) {
      decision = 'ACCEPT';
    }
  } else if (isAuthFailure) {
    decision = 'DENY / HATA';
  } else if (status && status >= 400) {
    decision = 'DENY / HATA';
  } else if (status) {
    decision = 'ACCEPT';
  }

  // Server Name
  let server =
    record.destination ||
    record.destination_custom ||
    record.dest ||
    record.sunucu_ismi ||
    record.server ||
    record.f5_virtual_server ||
    record.virtual_server ||
    null;

  // Method / Protocol
  if (!method) {
    if (state.isVpn || state.format === 'VPN_GATEWAY_CSV') {
      if (eventLower.includes('logout')) method = 'LOGOUT';
      else if (eventLower.includes('login')) method = 'LOGIN';
      else if (eventLower.includes('ended')) method = 'SESSION_END';
      else method = null;
    } else {
      method = null;
    }
  }

  const bytes = parseInt(record.byte_degeri || record.bytes || record.sc_bytes || '0', 10) || null;
  const weight = parseInt(record.count || record.total || record.occurrences || record.adet || '1', 10) || 1;

  // Forensic integrity check: Delimited line must have an identifiable IP address, user, valid date/request, or F5 schema
  const hasValidIp = Boolean(clientIp && clientIp !== '-' && (IPV4_REGEX.test(clientIp) || clientIp.includes('.') || clientIp.includes(':')));
  const hasValidUser = Boolean(user && user !== '-' && user.trim().length > 0);
  const hasValidDate = Boolean(dateStr && dateStr !== '-' && dateStr !== 'Log-Kaydı');
  const hasValidRequest = Boolean(eventName && eventName !== '-' && (eventName.startsWith('/') || eventName.includes('HTTP') || eventName.length > 2));
  const hasValidF5 = Boolean(record.policy_name_custom || record.threat_type_custom || record.response || record.destination || record.count || record.event_name || record.event || record.f5_status || record.log_source);
  if (!hasValidIp && !hasValidUser && !hasValidDate && !hasValidRequest && !hasValidF5) {
    return null;
  }

  return {
    kaynak_dosya: state.fileName,
    tarih: dateStr,
    tarih_obj: null,
    ip_adresi: clientIp === '-' ? null : clientIp,
    hedef_ip: record.destination || record.destination_custom || record.dest || record.hedef_ip || record.dst_ip || record.s_ip || record.destination_ip || null,
    hedef_port: parseInt(record.destination_port || record.dest_port || record.hedef_port || record.dst_port || record.s_port || record.port || '0', 10) || null,
    kaynak_port: parseInt(record.kaynak_port || record.src_port || record.c_port || '0', 10) || null,
    sunucu_ismi: server,
    islem_komutu: eventName,
    http_method: method,
    user_agent: record.user_agent || null,
    byte_degeri: bytes,
    istemci_byte: null,
    status_code: status,
    baglanti_karari: decision,
    kullanici_adi: user,
    referer: record.referer || null,
    response_time_ms: durationMs,
    session_cookie: session,
    weight: weight,
    policy_name: record.policy_name_custom || record.policy_name || record.policy || null,
    threat_type: record.threat_type_custom || record.threat_type || record.attack_type || null,
  };
}

// -------------------------------------------------------------
// 12. UNIVERSAL ADAPTIVE HEURISTIC ENGINE (Last-resort intelligent extractor)
// -------------------------------------------------------------
function parseUniversalAdaptiveLine(line: string, state: FileFormatState): NormalizedLog | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.length < 3) return null;

  // Find any IPv4 address (optional, not strictly mandatory)
  const ipMatch = trimmed.match(IPV4_REGEX);
  const clientIp = ipMatch ? ipMatch[0] : null;

  // Try extracting date/time (ISO, YYYY-MM-DD, or DD/MMM/YYYY)
  const dateMatch =
    trimmed.match(/\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/) ||
    trimmed.match(/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]/) ||
    trimmed.match(/\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/);

  // Try extracting HTTP method or common verbs
  const methodMatch = trimmed.match(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|PROPFIND)\b/i);

  // Try extracting status code (100-599 surrounded by whitespace/quotes/brackets)
  const statusMatch =
    trimmed.match(/(?:\s|"|')([1-5]\d{2})(?:\s|"|'|$)/) ||
    trimmed.match(/\bstatus[=:\s]+([1-5]\d{2})\b/i);

  // Try extracting URI, URL or command string
  const uriMatch =
    trimmed.match(/(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"']+)/i) ||
    trimmed.match(/https?:\/\/[^\s"']+/i) ||
    trimmed.match(/(\/[a-zA-Z0-9_.~%/?&=#+-]{2,})/);

  // Try extracting user
  const userMatch =
    trimmed.match(/\b(?:user|username|usr|account)\s*[:=]\s*["']?([^\s"';]+)/i) ||
    trimmed.match(/\bfor\s+(?:invalid user\s+)?([a-zA-Z0-9_\-\.]+)\s+from\b/i);

  // Try extracting host
  const hostMatch =
    trimmed.match(/\b(?:host|hostname|computer|devname)\s*[:=]\s*["']?([^\s"';]+)/i);

  // Connection decision
  let decision: ConnectionDecision = 'BILINMIYOR';
  const low = trimmed.toLowerCase();
  if (low.includes('deny') || low.includes('drop') || low.includes('block') || low.includes('reject') || low.includes('failed')) {
    decision = 'DENY';
  } else if (low.includes('allow') || low.includes('accept') || low.includes('permit') || low.includes('success')) {
    decision = 'ACCEPT';
  }

  const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : null;

  // Extract islem_komutu
  const islemKomutu = uriMatch ? uriMatch[1] : methodMatch ? `${methodMatch[1].toUpperCase()} İsteği` : trimmed.slice(0, 150);

  return {
    kaynak_dosya: state.fileName,
    tarih: dateMatch ? dateMatch[0] : null,
    tarih_obj: null,
    ip_adresi: clientIp,
    hedef_ip: null,
    hedef_port: null,
    kaynak_port: null,
    sunucu_ismi: hostMatch ? hostMatch[1] : null,
    islem_komutu: islemKomutu,
    http_method: methodMatch ? methodMatch[1].toUpperCase() : null,
    user_agent: null,
    byte_degeri: null,
    istemci_byte: null,
    status_code: statusCode,
    baglanti_karari: decision,
    kullanici_adi: userMatch ? userMatch[1] : null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };
}

// -------------------------------------------------------------
// STREAM SAMPLE EXTRACTION FOR LIVE WATCHER
// -------------------------------------------------------------
export function extractStreamSample(log: NormalizedLog): StreamEventSample {
  let threat: string | undefined;
  const uri = log.islem_komutu || '-';
  const lowUri = uri.toLowerCase();
  const status = log.status_code;
  const bytes = log.byte_degeri || 0;

  if (/filemanagement|cmd(\.exe)?|powershell|whoami|web\.config|\.asp|\.aspx|\.php|\.jsp/i.test(lowUri)) {
    threat = 'Webshell / Hassas Dosya Keşfi';
  } else if (/(\/etc\/passwd|c:\\boot\.ini|\.\.\/|\.\.\\)/i.test(lowUri)) {
    threat = 'Dizin Gezintisi (Path Traversal)';
  } else if (/' OR '1'='1|union\s+select|<script>|alert\(/i.test(lowUri)) {
    threat = 'SQLi / XSS Enjeksiyonu';
  } else if (status === 401 || status === 403 || status === 530) {
    threat = 'Kimlik Deneme / Yetki Reddi';
  } else if (status !== null && status !== undefined && status >= 500) {
    threat = 'Sunucu Hatası (5xx)';
  } else if (bytes > 10 * 1024 * 1024) {
    threat = `Hacimli Veri Transferi (${(bytes / (1024 * 1024)).toFixed(1)} MB)`;
  } else if (log.baglanti_karari === 'DENY') {
    threat = 'Firewall / Güvenlik Duvarı Engeli';
  }

  let timeStr = '00:00:00';
  if (log.tarih) {
    if (log.tarih.includes(' ')) {
      timeStr = log.tarih.split(' ')[1] || '00:00:00';
    } else if (log.tarih.includes('T')) {
      timeStr = log.tarih.split('T')[1]?.split('.')[0] || '00:00:00';
    } else {
      timeStr = log.tarih;
    }
  }

  return {
    time: timeStr,
    ip: log.ip_adresi || '0.0.0.0',
    method: log.http_method || 'REQ',
    uri,
    status: status || 0,
    server: log.sunucu_ismi || 'SRV',
    bytes,
    threatDetected: threat,
  };
}

export function isLogFilteredByAllowlist(
  log: NormalizedLog,
  allowlistData?: AllowlistData | null
): boolean {
  if (!allowlistData) return false;
  return isLogAllowedByAllowlist(log, allowlistData);
}

export function getQuarantineReason(line: string, formatState: FileFormatState): string {
  const trimmed = line.trim();
  if (trimmed.length < 5) {
    return 'Satır uzunluğu yetersiz veya eksik veri parçası';
  }
  if (formatState.isW3C || formatState.format === 'W3C_IIS') {
    return 'IIS W3C kolon eşleşmesi sağlanamadı (Eksik/uyuşmayan alan sayısı veya geçersiz zaman damgası)';
  }
  if (formatState.isJson || formatState.format === 'SURICATA_EVE' || (trimmed.startsWith('{') && trimmed.endsWith('}'))) {
    return 'Geçersiz JSON sözdizimi veya zorunlu adli alanlar (IP, zaman, olay) eksik';
  }
  if (formatState.isSyslog || formatState.format === 'SYSLOG_RFC') {
    return 'Syslog RFC formatına uymuyor (Geçerli başlık veya IP tespit edilemedi)';
  }
  if (formatState.isApacheNginx || formatState.format === 'APACHE_NGINX') {
    return 'Apache/Nginx birleşik log formatı regex eşleşmesi başarısız';
  }
  if (formatState.isPaloAlto || formatState.format === 'PALO_ALTO_CSV') {
    return 'Palo Alto CSV formatında beklenen trafik/tehdit alanları eksik';
  }
  if (formatState.isVpn || formatState.format === 'VPN_GATEWAY_CSV') {
    return 'VPN CSV formatında kolon/değer ayrıştırması veya geçerli IP adresi tespit edilemedi';
  }
  return 'Standart dışı log formatı (Geçerli IP adresi, zaman damgası veya olay yapısı ayrıştırılamadı)';
}
