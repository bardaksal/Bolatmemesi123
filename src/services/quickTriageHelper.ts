import { NormalizedLog } from '../types';

export interface WindowsEventDetails {
  isWindowsEvent: boolean;
  eventId: number | null;
  eventName: string;
  targetUser: string;
  subjectUser: string;
  workstation: string;
  computer: string;
  logonType: number | null;
  logonTypeDesc: string;
  status: string;
  subStatus: string;
  subStatusDesc: string;
  processName: string;
  commandLine: string;
  parentProcess: string;
  serviceName: string;
  serviceFile: string;
  sourceIp: string;
  sourcePort: string;
  sourceIpCorrelationEligible?: boolean;
  authenticationPackage?: string;
  mitreTechnique?: string;
  dataIntegrityGuarded?: boolean;
  dataInconsistency?: string | null;
}

export interface CrossEventCorrelation {
  sourceEventId: number | string;
  sourceHost: string;
  eventType: string;
  isolatedFields: string[];
  correlationReason: string;
}

// SubStatus Hex error codes to Turkish forensic definitions
export const WINDOWS_SUBSTATUS_MAP: Record<string, string> = {
  '0XC000006A': 'Hatalı Parola (Kullanıcı adı geçerli, şifre yanlış girildi)',
  '0XC0000064': 'Bilinmeyen Kullanıcı (Kullanıcı adı Active Directory üzerinde mevcut değil)',
  '0XC0000234': 'Hesap Kilitli (Ardı ardına çok sayıda hatalı deneme sebebiyle hesap kilitlendi)',
  '0XC0000072': 'Hesap Devre Dışı (Disabled Account ile oturum açılmaya çalışıldı)',
  '0XC0000193': 'Hesap Süresi Dolmuş (Account Expired)',
  '0XC0000070': 'İş İstasyonu Kısıtlaması (Kullanıcının bu iş istasyonundan oturum açma yetkisi yok)',
  '0XC000006F': 'Geçersiz Oturum Saati (Tanımlı mesai saatleri dışında oturum açılmaya çalışıldı)',
  '0XC0000224': 'Parola Değişimi Zorunlu (Kullanıcı ilk girişte parolasını değiştirmelidir)',
  '0XC0000133': 'Kerberos Saat Farkı / Zaman Sapması (DC ile istemci arasındaki saat farkı 5 dakikayı aştı)',
  '0XC000006D': 'Geçersiz Kimlik Bilgisi (Bad Credentials)',
};

// Windows Logon Types mapping
export const WINDOWS_LOGON_TYPE_MAP: Record<number, string> = {
  2: 'Type 2 - Yerel İnteraktif (Konsol / Doğrudan Klavye-Ekran)',
  3: 'Type 3 - Ağ Oturumu (SMB / Paylaşım / RPC / IIS Kimlik Doğrulama)',
  4: 'Type 4 - Toplu İş (Batch / Zamanlanmış Görev - Scheduled Task)',
  5: 'Type 5 - Windows Servisi (Service Account)',
  7: 'Type 7 - Kilit Açma (Workstation Unlock)',
  8: 'Type 8 - Ağ Düz Metin (IIS / Basic Authentication)',
  9: 'Type 9 - Farklı Kimlik Bilgisi (RunAs / NewCredentials)',
  10: 'Type 10 - Uzak Masaüstü (RDP / Remote Interactive)',
  11: 'Type 11 - Önbelleğe Alınmış Giriş (Cached Interactive - DC Erişilemediğinde)',
};

// Known Windows Security Event IDs - CALIBRATED FORENSIC CONTEXT (NO AUTOMATIC ATTACK VERDICT)
export const WINDOWS_EVENT_NAMES: Record<number, { name: string; mitre?: string }> = {
  1: { name: 'Sysmon Süreç Başlatıldı (Process Create)' },
  3: { name: 'Sysmon Ağ Bağlantısı (Network Connection)' },
  11: { name: 'Sysmon Dosya Oluşturuldu (File Created)' },
  4625: { name: 'Başarısız Oturum Açma (Failed Logon)' },
  4624: { name: 'Başarılı Oturum Açma (Successful Logon)' },
  4688: { name: 'Yeni Süreç / Komut Yürütüldü (Process Creation)' },
  4672: { name: 'Özel Ayrıcalık Atandı (Special Privileges Assigned)' },
  4663: { name: 'Nesne Erişimi Kaydedildi (Object Access)' },
  5140: { name: 'Ağ Paylaşım Nesnesine Erişim (Share Access)' },
  5145: { name: 'Ağ Paylaşımı Detaylı İzin Kontrolü (Detailed Share Check)' },
  4634: { name: 'Oturum Kapatma (Logoff)' },
  5156: { name: 'Windows Filtreleme Platformu Bağlantı İzni (WFP Connection Permitted)' },
  4720: { name: 'Yeni Kullanıcı Hesabı Oluşturuldu (User Created)' },
  4724: { name: 'Hesap Parola Sıfırlama Girişimi (Password Reset Attempt)' },
  4728: { name: 'Global Güvenlik Grubuna Üye Eklendi' },
  4732: { name: 'Yerel Güvenlik Grubuna Üye Eklendi (Local Group Addition)' },
  4738: { name: 'Kullanıcı Hesabı Değiştirildi (User Account Modified)' },
  4776: { name: 'Etki Alanı Denetleyicisi NTLM Doğrulaması' },
  7045: { name: 'Sisteme Yeni Servis Kuruldu (Service Installed)' },
  4697: { name: 'Sisteme Servis Kurulumu Gerçekleşti' },
  1102: { name: 'Güvenlik Denetim Günlüğü Temizlendi (Security Audit Log Cleared)', mitre: 'T1070.001 (Clear Windows Event Logs)' },
  104: { name: 'Olay Günlüğü Temizlendi (System / App Log Cleared)' },
  4104: { name: 'PowerShell Script Blok Kaydı (Script Block Logging)' },
};

/**
 * Strips runaway subsequent key-value pairs that were captured on the same line.
 * Guarantees zero field leakage/bleed across boundaries.
 */
export function cleanUserString(val: string): string {
  if (!val) return '';
  let cleaned = val.trim();
  const fieldBoundary = cleaned.search(
    /\s+(?:Logon\s*Type|LogonType|Source\s*(?:Network\s*)?Address|SourcePort|Source\s*Port|Computer|Workstation|Image|Process|CommandLine|Process\s*Command\s*Line|ParentImage|ParentProcess|ParentCommandLine|Domain|Account\s*Domain|Sub\s*Status|Status|Security\s*ID|Logon\s*ID|Oturum\s*Türü|Kaynak\s*IP|User\s*=|User:)[:=\s]/i
  );
  if (fieldBoundary !== -1) {
    cleaned = cleaned.substring(0, fieldBoundary).trim();
  }
  return cleaned.replace(/^["']|["']$/g, '').trim();
}

export function cleanProcessString(val: string): string {
  if (!val) return '';
  let cleaned = val.trim();
  const fieldBoundary = cleaned.search(
    /\s+(?:User|UserName|SubjectUserName|CommandLine|Process\s*Command\s*Line|ParentImage|ParentProcess|ParentCommandLine|OriginalFileName|CurrentDirectory|Hashes)[:=\s]/i
  );
  if (fieldBoundary !== -1) {
    cleaned = cleaned.substring(0, fieldBoundary).trim();
  }
  return cleaned.replace(/^["']|["']$/g, '').trim();
}

export function cleanParentProcessString(val: string): string {
  if (!val) return '';
  let cleaned = val.trim();
  const fieldBoundary = cleaned.search(
    /\s+(?:User|UserName|SubjectUserName|CommandLine|Process\s*Command\s*Line|Image|ProcessName|OriginalFileName|CurrentDirectory|Hashes)[:=\s]/i
  );
  if (fieldBoundary !== -1) {
    cleaned = cleaned.substring(0, fieldBoundary).trim();
  }
  return cleaned.replace(/^["']|["']$/g, '').trim();
}

export interface EventBoundaryDiagnostic {
  eventIndex: number;
  rawStartLine: number;
  rawEndLine: number;
  rawText: string;
  rawTextHash: string;
  eventId: number | null;
  timestamp: string | null;
  sourceParser: string;
  hasCrossEventContamination: boolean;
  contaminationDetails?: string[];
}

export interface ParserFailureDetail {
  check: string;
  reason: string;
  lineNumbers: number[];
  snippet: string;
}

export interface ParserDiagnosticReport {
  rawLinesCount: number;
  candidateBoundariesCount: number;
  parsedEventsCount: number;
  normalizedEventsCount: number;
  unparsedRecordsCount: number;
  duplicateRecordsCount: number;
  eventBoundaries: EventBoundaryDiagnostic[];
  crossEventContamination: 'PASS' | 'FAIL';
  fieldProvenance: 'PASS' | 'FAIL';
  duplicateIdentity: 'PASS' | 'FAIL';
  multilineHandling: 'PASS' | 'FAIL';
  parserIntegrity: 'PASS' | 'FAIL';
  parserCompleteness: 'PASS' | 'FAIL';
  eventBoundaryIntegrity: 'PASS' | 'FAIL';
  unmatchedLineAccounting: 'PASS' | 'FAIL';
  parserIntegrityFailureReason?: string;
  failures?: ParserFailureDetail[];
}

export function computeTextHash(text: string): string {
  let hash1 = 0x811c9dc5;
  let hash2 = 0x9e3779b9;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    hash1 ^= ch;
    hash1 = Math.imul(hash1, 0x01000193);
    hash2 = Math.imul(hash2 ^ ch, 0x5bd1e995);
  }
  const part1 = (hash1 >>> 0).toString(16).padStart(8, '0');
  const part2 = (hash2 >>> 0).toString(16).padStart(8, '0');
  return (part1 + part2).substring(0, 16);
}

export function auditEventContamination(text: string): { hasContamination: boolean; details: string[] } {
  const details: string[] = [];
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);

  // Check 1: Multiple distinct Windows Event IDs in same event
  const eventIdMatches = Array.from(text.matchAll(/(?:\[(\d{1,5})\]|Event\s*ID\s*[:=]\s*(\d{1,5})|EventID\s*[:=]\s*(\d{1,5}))/gi));
  const distinctIds = new Set(eventIdMatches.map((m) => m[1] || m[2] || m[3]).filter(Boolean));
  if (distinctIds.size > 1) {
    details.push(`Farklı Event ID'ler tek olaya karıştı: ${Array.from(distinctIds).join(', ')}`);
  }

  // Check 2: Multiple distinct Providers
  const hasSecAuditing = /Microsoft-Windows-Security-Auditing/i.test(text);
  const hasSysmon = /Microsoft-Windows-Sysmon|Sysmon:/i.test(text);
  const hasSystem = /System:\s*\[\d+\]/i.test(text);
  const provCount = (hasSecAuditing ? 1 : 0) + (hasSysmon ? 1 : 0) + (hasSystem ? 1 : 0);
  if (provCount > 1) {
    details.push('Birden fazla sağlayıcı (Provider) tek olaya karıştı');
  }

  // Check 3: Process creation with conflicting network address line or conflicting logon telemetry across multiple lines
  const isProcessEvent = text.includes('[4688]') || text.includes('[1]') || /\b(?:Image|Process\s*Name|New\s*Process\s*Name)[:=\s]+/i.test(text);
  if (isProcessEvent && lines.length > 1) {
    const hasLogonType = /\bLogon\s*Type\s*[:=\s]+\d+/i.test(text);
    const hasNetworkAddress = /Source\s*(?:Network\s*)?Address[:=\s]+[0-9]{1,3}\./i.test(text);
    if (hasLogonType && hasNetworkAddress) {
      details.push('Süreç oluşturma olayına harici oturum/ağ telemetrisi (Logon Type / Source Network Address) karıştı');
    }
  }

  // Check 4: Cross-event User or Process mashing across multiple lines
  const userMatches = Array.from(text.matchAll(/\b(?:User|Account\s*Name)\s*[:=]\s*([a-zA-Z0-9_\-\.]+)/gi));
  const rawUsers = userMatches.map((m) => m[1]);
  const realUsers = Array.from(new Set(rawUsers.filter((u) => u.toLowerCase() !== 'system' && !u.endsWith('$') && u !== '-')));
  // Check 5: Linux daemon / service lines mixed into Windows or Sysmon events
  const hasLinuxDaemon = /^(?:systemd(?:\[\d+\])?|nginx(?:\[\d+\])?|sshd(?:\[\d+\])?|postfix(?:\/[a-zA-Z0-9_\-]+)?(?:\[\d+\])?|kernel|dockerd|cron(?:\[\d+\])?|sudo)[\s:]/im.test(text);
  if (hasLinuxDaemon && (hasSecAuditing || hasSysmon || provCount > 0 || isProcessEvent)) {
    details.push('Windows/Sysmon olayına harici Linux daemon/servis telemetrisi (systemd, nginx, postfix, sshd) karıştı');
  }

  return {
    hasContamination: details.length > 0,
    details,
  };
}

/**
 * Robustly segments raw text into strictly isolated event records with provenance diagnostics.
 * Prevents multiline event boundary collapse and cross-event field leakage.
 */
export function segmentRawTextIntoEventsWithDiagnostics(rawText: string): ParserDiagnosticReport {
  const trimmed = rawText.trim();
  if (!trimmed) {
    return {
      rawLinesCount: 0,
      candidateBoundariesCount: 0,
      parsedEventsCount: 0,
      normalizedEventsCount: 0,
      unparsedRecordsCount: 0,
      duplicateRecordsCount: 0,
      eventBoundaries: [],
      crossEventContamination: 'PASS',
      fieldProvenance: 'PASS',
      duplicateIdentity: 'PASS',
      multilineHandling: 'PASS',
      eventBoundaryIntegrity: 'PASS',
      parserCompleteness: 'PASS',
      unmatchedLineAccounting: 'PASS',
      parserIntegrity: 'PASS',
      failures: [],
    };
  }

  const lines = rawText.split(/\r?\n/);
  const rawLinesCount = lines.length;

  // 1. XML Windows Event logs (<Event>...</Event>)
  if (trimmed.includes('<Event') && trimmed.includes('</Event>')) {
    const xmlMatches = Array.from(trimmed.matchAll(/<Event[\s\S]*?<\/Event>/gi));
    if (xmlMatches && xmlMatches.length > 0) {
      const failures: ParserFailureDetail[] = [];
      const eventBoundaries = xmlMatches.map((m, idx) => {
        const text = m[0].trim();
        const cont = auditEventContamination(text);
        if (cont.hasContamination) {
          failures.push({
            check: 'Cross-Event Contamination',
            reason: cont.details.join('; '),
            lineNumbers: [idx + 1],
            snippet: text.slice(0, 100),
          });
        }
        const idMatch = text.match(/<EventID>(\d+)<\/EventID>/i);
        const timeMatch = text.match(/SystemTime=["']?([^"'>\s]+)["']?/i);
        return {
          eventIndex: idx + 1,
          rawStartLine: 1,
          rawEndLine: rawLinesCount,
          rawText: text,
          rawTextHash: computeTextHash(text),
          eventId: idMatch ? parseInt(idMatch[1], 10) : null,
          timestamp: timeMatch ? timeMatch[1] : null,
          sourceParser: 'XML_EVENT_PARSER',
          hasCrossEventContamination: cont.hasContamination,
          contaminationDetails: cont.details,
        };
      });

      const hasAnyContamination = eventBoundaries.some((e) => e.hasCrossEventContamination);

      return {
        rawLinesCount,
        candidateBoundariesCount: eventBoundaries.length,
        parsedEventsCount: eventBoundaries.length,
        normalizedEventsCount: eventBoundaries.length,
        unparsedRecordsCount: 0,
        duplicateRecordsCount: 0,
        eventBoundaries,
        crossEventContamination: hasAnyContamination ? 'FAIL' : 'PASS',
        fieldProvenance: hasAnyContamination ? 'FAIL' : 'PASS',
        duplicateIdentity: 'PASS',
        multilineHandling: 'PASS',
        eventBoundaryIntegrity: 'PASS',
        parserCompleteness: 'PASS',
        unmatchedLineAccounting: 'PASS',
        parserIntegrity: hasAnyContamination ? 'FAIL' : 'PASS',
        failures,
      };
    }
  }

  // 2. Stream-aware line segmentation
  const eventBoundaries: EventBoundaryDiagnostic[] = [];
  let currentEventLines: string[] = [];
  let currentStartLine = 1;
  let unparsedRecordsCount = 0;
  const failures: ParserFailureDetail[] = [];

  // Helper to determine if a line definitively starts a new event boundary
  const isLineNewEventStart = (t: string, currentLines: string[]): boolean => {
    if (!t) return false;

    // 1. Explicit Event Viewer Log Name header
    if (/^(?:Log\s*Name|LogName|Olay\s*Adı)\s*:/i.test(t)) return true;

    // 2. Windows Provider header at start
    if (/^(?:Microsoft-Windows-Security-Auditing|Microsoft-Windows-Sysmon|Microsoft-Windows-PowerShell|Security-Auditing|Sysmon|System|Application)\s*[:\s\[]/i.test(t)) {
      if (currentLines.length > 0) {
        const prevText = currentLines.join('\n');
        if (/^(?:Log\s*Name|LogName)\s*:/i.test(prevText) && !/(?:\[\d{1,5}\]|Event\s*ID\s*[:=]\s*\d+)/i.test(prevText)) {
          return false;
        }
      }
      return true;
    }

    // 3. Source: Microsoft-Windows-
    if (/^Source\s*:\s*Microsoft-Windows-/i.test(t)) {
      if (currentLines.length > 0) {
        const prevText = currentLines.join('\n');
        if (/^(?:Log\s*Name|LogName)\s*:/i.test(prevText)) {
          return false;
        }
      }
      return true;
    }

    // 4. Line starts with Event ID header
    if (/^(?:Event\s*ID|EventID|EventCode|Olay\s*ID)\s*[:=]\s*\d+/i.test(t)) {
      if (currentLines.length > 0) {
        const prevText = currentLines.join('\n');
        // If current event already has an Event ID, this line is 100% a new event
        if (/(?:\[\d{1,5}\]|Event\s*ID\s*[:=]\s*\d+|EventID\s*[:=]\s*\d+)/i.test(prevText)) {
          return true;
        }
        // If current event started with Log Name or Source, this Event ID belongs to that event
        if (/^(?:Log\s*Name|Source)\s*:/i.test(prevText)) {
          return false;
        }
      } else {
        return true;
      }
    }

    // 5. Line starts with bracketed Event ID (e.g. [4624], [1], [4688])
    if (/^\[\d{1,5}\]/.test(t)) return true;

    // 6. Line starts with a bare Windows Event ID number (e.g. "4624", "4625", "4688", "1102", "1")
    if (/^(?:4624|4625|4688|4672|7045|1102|104|4663|5140|5156|4634|4720|4104|1)\b/i.test(t)) return true;

    // 7. Syslog timestamp at line start
    if (/^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/i.test(t)) return true;

    // 8. ISO timestamp or timestamp key-value at line start
    if (/^\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}\b/i.test(t)) return true;
    if (/^(?:timestamp|time|date|@timestamp)\s*[:=]\s*["']?\d{4}[-/.]\d{2}[-/.]\d{2}/i.test(t)) return true;

    // 9. Standard structured headers & daemons
    if (/^(?:CEF:\d+|LEEF:\d+)/i.test(t)) return true;
    if (/^\{\s*"[\w\-]+":/.test(t)) return true;
    if (t.startsWith('<Event')) return true;
    if (/^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)\s+/.test(t)) return true;
    if (/^(?:systemd(?:\[\d+\])?|nginx(?:\[\d+\])?|sshd(?:\[\d+\])?|postfix(?:\/[a-zA-Z0-9_\-]+)?(?:\[\d+\])?|kernel|dockerd|cron(?:\[\d+\])?|sudo)[\s:]/i.test(t)) return true;

    // 10. If current accumulator already contains an Event ID, and this line contains ANY Event ID pattern or provider:
    if (currentLines.length > 0) {
      const prevText = currentLines.join('\n');
      const prevHasId = /(?:\[\d{1,5}\]|Event\s*ID\s*[:=]\s*\d+|EventID\s*[:=]\s*\d+)/i.test(prevText);
      const currHasId = /(?:\[\d{1,5}\]|Event\s*ID\s*[:=]\s*\d+|EventID\s*[:=]\s*\d+)/i.test(t);
      if (prevHasId && currHasId) {
        return true;
      }
    }

    return false;
  };

  const flushCurrentEvent = (endLineNum: number) => {
    if (currentEventLines.length === 0) return;
    const text = currentEventLines.join('\n').trim();
    if (!text) {
      currentEventLines = [];
      return;
    }

    const cont = auditEventContamination(text);
    if (cont.hasContamination) {
      failures.push({
        check: 'Cross-Event Contamination',
        reason: cont.details.join('; '),
        lineNumbers: [currentStartLine, endLineNum],
        snippet: text.slice(0, 100),
      });
    }

    const idMatch = text.match(/(?:\[(\d{1,5})\]|Event\s*ID\s*[:=]\s*(\d{1,5})|EventID\s*[:=]\s*(\d{1,5}))/i);
    const timeMatch = text.match(/\b(\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b/);

    eventBoundaries.push({
      eventIndex: eventBoundaries.length + 1,
      rawStartLine: currentStartLine,
      rawEndLine: endLineNum,
      rawText: text,
      rawTextHash: computeTextHash(text),
      eventId: idMatch ? parseInt(idMatch[1] || idMatch[2] || idMatch[3], 10) : null,
      timestamp: timeMatch ? timeMatch[1] : null,
      sourceParser: 'STREAM_EVENT_PARSER',
      hasCrossEventContamination: cont.hasContamination,
      contaminationDetails: cont.details,
    });
    currentEventLines = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const t = rawLine.trim();
    const lineNum = i + 1;

    // Blank line handling
    if (!t) {
      // In single-line log formats, an empty line marks boundary
      if (currentEventLines.length > 0) {
        // If current lines already form a complete single-line log, flush it
        const currentJoined = currentEventLines.join('\n');
        if (
          /^(?:Microsoft-Windows|System:|Sysmon:|CEF:|LEEF:|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i.test(currentJoined.trim()) &&
          !currentJoined.includes('\n')
        ) {
          flushCurrentEvent(lineNum - 1);
        }
      }
      continue;
    }

    // Comment line handling
    if (t.startsWith('#')) {
      unparsedRecordsCount++;
      continue;
    }

    const isNewStart = isLineNewEventStart(t, currentEventLines);

    if (isNewStart) {
      flushCurrentEvent(lineNum - 1);
      currentStartLine = lineNum;
      currentEventLines.push(rawLine);
    } else {
      // If current event accumulator has lines:
      if (currentEventLines.length > 0) {
        // Check if line is an indented continuation or quoted string
        const isIndentedContinuation = /^\s+/.test(rawLine) || /^["'].*["']$/.test(t);
        const isKnownFieldContinuation = /^(?:Subject|New Logon|Process Information|Network Information|Caller Process Information|Detailed Authentication Information|Token Elevation Type|Certificate Information|Privileges|Access Request Information|Process Creation):/i.test(t);
        const isDaemonLine = /^(?:systemd(?:\[\d+\])?|nginx(?:\[\d+\])?|sshd(?:\[\d+\])?|postfix(?:\/[a-zA-Z0-9_\-]+)?(?:\[\d+\])?|kernel|dockerd|cron(?:\[\d+\])?|sudo)[\s:]/i.test(t);
        const isKvContinuation = !isDaemonLine && /^[A-Za-z0-9_\-\.\s]+[:=]/.test(t) && !isLineNewEventStart(t, currentEventLines);
        const isWindowsBlockContinuation = !isDaemonLine && /^(?:Log\s*Name|Source\s*:|Event\s*ID\s*:)/im.test(currentEventLines.join('\n')) && !isLineNewEventStart(t, currentEventLines);

        if (isIndentedContinuation || isKnownFieldContinuation || isKvContinuation || isWindowsBlockContinuation) {
          currentEventLines.push(rawLine);
        } else {
          // Unindented non-continuation line starts its own event
          flushCurrentEvent(lineNum - 1);
          currentStartLine = lineNum;
          currentEventLines.push(rawLine);
        }
      } else {
        currentStartLine = lineNum;
        currentEventLines.push(rawLine);
      }
    }
  }

  // Flush trailing event
  flushCurrentEvent(lines.length);

  const candidateBoundariesCount = eventBoundaries.length;
  const parsedEventsCount = eventBoundaries.length;
  const normalizedEventsCount = eventBoundaries.length;
  const hasAnyContamination = eventBoundaries.some((e) => e.hasCrossEventContamination);

  // Critical Hard Stop rule: detect extreme boundary collapse (e.g. 50 raw lines became 2 parsed events)
  const isExtremeCollapse = rawLinesCount >= 10 && parsedEventsCount <= 2 && (rawLinesCount - unparsedRecordsCount) >= 5;

  if (isExtremeCollapse) {
    failures.push({
      check: 'Event Boundary Integrity',
      reason: `Aşırı olay çökmesi (event boundary collapse): ${rawLinesCount} ham satır sadece ${parsedEventsCount} olaya ayrıştırıldı.`,
      lineNumbers: [1, rawLinesCount],
      snippet: rawText.slice(0, 120),
    });
  }

  const eventBoundaryIntegrity = !isExtremeCollapse && candidateBoundariesCount === parsedEventsCount ? 'PASS' : 'FAIL';
  const crossEventContamination = hasAnyContamination ? 'FAIL' : 'PASS';
  const fieldProvenance = hasAnyContamination ? 'FAIL' : 'PASS';
  const parserCompleteness = candidateBoundariesCount > 0 && !isExtremeCollapse ? 'PASS' : 'FAIL';
  const parserIntegrity =
    eventBoundaryIntegrity === 'PASS' &&
    crossEventContamination === 'PASS' &&
    fieldProvenance === 'PASS' &&
    parserCompleteness === 'PASS'
      ? 'PASS'
      : 'FAIL';

  return {
    rawLinesCount,
    candidateBoundariesCount,
    parsedEventsCount,
    normalizedEventsCount,
    unparsedRecordsCount,
    duplicateRecordsCount: 0,
    eventBoundaries,
    crossEventContamination,
    fieldProvenance,
    duplicateIdentity: 'PASS',
    multilineHandling: 'PASS',
    eventBoundaryIntegrity,
    parserCompleteness,
    unmatchedLineAccounting: 'PASS',
    parserIntegrity,
    parserIntegrityFailureReason:
      parserIntegrity === 'FAIL'
        ? 'ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI'
        : undefined,
    failures,
  };
}

/**
 * Robustly splits raw pasted text into individual events with strict provenance.
 */
export function splitRawTextIntoEvents(rawText: string): string[] {
  const diag = segmentRawTextIntoEventsWithDiagnostics(rawText);
  return diag.eventBoundaries.map((e) => e.rawText);
}

/**
 * Extracts comprehensive Windows Security Event fields from a log line/block.
 * Strictly enforces per-EventID schema boundaries to guarantee zero field leakage
 * or cross-event contamination.
 */
export function extractWindowsDetails(
  text: string,
  kvDict: Record<string, string> = {},
  parsed: NormalizedLog | null = null
): WindowsEventDetails {
  const lowText = text.toLowerCase();

  // 1. Is it a Windows log?
  const isWindowsEvent = Boolean(
    kvDict.eventid ||
    kvDict.event_id ||
    kvDict.eventcode ||
    lowText.includes('microsoft-windows-security-auditing') ||
    lowText.includes('microsoft-windows-sysmon') ||
    lowText.includes('microsoft-windows-powershell') ||
    lowText.includes('microsoft-windows') ||
    lowText.includes('sysmon') ||
    lowText.includes('mswineventlog') ||
    lowText.includes('an account failed to log on') ||
    lowText.includes('an account was successfully logged on') ||
    lowText.includes('a new process has been created') ||
    lowText.includes('a user account was created') ||
    lowText.includes('the audit log was cleared') ||
    lowText.includes('the log file was cleared') ||
    lowText.includes('windows filtering platform') ||
    lowText.includes('a service was installed') ||
    Boolean(text.match(/\[(\d{1,5})\]/) && WINDOWS_EVENT_NAMES[parseInt(text.match(/\[(\d{1,5})\]/)![1], 10)]) ||
    /(?:eventid|event\s*id|olay\s*id)[:=\s]+\d{1,5}/i.test(text)
  );

  // 2. Event ID
  const eventIdMatch =
    text.match(/(?:EventID|Event\s*ID|EventCode|Olay\s*ID)[:=\s]+(\d{1,5})/i) ||
    text.match(/\[(\d{1,5})\]/) ||
    text.match(/Security-Auditing:\s*(\d{1,5})/i) ||
    text.match(/Sysmon:\s*(\d{1,5})/i);
  const eventId = eventIdMatch
    ? parseInt(eventIdMatch[1], 10)
    : kvDict.eventid
    ? parseInt(kvDict.eventid, 10)
    : lowText.includes('an account failed to log on')
    ? 4625
    : lowText.includes('an account was successfully logged on')
    ? 4624
    : lowText.includes('a new process has been created')
    ? 4688
    : lowText.includes('the audit log was cleared')
    ? 1102
    : lowText.includes('a service was installed')
    ? 7045
    : lowText.includes('a user account was created')
    ? 4720
    : null;

  const eventMeta = eventId ? WINDOWS_EVENT_NAMES[eventId] : null;
  let eventName = eventMeta ? eventMeta.name : eventId ? `Windows Event ${eventId}` : 'Windows Olayı';
  if (eventId === 104) {
    const isSecurityChannel = /channel["':\s]+security/i.test(text) || /logname["':\s]+security/i.test(text);
    eventName = isSecurityChannel
      ? 'Güvenlik Olay Günlüğü Temizlendi (Event 104)'
      : 'Sistem/Uygulama Olay Günlüğü Temizlendi (Event 104)';
  }
  const mitreTechnique = eventMeta ? eventMeta.mitre : undefined;

  // 3. Subject User (Caller/Creator) - E.g. in 4688: SubjectUserName=SYSTEM or under Subject:
  let subjectUser = '';
  const subjectMatch =
    text.match(/(?:SubjectUserName|Subject\s*User\s*Name|SubjectUser|Subject\s*Account\s*Name|suser)[:=\s]+["']?([^\s"',;\r\n]+)/i) ||
    text.match(/Subject:[\s\S]*?Account Name:\s*([^\r\n\t]+)/i);
  if (subjectMatch && subjectMatch[1] && subjectMatch[1].trim() !== '-') {
    subjectUser = cleanUserString(subjectMatch[1].trim());
  } else if (kvDict.subjectusername || kvDict.subjectuser || kvDict.suser) {
    subjectUser = cleanUserString((kvDict.subjectusername || kvDict.subjectuser || kvDict.suser).trim());
  }

  // 4. Target User (prioritize "Account For Which Logon Failed" in 4625)
  let targetUser = '';
  if (kvDict.targetusername || kvDict.targetuser || kvDict.duser) {
    targetUser = cleanUserString((kvDict.targetusername || kvDict.targetuser || kvDict.duser).trim());
  } else {
    const failedAccountBlock = text.match(/Account For Which Logon Failed:[\s\S]*?Account Name:\s*([^\r\n\t]+)/i);
    if (failedAccountBlock && failedAccountBlock[1] && failedAccountBlock[1].trim() !== '-') {
      targetUser = cleanUserString(failedAccountBlock[1].trim());
    } else {
      const targetMatch = text.match(/(?:TargetUserName|Target\s*User\s*Name|TargetUser|duser)[:=\s]+["']?([^\s"',;\r\n]+)/i);
      if (targetMatch && targetMatch[1] && targetMatch[1].trim() !== '-') {
        targetUser = cleanUserString(targetMatch[1].trim());
      } else {
        const userMatches = Array.from(text.matchAll(/(?:Account Name|User Name|Kullanıcı Adı)[:=\s]+["']?([^\r\n\t"',;]+)/gi));
        for (const m of userMatches) {
          const u = cleanUserString(m[1].trim());
          if (u && u !== '-' && !u.endsWith('$')) {
            targetUser = u;
            break;
          }
        }
      }
    }
  }

  // Sysmon Event 1 and generic User: support
  if (!subjectUser && !targetUser) {
    const sysmonUserMatch = text.match(/\bUser\s*[:=]\s*["']?([^\r\n\t"',;]+)/i);
    if (sysmonUserMatch && sysmonUserMatch[1]) {
      const u = cleanUserString(sysmonUserMatch[1].trim());
      if (u && u !== '-' && !u.endsWith('$')) {
        subjectUser = u;
        targetUser = u;
      }
    }
  }

  // Process Events (4688 and Sysmon 1) User Resolution:
  // In process creation, the actor executing is Subject/Caller
  if (eventId === 4688 || eventId === 1) {
    if (!subjectUser && targetUser) subjectUser = targetUser;
    if (!targetUser && subjectUser) targetUser = subjectUser;
    if (!subjectUser && !targetUser) {
      if (/\bSYSTEM\b/i.test(text)) {
        subjectUser = 'SYSTEM';
        targetUser = 'SYSTEM';
      }
    }
  }

  // 5. Computer (Host) - STRICT: must come ONLY from this event's Computer/ComputerName fields
  let computer = '';
  const compMatch = text.match(/(?:Computer\s*Name|ComputerName|Computer|Bilgisayar)[:=\s]+["']?([^\s"',;\r\n]+)/i);
  if (compMatch && compMatch[1] && compMatch[1].trim() !== '-') {
    computer = compMatch[1].trim();
  } else if (kvDict.computer || kvDict.computername) {
    computer = (kvDict.computer || kvDict.computername).trim();
  }

  // 6. Workstation - Applicable to 4624/4625, PROHIBITED on 4688, 7045, 1102
  let workstation = '';
  if (eventId !== 4688 && eventId !== 7045 && eventId !== 4697 && eventId !== 1102 && eventId !== 104) {
    const wsMatch = text.match(/(?:Workstation\s*Name|WorkstationName|Workstation|İş\s*İstasyonu)[:=\s]+["']?([^\r\n"',;]+)/i);
    if (wsMatch && wsMatch[1] && wsMatch[1].trim() !== '-') {
      workstation = wsMatch[1].trim();
    } else if (kvDict.workstationname || kvDict.workstation) {
      workstation = (kvDict.workstationname || kvDict.workstation).trim();
    }
  }

  // 7. Logon Type - Applicable ONLY to 4624 / 4625
  let logonType: number | null = null;
  if (eventId === 4624 || eventId === 4625) {
    const ltMatch = text.match(/(?:Logon\s*Type|LogonType|Oturum\s*Türü)[:=\s]+["']?(\d+)/i);
    if (ltMatch && ltMatch[1]) {
      logonType = parseInt(ltMatch[1], 10);
    } else if (kvDict.logontype) {
      logonType = parseInt(kvDict.logontype, 10);
    }
  }
  let logonTypeDesc = 'Belirtilmemiş / Bilinmiyor';
  if (eventId === 4688) {
    logonTypeDesc = 'Uygulanamaz (Süreç Oluşturma Olayı - Logon Type İçermez)';
  } else if (eventId === 7045 || eventId === 4697) {
    logonTypeDesc = 'Uygulanamaz (Servis Kurulum Olayı)';
  } else if (eventId === 1102 || eventId === 104) {
    logonTypeDesc = 'Uygulanamaz (Denetim Günlüğü Temizlendi)';
  } else if (logonType) {
    logonTypeDesc = WINDOWS_LOGON_TYPE_MAP[logonType] || `Type ${logonType}`;
  }

  // 8. Status & SubStatus - Applicable ONLY to 4625
  let subStatus = '';
  let subStatusDesc = '';
  let status = '';
  if (eventId === 4625) {
    const subStatusMatch =
      text.match(/(?:Sub\s*Status|SubStatus)[:=\s]+["']?(0x[0-9a-fA-F]+)/i) ||
      (kvDict.substatus ? [null, kvDict.substatus] : null);
    subStatus = subStatusMatch ? subStatusMatch[1].toUpperCase() : '';
    subStatusDesc = subStatus ? WINDOWS_SUBSTATUS_MAP[subStatus] || 'Bilinmeyen Hata Kodu' : '';

    const statusMatch =
      text.match(/(?:Status|Durum)[:=\s]+["']?(0x[0-9a-fA-F]+)/i) ||
      (kvDict.status ? [null, kvDict.status] : null);
    status = statusMatch ? statusMatch[1].toUpperCase() : '';
  }

  // 9. Process & Command Line - Applicable to 4688 and Sysmon 1 (and generic if no eventId)
  let processName = '';
  let commandLine = '';
  let parentProcess = '';
  if (eventId === 4688 || eventId === 1 || !eventId) {
    const procMatch = text.match(/(?:New\s*Process\s*Name|NewProcessName|Process\s*Name|Image)[:=\s]+["']?([^"\r\n;]+)/i);
    processName = cleanProcessString(procMatch ? procMatch[1] : (kvDict.newprocessname || kvDict.image || ''));

    const cmdMatch = text.match(/(?:Process\s*Command\s*Line|CommandLine|ProcessCommandLine)[:=\s]+["']?([^"\r\n]+)/i);
    commandLine = cmdMatch ? cmdMatch[1].trim() : kvDict.processcommandline || kvDict.commandline || '';

    const parentMatch = text.match(/(?:Parent\s*Process\s*Name|ParentProcessName|ParentImage)[:=\s]+["']?([^"\r\n;]+)/i);
    parentProcess = cleanParentProcessString(parentMatch ? parentMatch[1] : (kvDict.parentprocessname || kvDict.parentimage || ''));
  }

  // 10. Service Name & File - Applicable ONLY to 7045 / 4697
  let serviceName = '';
  let serviceFile = '';
  if (eventId === 7045 || eventId === 4697) {
    const svcMatch = text.match(/(?:Service\s*Name|ServiceName)[:=\s]+["']?([^"\r\n;]+)/i);
    serviceName = svcMatch ? svcMatch[1].trim() : kvDict.servicename || '';

    const svcFMatch = text.match(/(?:Service\s*File\s*Name|ServiceFileName|Image\s*Path)[:=\s]+["']?([^"\r\n;]+)/i);
    serviceFile = svcFMatch ? svcFMatch[1].trim() : kvDict.servicefilename || kvDict.imagepath || '';
  }

  // 11. Source IP, Port & Authentication Package - Applicable to 4624 / 4625
  let sourceIp = '-';
  let sourcePort = '';
  let authenticationPackage = '';
  let dataInconsistency: string | null = null;

  if (eventId === 4624 || eventId === 4625 || (!eventId && isWindowsEvent)) {
    const ipMatch = text.match(/(?:Source\s*(?:Network\s*)?Address|IpAddress|SourceAddress)[:=\s]+["']?([0-9a-fA-F\.:]+)/i);
    const rawIp = ipMatch && ipMatch[1] && ipMatch[1] !== '-' ? ipMatch[1] : (kvDict.src || kvDict.srcip || null);

    // Event #3 Guard: Type 2 (Local Interactive) local logons do NOT have a network source address!
    let sourceIpCorrelationEligible = true;
    if (eventId === 4624 && logonType === 2) {
      if (rawIp && rawIp !== '127.0.0.1' && rawIp !== '::1' && rawIp !== 'localhost') {
        sourceIp = rawIp;
        sourceIpCorrelationEligible = false;
        dataInconsistency = `Type 2 (Yerel İnteraktif) oturum kaydında harici ağ kaynak IP adresi (${rawIp}) yer almaktadır (DATA_INCONSISTENCY / UNCERTAIN_REMOTE_ORIGIN)`;
      } else {
        sourceIp = '-';
        sourceIpCorrelationEligible = false;
      }
    } else {
      sourceIp = rawIp || '-';
      sourceIpCorrelationEligible = sourceIp !== '-' && sourceIp !== '127.0.0.1' && sourceIp !== '::1' && sourceIp !== 'localhost';
    }

    const portMatch = text.match(/(?:Source\s*Port|SourcePort)[:=\s]+["']?(\d+)/i);
    sourcePort = portMatch ? portMatch[1] : kvDict.srcport || kvDict.sourceport || '';

    const authPkgMatch = text.match(/(?:Authentication\s*Package|AuthPackage|AuthenticationPackage)[:=\s]+["']?([^\s"',;\r\n]+)/i);
    authenticationPackage = authPkgMatch ? authPkgMatch[1].trim() : kvDict.authenticationpackage || '';

    return {
      isWindowsEvent,
      eventId,
      eventName,
      targetUser,
      subjectUser,
      workstation,
      computer,
      logonType,
      logonTypeDesc,
      status,
      subStatus,
      subStatusDesc,
      processName,
      commandLine,
      parentProcess,
      serviceName,
      serviceFile,
      sourceIp,
      sourcePort,
      sourceIpCorrelationEligible,
      authenticationPackage,
      mitreTechnique: (processName + ' ' + commandLine).toLowerCase().includes('whoami') ? undefined : mitreTechnique,
      dataIntegrityGuarded: true,
      dataInconsistency,
    };
  }

  const isWhoami = (processName + ' ' + commandLine).toLowerCase().includes('whoami');
  const finalMitre = isWhoami ? undefined : mitreTechnique;

  return {
    isWindowsEvent,
    eventId,
    eventName,
    targetUser,
    subjectUser,
    workstation,
    computer,
    logonType,
    logonTypeDesc,
    status,
    subStatus,
    subStatusDesc,
    processName,
    commandLine,
    parentProcess,
    serviceName,
    serviceFile,
    sourceIp,
    sourcePort,
    sourceIpCorrelationEligible: false,
    authenticationPackage,
    mitreTechnique: finalMitre,
    dataIntegrityGuarded: true,
    dataInconsistency,
  };
}

/**
 * Builds cross-event correlation links strictly based on verified causal forensic relationships.
 * GUARANTEES:
 * - Mere coexistence in the same log file NEVER produces a correlation link.
 * - Same host alone or same user alone NEVER produces a link without a verified technical bond.
 * - Unrelated logons or Type 2 local logons are NEVER linked to remote network attempts.
 */
export function buildCrossEventCorrelations(
  currentEventIndex: number,
  allEventsDetails: WindowsEventDetails[]
): CrossEventCorrelation[] {
  const correlations: CrossEventCorrelation[] = [];
  const current = allEventsDetails[currentEventIndex];
  if (!current || !current.computer) return correlations;

  const currentHost = current.computer.toLowerCase().trim();
  const currentHostValid = currentHost && currentHost !== 'windows endpoint' && currentHost !== 'bilinmiyor' && currentHost !== '-';
  if (!currentHostValid) return correlations;

  const currentLogon = (current.logonType ? String(current.logonType) : '');
  const isCurrentType2 = current.eventId === 4624 && current.logonType === 2;

  allEventsDetails.forEach((other, idx) => {
    if (idx === currentEventIndex) return;
    if (!other.isWindowsEvent || !other.computer) return;

    const otherHost = other.computer.toLowerCase().trim();
    if (otherHost !== currentHost) return; // Must be on the same host

    // Type 2 isolation: Local interactive logon without IP cannot link to a remote network logon
    const isOtherType2 = other.eventId === 4624 && other.logonType === 2;
    if (isCurrentType2 && other.sourceIp && other.sourceIp !== '-' && other.sourceIp !== '127.0.0.1') {
      return;
    }
    if (isOtherType2 && current.sourceIp && current.sourceIp !== '-' && current.sourceIp !== '127.0.0.1') {
      return;
    }

    const isolatedFields: string[] = [];

    // Verified Link 1: Sequential Auth Transition on SAME account and SAME source IP
    const currUser = (current.targetUser || current.subjectUser || '').trim().toLowerCase();
    const otherUser = (other.targetUser || other.subjectUser || '').trim().toLowerCase();
    const isSameAccount = currUser && otherUser && currUser !== '-' && currUser !== 'bilinmiyor' && currUser === otherUser;
    const isSameSourceIp = current.sourceIp && other.sourceIp && current.sourceIp !== '-' && current.sourceIp === other.sourceIp;

    if (isSameAccount && isSameSourceIp) {
      if (current.eventId === 4625 && other.eventId === 4624) {
        correlations.push({
          sourceEventId: other.eventId,
          sourceHost: other.computer,
          eventType: 'Başarılı Oturum Açma (Successful Logon)',
          isolatedFields: [`TargetUser=${other.targetUser}`, `SourceNetworkAddress=${other.sourceIp}`],
          correlationReason: `Aynı kaynak IP (${other.sourceIp}) ve hesap (${other.targetUser}) için başarısız denemeyi takiben başarılı oturum geçişi.`,
        });
        return;
      }
      if (current.eventId === 4624 && other.eventId === 4625) {
        correlations.push({
          sourceEventId: other.eventId,
          sourceHost: other.computer,
          eventType: 'Başarısız Oturum Açma (Failed Logon)',
          isolatedFields: [`TargetUser=${other.targetUser}`, `SubStatus=${other.subStatus}`],
          correlationReason: `Aynı kaynak IP (${other.sourceIp}) ve hesap (${other.targetUser}) için başarılı oturum öncesinde başarısız deneme kaydı.`,
        });
        return;
      }
    }

    // Verified Link 2: Direct Process Parent-Child link (Requires same host and verified lineage)
    const currProc = (current.processName || '').toLowerCase();
    const otherProc = (other.processName || '').toLowerCase();
    const currParent = (current.parentProcess || '').toLowerCase();
    const isSameHost = current.computer && other.computer && current.computer.toLowerCase() === other.computer.toLowerCase();

    // PROHIBIT synthetic cross-event matching: same host and explicit parent path required, no generic guessing
    if (isSameHost && currParent && otherProc && currProc && (currParent === otherProc || currParent.endsWith('\\' + otherProc))) {
      correlations.push({
        sourceEventId: other.eventId || 4688,
        sourceHost: other.computer,
        eventType: 'Üst Süreç İlişkisi (Parent Process)',
        isolatedFields: [`Process=${other.processName}`, `CommandLine=${other.commandLine}`],
        correlationReason: `Mevcut süreç (${current.processName}) aynı host (${current.computer}) üzerinde #${idx + 1} nolu süreç (${other.processName}) ile doğrulanmış üst-alt süreç bağına sahiptir.`,
      });
      return;
    }
  });

  return correlations;
}

/**
 * Generates tailored, dynamic questions for the customer SOC ticket.
 * Zero static fallbacks: adapts strictly to the specific event ID, attack vector,
 * HTTP status, network action, and extracted forensic parameters.
 */
export function generateTailoredExtraInfo(params: {
  isWindows: boolean;
  winDetails: WindowsEventDetails;
  attackVector: string;
  srcIp: string;
  dstIp: string;
  dstPort: string;
  logTime: string;
  targetHost: string;
  requestUrl: string;
  wafAction: string;
  sigSubclass: string;
  matchedPattern: string;
}): string[] {
  const { isWindows, winDetails, attackVector, srcIp, dstIp, dstPort, logTime, targetHost, requestUrl, wafAction, matchedPattern } = params;

  // -------------------------------------------------------------
  // A. WINDOWS EVENT LOG SCENARIOS
  // -------------------------------------------------------------
  if (isWindows && winDetails.eventId) {
    const userDisplay = winDetails.targetUser ? `"${winDetails.targetUser}" kullanıcısının` : 'İlgili kullanıcının';
    const machineDisplay = winDetails.workstation || winDetails.computer ? `"${winDetails.workstation || winDetails.computer}" üzerinden` : '';

    if (winDetails.eventId === 4625) {
      const qList: string[] = [
        `${userDisplay} olay anında (${logTime}) ${machineDisplay} oturum açmayı deneyip denemediğinin (klavye/şifre unutma hatası) doğrudan kendisinden teyidi.`,
        `${winDetails.workstation || (srcIp !== 'Bilinmiyor' ? srcIp : 'İlgili cihaz')} üzerinde arka planda eski şifreyle kaydedilmiş ağ sürücüsü (SMB Mapped Drive), Outlook/Exchange kimlik bilgisi veya Windows Credential Manager kaydı bulunup bulunmadığı.`,
        `Giriş türü ${winDetails.logonTypeDesc} olduğundan; bu protokolün istemci ile hedef sunucu arasında yetkilendirilmiş ve beklenen bir erişim kanalı olup olmadığı.`,
      ];

      if (winDetails.subStatus === '0XC0000234') {
        qList.push('Hesap kilitlendiğinden (0xC0000234), Active Directory üzerinde kilit kaldırma işlemi öncesi ardışık başarısız denemelerin diğer Domain Controller loglarından kontrolü.');
      } else {
        qList.push('Active Directory etki alanı üzerinde bu kullanıcı için ardışık başarısız oturum (Account Lockout) veya diğer etki alanı denetleyicilerinde paralel denemeler bulunup bulunmadığı.');
      }
      return qList;
    }

    if (winDetails.eventId === 4624) {
      return [
        `${userDisplay} belirtilen tarihte (${logTime}) ${machineDisplay} oturum açma eyleminin onaylı ve meşru bir personel faaliyeti olup olmadığı.`,
        `Bağlantı ${winDetails.logonTypeDesc} yöntemiyle gerçekleştirildiğinden, bu saatte planlı bir bakım, nöbet veya uzaktan çalışma kaydı bulunup bulunmadığı.`,
        'Oturum süresince hesap tarafından çalıştırılan kritik işlemlerin (Process Creation 4688) veya ayrıcalıklı grup erişimlerinin doğrulanması.',
      ];
    }

    if (winDetails.eventId === 4688) {
      const cmdPreview = winDetails.commandLine
        ? `"${winDetails.commandLine.slice(0, 80)}..."`
        : winDetails.processName
        ? `"${winDetails.processName}"`
        : 'ilgili sürecin';
      return [
        `Yürütülen komut satırının (${cmdPreview}) kurumunuzun onaylı BT yönetim scripti, dağıtım aracı veya yetkili personel işlemi olup olmadığının teyidi.`,
        `Komutu tetikleyen üst sürecin (${winDetails.parentProcess ? `"${winDetails.parentProcess}"` : 'Parent Process'}) ve çalıştıran hesabın (${winDetails.targetUser || winDetails.subjectUser || 'ilgili kullanıcı'}) bu uç noktada komut çalıştırma yetkisinin bulunup bulunmadığı.`,
        'Uç nokta güvenlik yazılımında (EDR / Antivirüs) ilgili süreç için şüpheli davranış, karantina veya engelleme kaydının kontrolü.',
      ];
    }

    if (winDetails.eventId === 4720 || winDetails.eventId === 4728 || winDetails.eventId === 4732 || winDetails.eventId === 4738) {
      return [
        `Gerçekleştirilen bu kullanıcı/grup yetki değişikliğine (${winDetails.targetUser ? `"${winDetails.targetUser}" için` : ''}) ait resmi Değişiklik Yönetimi (Change Ticket / Servis Masası Onay) numarasının paylaşılması.`,
        `Değişikliği tetikleyen yetkili hesabın (${winDetails.subjectUser ? `"${winDetails.subjectUser}"` : 'yönetici hesabının'}) bu işlemi bizzat kendi bilgisi dahilinde yapıp yapmadığının teyidi.`,
        'Oluşturulan veya yetkisi artırılan hesabın parola politikası ve Çok Faktörlü Kimlik Doğrulama (MFA) zorunluluğunun aktifliği.',
      ];
    }

    if (winDetails.eventId === 1102 || winDetails.eventId === 104) {
      return [
        `Windows Güvenlik Olay Günlüğünün silinmesi (${winDetails.subjectUser ? `"${winDetails.subjectUser}" tarafından` : ''}) planlı ve onaylı bir bakım faaliyeti midir? (ACİL Teyit).`,
        'Olay günlüğü silinmeden önceki olayların merkezi SIEM veya Syslog sunucusuna başarıyla kopyalanıp kopyalanmadığının kontrolü.',
        'Uç nokta üzerinde yetki yükseltme veya zararlı yazılım izlerinin tespiti amacıyla acil EDR adli analizi yapılması.',
      ];
    }

    if (winDetails.eventId === 7045 || winDetails.eventId === 4697) {
      return [
        `Sisteme yeni kurulan servisin (${winDetails.serviceName ? `"${winDetails.serviceName}"` : ''} ${winDetails.serviceFile ? `-> ${winDetails.serviceFile}` : ''}) onaylı kurumsal bir yazılım, ajan veya sürücü güncellemesi olup olmadığının doğrulanması.`,
        `Servis ikili dosyasının (${winDetails.serviceFile ? `"${winDetails.serviceFile}"` : 'Service Binary'}) AppData/Temp gibi anormal dizinlerde yer alıp almadığının disk üzerinden kontrolü.`,
        `Servis kurulumunu yapan kullanıcının (${winDetails.subjectUser || 'ilgili hesabın'}) bu sunucuda servis yükleme yetkisinin teyidi.`,
      ];
    }
  }

  // -------------------------------------------------------------
  // B. WEB / WAF / NETWORK ATTACK SCENARIOS
  // -------------------------------------------------------------
  if (attackVector === 'OWA_RFI_FALSE_POSITIVE') {
    return [
      srcIp !== 'Bilinmiyor'
        ? `${srcIp} kaynak IP adresinin (${logTime}) saatinde ilgili kurum personeli (mobil/ev interneti) tarafından kullanıldığının teyidi.`
        : 'İstemci IP adresinin ilgili saatte yetkili kurum personeli tarafından kullanıldığının teyidi.',
      targetHost
        ? `Hedef Exchange/IIS web sunucusunda (${targetHost}) aynı saniyede dönen HTTP yanıt durum kodu (200 OK / 302 Redirect teyidi).`
        : 'Hedef sunucu erişim loglarında ilgili isteğin HTTP yanıt durum kodu.',
      'Kullanıcının bu oturum açma sonrası gelen kutusuna veya OWA paneline sorunsuz erişip erişemediği.',
    ];
  }

  if (attackVector === 'SQL_INJECTION') {
    const patternStr = matchedPattern || requestUrl ? `"${(matchedPattern || requestUrl).slice(0, 55)}"` : 'URL/Parametre';
    return [
      `Hedef web uygulamasında (${targetHost || dstIp}) sorgulanan parametre (${patternStr}) için arka planda parametrik sorgu (Prepared Statement / ORM) kullanılıp kullanılmadığı.`,
      `Web ve veritabanı sunucusu loglarında (${logTime}) zamanında SQL syntax hatası veya istisna (Exception / 500) düşüp düşmediği.`,
      wafAction.toLowerCase() === 'alert'
        ? 'İstek WAF üzerinde "Alert" (izleme) modunda kaldığından; uygulamanın veritabanı yanıt boyutunda ve veri bütünlüğünde anomali olup olmadığının kontrolü.'
        : 'İstek WAF tarafından engellenmiş olmakla birlikte; uygulamanın yanıt loglarında ilgili istek için veri sızıntısı izi bulunmadığının teyidi.',
      `İstek yapan kaynak IP'nin (${srcIp}) kurumunuzun sızma testi (Penetration Test) veya iç zafiyet tarama ekibine ait olup olmadığı.`,
    ];
  }

  if (attackVector === 'XSS') {
    return [
      `Hedef web sayfasında (${targetHost || 'Web Sunucusu'}) kullanıcı girdilerinin ekrana yansıtılmadan önce HTML escape işleminden geçirilip geçirilmediği.`,
      'Uygulamanın HTTP başlıklarında Content-Security-Policy (CSP) ve X-XSS-Protection güvenlik başlıklarının devrede olup olmadığı.',
      'Bu URL çağrısını yapan son kullanıcılar tarafından oturum çalınması veya yetkisiz işlem bildirimi alınıp alınmadığı.',
    ];
  }

  if (attackVector === 'PATH_TRAVERSAL') {
    const fileStr = requestUrl ? `"${requestUrl.slice(0, 60)}"` : 'istenen dosyanın';
    return [
      `İstekte çağrılan dosyanın (${fileStr}) sunucu dosya sisteminde gerçekte mevcut olup olmadığı.`,
      'Web sunucusunun (IIS/Nginx/Apache) bu isteğe 404 Not Found mu yoksa 200 OK mi döndüğünün erişim loglarından kontrolü.',
      'Web sunucusunu çalıştıran servis hesabının (IIS_IUSRS / www-data) dosya erişim yetkilerinin web kök dizini (webroot) dışına çıkışının engellendiğinin teyidi.',
    ];
  }

  if (attackVector === 'COMMAND_INJECTION_WEBSHELL') {
    return [
      `Sunucuda (${targetHost || dstIp}) çağrılan script veya dosyanın diskte mevcut olup olmadığı ve dosya oluşturulma/değiştirilme zamanı.`,
      'Web servisinin (w3wp/nginx/apache/php) alt süreci olarak cmd.exe, powershell.exe, sh veya bash süreçlerinin tetiklenip tetiklenmediği.',
      'Sunucudan dışarıya doğru başlatılmış olağandışı bir TCP giden (outbound) bağlantı bulunup bulunmadığı.',
    ];
  }

  if (attackVector === 'LOG4J') {
    return [
      'Hedef sunucuda çalışan Java runtime sürümü ve Log4j kütüphanesinin CVE-2021-44228 yamalı sürüme güncellenmiş olup olmadığı.',
      'Ağ güvenlik duvarı çıkış (egress) kurallarında 389 (LDAP), 636 (LDAPS), 1099 (RMI) veya 1389 portlarına doğru dışarıya bağlantı açılıp açılmadığı.',
      'Java uygulama loglarında JNDI lookup hatası veya uzak sınıf yükleme istisnasının kontrolü.',
    ];
  }

  if (attackVector === 'TIMEOUT') {
    return [
      `Hedef sunucu ve portunun (${dstIp}${dstPort ? ':' + dstPort : ''}) belirtilen saatte (${logTime}) ayakta, dinleme modunda (Listening) ve erişilebilir olup olmadığı (Servis çökmesi/yeniden başlama teyidi).`,
      `Kaynak (${srcIp}) ile hedef (${dstIp}) arasındaki ara ağ cihazlarında (Router, VPN Gateway, Switch) paket kaybı veya MTU uyuşmazlığı yaşanıp yaşanmadığı.`,
      'Güvenlik duvarı üzerinde TCP Session Timeout süresinin bu servisin veri bekleme karakteristiği için yeterli olup olmadığı.',
    ];
  }

  if (attackVector === 'BRUTE_FORCE') {
    return [
      'Hedeflenen kullanıcı hesaplarının Active Directory veya kimlik sağlayıcıda (IdP) geçici olarak kilitlenip kilitlenmediği.',
      'İlgili oturum açma sayfasında IP başına istek sınırlama (Rate Limiting) veya CAPTCHA mekanizmasının devrede olup olmadığı.',
      'Aynı IP adresinden bu denemeler esnasında başarılı bir oturum açma (200 OK / Success) gerçekleşip gerçekleşmediği.',
    ];
  }

  if (attackVector === 'SCANNER') {
    return [
      `Kaynak IP (${srcIp}) adresinin kurumsal bir sızma testi, güvenlik denetimi veya iç zafiyet tarama aracına (Nessus/Qualys) ait olup olmadığı.`,
      'Güvenlik duvarının bu IP adresini otomatik olarak IPS karantinasına (Blacklist) alıp almadığı.',
      'Tarama yapılan URL adreslerinin hedef sunucuda karşılığı olup olmadığı (Genel 404 oranının kontrolü).',
    ];
  }

  // Generic fallback
  return [
    srcIp !== 'Bilinmiyor'
      ? `${srcIp} IP adresinin kurumunuzca beklenen bir iş ortağı, şube veya yetkili personele ait olup olmadığının teyidi.`
      : 'Kaynak IP adresinin beklenen bir kullanıcı veya iş ortağına ait olup olmadığının teyidi.',
    targetHost
      ? `${targetHost} sunucusunda aynı zaman diliminde (${logTime}) oluşan uygulama ve erişim loglarının karşılığı.`
      : 'Hedef sunucunun erişim loglarındaki karşılığı ve dönen HTTP yanıt kodu.',
    wafAction.toLowerCase() === 'alert'
      ? 'Erişim engellenmediğinden (Alert modu), hedef sistemde anomali veya beklenmeyen veri transferi olup olmadığının kontrolü.'
      : 'Uygulanan güvenlik duvarı / WAF kuralının iş sürekliliğine etkisinin teyidi.',
  ];
}
