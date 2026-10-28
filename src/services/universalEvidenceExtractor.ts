import {
  UniversalEvidence,
  FieldObservation,
  InputAdmissibility,
  SourceType,
} from '../types/investigationEvidence';
import { NormalizedLog } from '../types';
import { extractWindowsDetails, WINDOWS_EVENT_NAMES, WINDOWS_SUBSTATUS_MAP, WINDOWS_LOGON_TYPE_MAP } from './quickTriageHelper';

function makeObservation<T = string | number | null>(
  value: T,
  rawValue: string | null | undefined,
  status: 'OBSERVED' | 'DERIVED' | 'UNCERTAIN' | 'NOT_PRESENT' | 'NOT_ASSESSED',
  sourceType: SourceType,
  extractionMethod: any,
  sourceReference?: string,
  supportingEvidence?: string[]
): FieldObservation<T> {
  return {
    value,
    rawValue: rawValue !== undefined ? rawValue : (value !== null ? String(value) : null),
    status,
    sourceType,
    extractionMethod,
    sourceReference,
    supportingEvidence,
  };
}

const notPresent = <T>(sourceType: SourceType = 'TEXT_LOG'): FieldObservation<T> =>
  makeObservation<T>(null as any, null, 'NOT_PRESENT', sourceType, 'REGEX');

/**
 * Assesses admissibility of input text:
 * Separates actual security telemetry from plain prose, song lyrics, or recipes.
 */
export function assessInputAdmissibility(rawText: string): InputAdmissibility {
  const trimmed = rawText.trim();
  if (!trimmed || trimmed.length < 5) {
    return {
      classification: 'INSUFFICIENT_DATA',
      isSecurityEvidence: false,
      confidence: 'KESİN',
      reason: 'Girdi verisi çok kısa veya boş; güvenlik değerlendirmesi için yetersiz.',
      detectedSignals: [],
    };
  }

  // Safe length bounding against ReDoS
  const sample = trimmed.slice(0, 10000);
  const lower = sample.toLowerCase();
  const signals: string[] = [];

  // 1. Network Telemetry Indicators
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
  if (ipv4Regex.test(sample)) signals.push('IPv4 Adresi');
  if (/\b(?:port[:=\s]+\d+|dport[:=\s]+\d+|sport[:=\s]+\d+)\b/i.test(sample)) signals.push('Ağ Portu');
  if (/\b(?:mac[:=\s]+[0-9a-f:]{17})\b/i.test(sample)) signals.push('MAC Adresi');

  // 2. Security System & Identity Indicators
  if (/\b(?:event(?:\s*id|id)?[:=\s]+\d{1,5})\b/i.test(sample) || /\[\d{1,5}\]/.test(sample) || /\b(?:eventid|eventcode)[:=\s]+\d{1,5}/i.test(sample)) signals.push('Event ID');
  if (lower.includes('microsoft-windows') || lower.includes('sysmon') || lower.includes('windows filtering platform') || lower.includes('the log file was cleared')) signals.push('Windows Güvenlik Olayı');
  if (/\b(?:targetusername|subjectusername|account\s+name|user|kullanici_adi)[:=\s]+/i.test(sample)) signals.push('Kullanıcı/Hesap Alanı');
  if (/\b(?:logontype|substatus|status_code|http_status|cs-status)[:=\s]+/i.test(sample)) signals.push('Güvenlik/Durum Kodu');

  // 3. Command & Process Indicators
  if (/\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|certutil(?:\.exe)?|whoami(?:\.exe)?|w3wp(?:\.exe)?|bash|sh|sudo)\b/i.test(sample)) signals.push('Güvenlik/Sistem Süreci');
  if (/(?:-[a-z0-9]+|--[a-z0-9_-]+)\s+/i.test(sample) && (lower.includes('bypass') || lower.includes('enc') || lower.includes('split') || lower.includes('decode') || lower.includes('noprofile'))) {
    signals.push('Sistem/CLI Parametreleri');
  }

  // 4. Log Format Structure
  if (sample.includes('<Event') && sample.includes('</Event>')) signals.push('Windows Event XML');
  if (/^<\d+>|\b(?:CEF|LEEF):\d+\b/.test(sample)) signals.push('Syslog/CEF Başlığı');
  if (sample.startsWith('{') && sample.endsWith('}') && (lower.includes('event') || lower.includes('status') || lower.includes('ip') || lower.includes('user'))) {
    signals.push('Yapılandırılmış JSON Log');
  }
  if (/\b(?:auth_failed|failed password|accepted password|logon failed|access denied|waf_action|drop|deny|block)\b/i.test(sample)) {
    signals.push('Güvenlik Aksiyon/Sonuç İfadesi');
  }

  // Non-security filters: Lyrics, recipes, prose with NO telemetry indicators
  const proseSongKeywords = ['[verse', '[chorus', '[hook', '[outro', '[intro', 'lyrics', 'şarkı', 'yemek tarifi', 'malzemeler:', 'su bardağı', 'tatlı kaşığı', 'tuz ekleyin'];
  const hasSongOrRecipe = proseSongKeywords.some(k => lower.includes(k));

  if (hasSongOrRecipe && signals.length === 0) {
    return {
      classification: 'NON_SECURITY_INPUT',
      isSecurityEvidence: false,
      confidence: 'KESİN',
      reason: 'Girdi düz metin/şarkı sözü/tarif formatındadır; güvenlik telemetrisi içermemektedir.',
      detectedSignals: [],
    };
  }

  // Normal conversational text with security keywords like "Siber güvenlik konferansı yarın saat 10'da"
  const isOrdinaryConferenceText = (lower.includes('konferans') || lower.includes('toplantı') || lower.includes('eğitim')) &&
    signals.length === 0 && !lower.includes('event') && !lower.includes('ip=') && !lower.includes('user=');
  if (isOrdinaryConferenceText) {
    return {
      classification: 'NON_SECURITY_INPUT',
      isSecurityEvidence: false,
      confidence: 'KESİN',
      reason: 'Metinde güvenlik terimleri geçmektedir ancak gerçek sistem/olay telemetrisi veya eylemi içermemektedir.',
      detectedSignals: [],
    };
  }

  if (signals.length >= 2 || (signals.length === 1 && (signals.includes('Event ID') || signals.includes('Windows Event XML') || signals.includes('Syslog/CEF Başlığı')))) {
    return {
      classification: 'SECURITY_EVIDENCE',
      isSecurityEvidence: true,
      confidence: signals.length >= 3 ? 'KESİN' : 'YÜKSEK',
      reason: `Geçerli güvenlik telemetrisi sinyalleri tespit edildi: ${signals.join(', ')}.`,
      detectedSignals: signals,
    };
  }

  if (signals.length === 1) {
    return {
      classification: 'POSSIBLE_SECURITY_EVIDENCE',
      isSecurityEvidence: true,
      confidence: 'ORTA',
      reason: `Sınırlı telemetri sinyali tespit edildi (${signals[0]}). Bağlam yetersiz olabilir ancak değerlendirilebilir.`,
      detectedSignals: signals,
    };
  }

  return {
    classification: 'NON_SECURITY_INPUT',
    isSecurityEvidence: false,
    confidence: 'YÜKSEK',
    reason: 'Girdi incelendi; geçerli bir güvenlik telemetrisi, log başlığı veya sistem göstergesi bulunamadı.',
    detectedSignals: [],
  };
}

/**
 * Universal Semantic Extractor:
 * Extracts actors, endpoints, actions, telemetry without forcing unknown inputs into rigid templates.
 */
export function extractUniversalEvidence(
  rawText: string,
  parsedLog?: NormalizedLog | null,
  sourceType: SourceType = 'TEXT_LOG'
): UniversalEvidence {
  const trimmed = rawText.trim();
  const admissibility = assessInputAdmissibility(trimmed);

  if (!admissibility.isSecurityEvidence) {
    // Return pristine empty evidence when input is non-security or insufficient
    return {
      admissibility,
      rawContent: rawText,
      actor: notPresent(sourceType),
      subjectUser: notPresent(sourceType),
      sourceEndpoint: { ip: notPresent(sourceType), port: notPresent(sourceType), host: notPresent(sourceType) },
      destinationEndpoint: { ip: notPresent(sourceType), port: notPresent(sourceType), host: notPresent(sourceType) },
      action: notPresent(sourceType),
      outcome: makeObservation('UNKNOWN', null, 'NOT_ASSESSED', sourceType, 'REGEX'),
      timestamp: notPresent(sourceType),
      process: { name: notPresent(sourceType), pid: notPresent(sourceType), commandLine: notPresent(sourceType), parentProcess: notPresent(sourceType) },
      telemetry: {
        protocol: notPresent(sourceType),
        httpStatus: notPresent(sourceType),
        wafAction: notPresent(sourceType),
        errorCode: notPresent(sourceType),
        errorDescription: notPresent(sourceType),
        rawPayload: notPresent(sourceType),
        eventId: notPresent(sourceType),
        eventName: notPresent(sourceType),
        logonType: notPresent(sourceType),
        subStatus: notPresent(sourceType),
        serviceName: notPresent(sourceType),
      },
      unparsedFields: {},
    };
  }

  const kvDict: Record<string, string> = {};
  const unparsedFields: Record<string, string> = {};

  // Try parsing JSON first if structured
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsedJson = JSON.parse(trimmed);
      for (const [k, v] of Object.entries(parsedJson)) {
        const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
        kvDict[k.toLowerCase()] = valStr;
        unparsedFields[k] = valStr;
      }
    } catch {
      // not valid json, fall back to kvRegex
    }
  }

  // Key-value extraction with safe bounding
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=([^\s\t\r\n",]+|"[^"]*")/g;
  let kvMatch;
  while ((kvMatch = kvRegex.exec(trimmed.slice(0, 10000))) !== null) {
    const k = kvMatch[1].toLowerCase();
    const v = kvMatch[2].replace(/^"|"$/g, '');
    kvDict[k] = v;
    unparsedFields[kvMatch[1]] = v;
  }

  // Windows Event Details via existing helper
  const win = extractWindowsDetails(trimmed, kvDict, parsedLog || null);

  // 1. ACTOR (User / Account)
  let actorObs = notPresent<string | null>(sourceType);
  if (win.targetUser && win.targetUser !== 'BILINMEYEN-USER') {
    actorObs = makeObservation(win.targetUser, win.targetUser, 'OBSERVED', sourceType, 'REGEX', 'TargetUserName');
  } else if (kvDict.user || kvDict.username || kvDict.account || kvDict.caller || kvDict.targetuser) {
    const rawVal = kvDict.user || kvDict.username || kvDict.account || kvDict.caller || kvDict.targetuser;
    actorObs = makeObservation(rawVal, rawVal, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'user/username/account');
  } else if (parsedLog?.kullanici_adi) {
    actorObs = makeObservation(parsedLog.kullanici_adi, parsedLog.kullanici_adi, 'OBSERVED', sourceType, 'DELIMITED_COLUMN');
  } else {
    const userMatch = trimmed.match(/(?:for|user)\s+(?:invalid user\s+)?([a-zA-Z0-9_\-\.\\]+)\s+from/i) ||
                      trimmed.match(/\b(?:sudo:\s+([a-zA-Z0-9_\-\.]+)\s*:)/i);
    if (userMatch && userMatch[1]) {
      actorObs = makeObservation(userMatch[1], userMatch[1], 'OBSERVED', sourceType, 'REGEX', 'syslog auth line');
    }
  }

  // Subject / Requesting user
  let subjectUserObs = notPresent<string | null>(sourceType);
  if (win.subjectUser) {
    subjectUserObs = makeObservation(win.subjectUser, win.subjectUser, 'OBSERVED', sourceType, 'REGEX', 'SubjectUserName');
  }

  // 2. ENDPOINTS (Source & Destination)
  let srcIpObs = notPresent<string | null>(sourceType);
  const rawSrcIp = (win.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-')
    ? win.sourceIp
    : (kvDict.ip || kvDict.src || kvDict.srcip || kvDict.sourceip || kvDict.client_ip || kvDict['c-ip'] || parsedLog?.ip_adresi);

  if (rawSrcIp) {
    srcIpObs = makeObservation(rawSrcIp, rawSrcIp, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'Source IP');
  } else {
    const ipMatch = trimmed.match(/\b(?:src|srcip|sourceip|client_ip|c-ip)\s*[:=]\s*["']?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i) ||
                    trimmed.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);
    if (ipMatch && ipMatch[1]) {
      srcIpObs = makeObservation(ipMatch[1], ipMatch[1], 'OBSERVED', sourceType, 'REGEX', 'ip regex');
    }
  }

  const rawSrcPort = win.sourcePort || kvDict.srcport || kvDict.sport || kvDict.source_port;
  const srcPortObs = rawSrcPort && !isNaN(parseInt(rawSrcPort, 10))
    ? makeObservation(parseInt(rawSrcPort, 10), rawSrcPort, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'Source Port')
    : notPresent<number | null>(sourceType);

  const rawDstIp = kvDict.dst || kvDict.dstip || kvDict.destinationip || parsedLog?.hedef_ip;
  const dstIpObs = rawDstIp && rawDstIp !== 'Bilinmiyor'
    ? makeObservation(rawDstIp, rawDstIp, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'Destination IP')
    : notPresent<string | null>(sourceType);

  const rawDstPort = kvDict.dstport || kvDict.dport || kvDict.destination_port || (parsedLog?.hedef_port ? String(parsedLog.hedef_port) : null);
  const dstPortObs = rawDstPort && !isNaN(parseInt(rawDstPort, 10))
    ? makeObservation(parseInt(rawDstPort, 10), rawDstPort, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'Destination Port')
    : notPresent<number | null>(sourceType);

  const rawHost = win.computer || win.workstation || kvDict.host || kvDict.hostname || kvDict.computer || kvDict.destination || parsedLog?.sunucu_ismi;
  const hostObs = rawHost && rawHost !== 'BILINMEYEN-HOST' && rawHost !== '-'
    ? makeObservation(rawHost, rawHost, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'Host/Computer')
    : notPresent<string | null>(sourceType);

  // 3. ACTION & OUTCOME
  let explicitAction = kvDict.action || kvDict.act || kvDict.device_action || kvDict.waf_action || kvDict.policy_action || kvDict.disposition;
  if (!explicitAction) {
    const actionMatch = trimmed.match(/(?:\||\t|,|\s)\s*(blocked|deny|drop|reject|reset|prevent|allowed|allow|alert|pass)\s*(?:\||\t|,|\s|$)/i);
    if (actionMatch && actionMatch[1]) {
      const word = actionMatch[1].toLowerCase();
      explicitAction = (word === 'blocked' || word === 'deny' || word === 'drop' || word === 'reject' || word === 'reset' || word === 'prevent')
        ? 'DENY'
        : (word === 'alert')
        ? 'ALERT'
        : 'ALLOW';
    }
  }

  const rawOutcome = kvDict.outcome || kvDict.result;
  const firewallDecision = (parsedLog?.baglanti_karari === 'DENY' || parsedLog?.baglanti_karari === 'ACCEPT') ? parsedLog.baglanti_karari : null;
  const effectiveAction = explicitAction || firewallDecision;

  let outcomeVal: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN' = 'UNKNOWN';
  let outcomeStatus: 'OBSERVED' | 'DERIVED' | 'NOT_ASSESSED' = 'NOT_ASSESSED';

  if (effectiveAction && /^(?:drop|deny|block|reject|reset|close|prevent|blocked|engellendi)$/i.test(effectiveAction)) {
    outcomeVal = 'BLOCKED';
    outcomeStatus = 'OBSERVED';
  } else if (win.eventId === 4625 || /failed|failure|auth_failed|rejected/i.test(rawOutcome || explicitAction || trimmed)) {
    outcomeVal = 'FAILURE';
    outcomeStatus = 'DERIVED';
  } else if (win.eventId === 4624 || /accepted|success|successful|authorized/i.test(rawOutcome || explicitAction || trimmed)) {
    outcomeVal = 'SUCCESS';
    outcomeStatus = 'DERIVED';
  }

  const outcomeObs: FieldObservation<'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN'> =
    makeObservation(outcomeVal, effectiveAction || rawOutcome || null, outcomeStatus, sourceType, 'DERIVED_TRANSLATION', 'status/eventId/action');

  const actionObs = explicitAction
    ? makeObservation(explicitAction, explicitAction, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'action')
    : firewallDecision
    ? makeObservation(firewallDecision, firewallDecision, 'OBSERVED', sourceType, 'DERIVED_TRANSLATION', 'firewall decision')
    : notPresent<string | null>(sourceType);

  // 4. TIMESTAMP
  const rawTime = kvDict.timestamp || kvDict.time || kvDict.date || parsedLog?.tarih;
  const timestampObs = rawTime
    ? makeObservation(rawTime, rawTime, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'time/timestamp')
    : notPresent<string | null>(sourceType);

  // 5. PROCESS & EXECUTION (HTTP Request ≠ Process Command Line)
  const isHttpRequest = Boolean(
    parsedLog?.islem_komutu &&
    (/^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+/i.test(parsedLog.islem_komutu) ||
     /^\/.*(?:HTTP\/|\?|\b)/i.test(parsedLog.islem_komutu) ||
     /\bHTTP\/[0-9\.]+\b/i.test(parsedLog.islem_komutu))
  );

  const rawProc = win.processName || kvDict.process || kvDict.proc || kvDict.image || kvDict.binary;
  const procNameObs = rawProc
    ? makeObservation(rawProc, rawProc, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'process/image')
    : notPresent<string | null>(sourceType);

  let rawCmd = win.commandLine || kvDict.commandline || kvDict.command || kvDict.cmd || kvDict.args;
  let rawHttpPayload = kvDict.payload || kvDict.rawpayload || kvDict.uri || kvDict.url || kvDict.request || null;

  if (isHttpRequest) {
    rawHttpPayload = parsedLog!.islem_komutu;
  } else if (!rawCmd && parsedLog?.islem_komutu && !win.isWindowsEvent) {
    // Only if not an HTTP request and genuine process telemetry
    if (!/^(?:GET|POST|PUT|DELETE|\/)/i.test(parsedLog.islem_komutu)) {
      rawCmd = parsedLog.islem_komutu;
    }
  }

  if (!rawHttpPayload) {
    const httpRegex = /"?(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"\|]+)/i;
    const httpMatch = trimmed.match(httpRegex);
    if (httpMatch && httpMatch[1]) {
      rawHttpPayload = httpMatch[1];
    }
  }

  const cmdLineObs = rawCmd
    ? makeObservation(rawCmd, rawCmd, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'commandLine')
    : notPresent<string | null>(sourceType);

  const rawParent = win.parentProcess || kvDict.parentprocess || kvDict.parentimage;
  const parentProcObs = rawParent
    ? makeObservation(rawParent, rawParent, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'parentProcess')
    : notPresent<string | null>(sourceType);

  // 6. TELEMETRY DETAILS
  const rawEventId = win.eventId || (kvDict.eventid ? parseInt(kvDict.eventid, 10) : null);
  const eventIdObs = rawEventId
    ? makeObservation(rawEventId, String(rawEventId), 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'EventID')
    : notPresent<number | null>(sourceType);

  const eventNameObs = rawEventId && WINDOWS_EVENT_NAMES[rawEventId]
    ? makeObservation(WINDOWS_EVENT_NAMES[rawEventId].name, null, 'DERIVED', sourceType, 'DERIVED_TRANSLATION', 'WINDOWS_EVENT_NAMES')
    : notPresent<string | null>(sourceType);

  const rawSubStatus = win.subStatus || kvDict.substatus;
  const subStatusObs = rawSubStatus
    ? makeObservation(rawSubStatus, rawSubStatus, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'SubStatus')
    : notPresent<string | null>(sourceType);

  const subStatusDesc = rawSubStatus && WINDOWS_SUBSTATUS_MAP[rawSubStatus.toUpperCase()]
    ? makeObservation(WINDOWS_SUBSTATUS_MAP[rawSubStatus.toUpperCase()], null, 'DERIVED', sourceType, 'DERIVED_TRANSLATION', 'WINDOWS_SUBSTATUS_MAP')
    : notPresent<string | null>(sourceType);

  const rawLogonType = win.logonType || (kvDict.logontype ? parseInt(kvDict.logontype, 10) : null);
  const logonTypeObs = rawLogonType
    ? makeObservation(rawLogonType, String(rawLogonType), 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'LogonType')
    : notPresent<number | null>(sourceType);

  const rawReason = kvDict.reason || kvDict.error || kvDict.err;
  const errorCodeObs = rawReason
    ? makeObservation(rawReason, rawReason, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'reason/error')
    : notPresent<string | null>(sourceType);

  // HTTP status code without equating to WAF Block
  let rawHttpStatus = parsedLog?.status_code || (kvDict.status_code ? parseInt(kvDict.status_code, 10) : null);
  if (!rawHttpStatus) {
    const statusMatch = trimmed.match(/"\s+(\d{3})\s+/);
    if (statusMatch && statusMatch[1]) {
      rawHttpStatus = parseInt(statusMatch[1], 10);
    }
  }
  const httpStatusObs = rawHttpStatus
    ? makeObservation(rawHttpStatus, String(rawHttpStatus), 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'HTTP status code')
    : notPresent<number | null>(sourceType);

  const rawWafAction =
    kvDict.waf_action ||
    kvDict.device_action ||
    (kvDict.action && /block|drop|deny|alert|pass/i.test(kvDict.action) ? kvDict.action : null) ||
    (explicitAction && /block|drop|deny|alert|pass/i.test(explicitAction) ? explicitAction : null);
  const wafActionObs = rawWafAction
    ? makeObservation(rawWafAction, rawWafAction, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'WAF Action')
    : notPresent<string | null>(sourceType);

  return {
    admissibility,
    rawContent: rawText,
    actor: actorObs,
    subjectUser: subjectUserObs,
    sourceEndpoint: { ip: srcIpObs, port: srcPortObs, host: notPresent(sourceType) },
    destinationEndpoint: { ip: dstIpObs, port: dstPortObs, host: hostObs },
    action: actionObs,
    outcome: outcomeObs,
    timestamp: timestampObs,
    process: { name: procNameObs, pid: notPresent(sourceType), commandLine: cmdLineObs, parentProcess: parentProcObs },
    telemetry: {
      protocol: kvDict.proto ? makeObservation(kvDict.proto, kvDict.proto, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE') : notPresent(sourceType),
      httpStatus: httpStatusObs,
      wafAction: wafActionObs,
      errorCode: errorCodeObs,
      errorDescription: subStatusDesc,
      rawPayload: rawHttpPayload
        ? makeObservation(rawHttpPayload, rawHttpPayload, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE', 'rawPayload/httpRequest')
        : notPresent<string | null>(sourceType),
      eventId: eventIdObs,
      eventName: eventNameObs,
      logonType: logonTypeObs,
      subStatus: subStatusObs,
      serviceName: win.serviceName ? makeObservation(win.serviceName, win.serviceName, 'OBSERVED', sourceType, 'DIRECT_KEY_VALUE') : notPresent(sourceType),
    },
    unparsedFields,
  };
}
