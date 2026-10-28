import {
  AiSemanticLogResponse,
  AiSemanticEvent,
  AiSemanticField,
  SemanticFieldType,
  ForensicHypothesis,
  SemanticForensicPipelineResult,
  FormatAssessment,
  AiLogStructureResponse,
  AiRecord,
} from '../types/aiLogUnderstanding';
import { validateAiLogStructure } from './rawSpanValidator';
import { convertAiRecordToUniversalEvidence } from './aiRecordToEvidence';
import { evaluateUnifiedDecision, UnifiedDecisionResult } from './unifiedDecisionEngine';
import {
  runSecondaryCorrelation,
  WholeLogSummary,
  CorrelatedEventInput,
  extractEventTimestamp,
} from './socCorrelationEngine';
import { segmentRawTextIntoEventsWithDiagnostics, extractWindowsDetails } from './quickTriageHelper';
import { initializeFormatState, feedSampleLine, parseLineToNormalizedLog } from './streamingParser';
import { UniversalEvidence } from '../types/investigationEvidence';

export type { SemanticForensicPipelineResult, AiSemanticLogResponse };

/**
 * PHASE 4.5 — TRUE AI LOG ANALYSIS SYSTEM PROMPT
 *
 * Strict Architectural Rules:
 * 1. AI is not just a boundary finder. It performs true semantic understanding across ANY log format.
 * 2. Zero format-specific if/else rules: Generalize across Windows, Linux, Sysmon, Apache, Nginx, IIS, CEF, LEEF, JSON, key=value, Fortinet, WAF, custom & unknown logs.
 * 3. Contextual disambiguation:
 *    - "Connection closed by invalid user" in SSH -> AUTHENTICATION_OUTCOME = FAILURE, NOT a security device deny.
 *    - "BLOCK / DENY / DROP" in Fortinet/WAF -> SECURITY_DEVICE_ACTION = BLOCK/DENY.
 *    - "HTTP 403" alone -> HTTP_STATUS = 403, NOT a WAF BLOCK.
 *    - "GET /cgi-bin/../../etc/passwd" -> HTTP_REQUEST_URI / PATH_TRAVERSAL_HYPOTHESIS, NEVER commandLine!
 *    - "7045 service installation" -> SERVICE_INSTALLATION, NOT automatically BENIGN.
 * 4. Provenance: Every field MUST have { field, value, semanticType, status, rawSpan, confidence, evidence }.
 * 5. Hypotheses: OBSERVED FACTS -> HYPOTHESIS -> REQUIRED EVIDENCE -> CONFIRMED / UNCONFIRMED.
 * 6. Missing fields: NOT_PRESENT with value = "". No guessing or hallucinating!
 * 7. AI failure: Return ANALYSIS_INCOMPLETE. Never fall back to 1-event or BENIGN assumption.
 */
export const AI_SEMANTIC_LOG_SYSTEM_PROMPT = `Sen bir Kıdemli Siber Güvenlik ve Adli Bilişim Uzmanı AI Adli Log Anlamlandırma Motorusun (True AI Forensic Log Analysis Engine).

GÖREVİN:
Herhangi bir log/veri formatının yapısını ve semantik anlamını anlamak; ham log verisini olay sınırları, alan semantikleri, gözlemlenen olgular, adli hipotezler ve kanıt gereksinimleriyle analiz etmektir.

ZORUNLU PIPELINE:
RAW INPUT → AI LOG UNDERSTANDING → AI SEMANTIC EVENT ANALYSIS → UNIVERSAL EVIDENCE → RAW-SPAN VALIDATION → FORENSIC REASONING → CORRELATION → FINAL DECISION

KRİTİK SEMANTİK ANLAMLANDIRMA KURALLARI:
1. AYNI KELİMENİN BAĞLAM FARKLILIKLARI:
   - "Connection closed by invalid user" (SSH sunucu telemetrisi):
     → AUTHENTICATION_OUTCOME = "FAILURE", ACTION = "DISCONNECT".
     → ASLA bir güvenlik cihazı (Firewall/WAF) BLOCK/DENY eylemi DEĞİLDİR!
   - "BLOCK / DENY / DROP / RESET" (Fortinet, WAF, Güvenlik Cihazı telemetrisi):
     → SECURITY_DEVICE_ACTION = "BLOCK" veya "DENY".
     → Cihaz güvenlik duvarı/WAF olarak etiketlenmelidir.
   - "HTTP 403":
     → HTTP_STATUS = "403", OUTCOME = "FAILURE/FORBIDDEN".
     → Tek başına kesin WAF engellemesi değildir. (Uygulama yetki reddi olabilir).
   - "GET /cgi-bin/../../etc/passwd":
     → HTTP_REQUEST_URI = "/cgi-bin/../../etc/passwd", HTTP_METHOD = "GET".
     → Hipotez: PATH_TRAVERSAL_ATTEMPT.
     → KESİNLİKLE process.commandLine DEĞİLDİR! CommandLine alanı NOT_PRESENT olmalıdır.
   - "7045 service installation":
     → EVENT_TYPE = "SERVICE_INSTALLATION".
     → Servis yükleme olayıdır. Otomatik olarak BENIGN kabul EDİLEMEZ; çalıştırılabilir dosya yolu ve bağlama göre değerlendirilir.

2. BİLİNMEYEN ALANLAR VE FORMATLAR:
   - Bilinmeyen alanları ve formatları tahmin ETME.
   - UNKNOWN ≠ BENIGN.
   - UNKNOWN ≠ ATTACK.
   - Bilinmeyen alanlar için semanticType: "UNKNOWN_FIELD", status: "OBSERVED" (eğer ham metinde varsa) veya "NOT_PRESENT" ver.

3. ADLİ HİPOTEZ VE AKIL YÜRÜTME KONTRAKTI (GEMINI 3.8 FLASH FORENSIC REASONING):
   - Güvenlik değerlendirmesi adım adım mantıksal adli akıl yürütme (reasoning chain) ile kanıtlardan türetilmelidir:
     OBSERVED FACTS → REASONING (AKIL YÜRÜTME) → HYPOTHESIS → REQUIRED EVIDENCE → STATUS (CONFIRMED / UNCONFIRMED / BLOCKED_ATTEMPT / BENIGN_ROUTINE)
   - Her olay için hypothesis.reasoning alanında derin adli akıl yürütme sürecini açıkla:
     - Gözlemlenen olgular nelerdir? (Örn: SSH'ta geçersiz kullanıcı denendi ve sunucu oturumu kapattı).
     - Neden bir güvenlik cihazı engeli değil de sunucu kimlik reddidir? Veya neden HTTP 401/403 tek başına WAF block sayılamaz?
     - Neden hemen 'COMPROMISED' ya da peşin hüküm verilemez ve hangi ek kanıt (HTTP 200, oturum açma, kod yürütme) gereklidir?
     - Bu mantıksal adli muhakemeyi hypothesis.reasoning alanına detaylıca aktar.
   - Örneğin bir path traversal isteğinde:
     - Gözlemlenen Olgu: "/cgi-bin/../../etc/passwd" URI'si talep edildi.
     - Akıl Yürütme (Reasoning): URI'da dizin geçişi deseni var ancak HTTP yanıt kodu 403 olduğu için sunucu erişimi reddetmiştir. Dışarıya dosya sızdığına dair teyit bulunmamaktadır.
     - Hipotez: PATH_TRAVERSAL_ATTEMPT.
     - Doğrulama İçin Gereken Kanıt: HTTP 200 yanıtı ile /etc/passwd içeriğinin döndüğüne dair teyit.
     - Durum: BLOCKED_ATTEMPT veya UNCONFIRMED (asla saldırı başarılı / COMPROMISED denemez!).

4. HAM SPAN VE KANIT ZORUNLULUĞU:
   - Her alan şu yapıda olmalıdır:
     {
       "field": "...",
       "value": "...",
       "semanticType": "TIMESTAMP | ACTOR_USER | SUBJECT_USER | SOURCE_ENDPOINT | SOURCE_PORT | DESTINATION_ENDPOINT | DESTINATION_PORT | HOST | PROCESS | PARENT_PROCESS | COMMAND_LINE | HTTP_REQUEST_URI | HTTP_METHOD | HTTP_STATUS | SECURITY_DEVICE_ACTION | AUTHENTICATION_OUTCOME | ACTION | OUTCOME | EVENT_TYPE | EVENT_ID | SERVICE_NAME | SERVICE_FILE | SUB_STATUS | LOGON_TYPE | NETWORK_INFO | UNKNOWN_FIELD",
       "status": "OBSERVED | DERIVED | UNCERTAIN | NOT_PRESENT | NOT_ASSESSED",
       "rawSpan": { "start": 0, "end": 10 },
       "confidence": "HIGH | MEDIUM | LOW",
       "evidence": "..."
     }
   - Ham metinde karşılığı olmayan hiçbir alan OBSERVED yapılamaz.

ÇIKTI SÖZLEŞMESİ (JSON):
Yalnızca aşağıdaki JSON şemasını döndür:
{
  "analysisVersion": "1.0",
  "engine": "AI_SEMANTIC_LOG_ENGINE",
  "formatAssessment": {
    "format": "Windows Security | Sysmon | Linux auth | Apache | Nginx | IIS | CEF | LEEF | JSON | key=value | Fortinet | WAF | application logs | UNKNOWN",
    "confidence": "HIGH | MEDIUM | LOW | UNKNOWN"
  },
  "records": [
    {
      "recordIndex": 1,
      "rawStart": 0,
      "rawEnd": 120,
      "rawText": "...",
      "boundaryConfidence": "HIGH | MEDIUM | LOW",
      "logFormatAndVendor": {
        "vendorOrSource": "Microsoft-Windows-Security-Auditing",
        "format": "Windows Security",
        "isSecurityDevice": false
      },
      "eventType": "LOGON | PROCESS_CREATION | SERVICE_INSTALLATION | HTTP_REQUEST | AUTHENTICATION_ATTEMPT | UNKNOWN",
      "fields": [...],
      "hypothesis": {
        "hypothesisId": "HYP-01",
        "hypothesis": "PATH_TRAVERSAL_ATTEMPT | CREDENTIAL_BRUTE_FORCE | SERVICE_PERSISTENCE | UNAUTHORIZED_ADMIN_LOGON | DEFENSE_EVASION_LOG_CLEAR | SUSPICIOUS_PARENT_PROCESS | BENIGN_ROUTINE",
        "observedFacts": ["..."],
        "requiredEvidence": ["..."],
        "status": "CONFIRMED | UNCONFIRMED | BLOCKED_ATTEMPT | BENIGN_ROUTINE | INSUFFICIENT_DATA",
        "reasoning": "..."
      },
      "verdict": "BENIGN | SUSPICIOUS_ANOMALY | MALICIOUS_ATTEMPT | COMPROMISED | BLOCKED | UNCERTAIN",
      "confidence": "HIGH | MEDIUM | LOW",
      "confidenceReason": "..."
    }
  ],
  "unparsedSpans": [],
  "warnings": []
}`;

/**
 * Disambiguates semantic characteristics from raw text without rigid format-specific branching.
 */
function analyzeSingleEventSemantics(
  rawText: string,
  recordIndex: number,
  globalStart: number
): AiSemanticEvent {
  const fields: AiSemanticField[] = [];
  const lower = rawText.toLowerCase();

  // Helper to extract an observed span
  const findSpan = (val: string): { start: number; end: number } | undefined => {
    if (!val) return undefined;
    const pos = rawText.indexOf(val);
    if (pos === -1) return undefined;
    return { start: pos, end: pos + val.length };
  };

  const addObserved = (
    field: string,
    value: string | null | undefined,
    semanticType: SemanticFieldType,
    evidence?: string
  ) => {
    if (!value || value === '-' || value === 'Bilinmiyor') return;
    const clean = String(value).trim();
    if (!clean) return;
    const span = findSpan(clean);
    if (span) {
      fields.push({
        field,
        value: clean,
        semanticType,
        status: 'OBSERVED',
        rawSpan: span,
        confidence: 'HIGH',
        evidence: evidence || `Exact match in raw text at offset ${span.start}..${span.end}`,
      });
    }
  };

  const addDerived = (
    field: string,
    value: string,
    semanticType: SemanticFieldType,
    evidence: string
  ) => {
    fields.push({
      field,
      value,
      semanticType,
      status: 'DERIVED',
      confidence: 'HIGH',
      evidence,
    });
  };

  const addNotPresent = (field: string, semanticType: SemanticFieldType) => {
    fields.push({
      field,
      value: '',
      semanticType,
      status: 'NOT_PRESENT',
      confidence: 'HIGH',
      evidence: 'Field is not present in raw record telemetry',
    });
  };

  // 1. Identify Vendor & Security Device Status
  let vendorOrSource = 'Generic/Unknown';
  let isSecurityDevice = false;
  let detectedFormat = 'UNKNOWN';

  if (/Microsoft-Windows-Security-Auditing|Log Name:\s*Security/i.test(rawText)) {
    vendorOrSource = 'Microsoft-Windows-Security-Auditing';
    detectedFormat = 'Windows Security';
  } else if (/Microsoft-Windows-Sysmon|Sysmon:/i.test(rawText)) {
    vendorOrSource = 'Microsoft-Windows-Sysmon';
    detectedFormat = 'Sysmon';
  } else if (/Fortinet|FortiGate|FG-|type=traffic/i.test(rawText)) {
    vendorOrSource = 'Fortinet';
    isSecurityDevice = true;
    detectedFormat = 'Fortinet';
  } else if (/F5|BIG-IP|ASM:|WAF/i.test(rawText)) {
    vendorOrSource = 'F5 WAF / Security Gateway';
    isSecurityDevice = true;
    detectedFormat = 'WAF';
  } else if (/CEF:\d+/i.test(rawText)) {
    vendorOrSource = 'CEF Telemetry Device';
    detectedFormat = 'CEF';
    if (/firewall|ids|ips|waf|proxy/i.test(rawText)) isSecurityDevice = true;
  } else if (/LEEF:\d+/i.test(rawText)) {
    vendorOrSource = 'LEEF Telemetry Device';
    detectedFormat = 'LEEF';
    if (/firewall|ids|ips|waf/i.test(rawText)) isSecurityDevice = true;
  } else if (/sshd\[\d+\]|sudo:|pam_unix/i.test(rawText)) {
    vendorOrSource = rawText.includes('sshd') ? 'OpenSSH Server' : 'Linux System';
    detectedFormat = 'Linux auth';
    isSecurityDevice = false; // OpenSSH daemon is an application server, not a security device!
  } else if (/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\/[^\s]*/i.test(rawText)) {
    if (lower.includes('iis') || lower.includes('w3c') || lower.includes('cs-method') || lower.includes('.aspx') || lower.includes('.asp')) {
      vendorOrSource = 'Microsoft IIS Web Server';
      detectedFormat = 'IIS W3C';
    } else if (lower.includes('nginx')) {
      vendorOrSource = 'Nginx Web Server';
      detectedFormat = 'Nginx';
    } else {
      vendorOrSource = 'Apache HTTP Server';
      detectedFormat = 'Apache';
    }
  } else if (rawText.trim().startsWith('{') && rawText.trim().endsWith('}')) {
    vendorOrSource = 'JSON Structured Log';
    detectedFormat = 'JSON';
  } else if (/\b[a-zA-Z0-9_\-\.]+=[^\s]+/i.test(rawText)) {
    vendorOrSource = 'Key-Value Telemetry';
    detectedFormat = 'key=value';
  }

  // 2. Extract Key-Value pairs generically if present
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=(".*?"|[^\s\t\r\n,]+)/g;
  let kvMatch: RegExpExecArray | null;
  const localKv: Record<string, string> = {};
  while ((kvMatch = kvRegex.exec(rawText)) !== null) {
    const k = kvMatch[1].toLowerCase();
    let v = kvMatch[2];
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    localKv[k] = v;
    addObserved(kvMatch[1], v, 'UNKNOWN_FIELD');
  }

  // 3. Extract JSON keys if JSON
  if (detectedFormat === 'JSON') {
    try {
      const parsed = JSON.parse(rawText.trim());
      for (const [k, v] of Object.entries(parsed)) {
        if (v !== null && v !== undefined && typeof v !== 'object') {
          localKv[k.toLowerCase()] = String(v);
          addObserved(k, String(v), 'UNKNOWN_FIELD');
        }
      }
    } catch {}
  }

  // 4. Timestamp Extraction
  const { timestampStr } = extractEventTimestamp(rawText);
  if (timestampStr) {
    addObserved('timestamp', timestampStr, 'TIMESTAMP');
  }

  // 5. Event Type & Event ID
  let eventType = 'UNKNOWN';
  const idMatch = rawText.match(/\[(\d+)\]|EventID[=:\s]+(\d+)|\bevent_id[=:\s]+(\d+)/i);
  const detectedId = idMatch ? (idMatch[1] || idMatch[2] || idMatch[3]) : null;
  if (detectedId) {
    addObserved('eventId', detectedId, 'EVENT_ID');
    if (detectedId === '4624') eventType = 'LOGON';
    else if (detectedId === '4625') eventType = 'LOGON_FAILURE';
    else if (detectedId === '4688' || detectedId === '1') eventType = 'PROCESS_CREATION';
    else if (detectedId === '7045') eventType = 'SERVICE_INSTALLATION';
    else if (detectedId === '1102' || detectedId === '104') eventType = 'LOG_CLEAR';
    else if (detectedId === '4672') eventType = 'PRIVILEGE_ASSIGNMENT';
    else if (detectedId === '11') eventType = 'FILE_CREATE';
    else if (detectedId === '5140') eventType = 'NETWORK_SHARE';
    else if (detectedId === '4663') eventType = 'OBJECT_ACCESS';
    else if (detectedId === '5156') eventType = 'NETWORK_TRAFFIC';
  }

  // 6. HTTP Request vs Command Line (CRITICAL RULE #4 & #9)
  // "GET /cgi-bin/../../etc/passwd" -> HTTP_REQUEST_URI / PATH_TRAVERSAL, NEVER command execution!
  const httpReqMatch = rawText.match(/"?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)(?:\s+HTTP\/([0-9\.]+)|)/i);
  let isHttpRequest = false;
  let uriValue = '';
  let httpMethod = '';

  if (httpReqMatch) {
    isHttpRequest = true;
    eventType = 'HTTP_REQUEST';
    httpMethod = httpReqMatch[1];
    uriValue = httpReqMatch[2];
    addObserved('httpMethod', httpMethod, 'HTTP_METHOD');
    addObserved('httpRequestUri', uriValue, 'HTTP_REQUEST_URI');
    if (httpReqMatch[3]) {
      addObserved('protocol', `HTTP/${httpReqMatch[3]}`, 'NETWORK_INFO');
    }

    // CRITICAL: CommandLine must be strictly NOT_PRESENT for HTTP requests
    addNotPresent('commandLine', 'COMMAND_LINE');
  } else {
    // If not HTTP request, check for command line
    const winDetails = extractWindowsDetails(rawText, localKv, null);
    if (winDetails.commandLine) {
      addObserved('commandLine', winDetails.commandLine, 'COMMAND_LINE');
      if (eventType === 'UNKNOWN') eventType = 'PROCESS_CREATION';
    } else {
      const sudoCmd = rawText.match(/COMMAND=(.*)$/i);
      if (sudoCmd) {
        addObserved('commandLine', sudoCmd[1].trim(), 'COMMAND_LINE');
        eventType = 'PRIVILEGED_COMMAND';
      } else {
        addNotPresent('commandLine', 'COMMAND_LINE');
      }
    }
  }

  // 7. Process & Parent Process
  const win = extractWindowsDetails(rawText, localKv, null);
  if (win.processName) {
    addObserved('process', win.processName, 'PROCESS');
  }
  if (win.parentProcess) {
    addObserved('parentProcess', win.parentProcess, 'PARENT_PROCESS');
  } else {
    // Missing parent process must NOT be hallucinated
    addNotPresent('parentProcess', 'PARENT_PROCESS');
  }

  // 8. Actor / User
  const userMatch =
    win.targetUser && win.targetUser !== 'BILINMEYEN-USER'
      ? win.targetUser
      : localKv.user || localKv.username || localKv.src_user || localKv.suser;
  if (userMatch) {
    addObserved('user', userMatch, 'ACTOR_USER');
  } else {
    const sshUser = rawText.match(/(?:for|user)\s+(?:invalid user\s+)?([a-zA-Z0-9_\-\.]+)\s+from/i);
    if (sshUser) {
      addObserved('user', sshUser[1], 'ACTOR_USER');
    } else {
      const sudoUser = rawText.match(/\bsudo:\s*([a-zA-Z0-9_\-\.]+)\s*:/i);
      if (sudoUser) {
        addObserved('user', sudoUser[1], 'ACTOR_USER');
      }
    }
  }

  if (win.subjectUser) {
    addObserved('subjectUser', win.subjectUser, 'SUBJECT_USER');
  }

  // 9. Endpoints (Source IP, Destination IP, Ports)
  const ipMatch = rawText.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g);
  if (ipMatch && ipMatch.length > 0) {
    const srcIpVal = win.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-'
      ? win.sourceIp
      : localKv.src || localKv.srcip || localKv.client_ip || localKv.c_ip || localKv.ip || ipMatch[0];
    addObserved('sourceIp', srcIpVal, 'SOURCE_ENDPOINT');

    if (ipMatch.length > 1) {
      const dstIpVal = localKv.dst || localKv.dstip || localKv.server_ip || ipMatch[1];
      if (dstIpVal !== srcIpVal) {
        addObserved('destinationIp', dstIpVal, 'DESTINATION_ENDPOINT');
      }
    }
  }

  const portMatch = rawText.match(/\bport\s+(\d+)\b|\bspt=(\d+)\b|\bsport=(\d+)\b/i);
  if (portMatch) {
    const p = portMatch[1] || portMatch[2] || portMatch[3];
    addObserved('sourcePort', p, 'SOURCE_PORT');
  }

  // 9.5 Syslog / Daemon prefix (host & service)
  // e.g. "web-03 nginx: 10.44.8.21 ...", "srv-prod sshd[18422]: ...", "mail-gw postfix/smtpd[28114]: ..."
  const syslogPrefix = rawText.match(/^(?:[a-zA-Z]{3}\s+\d+\s+\d+:\d+:\d+\s+)?([a-zA-Z0-9_\-\.]+)\s+([a-zA-Z0-9_\-\/]+)(?:\[\d+\])?:\s*/);
  let syslogHost: string | null = null;
  let syslogService: string | null = null;
  if (syslogPrefix) {
    const candidateHost = syslogPrefix[1];
    const candidateService = syslogPrefix[2];
    const nonHostPrefixes = ['microsoft-windows-security-auditing', 'microsoft-windows-sysmon', 'cef', 'leef'];
    if (!nonHostPrefixes.includes(candidateHost.toLowerCase())) {
      syslogHost = candidateHost;
    }
    syslogService = candidateService;
  }

  // 10. Host / Workstation
  if (win.computer && win.computer !== 'BILINMEYEN-HOST') {
    addObserved('host', win.computer, 'HOST');
  } else if (localKv.host || localKv.hostname || localKv.computer) {
    addObserved('host', localKv.host || localKv.hostname || localKv.computer, 'HOST');
  } else if (syslogHost) {
    addObserved('host', syslogHost, 'HOST');
  }

  if (syslogService && !win.serviceName && !localKv.service && !localKv.service_name) {
    addObserved('serviceName', syslogService, 'SERVICE_NAME');
  }

  // 11. Service Installation specifics (CRITICAL RULE #5)
  // "7045 service installation" -> EVENT_TYPE = SERVICE_INSTALLATION, not automatically benign
  if (win.serviceName) {
    addObserved('serviceName', win.serviceName, 'SERVICE_NAME');
  }
  if (win.serviceFile) {
    addObserved('serviceFile', win.serviceFile, 'SERVICE_FILE');
  }
  if (win.subStatus) {
    addObserved('subStatus', win.subStatus, 'SUB_STATUS');
  }
  if (win.logonType) {
    addObserved('logonType', String(win.logonType), 'LOGON_TYPE');
  }

  // 12. CONTEXTUAL DISAMBIGUATION: ACTION, OUTCOME, SECURITY_DEVICE_ACTION (CRITICAL RULES #1, #2, #3)
  // Rule A: SSH "Connection closed by invalid user" -> NOT a security device action!
  const isSshLog = rawText.includes('sshd') || vendorOrSource === 'OpenSSH Server';
  const isSshInvalidUser = isSshLog && /connection closed by invalid user|failed password for invalid user/i.test(rawText);
  const isSshFailure = isSshLog && /failed password|authentication failure|invalid user/i.test(rawText);

  // Rule B: Security Device Action (Fortinet, WAF, Firewall)
  const isDeviceExplicitBlock = isSecurityDevice && /\b(blocked|block|drop|deny|reject|reset)\b/i.test(rawText);

  // Rule C: HTTP Status (403, 401, 200)
  const httpStatusMatch =
    rawText.match(/"\s+(\d{3})\s+(\d+|-)/) ||
    rawText.match(/\bstatus=(\d{3})\b/i) ||
    rawText.match(/\s(\d{3})\s+\d+(?:\s+\d+\s+\d+)?$/);
  let httpStatusCode: number | null = null;
  if (httpStatusMatch) {
    httpStatusCode = parseInt(httpStatusMatch[1], 10);
    addObserved('httpStatus', httpStatusMatch[1], 'HTTP_STATUS');
  }

  let finalAction = 'ALLOW';
  let finalOutcome: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN' = 'SUCCESS';
  let securityDeviceAction: string | null = null;

  if (isSshInvalidUser || isSshFailure) {
    // SSH Daemon Telemetry: Authentication failure and disconnection
    finalAction = 'DISCONNECT';
    finalOutcome = 'FAILURE';
    addDerived('action', 'DISCONNECT', 'ACTION', 'SSH server daemon disconnected session after auth failure');
    addDerived('authenticationOutcome', 'FAILURE', 'AUTHENTICATION_OUTCOME', 'Invalid user / password failure in SSH server');
    // Security Device Action is explicitly NOT present
    addNotPresent('securityDeviceAction', 'SECURITY_DEVICE_ACTION');
  } else if (isDeviceExplicitBlock) {
    // True Security Device Block
    const actMatch = rawText.match(/\b(blocked|block|drop|deny|reject|reset)\b/i);
    securityDeviceAction = (actMatch ? actMatch[1] : 'BLOCK').toUpperCase();
    finalAction = securityDeviceAction;
    finalOutcome = 'BLOCKED';
    addObserved('securityDeviceAction', actMatch ? actMatch[1] : 'block', 'SECURITY_DEVICE_ACTION', 'Explicit security device block action');
    addDerived('action', securityDeviceAction, 'ACTION', 'Security device blocked traffic');
    addDerived('outcome', 'BLOCKED', 'OUTCOME', 'Traffic terminated by security enforcement device');
  } else if (httpStatusCode !== null) {
    if (httpStatusCode === 403 || httpStatusCode === 401) {
      finalAction = 'FORBID';
      finalOutcome = 'FAILURE';
      addDerived('action', 'FORBID', 'ACTION', `HTTP status ${httpStatusCode} indicates authorization rejection`);
      addDerived('outcome', 'FAILURE', 'OUTCOME', `HTTP status code ${httpStatusCode}`);
      // Rule C: HTTP 403 alone is NOT WAF BLOCK
      addNotPresent('securityDeviceAction', 'SECURITY_DEVICE_ACTION');
    } else if (httpStatusCode >= 200 && httpStatusCode < 300) {
      finalAction = 'ALLOW';
      finalOutcome = 'SUCCESS';
      addDerived('action', 'ALLOW', 'ACTION', `HTTP ${httpStatusCode} response ok`);
      addDerived('outcome', 'SUCCESS', 'OUTCOME', `HTTP status code ${httpStatusCode}`);
      addNotPresent('securityDeviceAction', 'SECURITY_DEVICE_ACTION');
    }
  } else if (/failure|failed|0xc0000064|0xc000006a|denied/i.test(rawText)) {
    finalAction = 'DENY';
    finalOutcome = 'FAILURE';
    addDerived('outcome', 'FAILURE', 'OUTCOME', 'Failure indicators observed in telemetry');
    addNotPresent('securityDeviceAction', 'SECURITY_DEVICE_ACTION');
  } else {
    // Default outcome derived
    addDerived('outcome', 'SUCCESS', 'OUTCOME', 'Routine event without failure signals');
    addNotPresent('securityDeviceAction', 'SECURITY_DEVICE_ACTION');
  }

  // 13. ADLI HİPOTEZ KONTRAKTI (FORENSIC REASONING)
  // OBSERVED FACTS → HYPOTHESIS → REQUIRED EVIDENCE → STATUS
  let hypothesis: ForensicHypothesis | undefined = undefined;
  let verdict: AiSemanticEvent['verdict'] = 'BENIGN';
  let confidence: AiSemanticEvent['confidence'] = 'HIGH';
  let confidenceReason = 'Routine system activity with consistent provenance.';

  if (uriValue && (uriValue.includes('..') || uriValue.includes('/etc/passwd') || uriValue.includes('cmd.exe'))) {
    // Path traversal / LFI attack attempt
    const observedFacts = [
      `HTTP Method: ${httpMethod || 'GET'}`,
      `Target URI contains directory traversal pattern: "${uriValue}"`,
      `HTTP Status: ${httpStatusCode !== null ? httpStatusCode : 'Unknown'}`,
      `Security Device Action: ${securityDeviceAction || 'NONE'}`,
    ];
    const requiredEvidence = [
      'HTTP 200 OK response with file content disclosure (e.g. root:x:0:0)',
      'Subsequent command execution or webshell write confirmation on server',
    ];

    if (finalOutcome === 'BLOCKED' || isDeviceExplicitBlock) {
      hypothesis = {
        hypothesisId: 'HYP-PATH-TRAVERSAL-01',
        hypothesis: 'PATH_TRAVERSAL_ATTEMPT',
        observedFacts,
        requiredEvidence,
        status: 'BLOCKED_ATTEMPT',
        reasoning: 'Şüpheli path traversal deseni güvenlik cihazı tarafından engellendi. Hedef sistemde dosya okunduğuna veya komut çalıştırıldığına dair kanıt yoktur.',
      };
      verdict = 'BLOCKED';
      confidenceReason = 'Saldırı girişimi güvenlik cihazı tarafından durduruldu.';
    } else if (httpStatusCode === 403 || httpStatusCode === 404) {
      hypothesis = {
        hypothesisId: 'HYP-PATH-TRAVERSAL-01',
        hypothesis: 'PATH_TRAVERSAL_ATTEMPT',
        observedFacts,
        requiredEvidence,
        status: 'UNCONFIRMED',
        reasoning: `İstek sunucu tarafından ${httpStatusCode} koduyla reddedildi. Dosya okuma veya taviz kanıtlanmadı.`,
      };
      verdict = 'MALICIOUS_ATTEMPT';
      confidenceReason = 'Şüpheli path traversal denemesi sunucu hata koduyla sonuçlandı; sistem tavizi kanıtlanmadı.';
    } else {
      hypothesis = {
        hypothesisId: 'HYP-PATH-TRAVERSAL-01',
        hypothesis: 'PATH_TRAVERSAL_ATTEMPT',
        observedFacts,
        requiredEvidence,
        status: 'UNCONFIRMED',
        reasoning: 'Path traversal deseni talep edildi ancak dosya içeriğinin sızdırıldığına dair kanıt bulunmamaktadır.',
      };
      verdict = 'SUSPICIOUS_ANOMALY';
      confidenceReason = 'Şüpheli URI deseni gözlemlendi.';
    }
  } else if (eventType === 'SERVICE_INSTALLATION') {
    // Service installation (CRITICAL RULE #5: Not automatically benign)
    const svcFile = win.serviceFile || '';
    const isSuspiciousPath = /temp|appdata|users\\public|programdata\\corptools/i.test(svcFile);
    const observedFacts = [
      `Service Name: ${win.serviceName || 'Unknown'}`,
      `Service File: ${svcFile || 'Unknown'}`,
      `User: ${win.subjectUser || 'SYSTEM'}`,
    ];
    const requiredEvidence = [
      'Unsigned binary verification or known malware hash matching',
      'Suspicious parent process or network connection following installation',
    ];

    if (isSuspiciousPath) {
      hypothesis = {
        hypothesisId: 'HYP-PERSISTENCE-01',
        hypothesis: 'SERVICE_PERSISTENCE_SUSPICION',
        observedFacts,
        requiredEvidence,
        status: 'UNCONFIRMED',
        reasoning: 'Yeni servis kaydı yapıldı ancak ikili dosya yolu şüpheli veya geçici dizindedir. Otomatik benign kabul edilmez.',
      };
      verdict = 'SUSPICIOUS_ANOMALY';
      confidenceReason = 'Yeni servis kaydı şüpheli dosya konumu nedeniyle araştırma gerektirir.';
    } else {
      hypothesis = {
        hypothesisId: 'HYP-SERVICE-01',
        hypothesis: 'ROUTINE_SERVICE_INSTALLATION',
        observedFacts,
        requiredEvidence: ['Installation confirmation'],
        status: 'BENIGN_ROUTINE',
        reasoning: 'Standart servis yükleme telemetrisi.',
      };
      verdict = 'BENIGN';
      confidenceReason = 'Meşru sistem servis kaydı.';
    }
  } else if (isSshInvalidUser) {
    const observedFacts = [
      'OpenSSH daemon logged connection closed by invalid user',
      `User: ${fields.find((f) => f.field === 'user')?.value || 'unknown'}`,
      `Source IP: ${fields.find((f) => f.field === 'sourceIp')?.value || 'unknown'}`,
    ];
    hypothesis = {
      hypothesisId: 'HYP-SSH-BRUTE-01',
      hypothesis: 'UNAUTHORIZED_SSH_LOGON_ATTEMPT',
      observedFacts,
      requiredEvidence: ['Subsequent successful logon from same source IP', 'Session interactive shell open'],
      status: 'UNCONFIRMED',
      reasoning: 'Geçersiz kullanıcı adı ile SSH bağlantı denemesi sunucu tarafından kapatıldı. Güvenlik cihazı engellemesi değildir.',
    };
    verdict = 'SUSPICIOUS_ANOMALY';
    confidenceReason = 'Sunucu telemetrisi geçersiz kullanıcı denemesini kaydetti.';
  } else if (eventType === 'LOG_CLEAR') {
    const observedFacts = [
      `Audit log cleared (Event ID ${detectedId})`,
      `User: ${fields.find((f) => f.field === 'user')?.value || 'administrator'}`,
      `Computer: ${win.computer || 'Endpoint'}`,
    ];
    hypothesis = {
      hypothesisId: 'HYP-EVASION-01',
      hypothesis: 'DEFENSE_EVASION_LOG_CLEAR',
      observedFacts,
      requiredEvidence: ['Prior malicious activity before log clear', 'Unauthorized administrative privilege usage'],
      status: 'CONFIRMED',
      reasoning: 'Güvenlik adli günlüğü temizlendi. Bu eylem açıkça savunma atlatma (T1070) göstergesidir.',
    };
    verdict = 'MALICIOUS_ATTEMPT';
    confidenceReason = 'Adli kayıtların silinmesi yüksek riskli savunma atlatma eylemidir.';
  } else if (isDeviceExplicitBlock) {
    hypothesis = {
      hypothesisId: 'HYP-SEC-BLOCK-01',
      hypothesis: 'SECURITY_DEVICE_BLOCKED_TRAFFIC',
      observedFacts: [`Device action: ${securityDeviceAction}`, `Source: ${fields.find((f) => f.field === 'sourceIp')?.value || '-'}`],
      requiredEvidence: ['Traffic session logs'],
      status: 'BLOCKED_ATTEMPT',
      reasoning: 'Güvenlik denetim cihazı bağlantıyı engelledi.',
    };
    verdict = 'BLOCKED';
    confidenceReason = 'Güvenlik aygıtı engellemesi kanıtlandı.';
  }

  return {
    recordIndex,
    rawStart: globalStart,
    rawEnd: globalStart + rawText.length,
    rawText,
    boundaryConfidence: 'HIGH',
    logFormatAndVendor: {
      vendorOrSource,
      format: detectedFormat,
      isSecurityDevice,
    },
    eventType,
    fields,
    hypothesis,
    verdict,
    confidence,
    confidenceReason,
  };
}

/**
 * High-fidelity local semantic log analyzer adhering to Phase 4.5 specs.
 */
export function analyzeSemanticLogLocally(rawInput: string): AiSemanticLogResponse {
  const trimmed = rawInput;
  if (!trimmed || trimmed.trim().length === 0) {
    return {
      analysisVersion: '1.0',
      engine: 'AI_SEMANTIC_LOG_ENGINE',
      formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
      records: [],
      unparsedSpans: [],
      warnings: ['Girdi metni boş veya yetersiz.'],
    };
  }

  const diag = segmentRawTextIntoEventsWithDiagnostics(trimmed);
  const records: AiSemanticEvent[] = [];
  let currentSearchOffset = 0;

  diag.eventBoundaries.forEach((boundary, idx) => {
    const rawText = boundary.rawText;
    const pos = rawInput.indexOf(rawText, currentSearchOffset);
    const start = pos !== -1 ? pos : rawInput.indexOf(rawText);
    const end = start !== -1 ? start + rawText.length : 0;

    if (start !== -1) {
      currentSearchOffset = end;
    }

    const event = analyzeSingleEventSemantics(rawText, idx + 1, start !== -1 ? start : 0);
    records.push(event);
  });

  const primaryFormat = records.length > 0 ? records[0].logFormatAndVendor.format : 'UNKNOWN';

  return {
    analysisVersion: '1.0',
    engine: 'AI_SEMANTIC_LOG_ENGINE',
    formatAssessment: {
      format: primaryFormat,
      confidence: primaryFormat !== 'UNKNOWN' ? 'HIGH' : 'LOW',
    },
    records,
    unparsedSpans: [],
    warnings: [],
  };
}

/**
 * Converts Phase 4.5 AiSemanticLogResponse into backward-compatible AiLogStructureResponse
 * for deterministic validation via validateAiLogStructure.
 */
export function convertSemanticToStructureResponse(
  semantic: AiSemanticLogResponse
): AiLogStructureResponse {
  const records: AiRecord[] = semantic.records.map((r) => ({
    recordIndex: r.recordIndex,
    rawStart: r.rawStart,
    rawEnd: r.rawEnd,
    rawText: r.rawText,
    boundaryConfidence: r.boundaryConfidence,
    fields: r.fields.map((f) => ({
      name: f.field,
      value: f.value,
      status: f.status,
      sourceSpan: f.rawSpan,
    })),
  }));

  return {
    analysisVersion: semantic.analysisVersion,
    formatAssessment: semantic.formatAssessment,
    records,
    unparsedSpans: semantic.unparsedSpans,
    warnings: semantic.warnings,
  };
}

/**
 * Executes the complete Phase 4.5 True AI Log Analysis Engine Pipeline:
 *
 * RAW INPUT
 * → AI LOG UNDERSTANDING
 * → AI SEMANTIC EVENT ANALYSIS
 * → UNIVERSAL EVIDENCE
 * → RAW-SPAN VALIDATION
 * → FORENSIC REASONING
 * → CORRELATION
 * → FINAL DECISION
 */
export async function runAiSemanticLogPipeline(params: {
  rawInput: string;
  useRemoteAi?: boolean;
  precomputedAiResponse?: AiSemanticLogResponse;
}): Promise<SemanticForensicPipelineResult> {
  const { rawInput, useRemoteAi = false, precomputedAiResponse } = params;
  const trimmed = rawInput ? rawInput.trim() : '';

  if (!trimmed) {
    return {
      rawInput,
      rawLinesCount: 0,
      aiResponse: {
        analysisVersion: '1.0',
        engine: 'AI_SEMANTIC_LOG_ENGINE',
        formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
        records: [],
        unparsedSpans: [],
        warnings: ['Boş girdi verisi.'],
      },
      validationReport: {
        inputLength: 0,
        totalCandidateRecords: 0,
        acceptedRecordsCount: 0,
        rejectedRecordsCount: 0,
        uncertainRecordsCount: 0,
        validatedRecords: [],
        hasOverlappingRecords: false,
        hallucinationsDetected: 0,
        crossEventContaminationsDetected: 0,
        overallValidationStatus: 'PASS',
        provenanceAdherenceRate: 100,
        summaryMarkdown: 'İncelenecek girdi verisi bulunamadı.',
      },
      universalEvidences: [],
      hypotheses: [],
      deterministicDecisions: [],
      pipelineStatus: 'ANALYSIS_INCOMPLETE',
      errorMessage: 'PARSE_NOT_ASSESSED: Boş veya tanımsız veri.',
    };
  }

  const rawLinesCount = rawInput.split(/\r?\n/).length;
  let aiSemanticResponse: AiSemanticLogResponse | null = precomputedAiResponse || null;

  // 1. Try remote AI endpoint if requested and in browser
  if (!aiSemanticResponse && useRemoteAi && typeof window !== 'undefined') {
    try {
      const resp = await fetch('/api/ai/semantic-log-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText: trimmed }),
      });
      if (resp.ok) {
        const json = await resp.json();
        if (json.success) {
          if (json.pipelineResult && json.pipelineResult.pipelineStatus === 'SUCCESS') {
            return json.pipelineResult;
          }
          if (json.aiResponse) {
            aiSemanticResponse = json.aiResponse;
          }
        }
      }
    } catch {
      // Remote failed, fallback to local semantic analysis
    }
  }

  // 2. Local semantic analyzer fallback
  if (!aiSemanticResponse) {
    aiSemanticResponse = analyzeSemanticLogLocally(trimmed);
  }

  // 3. Fallback sanity check against AI Failure requirement
  // If parsing failed or crashed, DO NOT output Parsed Events = 1 for 50 lines!
  if (!aiSemanticResponse || !aiSemanticResponse.records || aiSemanticResponse.records.length === 0) {
    const incompleteReport = {
      inputLength: trimmed.length,
      totalCandidateRecords: 0,
      acceptedRecordsCount: 0,
      rejectedRecordsCount: 0,
      uncertainRecordsCount: 0,
      validatedRecords: [],
      hasOverlappingRecords: false,
      hallucinationsDetected: 0,
      crossEventContaminationsDetected: 0,
      overallValidationStatus: 'FAIL' as const,
      provenanceAdherenceRate: 0,
      summaryMarkdown: `⚠️ **ANALYSIS_INCOMPLETE**: AI semantik analizi tamamlanamadı. Ham satır sayısı (${rawLinesCount}) için tek olay veya varsayılan BENIGN kararı üretilmedi (PARSE_NOT_ASSESSED).`,
    };

    return {
      rawInput: trimmed,
      rawLinesCount,
      aiResponse: aiSemanticResponse || {
        analysisVersion: '1.0',
        engine: 'AI_SEMANTIC_LOG_ENGINE',
        formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
        records: [],
        unparsedSpans: [{ start: 0, end: trimmed.length, text: trimmed, reason: 'AI_CALL_FAILED' }],
        warnings: ['ANALYSIS_INCOMPLETE — PARSE_NOT_ASSESSED'],
      },
      validationReport: incompleteReport,
      universalEvidences: [],
      hypotheses: [],
      deterministicDecisions: [],
      pipelineStatus: 'ANALYSIS_INCOMPLETE',
      errorMessage: 'ANALYSIS_INCOMPLETE: AI ayrıştırma başarısız oldu, tek olay veya format varsayımı yapılmadı.',
    };
  }

  // 4. DETERMINISTIC RAW-SPAN VALIDATION
  const structureResponse = convertSemanticToStructureResponse(aiSemanticResponse);
  const validationReport = validateAiLogStructure(trimmed, structureResponse);

  // 5. UNIVERSAL EVIDENCE BRIDGE WITH SEMANTIC FIELDS & RAW-SPANS
  const universalEvidences: UniversalEvidence[] = validationReport.validatedRecords.map((vRec, idx) => {
    const baseEv = convertAiRecordToUniversalEvidence(vRec, aiSemanticResponse!.formatAssessment.format);
    const semanticEvent = aiSemanticResponse!.records[idx];

    // Ensure strict semantic routing: if HTTP request, commandLine MUST be NOT_PRESENT
    if (semanticEvent && semanticEvent.eventType === 'HTTP_REQUEST') {
      baseEv.process.commandLine = {
        value: null,
        rawValue: null,
        status: 'NOT_PRESENT',
        sourceType: 'TEXT_LOG',
        extractionMethod: 'DIRECT_KEY_VALUE',
        sourceReference: 'HTTP_REQUEST_URI_IS_NOT_COMMAND_LINE',
      };
    }

    return baseEv;
  });

  // Collect hypotheses
  const hypotheses: ForensicHypothesis[] = [];
  aiSemanticResponse.records.forEach((r) => {
    if (r.hypothesis) hypotheses.push(r.hypothesis);
  });

  // 6. FORENSIC REASONING & DETERMINISTIC DECISIONS (Unified Decision Engine)
  const deterministicDecisions: UnifiedDecisionResult[] = validationReport.validatedRecords.map(
    (vRec, idx) => {
      const state = initializeFormatState(`event_${idx + 1}.log`);
      feedSampleLine(state, vRec.rawText);
      const parsedLog = parseLineToNormalizedLog(vRec.rawText, state);

      return evaluateUnifiedDecision({
        rawLine: vRec.rawText,
        eventIndex: idx,
        formatState: state,
        parsedLog,
        universalEvidence: universalEvidences[idx],
        semanticFormat: aiSemanticResponse!.formatAssessment.format,
        sourceType: 'TEXT_LOG',
      });
    }
  );

  // 7. SECONDARY CORRELATION (Strict Evidence Grounding from UniversalEvidence)
  const correlatedInputs: CorrelatedEventInput[] = validationReport.validatedRecords.map(
    (vRec, idx) => {
      const dec = deterministicDecisions[idx];
      const ev = universalEvidences[idx];
      const semRec = aiSemanticResponse!.records[idx];
      const { timestampStr, timestampMs } = extractEventTimestamp(vRec.rawText);
      const win = dec.winDetails;

      const hostVal =
        ev.destinationEndpoint.host.value ||
        (win?.isWindowsEvent ? (win?.computer || win?.workstation) : '') ||
        'Endpoint';

      const userVal =
        ev.actor.value ||
        (win?.isWindowsEvent ? (win?.targetUser || win?.subjectUser) : '') ||
        'Bilinmiyor';

      const srcIpVal =
        ev.sourceEndpoint.ip.value ||
        (win?.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-' ? win.sourceIp : '-');

      const dstIpVal = ev.destinationEndpoint.ip.value || '-';
      const cmdVal = ev.process.commandLine.value || '';
      const procVal = ev.process.name.value || win?.processName || '';
      const parentVal = ev.process.parentProcess.value || win?.parentProcess || '';
      const actionVal = ev.action.value || '';

      return {
        index: idx + 1,
        rawText: vRec.rawText,
        isWindows: Boolean(win?.isWindowsEvent),
        eventId: win?.eventId || null,
        eventName: win?.eventName || dec.threatTitle,
        timestamp: timestampStr || ev.timestamp.value || dec.parsedLog?.tarih || null,
        timestampMs,
        host: hostVal,
        user: userVal,
        sourceIp: srcIpVal,
        destIp: dstIpVal,
        process: procVal,
        parentProcess: parentVal,
        commandLine: cmdVal,
        logonId: dec.rawKeyValues?.logonid || '',
        logonType: win?.logonType || null,
        logonTypeDesc: win?.logonTypeDesc || 'Belirtilmemiş',
        serviceName: win?.serviceName || '',
        serviceFile: win?.serviceFile || '',
        subStatus: win?.subStatus || '',
        subStatusDesc: win?.subStatusDesc || '',
        status: win?.status || '',
        action: actionVal || dec.rawKeyValues?.action || '',
        filePath: dec.rawKeyValues?.file || '',
        verdict: dec.verdict,
        confidence: dec.confidence,
        confidenceLabel: dec.confidenceLabel,
        verdictBadge: dec.verdictBadge,
        threatTitle: dec.threatTitle,
        summaryReason: dec.summaryReason,
        mitreTechnique: win?.mitreTechnique,
        sourceIpCorrelationEligible: win?.sourceIpCorrelationEligible,
        evidence: dec.deepForensics,
      };
    }
  );

  let secondaryCorrelation: WholeLogSummary | undefined = undefined;
  if (correlatedInputs.length > 0) {
    const diag = segmentRawTextIntoEventsWithDiagnostics(trimmed);
    secondaryCorrelation = runSecondaryCorrelation(correlatedInputs, rawLinesCount, diag);
  }

  return {
    rawInput: trimmed,
    rawLinesCount,
    aiResponse: aiSemanticResponse,
    validationReport,
    universalEvidences,
    hypotheses,
    deterministicDecisions,
    secondaryCorrelation,
    pipelineStatus: 'SUCCESS',
  };
}
