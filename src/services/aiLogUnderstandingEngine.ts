import {
  AiLogStructureResponse,
  AiRecord,
  AiField,
  FullLogUnderstandingPipelineResult,
  FormatAssessment,
} from '../types/aiLogUnderstanding';
import { validateAiLogStructure } from './rawSpanValidator';
import { convertAiRecordToUniversalEvidence } from './aiRecordToEvidence';
import { evaluateUnifiedDecision, UnifiedDecisionResult } from './unifiedDecisionEngine';
import { runSecondaryCorrelation, WholeLogSummary, CorrelatedEventInput, extractEventTimestamp } from './socCorrelationEngine';
import { initializeFormatState, feedSampleLine, parseLineToNormalizedLog } from './streamingParser';
import { segmentRawTextIntoEventsWithDiagnostics, extractWindowsDetails } from './quickTriageHelper';

/**
 * PHASE 4 — AI SYSTEM PROMPT SPECIFICATION
 * Strict boundaries: Event structure, field semantics, observed facts, raw spans.
 * Zero security verdicts (ATTACK / SAFE / MALICIOUS / BENIGN).
 */
export const AI_LOG_UNDERSTANDING_SYSTEM_PROMPT = `Sen bir AI Adli Log Anlamlandırma Motorusun (AI Forensic Log Understanding Engine).
GÖREVİN:
Sisteme gelen herhangi bir log veya veri akışının yapısını anlamak, mantıksal olay sınırlarını (event boundaries) belirlemek, alan semantiklerini (field semantics) ve gözlemlenen olguları (observed facts) tam raw-span referanslarıyla çıkarmaktır.

KESİN GÜVENLİK SINIRI:
1. Sen SALDIRI KARARI VERMEYECEKSİN.
2. Kesinlikle şu hükümleri veya benzerlerini doğrudan ÜRETME: "ATTACK", "SAFE", "MALICIOUS", "BENIGN", "COMPROMISED", "BRUTE_FORCE", "CREDENTIAL_SPRAYING".
3. Güvenlik ve tehdit kararı senin çıktın üzerinden deterministik forensic motoru tarafından verilecektir.
4. Senin görevin yalnızca: RAW LOG → EVENT STRUCTURE → FIELD SEMANTICS → OBSERVED FACTS çıkarmaktır.

RAW SPAN ZORUNLULUĞU & HALÜSİNASYON YASAĞI:
1. Her logical record için gerçek rawStart ve rawEnd (karakter indisleri) belirtilmelidir.
2. rawText, verilen girdi içindeki slice([rawStart, rawEnd]) ile birebir eşleşmelidir.
3. Çıkardığın her alan (field) için o alanın değeri ("value") ilgili event'in rawText'inde GERÇEKTEN bulunmalıdır.
4. Başka bir olaydan değer taşımak (cross-event contamination) KESİNLİKLE YASAKTIR.
5. Eğer bir alan logda yoksa (örn: ParentImage verilmemişse), DEĞER UYDURMA; status: "NOT_PRESENT" veya "NOT_ASSESSED" olarak işaretle.

BİLİNMEYEN FORMATLAR:
1. Formatı tanımıyorsan formatAssessment.format = "UNKNOWN" yazabilirsin.
2. UNKNOWN FORMAT ≠ NON-SECURITY, UNKNOWN FORMAT ≠ ATTACK.
3. Format bilinmese dahi logical event boundaries ve alanlar çıkarılmalıdır.

ÇIKTI SÖZLEŞMESİ (JSON):
Yalnızca aşağıdaki JSON şemasını döndür:
{
  "analysisVersion": "1.0",
  "formatAssessment": {
    "format": "Windows Security | Sysmon | Linux auth | Apache | Nginx | IIS | CEF | LEEF | JSON | key=value | plain text | application logs | UNKNOWN",
    "confidence": "HIGH | MEDIUM | LOW | UNKNOWN"
  },
  "records": [
    {
      "recordIndex": 1,
      "rawStart": 0,
      "rawEnd": 120,
      "rawText": "...",
      "boundaryConfidence": "HIGH | MEDIUM | LOW",
      "fields": [
        {
          "name": "user | host | sourceIp | destinationIp | process | parentProcess | commandLine | action | outcome | status | eventId | timestamp",
          "value": "...",
          "status": "OBSERVED | DERIVED | UNCERTAIN | NOT_PRESENT | NOT_ASSESSED",
          "sourceSpan": { "start": 10, "end": 22 }
        }
      ]
    }
  ],
  "unparsedSpans": [],
  "warnings": []
}`;

/**
 * Intelligent structure analyzer fallback:
 * Emulates the exact AI log understanding contract with zero hallucinations and accurate spans.
 * Used when running offline, in automated test environments, or when the server model call is unavailable.
 */
export function analyzeLogStructureLocally(rawInput: string): AiLogStructureResponse {
  const trimmed = rawInput;
  if (!trimmed || trimmed.trim().length === 0) {
    return {
      analysisVersion: '1.0',
      formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
      records: [],
      unparsedSpans: [],
      warnings: ['Girdi metni boş veya yetersiz.'],
    };
  }

  // 1. Detect format classification
  const lower = trimmed.slice(0, 5000).toLowerCase();
  let detectedFormat = 'UNKNOWN';
  let formatConfidence: FormatAssessment['confidence'] = 'MEDIUM';

  if (trimmed.includes('<Event') && trimmed.includes('</Event>')) {
    detectedFormat = 'Windows Event XML';
    formatConfidence = 'HIGH';
  } else if (/Microsoft-Windows-Sysmon|Sysmon:/i.test(trimmed)) {
    detectedFormat = 'Sysmon';
    formatConfidence = 'HIGH';
  } else if (/Microsoft-Windows-Security-Auditing|Log Name:\s*Security/i.test(trimmed)) {
    detectedFormat = 'Windows Security';
    formatConfidence = 'HIGH';
  } else if (/sshd\[\d+\]|sudo:|pam_unix/i.test(trimmed)) {
    detectedFormat = 'Linux auth';
    formatConfidence = 'HIGH';
  } else if (/^CEF:\d+/im.test(trimmed)) {
    detectedFormat = 'CEF';
    formatConfidence = 'HIGH';
  } else if (/^LEEF:\d+/im.test(trimmed)) {
    detectedFormat = 'LEEF';
    formatConfidence = 'HIGH';
  } else if (trimmed.trim().startsWith('{') && trimmed.trim().endsWith('}')) {
    detectedFormat = 'JSON';
    formatConfidence = 'HIGH';
  } else if (/\bGET\s+\/[^\s]*\s+HTTP\/|\bPOST\s+\/[^\s]*\s+HTTP\//i.test(trimmed)) {
    if (lower.includes('iis') || lower.includes('w3c') || lower.includes('cs-method')) {
      detectedFormat = 'IIS W3C';
    } else if (lower.includes('nginx')) {
      detectedFormat = 'Nginx';
    } else {
      detectedFormat = 'Apache';
    }
    formatConfidence = 'HIGH';
  } else if (/\b[a-zA-Z0-9_\-\.]+=[^\s]+/i.test(trimmed)) {
    detectedFormat = 'key=value';
    formatConfidence = 'HIGH';
  } else if (trimmed.includes('\n\tat ') || trimmed.includes('Exception:') || trimmed.includes('Traceback (most recent call last):')) {
    detectedFormat = 'application logs';
    formatConfidence = 'HIGH';
  }

  // 2. Discover Logical Event Boundaries and Spans
  const diag = segmentRawTextIntoEventsWithDiagnostics(trimmed);
  const records: AiRecord[] = [];
  const unparsedSpans: AiLogStructureResponse['unparsedSpans'] = [];

  // Track raw positions in original rawInput string
  let currentSearchOffset = 0;

  diag.eventBoundaries.forEach((boundary, idx) => {
    const rawText = boundary.rawText;
    const pos = rawInput.indexOf(rawText, currentSearchOffset);
    const start = pos !== -1 ? pos : rawInput.indexOf(rawText);
    const end = start !== -1 ? start + rawText.length : 0;

    if (start !== -1) {
      currentSearchOffset = end;
    }

    // Extract fields strictly present in rawText
    const fields: AiField[] = [];

    // Helper to safely add an OBSERVED field with verified span
    const addObservedField = (name: string, val: string | null | undefined) => {
      if (!val || val === '-' || val === 'Bilinmiyor') return;
      const cleanVal = String(val).trim();
      if (!cleanVal) return;
      const fPos = rawText.indexOf(cleanVal);
      if (fPos !== -1) {
        fields.push({
          name,
          value: cleanVal,
          status: 'OBSERVED',
          sourceSpan: {
            start: fPos,
            end: fPos + cleanVal.length,
          },
        });
      }
    };

    // Helper for DERIVED field
    const addDerivedField = (name: string, val: string) => {
      fields.push({
        name,
        value: val,
        status: 'DERIVED',
      });
    };

    // Helper for NOT_PRESENT field
    const addNotPresentField = (name: string) => {
      fields.push({
        name,
        value: '',
        status: 'NOT_PRESENT',
      });
    };

    // Parse strictly from this record's rawText (zero cross-event bleed)
    // 1. JSON if structured
    let parsedJson: any = null;
    if (rawText.startsWith('{') && rawText.endsWith('}')) {
      try {
        parsedJson = JSON.parse(rawText);
        for (const [k, v] of Object.entries(parsedJson)) {
          if (v !== null && v !== undefined && typeof v !== 'object') {
            addObservedField(k, String(v));
          }
        }
      } catch {}
    }

    // 2. Key-Value pairs
    const kvRegex = /([a-zA-Z0-9_\-\.]+)=(".*?"|[^\s\t\r\n,]+)/g;
    let match: RegExpExecArray | null;
    const localKv: Record<string, string> = {};
    while ((match = kvRegex.exec(rawText)) !== null) {
      const k = match[1].toLowerCase();
      let v = match[2];
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      localKv[k] = v;
      addObservedField(match[1], v);
    }

    // 3. Windows details if Windows or Sysmon
    const win = extractWindowsDetails(rawText, localKv, null);

    if (win.eventId) {
      addObservedField('eventId', String(win.eventId));
      if (win.eventName) addDerivedField('eventName', win.eventName);
    }
    if (win.targetUser && win.targetUser !== 'BILINMEYEN-USER') {
      addObservedField('user', win.targetUser);
    }
    if (win.subjectUser) {
      addObservedField('subjectUser', win.subjectUser);
    }
    if (win.workstation && win.workstation !== 'BILINMEYEN-WORKSTATION') {
      addObservedField('workstation', win.workstation);
    }
    if (win.computer && win.computer !== 'BILINMEYEN-HOST') {
      addObservedField('host', win.computer);
    }
    if (win.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-') {
      addObservedField('sourceIp', win.sourceIp);
    }
    if (win.sourcePort) {
      addObservedField('sourcePort', String(win.sourcePort));
    }
    if (win.processName) {
      addObservedField('process', win.processName);
    }
    if (win.commandLine) {
      addObservedField('commandLine', win.commandLine);
    }
    if (win.parentProcess) {
      addObservedField('parentProcess', win.parentProcess);
    } else {
      addNotPresentField('parentProcess');
    }
    if (win.subStatus) {
      addObservedField('subStatus', win.subStatus);
    }
    if (win.logonType) {
      addObservedField('logonType', String(win.logonType));
    }
    if (win.serviceName) {
      addObservedField('serviceName', win.serviceName);
    }
    if (win.serviceFile) {
      addObservedField('serviceFile', win.serviceFile);
    }

    // 4. Linux auth / syslog patterns (sshd, sudo)
    if (detectedFormat === 'Linux auth' || rawText.includes('sshd') || rawText.includes('sudo:')) {
      const sshUser = rawText.match(/(?:for|user)\s+(?:invalid user\s+)?([a-zA-Z0-9_\-\.]+)\s+from\s+([0-9\.]+)/i);
      if (sshUser) {
        addObservedField('user', sshUser[1]);
        addObservedField('sourceIp', sshUser[2]);
      }
      const sudoUser = rawText.match(/\bsudo:\s*([a-zA-Z0-9_\-\.]+)\s*:/i);
      if (sudoUser) {
        addObservedField('user', sudoUser[1]);
      }
      const sudoCmd = rawText.match(/COMMAND=(.*)$/i);
      if (sudoCmd) {
        addObservedField('commandLine', sudoCmd[1].trim());
      }
      if (/failed password|authentication failure|invalid user/i.test(rawText)) {
        addDerivedField('outcome', 'FAILURE');
      } else if (/accepted password|session opened/i.test(rawText)) {
        addDerivedField('outcome', 'SUCCESS');
      }
    }

    // 4.5. Syslog / daemon prefix host & service extraction
    // e.g. "web-03 nginx: ...", "srv-prod sshd[18422]: ...", "mail-gw postfix/smtpd[28114]: ..."
    const syslogPrefixMatch = rawText.match(/^(?:[a-zA-Z]{3}\s+\d+\s+\d+:\d+:\d+\s+)?([a-zA-Z0-9_\-\.]+)\s+([a-zA-Z0-9_\-\/]+)(?:\[\d+\])?:\s*/);
    if (syslogPrefixMatch) {
      const candidateHost = syslogPrefixMatch[1];
      const candidateService = syslogPrefixMatch[2];
      const nonHostPrefixes = ['microsoft-windows-security-auditing', 'microsoft-windows-sysmon', 'cef', 'leef'];
      if (!nonHostPrefixes.includes(candidateHost.toLowerCase()) && !fields.some((f) => f.name === 'host')) {
        addObservedField('host', candidateHost);
      }
      if (!fields.some((f) => f.name === 'serviceName' || f.name === 'process')) {
        addObservedField('serviceName', candidateService);
      }
    }

    // 5. Web server patterns (Apache / Nginx / IIS)
    const httpReqMatch = rawText.match(/"?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)\s+HTTP\/([0-9\.]+)/i);
    if (httpReqMatch) {
      addObservedField('httpMethod', httpReqMatch[1]);
      addObservedField('rawPayload', httpReqMatch[2]);
      addObservedField('protocol', `HTTP/${httpReqMatch[3]}`);
    }

    const webIpMatch = rawText.match(/(?:^|:\s*)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+(?:-\s+)?(?:-\s+)?\[/);
    if (webIpMatch && !fields.some((f) => f.name === 'sourceIp')) {
      addObservedField('sourceIp', webIpMatch[1]);
    } else {
      const ipMatch = rawText.match(/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);
      if (ipMatch && !fields.some((f) => f.name === 'sourceIp')) {
        addObservedField('sourceIp', ipMatch[1]);
      }
    }

    const statusMatch = rawText.match(/"\s+(\d{3})\s+(\d+|-)/);
    if (statusMatch) {
      addObservedField('httpStatus', statusMatch[1]);
      const code = parseInt(statusMatch[1], 10);
      if (code >= 200 && code < 300) addDerivedField('outcome', 'SUCCESS');
      else if (code >= 400) addDerivedField('outcome', 'FAILURE');
    }

    // 6. Action check
    const actionMatch = rawText.match(/\b(blocked|block|drop|deny|reject|allowed|allow|alert|reset)\b/i);
    if (actionMatch && !fields.some((f) => f.name === 'action')) {
      addObservedField('action', actionMatch[1]);
    }

    // 7. Timestamp extraction
    const { timestampStr } = extractEventTimestamp(rawText);
    if (timestampStr) {
      addObservedField('timestamp', timestampStr);
    }

    records.push({
      recordIndex: idx + 1,
      rawStart: start !== -1 ? start : 0,
      rawEnd: end !== -1 ? end : rawText.length,
      rawText,
      boundaryConfidence: boundary.hasCrossEventContamination ? 'LOW' : 'HIGH',
      fields,
    });
  });

  return {
    analysisVersion: '1.0',
    formatAssessment: {
      format: detectedFormat,
      confidence: formatConfidence,
    },
    records,
    unparsedSpans,
    warnings: [],
  };
}

/**
 * Executes the complete 7-stage Phase 4 Pipeline:
 * RAW INPUT
 * ↓
 * AI LOG UNDERSTANDING
 * ↓
 * STRUCTURED EVENT CANDIDATES
 * ↓
 * RAW-SPAN VALIDATION
 * ↓
 * UNIVERSAL EVIDENCE
 * ↓
 * DETERMINISTIC FORENSIC ANALYSIS
 * ↓
 * CORRELATION
 * ↓
 * FINAL DECISION
 */
export async function runAiLogUnderstandingPipeline(params: {
  rawInput: string;
  useRemoteAi?: boolean;
}): Promise<FullLogUnderstandingPipelineResult> {
  const { rawInput, useRemoteAi = false } = params;
  const trimmed = rawInput ? rawInput.trim() : '';

  if (!trimmed) {
    return {
      rawInput,
      rawLinesCount: 0,
      aiResponse: {
        analysisVersion: '1.0',
        formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
        records: [],
        unparsedSpans: [],
        warnings: ['Boş girdi metni.'],
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
      deterministicDecisions: [],
      pipelineStatus: 'ANALYSIS_INCOMPLETE',
      errorMessage: 'PARSE_NOT_ASSESSED: Boş veya tanımsız veri.',
    };
  }

  const rawLinesCount = rawInput.split(/\r?\n/).length;

  let aiResponse: AiLogStructureResponse | null = null;

  // 1. Try remote AI endpoint if requested and in browser
  if (useRemoteAi && typeof window !== 'undefined') {
    try {
      const resp = await fetch('/api/ai/understand-log-structure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText: trimmed }),
      });
      if (resp.ok) {
        const json = await resp.json();
        if (json.success && json.aiResponse) {
          aiResponse = json.aiResponse;
        }
      }
    } catch {
      // remote failed, fall back safely
    }
  }

  // 2. Use local structure understanding if remote not available or in test environment
  if (!aiResponse) {
    aiResponse = analyzeLogStructureLocally(trimmed);
  }

  // 3. Fallback sanity check against AI Failure requirement (Section 13)
  // If parsing failed or crashed, DO NOT output Parsed Events = 1 for 50 lines!
  if (!aiResponse || !aiResponse.records || aiResponse.records.length === 0) {
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
      summaryMarkdown: `⚠️ **ANALYSIS_INCOMPLETE**: AI yapı analizi tamamlanamadı. Ham satır sayısı (${rawLinesCount}) için deterministik olay sayısı değerlendirilmedi (PARSE_NOT_ASSESSED).`,
    };

    return {
      rawInput: trimmed,
      rawLinesCount,
      aiResponse: aiResponse || {
        analysisVersion: '1.0',
        formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
        records: [],
        unparsedSpans: [{ start: 0, end: trimmed.length, text: trimmed, reason: 'AI_CALL_FAILED' }],
        warnings: ['ANALYSIS_INCOMPLETE — PARSE_NOT_ASSESSED'],
      },
      validationReport: incompleteReport,
      universalEvidences: [],
      deterministicDecisions: [],
      pipelineStatus: 'ANALYSIS_INCOMPLETE',
      errorMessage: 'ANALYSIS_INCOMPLETE: AI ayrıştırma başarısız oldu, tek olay varsayımı yapılmadı.',
    };
  }

  // 4. DETERMINISTIC RAW-SPAN VALIDATION
  const validationReport = validateAiLogStructure(trimmed, aiResponse);

  // 5. UNIVERSAL EVIDENCE BRIDGE
  const universalEvidences = validationReport.validatedRecords.map((vRec) => {
    return convertAiRecordToUniversalEvidence(vRec, aiResponse!.formatAssessment.format);
  });

  // 6. DETERMINISTIC FORENSIC ANALYSIS (evaluateUnifiedDecision)
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
        semanticFormat: aiResponse!.formatAssessment.format,
        sourceType: 'TEXT_LOG',
      });
    }
  );

  // 7. SECONDARY CORRELATION (Strict Evidence Grounding from UniversalEvidence)
  const correlatedInputs: CorrelatedEventInput[] = validationReport.validatedRecords.map(
    (vRec, idx) => {
      const dec = deterministicDecisions[idx];
      const ev = universalEvidences[idx];
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
    aiResponse,
    validationReport,
    universalEvidences,
    deterministicDecisions,
    secondaryCorrelation,
    pipelineStatus: 'SUCCESS',
  };
}
