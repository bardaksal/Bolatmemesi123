import {
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
} from './streamingParser';
import { RawLogTriageSummary } from '../types';
import {
  extractWindowsDetails,
  splitRawTextIntoEvents,
  segmentRawTextIntoEventsWithDiagnostics,
  ParserDiagnosticReport,
} from './quickTriageHelper';
import {
  evaluateUnifiedDecision,
  UnifiedDecisionResult,
  ForensicVerdict,
} from './unifiedDecisionEngine';
import {
  CorrelatedEventInput,
  WholeLogSummary,
  runSecondaryCorrelation,
  generateComprehensive6StageReport,
  extractEventTimestamp,
} from './socCorrelationEngine';

export type { ForensicVerdict };
export type QuickAnalysisResult = UnifiedDecisionResult;

export interface QuickLogTriageResult {
  file: File;
  triageSummary: RawLogTriageSummary;
  analysisResults: QuickAnalysisResult[];
  correlatedEvents: CorrelatedEventInput[];
  wholeLogSummary: WholeLogSummary;
  comprehensive6StageReport: string;
  totalEvents?: number;
  eventsCount: number;
  rawLinesCount: number;
  parsedRecordsCount: number;
  normalizedEventsCount: number;
  incidentsCount: number;
  uncorrelatedEventsCount: number;
  parserDiagnostic?: ParserDiagnosticReport;
}

/**
 * Analyzes raw pasted log text (single or multi-line / multi-event) with forensic rigor,
 * clusters correlated incidents, and prepares a ready-to-import File + RawLogTriageSummary.
 */
export function analyzeRawLogText(rawText: string): QuickLogTriageResult | null {
  const trimmed = rawText.trim();
  if (!trimmed) return null;

  const rawLinesCount = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
  const diag = segmentRawTextIntoEventsWithDiagnostics(trimmed);
  const lines = diag.eventBoundaries.map((e) => e.rawText);
  if (lines.length === 0) return null;

  // 1. First pass: parse each line in strict isolation
  const parsedEvents = lines.map((line, idx) => {
    const state = initializeFormatState(`pasted_log_${idx + 1}.log`);
    feedSampleLine(state, line);
    const parsed = parseLineToNormalizedLog(line, state);

    // Extract raw key-values strictly for this event
    const kvRegex = /([a-zA-Z0-9_\-\.]+)=(".*?"|\S+)/g;
    const kvDict: Record<string, string> = {};
    let match: RegExpExecArray | null;
    while ((match = kvRegex.exec(line)) !== null) {
      const k = match[1].toLowerCase();
      let v = match[2];
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      kvDict[k] = v;
    }

    // Check Windows details strictly from this event line
    const winDetails = extractWindowsDetails(line, kvDict, parsed);
    return { line, idx, state, parsed, kvDict, winDetails };
  });

  // 2. Collect unpolluted Windows details for cross-event correlation tracking
  const allWinDetails = parsedEvents.map((p) => p.winDetails);

  // 3. Evaluate unified forensic decisions through the central engine
  const analysisResults: QuickAnalysisResult[] = parsedEvents.map(({ line, idx, state, parsed }) => {
    return evaluateUnifiedDecision({
      rawLine: line,
      eventIndex: idx,
      formatState: state,
      parsedLog: parsed,
      allWinDetails,
      sourceType: 'TEXT_LOG',
    });
  });

  // Build correlated event inputs for secondary correlation engine
  const correlatedEvents: CorrelatedEventInput[] = analysisResults.map((res, idx) => {
    const line = lines[idx] || '';
    const { timestampStr, timestampMs } = extractEventTimestamp(line);
    const isWin = Boolean(res.winDetails?.isWindowsEvent);
    const win = res.winDetails;

    const host = isWin
      ? (win?.computer || win?.workstation || '')
      : (res.rawKeyValues?.http_host || res.parsedLog?.sunucu_ismi || res.rawKeyValues?.host || '');

    const user = isWin
      ? ((win?.eventId === 4688 || win?.eventId === 1)
          ? (win?.subjectUser || win?.targetUser || '')
          : (win?.targetUser || win?.subjectUser || ''))
      : (res.parsedLog?.kullanici_adi || res.rawKeyValues?.user || res.rawKeyValues?.username || '');

    const srcIp = isWin
      ? (win?.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-' ? win.sourceIp : '-')
      : (res.parsedLog?.ip_adresi || res.rawKeyValues?.src || res.rawKeyValues?.srcip || '-');

    const destIp = isWin
      ? '-'
      : (res.parsedLog?.hedef_ip || res.rawKeyValues?.dst || res.rawKeyValues?.dstip || '-');

    return {
      index: idx + 1,
      rawText: line,
      isWindows: isWin,
      eventId: win?.eventId || null,
      eventName: win?.eventName || res.threatTitle,
      timestamp: timestampStr || res.parsedLog?.tarih || null,
      timestampMs,
      host: host || (isWin ? 'Windows Endpoint' : 'Bilinmiyor'),
      user: user || 'Bilinmiyor',
      sourceIp: srcIp,
      destIp: destIp,
      process: win?.processName || res.rawKeyValues?.process || '',
      parentProcess: win?.parentProcess || res.rawKeyValues?.parentprocess || '',
      commandLine: win?.commandLine || res.parsedLog?.islem_komutu || '',
      logonId: res.rawKeyValues?.logonid || '',
      logonType: win?.logonType || null,
      logonTypeDesc: win?.logonTypeDesc || 'Belirtilmemiş',
      serviceName: win?.serviceName || '',
      serviceFile: win?.serviceFile || '',
      subStatus: win?.subStatus || '',
      subStatusDesc: win?.subStatusDesc || '',
      status: win?.status || '',
      action:
        res.rawKeyValues?.action ||
        res.rawKeyValues?.act ||
        res.rawKeyValues?.device_action ||
        res.rawKeyValues?.waf_action ||
        res.rawKeyValues?.disposition ||
        (res.parsedLog?.baglanti_karari === 'DENY' || res.parsedLog?.baglanti_karari === 'ACCEPT'
          ? res.parsedLog.baglanti_karari
          : ''),
      filePath: res.rawKeyValues?.filepath || res.rawKeyValues?.file || '',
      verdict: res.verdict,
      confidence: res.confidence,
      confidenceLabel: res.confidenceLabel,
      verdictBadge: res.verdictBadge,
      threatTitle: res.threatTitle,
      summaryReason: res.summaryReason,
      mitreTechnique: win?.mitreTechnique,
      sourceIpCorrelationEligible: win?.sourceIpCorrelationEligible,
      evidence: res.deepForensics,
    };
  });

  const wholeLogSummary = runSecondaryCorrelation(correlatedEvents, rawLinesCount, diag);
  const comprehensive6StageReport = generateComprehensive6StageReport(
    correlatedEvents,
    wholeLogSummary,
    lines.length > 1 ? `${lines.length} Olaylık Çoklu Log Dosyası` : 'Münferit Log Olayı',
    diag
  );

  const blob = new Blob([trimmed], { type: 'text/plain;charset=utf-8' });
  const file = new File([blob], 'pasted_customer_logs.log', { type: 'text/plain' });

  const triageSummary: RawLogTriageSummary = {
    pastedAt: new Date().toISOString(),
    totalEvents: lines.length,
    overallPosture: wholeLogSummary.overallPosture,
    postureTitle: wholeLogSummary.postureTitle,
    evidenceBasedSummary: wholeLogSummary.evidenceBasedSummary,
    incidentCandidatesCount: wholeLogSummary.incidentCandidates.length,
    overallFindings: wholeLogSummary.overallFindings,
    analystActions: wholeLogSummary.analystActions,
    fullReportText: comprehensive6StageReport,
    rawText: trimmed,
  };

  return {
    file,
    triageSummary,
    analysisResults,
    correlatedEvents,
    wholeLogSummary,
    comprehensive6StageReport,
    totalEvents: lines.length,
    eventsCount: lines.length,
    rawLinesCount,
    parsedRecordsCount: lines.length,
    normalizedEventsCount: correlatedEvents.length,
    incidentsCount: wholeLogSummary.incidentCandidates.length,
    uncorrelatedEventsCount: wholeLogSummary.uncorrelatedEventsCount,
    parserDiagnostic: diag,
  };
}
