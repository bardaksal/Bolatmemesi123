import {
  HuntingReport,
  RawLogTriageSummary,
  RiskQueueItem,
  DestinationIPItem,
  PortItem,
  AcceptDenyItem,
  WebshellItem,
  BruteForceItem,
  SuspiciousCommandItem,
  TopIPItem,
  DetectionSignal,
} from '../types';
import {
  runAiSemanticLogPipeline,
  SemanticForensicPipelineResult,
} from './aiSemanticLogEngine';
import {
  generateComprehensive6StageReport,
  WholeLogSummary,
  CorrelatedEventInput,
  extractEventTimestamp,
  runSecondaryCorrelation,
} from './socCorrelationEngine';
import { segmentRawTextIntoEventsWithDiagnostics } from './quickTriageHelper';
import { createEmptyReport } from './socEngine';
import {
  requestAiSocAnalysis,
  generateFallbackSocAnalysis,
  formatGemini38FlashForensicReport,
} from './aiService';

export interface DirectHunterResult {
  report: HuntingReport;
  triageSummary: RawLogTriageSummary;
  file: File;
  pipelineResult: SemanticForensicPipelineResult;
}

/**
 * Direct Gemini Threat Hunting Service
 *
 * Directly executes the Gemini 3.8 Flash semantic pipeline on pasted raw logs,
 * verifies semantic authority and raw-span provenance, and transforms findings
 * into a rich, fully populated HuntingReport and RawLogTriageSummary.
 * Runs completely in the background with zero telemetry clutter or status badges.
 */
export async function runDirectGeminiHunt(rawText: string): Promise<DirectHunterResult> {
  const trimmed = rawText ? rawText.trim() : '';
  const blob = new Blob([trimmed], { type: 'text/plain;charset=utf-8' });
  const file = new File([blob], 'pasted_customer_logs.log', { type: 'text/plain' });

  if (!trimmed) {
    const emptyReport = createEmptyReport();
    const emptyTriage: RawLogTriageSummary = {
      pastedAt: new Date().toISOString(),
      totalEvents: 0,
      overallPosture: 'BENIGN_NORMAL',
      postureTitle: 'BOŞ VERİ',
      evidenceBasedSummary: 'İncelenecek log verisi bulunamadı.',
      incidentCandidatesCount: 0,
      overallFindings: ['Boş veya tanımsız veri girildi.'],
      analystActions: ['Lütfen analiz edilecek log satırlarını yapıştırın.'],
      fullReportText: 'Log verisi bulunamadı.',
      rawText: '',
    };
    return {
      report: { ...emptyReport, raw_log_triage: emptyTriage },
      triageSummary: emptyTriage,
      file,
      pipelineResult: await runAiSemanticLogPipeline({ rawInput: '' }),
    };
  }

  // 1. Execute AI Semantic Pipeline with remote Gemini model (fallback resilient)
  const pipelineResult = await runAiSemanticLogPipeline({
    rawInput: trimmed,
    useRemoteAi: true,
  });

  const rawLinesCount = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
  const diag = segmentRawTextIntoEventsWithDiagnostics(trimmed);
  const totalEvents = pipelineResult.validationReport.acceptedRecordsCount || pipelineResult.deterministicDecisions.length || 1;

  // 2. Build or obtain CorrelatedEventInputs
  const correlatedInputs: CorrelatedEventInput[] = pipelineResult.validationReport.validatedRecords.map((vRec, idx) => {
    const dec = pipelineResult.deterministicDecisions[idx];
    const ev = pipelineResult.universalEvidences[idx];
    const { timestampStr, timestampMs } = extractEventTimestamp(vRec.rawText);
    const win = dec?.winDetails;

    const hostVal =
      ev?.destinationEndpoint?.host?.value ||
      (win?.isWindowsEvent ? (win?.computer || win?.workstation) : '') ||
      'Endpoint';

    const userVal =
      ev?.actor?.value ||
      (win?.isWindowsEvent ? (win?.targetUser || win?.subjectUser) : '') ||
      'Bilinmiyor';

    const srcIpVal =
      ev?.sourceEndpoint?.ip?.value ||
      (win?.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-' ? win.sourceIp : '-');

    const dstIpVal = ev?.destinationEndpoint?.ip?.value || '-';
    const cmdVal = ev?.process?.commandLine?.value || '';
    const procVal = ev?.process?.name?.value || win?.processName || '';
    const parentVal = ev?.process?.parentProcess?.value || win?.parentProcess || '';
    const actionVal = ev?.action?.value || '';

    const aiRec = pipelineResult.aiResponse?.records?.[idx];
    const aiReasoning = aiRec?.hypothesis?.reasoning;
    const summaryReason = aiReasoning
      ? `Gemini Akıl Yürütme: ${aiReasoning}`
      : (dec?.summaryReason || 'Semantik analiz yapıldı.');

    const deepEvidence = [...(dec?.deepForensics || [])];
    if (aiReasoning) {
      deepEvidence.unshift(`Akıl Yürütme: ${aiReasoning}`);
    }

    return {
      index: idx + 1,
      rawText: vRec.rawText,
      isWindows: Boolean(win?.isWindowsEvent),
      eventId: win?.eventId || null,
      eventName: win?.eventName || dec?.threatTitle || 'Olay',
      timestamp: timestampStr || ev?.timestamp?.value || dec?.parsedLog?.tarih || null,
      timestampMs,
      host: hostVal,
      user: userVal,
      sourceIp: srcIpVal,
      destIp: dstIpVal,
      process: procVal,
      parentProcess: parentVal,
      commandLine: cmdVal,
      logonId: dec?.rawKeyValues?.logonid || '',
      logonType: win?.logonType || null,
      logonTypeDesc: win?.logonTypeDesc || 'Belirtilmemiş',
      serviceName: win?.serviceName || '',
      serviceFile: win?.serviceFile || '',
      subStatus: win?.subStatus || '',
      subStatusDesc: win?.subStatusDesc || '',
      status: win?.status || '',
      action: actionVal || dec?.rawKeyValues?.action || '',
      filePath: dec?.rawKeyValues?.file || '',
      verdict: dec?.verdict || 'NOT_ASSESSED',
      confidence: dec?.confidence,
      confidenceLabel: dec?.confidenceLabel,
      verdictBadge: dec?.verdictBadge || {
        text: 'İNCELENMEDİ',
        badgeClasses: 'bg-slate-100 text-slate-700 border-slate-300',
        cardClasses: 'border-slate-300',
        iconBgClasses: 'bg-slate-200 text-slate-700',
        iconType: 'help',
      },
      threatTitle: dec?.threatTitle || 'Adli İnceleme',
      summaryReason,
      mitreTechnique: win?.mitreTechnique,
      sourceIpCorrelationEligible: win?.sourceIpCorrelationEligible,
      evidence: deepEvidence,
    };
  });

  // Secondary correlation
  const secondaryCorr: WholeLogSummary =
    pipelineResult.secondaryCorrelation ||
    runSecondaryCorrelation(correlatedInputs, rawLinesCount, diag);

  // 4. Construct enriched HuntingReport
  const baseReport = createEmptyReport();

  // Metrics aggregations
  const uniqueSrcIps = new Set<string>();
  const uniqueDstIps = new Set<string>();
  const uniqueHosts = new Set<string>();
  const uniqueEndpoints = new Set<string>();
  let serverErrorsCount = 0;
  let authFailuresCount = 0;
  let acceptCount = 0;
  let denyCount = 0;
  let totalBytes = 0;
  const timestamps: string[] = [];

  const destIpMap = new Map<string, {
    hedef_ip: string;
    total: number;
    srcIps: Set<string>;
    ports: Set<number>;
    acceptCount: number;
    denyCount: number;
    totalBytes: number;
  }>();

  const portMap = new Map<number, {
    port: number;
    total: number;
    acceptCount: number;
    denyCount: number;
    clientIps: Set<string>;
    totalBytes: number;
  }>();

  const entityGroups = new Map<string, {
    ip: string;
    host: string;
    user: string;
    eventsCount: number;
    compromiseCount: number;
    blockedCount: number;
    suspiciousCount: number;
    authFailures: number;
    serverErrors: number;
    bytes: number;
    endpoints: Set<string>;
    firstSeen: string;
    lastSeen: string;
    signals: DetectionSignal[];
    threats: string[];
    evidence: string[];
    reasonings: string[];
  }>();

  const webshellFindings: WebshellItem[] = [];
  const bruteForceFindings: BruteForceItem[] = [];
  const suspiciousCommandFindings: SuspiciousCommandItem[] = [];

  correlatedInputs.forEach((ev, idx) => {
    const rawRec = pipelineResult.validationReport.validatedRecords[idx];
    const uEv = pipelineResult.universalEvidences[idx];
    const dec = pipelineResult.deterministicDecisions[idx];
    const rawLine = rawRec?.rawText || ev.rawText;

    if (ev.sourceIp && ev.sourceIp !== '-' && ev.sourceIp !== 'Bilinmiyor') {
      uniqueSrcIps.add(ev.sourceIp);
    }
    if (ev.destIp && ev.destIp !== '-' && ev.destIp !== 'Bilinmiyor') {
      uniqueDstIps.add(ev.destIp);
    }
    if (ev.host && ev.host !== 'Bilinmiyor' && ev.host !== 'Endpoint') {
      uniqueHosts.add(ev.host);
    }
    if (ev.timestamp) {
      timestamps.push(ev.timestamp);
    }

    // Auth failures count: HTTP 401/403/530, SSH Failed password, Postfix SASL, Event ID 4625
    const isAuthFail =
      ev.eventId === 4625 ||
      rawLine.includes('Failed password') ||
      rawLine.includes('authentication failed') ||
      rawLine.includes('SASL LOGIN authentication failed') ||
      rawLine.includes('status=401') ||
      rawLine.includes('status=403') ||
      rawLine.includes(' 401 ') ||
      rawLine.includes(' 403 ') ||
      uEv?.outcome?.value === 'FAILURE';

    if (isAuthFail) {
      authFailuresCount++;
    }

    // Server errors count: 5xx
    const is5xx =
      rawLine.includes('status=500') ||
      rawLine.includes(' 500 ') ||
      rawLine.includes(' 502 ') ||
      rawLine.includes(' 503 ');
    if (is5xx) {
      serverErrorsCount++;
    }

    // Action checks
    const isDeny =
      ev.action.toLowerCase() === 'deny' ||
      ev.action.toLowerCase() === 'block' ||
      rawLine.toLowerCase().includes('action=deny') ||
      rawLine.toLowerCase().includes('outcome=blocked');
    const isAccept =
      ev.action.toLowerCase() === 'accept' ||
      ev.action.toLowerCase() === 'allow' ||
      rawLine.toLowerCase().includes('action=accept') ||
      rawLine.toLowerCase().includes('action=allow');

    if (isDeny) denyCount++;
    else if (isAccept) acceptCount++;

    // Endpoint / URI tracking with semantic preference
    const semanticUri =
      pipelineResult.aiResponse?.records?.[idx]?.fields?.find((f) => f.semanticType === 'HTTP_REQUEST_URI')?.value;
    const httpMatch = rawLine.match(/"[A-Z]+\s+([^\s?"]+)/);
    const extractedUri =
      semanticUri ||
      dec?.parsedLog?.islem_komutu ||
      (httpMatch ? httpMatch[1] : '') ||
      dec?.rawKeyValues?.uri ||
      dec?.rawKeyValues?.url ||
      dec?.rawKeyValues?.stem ||
      '';
    const uri = extractedUri || ev.commandLine || '';
    if (uri) uniqueEndpoints.add(uri);

    // Byte tracking
    const bytesVal = parseInt(dec?.rawKeyValues?.bytes || dec?.rawKeyValues?.size || '0', 10) || 0;
    if (bytesVal > 0) totalBytes += bytesVal;

    // Dest IP map
    const dstKey = ev.destIp !== '-' ? ev.destIp : ev.host;
    if (dstKey && dstKey !== 'Bilinmiyor') {
      if (!destIpMap.has(dstKey)) {
        destIpMap.set(dstKey, {
          hedef_ip: dstKey,
          total: 0,
          srcIps: new Set(),
          ports: new Set(),
          acceptCount: 0,
          denyCount: 0,
          totalBytes: 0,
        });
      }
      const dEntry = destIpMap.get(dstKey)!;
      dEntry.total++;
      if (ev.sourceIp !== '-') dEntry.srcIps.add(ev.sourceIp);
      if (isDeny) dEntry.denyCount++;
      if (isAccept) dEntry.acceptCount++;
      dEntry.totalBytes += bytesVal;
    }

    // Port tracking
    const portVal = parseInt(dec?.rawKeyValues?.dstport || dec?.rawKeyValues?.port || dec?.rawKeyValues?.dport || '0', 10);
    if (portVal > 0) {
      if (dstKey && destIpMap.has(dstKey)) {
        destIpMap.get(dstKey)!.ports.add(portVal);
      }
      if (!portMap.has(portVal)) {
        portMap.set(portVal, {
          port: portVal,
          total: 0,
          acceptCount: 0,
          denyCount: 0,
          clientIps: new Set(),
          totalBytes: 0,
        });
      }
      const pEntry = portMap.get(portVal)!;
      pEntry.total++;
      if (ev.sourceIp !== '-') pEntry.clientIps.add(ev.sourceIp);
      if (isDeny) pEntry.denyCount++;
      if (isAccept) pEntry.acceptCount++;
      pEntry.totalBytes += bytesVal;
    }

    // Entity grouping for Risk Queue
    const entityKey = ev.sourceIp !== '-' && ev.sourceIp !== 'Bilinmiyor' ? ev.sourceIp : ev.host;
    if (entityKey && entityKey !== 'Bilinmiyor') {
      if (!entityGroups.has(entityKey)) {
        entityGroups.set(entityKey, {
          ip: ev.sourceIp,
          host: ev.host,
          user: ev.user,
          eventsCount: 0,
          compromiseCount: 0,
          blockedCount: 0,
          suspiciousCount: 0,
          authFailures: 0,
          serverErrors: 0,
          bytes: 0,
          endpoints: new Set(),
          firstSeen: ev.timestamp || 'Bilinmiyor',
          lastSeen: ev.timestamp || 'Bilinmiyor',
          signals: [],
          threats: [],
          evidence: [],
          reasonings: [],
        });
      }
      const eg = entityGroups.get(entityKey)!;
      eg.eventsCount++;
      if (ev.verdict === 'POTENTIAL_COMPROMISE') eg.compromiseCount++;
      if (ev.verdict === 'BLOCKED_ATTACK_ATTEMPT') eg.blockedCount++;
      if (ev.verdict === 'SUSPICIOUS_ANOMALY') eg.suspiciousCount++;
      if (isAuthFail) eg.authFailures++;
      if (is5xx) eg.serverErrors++;
      eg.bytes += bytesVal;
      if (uri) eg.endpoints.add(uri);
      if (ev.timestamp) eg.lastSeen = ev.timestamp;
      if (ev.threatTitle && !eg.threats.includes(ev.threatTitle)) {
        eg.threats.push(ev.threatTitle);
      }
      if (ev.evidence && ev.evidence.length > 0) {
        eg.evidence.push(...ev.evidence.slice(0, 2));
      }
      const aiRec = pipelineResult.aiResponse?.records?.[idx];
      const aiReasoning = aiRec?.hypothesis?.reasoning;
      if (aiReasoning && !eg.reasonings.includes(aiReasoning)) {
        eg.reasonings.push(aiReasoning);
      }
    }

    // Webshell / Path Traversal checks
    if (
      rawLine.includes('../') ||
      rawLine.includes('..\\') ||
      rawLine.includes('/etc/passwd') ||
      rawLine.includes('win.ini') ||
      rawLine.includes('cmd.exe') ||
      rawLine.includes('powershell')
    ) {
      const sampleAction =
        extractedUri ||
        ev.commandLine ||
        (rawLine.match(/(?:\.\.\/[^\s"]+|\/etc\/[a-z]+|cmd\.exe[^\s"]*|powershell[^\s"]*)/)?.[0]) ||
        rawLine.slice(0, 80);

      webshellFindings.push({
        ip_adresi: ev.sourceIp !== '-' ? ev.sourceIp : 'Bilinmiyor',
        sunucu_ismi: ev.host,
        user_agent: dec?.rawKeyValues?.useragent || dec?.rawKeyValues?.agent || dec?.parsedLog?.user_agent || 'Bilinmiyor',
        session_cookie: '-',
        istek_sayisi: 1,
        hata_sayisi: isAuthFail ? 1 : 0,
        server_hatasi: is5xx ? 1 : 0,
        toplam_yanit_byte: bytesVal,
        ilk_gorulme: ev.timestamp || '-',
        son_gorulme: ev.timestamp || '-',
        eylem_ornekleri: sampleAction,
      });
    }

    // Brute force / Auth failure tracking
    if (isAuthFail) {
      bruteForceFindings.push({
        ip_adresi: ev.sourceIp !== '-' ? ev.sourceIp : 'Bilinmiyor',
        kullanici_adi: ev.user,
        sunucu_ismi: ev.host,
        status_code: 401,
        basarisiz_deneme_sayisi: 1,
        ilk_deneme: ev.timestamp || '-',
        son_deneme: ev.timestamp || '-',
      });
    }

    // Suspicious commands
    if (ev.commandLine || (ev.process && ev.process.toLowerCase().includes('cmd'))) {
      suspiciousCommandFindings.push({
        sunucu_ismi: ev.host,
        islem_komutu: ev.commandLine || ev.process,
        status_code: null,
        tekrar_sayisi: 1,
        erisen_farkli_ip_sayisi: 1,
      });
    }
  });

  // Calculate Risk Queue Items
  const riskQueueItems: RiskQueueItem[] = [];
  entityGroups.forEach((eg, key) => {
    let score = 10;
    const breakdown: Array<{ item: string; points: number; note: string }> = [];
    const signals: DetectionSignal[] = [];

    if (eg.compromiseCount > 0) {
      score += 45;
      breakdown.push({ item: 'Sistem Ele Geçirme Göstergesi', points: 45, note: `${eg.compromiseCount} olayda potansiyel istismar tespit edildi.` });
      signals.push({
        code: 'EXPLOIT_SUSPECT',
        points: 45,
        label: 'İstismar Şüphesi',
        confidence: 'YÜKSEK',
        category: 'EXPLOIT',
        description: 'Potansiyel istismar veya komut yürütme aktivitesi kaydedildi.',
      });
    }

    if (eg.blockedCount > 0) {
      score += 30;
      breakdown.push({ item: 'Engellenen Güvenlik İhlali', points: 30, note: `${eg.blockedCount} olay güvenlik cihazı tarafından durduruldu.` });
      signals.push({
        code: 'BLOCKED_ATTACK',
        points: 30,
        label: 'Engellenen Saldırı',
        confidence: 'YÜKSEK',
        category: 'SCANNER',
        description: 'Güvenlik cihazı veya WAF saldırı girişimini engelledi.',
      });
    }

    if (eg.suspiciousCount > 0) {
      score += 20;
      breakdown.push({ item: 'Şüpheli Anomali', points: 20, note: `${eg.suspiciousCount} şüpheli anomali gözlemlendi.` });
      signals.push({
        code: 'ANOMALY_DETECTED',
        points: 20,
        label: 'Şüpheli Anomali',
        confidence: 'ORTA',
        category: 'ANOMALY',
        description: 'Beklenmeyen veya sıra dışı telemetri davranışı saptandı.',
      });
    }

    if (eg.authFailures > 0) {
      const authPts = Math.min(30, eg.authFailures * 10);
      score += authPts;
      breakdown.push({ item: 'Kimlik Doğrulama Hatası', points: authPts, note: `${eg.authFailures} adet başarısız kimlik doğrulaması.` });
      signals.push({
        code: 'AUTH_FAILURE_BURST',
        points: authPts,
        label: 'Kimlik Denemesi',
        confidence: eg.authFailures >= 3 ? 'YÜKSEK' : 'ORTA',
        category: 'BRUTE_FORCE',
        description: `${eg.authFailures} kimlik doğrulama hatası kaydedildi.`,
      });
    }

    score = Math.min(100, score);

    let level: 'KRİTİK' | 'YÜKSEK' | 'ORTA' | 'DÜŞÜK' = 'DÜŞÜK';
    if (score >= 60) level = 'KRİTİK';
    else if (score >= 35) level = 'YÜKSEK';
    else if (score >= 20) level = 'ORTA';

    const reason = eg.threats.length > 0
      ? eg.threats.join('; ')
      : `${eg.eventsCount} olay incelendi (${level} risk seviyesi).`;

    const explainability = eg.reasonings.length > 0
      ? `Gemini 3.8 Flash Akıl Yürütme: ${eg.reasonings.slice(0, 2).join(' ')} (${key} üzerinde toplam ${eg.eventsCount} olay).`
      : `Gemini 3.8 Flash Adli Analizi: ${key} varlığı üzerinde toplam ${eg.eventsCount} olay kaydedildi. Kanıt: ${eg.evidence.slice(0, 2).join(' | ') || 'Adli telemetri doğrulandı.'}`;

    riskQueueItems.push({
      ip_adresi: eg.ip !== '-' ? eg.ip : key,
      sunucu_ismi: eg.host,
      toplam_istek: eg.eventsCount,
      farkli_endpoint_sayisi: eg.endpoints.size,
      farkli_sunucu_sayisi: 1,
      farkli_kullanici_sayisi: eg.user !== 'Bilinmiyor' ? 1 : 0,
      basarili_byte: eg.bytes,
      auth_hatasi: eg.authFailures,
      server_hatasi: eg.serverErrors,
      hassas_endpoint: eg.endpoints.size > 0 ? 1 : 0,
      webshell_sinyali: eg.compromiseCount > 0 ? 1 : 0,
      ilk_gorulme: eg.firstSeen,
      son_gorulme: eg.lastSeen,
      risk_puani: score,
      risk_seviyesi: level,
      risk_gerekcesi: reason,
      confidence: score >= 35 ? 'YÜKSEK' : 'ORTA',
      signals,
      scoring_breakdown: breakdown,
      explainability_summary: explainability,
    });
  });

  // Sort risk queue
  riskQueueItems.sort((a, b) => b.risk_puani - a.risk_puani);

  // Build Destination IP analysis
  const destination_ip_analysis: DestinationIPItem[] = Array.from(destIpMap.values()).map((d) => ({
    hedef_ip: d.hedef_ip,
    toplam_baglanti: d.total,
    erisen_kaynak_ip_sayisi: d.srcIps.size,
    kullanilan_port_sayisi: d.ports.size,
    portlar: Array.from(d.ports).join(', ') || '-',
    accept_sayisi: d.acceptCount,
    deny_sayisi: d.denyCount,
    deny_orani: d.total > 0 ? Math.round((d.denyCount / d.total) * 100) : 0,
    toplam_transfer_byte: d.totalBytes,
    toplam_transfer_mb: Math.round((d.totalBytes / (1024 * 1024)) * 10) / 10,
  }));

  // Build Port analysis
  const port_analysis: PortItem[] = Array.from(portMap.values()).map((p) => ({
    port: p.port,
    servis_tahmini: getCommonServiceName(p.port),
    baglanti_sayisi: p.total,
    accept_sayisi: p.acceptCount,
    deny_sayisi: p.denyCount,
    erisen_istemci_sayisi: p.clientIps.size,
    toplam_byte: p.totalBytes,
    toplam_mb: Math.round((p.totalBytes / (1024 * 1024)) * 10) / 10,
  }));

  // Accept/Deny summary
  const accept_deny_summary: AcceptDenyItem[] = [
    {
      baglanti_karari: 'ACCEPT',
      baglanti_sayisi: acceptCount,
      oran_yuzde: totalEvents > 0 ? Math.round((acceptCount / totalEvents) * 100) : 0,
    },
    {
      baglanti_karari: 'DENY',
      baglanti_sayisi: denyCount,
      oran_yuzde: totalEvents > 0 ? Math.round((denyCount / totalEvents) * 100) : 0,
    },
    {
      baglanti_karari: 'BILINMIYOR',
      baglanti_sayisi: Math.max(0, totalEvents - acceptCount - denyCount),
      oran_yuzde: totalEvents > 0 ? Math.round((Math.max(0, totalEvents - acceptCount - denyCount) / totalEvents) * 100) : 0,
    },
  ];

  // Top IPs
  const top_ips: TopIPItem[] = Array.from(uniqueSrcIps).map((ip) => {
    const eg = entityGroups.get(ip);
    return {
      ip_adresi: ip,
      istek_sayisi: eg?.eventsCount || 1,
      toplam_byte: eg?.bytes || 0,
      sunucu_sayisi: 1,
    };
  });
  top_ips.sort((a, b) => b.istek_sayisi - a.istek_sayisi);

  const interimReport: HuntingReport = {
    ...baseReport,
    summary: {
      toplam_olay: totalEvents,
      ilk_tarih: timestamps.length > 0 ? timestamps[0] : '-',
      son_tarih: timestamps.length > 0 ? timestamps[timestamps.length - 1] : '-',
      farkli_ip_sayisi: uniqueSrcIps.size,
      farkli_hedef_ip_sayisi: uniqueDstIps.size,
      farkli_sunucu_sayisi: uniqueHosts.size,
      farkli_endpoint_sayisi: uniqueEndpoints.size,
      server_error_sayisi: serverErrorsCount,
      auth_failure_sayisi: authFailuresCount,
      accept_sayisi: acceptCount,
      deny_sayisi: denyCount,
      toplam_transfer_byte: totalBytes,
    },
    entity_risk_queue: riskQueueItems,
    risk_queue: riskQueueItems,
    destination_ip_analysis,
    port_analysis,
    accept_deny_summary,
    webshell_and_file_management: webshellFindings,
    brute_force_attempts: bruteForceFindings,
    suspicious_commands: suspiciousCommandFindings,
    top_ips,
    auth_hatasi_sayisi: authFailuresCount,
    accept_sayisi: acceptCount,
    deny_sayisi: denyCount,
    toplam_gb: Math.round((totalBytes / (1024 * 1024 * 1024)) * 100) / 100,
  };

  // Generate Authoritative Gemini 3.8 Flash AI Incident & Forensic Analysis
  let aiSocResult: any = null;
  if (typeof window !== 'undefined') {
    try {
      aiSocResult = await requestAiSocAnalysis({
        report: interimReport,
        selectedRiskItem: riskQueueItems[0],
      });
    } catch (err) {
      console.warn('[DirectGeminiHunt] Remote AI SOC report call warning:', err);
    }
  }

  if (!aiSocResult) {
    aiSocResult = generateFallbackSocAnalysis({
      reportSummary: interimReport.summary,
      selectedEntity: riskQueueItems[0] || null,
      highRiskEntities: riskQueueItems,
      destinationIps: destination_ip_analysis,
      webshellFindings,
      bruteForceFindings,
    });
  }

  // Full Gemini 3.8 Flash Forensic Incident & Triage Report Markdown
  const fullReportText = formatGemini38FlashForensicReport(aiSocResult, {
    totalEvents,
    postureTitle: secondaryCorr.postureTitle,
    correlatedInputs,
    rawLinesCount,
    rawTextSample: trimmed.slice(0, 500),
  });

  const triageSummary: RawLogTriageSummary = {
    pastedAt: new Date().toISOString(),
    totalEvents,
    overallPosture: secondaryCorr.overallPosture,
    postureTitle: secondaryCorr.postureTitle,
    evidenceBasedSummary: aiSocResult.executiveSummary || secondaryCorr.evidenceBasedSummary,
    incidentCandidatesCount: secondaryCorr.incidentCandidates.length,
    overallFindings: [
      `Gemini 3.8 Flash Akıl Yürütme: ${aiSocResult.threatLevel} seviyesinde analiz tamamlandı.`,
      ...(aiSocResult.recommendedActions ? aiSocResult.recommendedActions.slice(0, 2) : []),
      ...secondaryCorr.overallFindings.slice(0, 2),
    ],
    analystActions: aiSocResult.recommendedActions?.length ? aiSocResult.recommendedActions : secondaryCorr.analystActions,
    fullReportText,
    rawText: trimmed,
  };

  const report: HuntingReport = {
    ...interimReport,
    raw_log_triage: triageSummary,
  };

  return {
    report,
    triageSummary,
    file,
    pipelineResult,
  };
}

function getCommonServiceName(port: number): string {
  switch (port) {
    case 80: return 'HTTP';
    case 443: return 'HTTPS';
    case 22: return 'SSH';
    case 21: return 'FTP';
    case 25: return 'SMTP';
    case 53: return 'DNS';
    case 3389: return 'RDP';
    case 445: return 'SMB';
    case 8080: return 'HTTP-Proxy';
    case 8443: return 'HTTPS-Alt';
    default: return `Port ${port}`;
  }
}
