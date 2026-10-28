import { explainCommand, CommandExplainerResult } from './commandExplainer';
import { generateL2InvestigationPlan, L2InvestigationPlan } from './l2InvestigationEngine';
import type { RealPixelProvenance } from './realPixelVisionService';
import {
  AnalysisFirstForensicReport,
  generateAnalysisFirstReport,
} from './analysisFirstForensicReporting';
import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
  analyzeHttpRequestSecurity,
  type HttpRequestDetails,
  type HttpRequestSecurityAnalysis,
} from './httpRequestAnalyzer';

export interface ObservedFromImage {
  eventId: string | null;
  provider: string | null;
  timestamp: string | null;
  host: string | null;
  username: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  port: string | null;
  processName: string | null;
  parentProcess: string | null;
  commandLine: string | null;
  action: string | null;
  status: string | null;
  rawMessage: string | null;
  httpRequest?: HttpRequestDetails | null;
}

export interface ImageHypothesis {
  title: string;
  statement: string;
  strengtheningEvidence: string[];
  weakeningEvidence: string[];
}

export interface ImageInvestigationStep {
  step: number;
  title: string;
  objective: string;
  logsToCheck: string[];
  action: string;
}

export interface SourceConflictItem {
  field: string;
  screenshotValue: string;
  textValue: string;
  impact: string;
}

export interface SourceConflictDetails {
  hasConflict: boolean;
  screenshotEvidence: Record<string, string>;
  textEvidence: Record<string, string>;
  conflicts: SourceConflictItem[];
  nextVerification: string[];
}

export interface SafeContainmentGuidance {
  action: string;
  why: string;
  when: string;
  risk: string;
  evidenceRequired: string;
  isDestructiveOrImpacting: boolean;
}

export interface QueryFieldProvenance {
  field: string;
  value: string;
  classification: 'OBSERVED' | 'DERIVED' | 'PLACEHOLDER' | 'STATIC_QUERY_SYNTAX';
  source: string;
}

export interface ImageIocBreakdown {
  observedIocs: Array<{ type: string; value: string; field: string }>;
  potentialIocs: Array<{ type: string; value: string; condition: string }>;
}

export interface StructuredTableRow {
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  port: string;
  action: string;
  ruleOrEvent: string;
}

export interface DiscrepancyItem {
  field: string;
  ocrValue?: string;
  visualValue?: string;
  uncertainty: string;
  recommendedVerification: string;
}

export interface ImageForensicResult {
  visualPlatform: string;
  confidence: 'KESİN' | 'YÜKSEK' | 'ORTA' | 'BELİRSİZ';
  visualSource?: 'VISUAL_INSPECTION' | 'FALLBACK_NON_VISUAL' | 'METADATA_ONLY';
  evidenceSource?: 'VISUAL_INSPECTION' | 'FALLBACK_NON_VISUAL' | 'METADATA_ONLY';
  fallbackLimitation?: {
    modelCallFailed: boolean;
    ocrNotAvailableLocally: boolean;
    analyzedViaSupplementalOnly: boolean;
    confidenceReduced?: boolean;
    errorCode?: string;
    warningMessage: string;
  };
  provenance?: RealPixelProvenance;
  observedFromImage: ObservedFromImage;
  structuredTableRows?: StructuredTableRow[];
  discrepancyNotes?: string[];
  discrepancies?: DiscrepancyItem[];
  missingOrUncertainFields: string[];
  imageQualityNote: string;
  highResolutionAnalysisConducted?: boolean;
  commandAnalysis?: {
    command: string;
    purpose: string;
    riskLevel: string;
    willCauseTrouble: string;
  };
  localCommandExplainer?: CommandExplainerResult | null;
  hypotheses: ImageHypothesis[];
  investigationSteps: ImageInvestigationStep[];
  queries: {
    splunk: string;
    kql: string;
    elastic: string;
    qradarAql: string;
  };
  queryFieldProvenance?: QueryFieldProvenance[];
  iocs: string[];
  iocBreakdown?: ImageIocBreakdown;
  detectionRecommendation: string;
  containmentActions: string[];
  safeContainment?: SafeContainmentGuidance[];
  fullReportMarkdown: string;
  analysisReport?: AnalysisFirstForensicReport;
  httpRequestAnalysis?: HttpRequestSecurityAnalysis | null;
  supplementalTextIntegrated?: boolean;
  sourceConflict?: SourceConflictDetails | null;
  localL2Plan?: L2InvestigationPlan | null;
}

/**
 * Converts a browser File to base64 data string
 */
export async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const res = reader.result as string;
      resolve(res);
    };
    reader.onerror = (err) => reject(err);
    reader.readAsDataURL(file);
  });
}

/**
 * Extracts key fields from text for conflict detection
 */
function extractFieldsFromText(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!text) return result;

  const userMatch = text.match(/\b(?:User|username|TargetUserName|Account(?:\s+Name)?|usr)\s*[:=]\s*["']?([^\s"';]+)/i);
  if (userMatch) result.user = userMatch[1].trim();

  const ipMatch = text.match(/\b(?:Source\s*(?:Network\s*)?Address|Source\s*IP|src|srcip|client_ip|c-ip)\s*[:=]\s*["']?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i) ||
                  text.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);
  if (ipMatch) result.sourceIp = ipMatch[1].trim();

  const hostMatch = text.match(/\b(?:Computer|Host|Workstation|devname|hostname)\s*[:=]\s*["']?([^\s"';]+)/i);
  if (hostMatch) result.host = hostMatch[1].trim();

  const eventIdMatch = text.match(/\b(?:Event\s*ID|EventID|eventId)\s*[:=]\s*["']?(\d+)/i) ||
                       text.match(/\b(4624|4625|4688|4672|7045|1102)\b/);
  if (eventIdMatch) result.eventId = eventIdMatch[1].trim();

  const cmdMatch = text.match(/\b(?:CommandLine|cmd|Process_Command_Line)\s*[:=]\s*["']?([^"\r\n]+)/i);
  if (cmdMatch) result.commandLine = cmdMatch[1].trim();

  return result;
}

/**
 * Detects conflicts between screenshot evidence and supplemental text evidence
 */
export function detectEvidenceConflict(
  observed: ObservedFromImage,
  text: string
): SourceConflictDetails | null {
  if (!text || !text.trim()) return null;

  const textFields = extractFieldsFromText(text);
  const conflicts: SourceConflictItem[] = [];
  const screenshotEvidence: Record<string, string> = {};
  const textEvidence: Record<string, string> = {};

  if (observed.username && textFields.user) {
    screenshotEvidence.user = observed.username;
    textEvidence.user = textFields.user;
    if (observed.username.toLowerCase() !== textFields.user.toLowerCase()) {
      conflicts.push({
        field: 'Kullanıcı Hesabı (User)',
        screenshotValue: observed.username,
        textValue: textFields.user,
        impact: 'Farklı hesap kimlikleri. Yetki kapsamı ve saldırı hedefi farklılaşabilir.',
      });
    }
  }

  if (observed.sourceIp && textFields.sourceIp) {
    screenshotEvidence.sourceIp = observed.sourceIp;
    textEvidence.sourceIp = textFields.sourceIp;
    if (observed.sourceIp !== textFields.sourceIp) {
      conflicts.push({
        field: 'Kaynak IP Adresi (Source IP)',
        screenshotValue: observed.sourceIp,
        textValue: textFields.sourceIp,
        impact: 'Farklı ağ segmenti. Tehdit aktörü kaynağı ve yerel/uzak erişim ayrımı çelişmektedir.',
      });
    }
  }

  if (observed.host && textFields.host) {
    screenshotEvidence.host = observed.host;
    textEvidence.host = textFields.host;
    if (observed.host.toLowerCase() !== textFields.host.toLowerCase()) {
      conflicts.push({
        field: 'Hedef Host / Bilgisayar',
        screenshotValue: observed.host,
        textValue: textFields.host,
        impact: 'Farklı sistem uç noktaları. Olayların aynı makinede gerçekleşip gerçekleşmediği belirsizdir.',
      });
    }
  }

  if (observed.eventId && textFields.eventId) {
    screenshotEvidence.eventId = observed.eventId;
    textEvidence.eventId = textFields.eventId;
    if (observed.eventId !== textFields.eventId) {
      conflicts.push({
        field: 'Olay Kimliği (Event ID)',
        screenshotValue: observed.eventId,
        textValue: textFields.eventId,
        impact: 'Olay türü uyuşmazlığı. Güvenlik denetim telemetrisi farklı kategorilere işaret ediyor.',
      });
    }
  }

  if (conflicts.length === 0) {
    return null;
  }

  return {
    hasConflict: true,
    screenshotEvidence,
    textEvidence,
    conflicts,
    nextVerification: [
      'Görüntüdeki olay zaman damgası (Timestamp) ile log metninin zaman damgasını karşılaştırın.',
      'Aynı Logon ID (Oturum Kimliği) veya PID (İşlem Kimliği) referansını doğrulayın.',
      'Farklı iki eşzamanlı olay olma ihtimaline karşı her iki delili bağımsız kanıt olarak saklayın.',
    ],
  };
}

/**
 * Compares pure OCR raw reading against Visual Layout understanding to detect discrepancies
 */
export function detectOcrVisualDiscrepancies(
  ocrFields: Partial<ObservedFromImage>,
  visualFields: Partial<ObservedFromImage>
): DiscrepancyItem[] {
  const discrepancies: DiscrepancyItem[] = [];

  const compareField = (
    fieldName: string,
    ocrVal: string | null | undefined,
    visVal: string | null | undefined,
    verificationAdvice: string
  ) => {
    if (ocrVal && visVal && ocrVal.trim() !== visVal.trim()) {
      discrepancies.push({
        field: fieldName,
        ocrValue: ocrVal.trim(),
        visualValue: visVal.trim(),
        uncertainty: `Bu alan görüntüden iki farklı şekilde okunuyor (${ocrVal.trim()} vs ${visVal.trim()}); doğrulama gerekli.`,
        recommendedVerification: verificationAdvice,
      });
    }
  };

  compareField(
    'Kaynak IP (Source IP)',
    ocrFields.sourceIp,
    visualFields.sourceIp,
    'Ağ güvenlik cihazı (Firewall/NetFlow) oturum tablosundan IP eşleşmesini teyit edin.'
  );
  compareField(
    'Kullanıcı Hesabı (User)',
    ocrFields.username,
    visualFields.username,
    'Domain Controller 4768/4769 Kerberos bilet logları ile kullanıcı adını doğrulayın.'
  );
  compareField(
    'Olay Kimliği (Event ID)',
    ocrFields.eventId,
    visualFields.eventId,
    'Log sağlayıcının (Provider) Windows Olay Günlüğü şemasıyla Event ID numarasını teyit edin.'
  );
  compareField(
    'Komut Satırı (Command Line)',
    ocrFields.commandLine,
    visualFields.commandLine,
    'EDR veya Sysmon Event 1 telemetrisinden komut parametrelerini eksiksiz çekin.'
  );

  return discrepancies;
}

/**
 * Builds safe, conditional containment guidance
 */
function buildSafeContainmentGuidance(
  observed: ObservedFromImage,
  hypotheses: ImageHypothesis[]
): SafeContainmentGuidance[] {
  const steps: SafeContainmentGuidance[] = [];
  const host = observed.host || 'Uç Nokta';
  const user = observed.username || 'İlgili Kullanıcı';

  // 1. Host Isolation evaluation (CONDITIONAL, never unconditional)
  steps.push({
    action: `Host Ağ İzolasyonu Değerlendirmesi (${host})`,
    why: 'Zararlı C2 trafiğini veya lateral movement yayılımını durdurmak.',
    when: 'Yalnızca uç noktada yetkisiz komut yürütme (RCE/Webshell) veya aktif ters kabuk bağlantısı kanıtlandığında uygulanmalıdır.',
    risk: 'Kritik sunucu ve üretim servislerinin durması, iş sürekliliği kesintisi riski.',
    evidenceRequired: 'Sysmon Event 3 dış ağ bağlantısı veya 4688 üzerinden doğrulanmış zararlı süreç.',
    isDestructiveOrImpacting: true,
  });

  // 2. Account Lockout / Force Password Reset evaluation
  steps.push({
    action: `Hesap Parola Sıfırlama ve Oturum İptali (${user})`,
    why: 'Çalınmış olabilecek kimlik bilgisinin kötüye kullanımını engellemek.',
    when: 'Başarılı oturum açma (4624) sonrasında anormal yetki ataması (4672) veya olağandışı kaynak IP tespit edildiğinde.',
    risk: 'Meşru personelin iş akışının kesilmesi veya otomatik servis hesaplarının kilitlenmesi.',
    evidenceRequired: 'Yetkisiz coğrafi konumdan başarılı kimlik doğrulama veya olağandışı saatte oturum.',
    isDestructiveOrImpacting: false,
  });

  // 3. Firewall IP Block evaluation
  if (observed.sourceIp) {
    steps.push({
      action: `Kaynak IP Geçici Blokajı (${observed.sourceIp})`,
      why: 'Saldırgan IP adresinden gelen sonraki istekleri sınırda kesmek.',
      when: 'Aynı IP adresinden çoklu hedeflere kaba kuvvet veya istismar gönderimi doğrulandığında.',
      risk: 'Eğer kaynak IP bir kurumsal proxy, NAT geçidi veya CDN ise meşru kullanıcıların da engellenmesi riski.',
      evidenceRequired: 'Tehdit istihbaratı (Threat Intel) teyidi veya 10+ ardışık istismar isteği.',
      isDestructiveOrImpacting: true,
    });
  }

  return steps;
}

/**
 * Builds field provenance list for generated SIEM queries
 */
function buildQueryFieldProvenance(
  observed: ObservedFromImage,
  queries: { splunk: string; kql: string; elastic: string; qradarAql: string }
): QueryFieldProvenance[] {
  const list: QueryFieldProvenance[] = [];

  if (observed.eventId) {
    list.push({ field: 'EventID', value: observed.eventId, classification: 'OBSERVED', source: 'Ekran Görüntüsü / Telemetri' });
  }
  if (observed.host) {
    list.push({ field: 'host / Computer', value: observed.host, classification: 'OBSERVED', source: 'Ekran Görüntüsü / Telemetri' });
  }
  if (observed.username) {
    list.push({ field: 'user / TargetUserName', value: observed.username, classification: 'OBSERVED', source: 'Ekran Görüntüsü / Telemetri' });
  }
  if (observed.sourceIp) {
    list.push({ field: 'src_ip / IpAddress', value: observed.sourceIp, classification: 'OBSERVED', source: 'Ekran Görüntüsü / Telemetri' });
  } else {
    list.push({ field: 'src_ip', value: 'UYGULANMAZ (Mevcut Değil)', classification: 'PLACEHOLDER', source: 'Görüntüde veya logda kaynak IP bulunmuyor' });
  }
  if (observed.commandLine) {
    list.push({ field: 'CommandLine', value: observed.commandLine.slice(0, 40) + '...', classification: 'OBSERVED', source: 'Ekran Görüntüsü / Telemetri' });
  }

  list.push({
    field: 'TimeWindow',
    value: '-2h / now',
    classification: 'DERIVED',
    source: 'Olay etrafındaki adli inceleme penceresi',
  });
  list.push({
    field: 'Index & Model',
    value: 'CIM / ASIM / ECS Uyumlu',
    classification: 'STATIC_QUERY_SYNTAX',
    source: 'SIEM sorgu sözdizimi standardı',
  });

  return list;
}

/**
 * Separates observed IOCs from potential IOCs
 */
function buildIocProvenanceBreakdown(
  observed: ObservedFromImage,
  rawIocs: string[]
): ImageIocBreakdown {
  const observedIocs: Array<{ type: string; value: string; field: string }> = [];
  const potentialIocs: Array<{ type: string; value: string; condition: string }> = [];

  if (observed.sourceIp && /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(observed.sourceIp)) {
    observedIocs.push({ type: 'IPv4', value: observed.sourceIp, field: 'SourceNetworkAddress' });
  }
  if (observed.host) {
    observedIocs.push({ type: 'Hostname', value: observed.host, field: 'Computer / Host' });
  }
  if (observed.username && observed.username !== 'SYSTEM') {
    observedIocs.push({ type: 'Account', value: observed.username, field: 'TargetUserName' });
  }
  if (observed.processName) {
    observedIocs.push({ type: 'Process', value: observed.processName, field: 'NewProcessName' });
  }

  // Potential IOCs based on command line or missing network evidence
  if (observed.commandLine) {
    const domainMatch = observed.commandLine.match(/https?:\/\/([a-zA-Z0-9_\-\.]+)/i);
    if (domainMatch) {
      observedIocs.push({ type: 'URL / Domain', value: domainMatch[1], field: 'CommandLine' });
    } else {
      potentialIocs.push({
        type: 'Domain / IP',
        value: '<C2_SUNUCU_IP>',
        condition: 'Süreç dış ağa bağlanırsa Sysmon Event 3 veya Firewall üzerinden doğrulanmalıdır.',
      });
    }
  }

  return { observedIocs, potentialIocs };
}

/**
 * Sends screenshot image (and optional supplemental text) to backend for forensic extraction
 */
export async function analyzeForensicScreenshot(
  imageBase64: string,
  mimeType: string = 'image/png',
  supplementalText?: string
): Promise<ImageForensicResult> {
  const resp = await fetch('/api/ai/investigate-image', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      imageBase64,
      mimeType,
      supplementalText: supplementalText?.trim() || '',
    }),
  });

  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error || `Görüntü adli analizi başarısız oldu (HTTP ${resp.status})`);
  }

  const data = await resp.json();
  const res: ImageForensicResult = data.result;

  // 1. Detect Source Conflict between screenshot and supplemental text
  if (res.observedFromImage && supplementalText) {
    res.sourceConflict = detectEvidenceConflict(res.observedFromImage, supplementalText);
  }

  // 2. Safe Containment Guidance with WHY, WHEN, RISK, EVIDENCE REQUIRED
  res.safeContainment = buildSafeContainmentGuidance(res.observedFromImage, res.hypotheses || []);

  // 3. Query Field Provenance classification
  res.queryFieldProvenance = buildQueryFieldProvenance(res.observedFromImage, res.queries);

  // 4. IOC Provenance breakdown (Observed IOCs vs Potential IOCs)
  res.iocBreakdown = buildIocProvenanceBreakdown(res.observedFromImage, res.iocs || []);

  // CRITICAL SEMANTIC ROUTING: HTTP REQUEST != COMMAND
  // If commandLine actually contains an HTTP request (e.g. "POST /druid/... HTTP/1.1"),
  // reclassify it as httpRequest and wipe commandLine!
  if (res.observedFromImage?.commandLine && isHttpRequestPattern(res.observedFromImage.commandLine)) {
    const parsedHttp = parseHttpRequestSemantics(res.observedFromImage.commandLine);
    if (parsedHttp) {
      res.observedFromImage.httpRequest = parsedHttp;
    }
    res.observedFromImage.commandLine = null;
  }

  // If rawMessage contains an HTTP request and httpRequest is not yet parsed, extract it
  if (!res.observedFromImage?.httpRequest && res.observedFromImage?.rawMessage) {
    if (isHttpRequestPattern(res.observedFromImage.rawMessage)) {
      const parsed = parseHttpRequestSemantics(res.observedFromImage.rawMessage);
      if (parsed) {
        res.observedFromImage.httpRequest = parsed;
      }
    }
  }

  // COMMAND ANALYZER ROUTING PROTECTION:
  // If an HTTP request was detected, NEVER call explainCommand!
  if (res.observedFromImage?.httpRequest) {
    res.httpRequestAnalysis = analyzeHttpRequestSecurity(res.observedFromImage.httpRequest, {
      sourceIp: res.observedFromImage.sourceIp,
      action: res.observedFromImage.action,
      statusCode: res.observedFromImage.status,
      deviceOrPlatform: res.visualPlatform,
    });
    res.localCommandExplainer = null;
  } else if (res.observedFromImage?.commandLine && !isHttpRequestPattern(res.observedFromImage.commandLine)) {
    try {
      res.localCommandExplainer = explainCommand(res.observedFromImage.commandLine, {
        username: res.observedFromImage.username || undefined,
        host: res.observedFromImage.host || undefined,
        parentProcess: res.observedFromImage.parentProcess || undefined,
        processName: res.observedFromImage.processName || undefined,
        eventId: res.observedFromImage.eventId ? parseInt(res.observedFromImage.eventId, 10) : undefined,
      });
    } catch (e) {
      console.warn('Local command explainer enrichment skipped:', e);
    }
  }

  // Synthesize equivalent raw log line for deterministic L2 Engine fallback
  const synthParts = [
    res.observedFromImage?.eventId ? `EventID=${res.observedFromImage.eventId}` : '',
    res.observedFromImage?.host ? `Computer="${res.observedFromImage.host}"` : '',
    res.observedFromImage?.username ? `TargetUserName="${res.observedFromImage.username}"` : '',
    res.observedFromImage?.sourceIp ? `IpAddress="${res.observedFromImage.sourceIp}"` : '',
    res.observedFromImage?.commandLine ? `CommandLine="${res.observedFromImage.commandLine}"` : '',
    res.observedFromImage?.status ? `SubStatus="${res.observedFromImage.status}"` : '',
    res.observedFromImage?.rawMessage || '',
  ].filter(Boolean).join(' ');

  // 5. Generate Analysis-First Forensic Report (User & Security Analyst Centric)
  res.analysisReport = generateAnalysisFirstReport({
    observed: res.observedFromImage,
    visualPlatform: res.visualPlatform,
    confidence: res.confidence,
    structuredTableRows: res.structuredTableRows,
    fallbackLimitation: res.fallbackLimitation,
    rawOcrText: res.provenance?.rawOcrText,
  });

  if (res.analysisReport?.markdownReport) {
    res.fullReportMarkdown = res.analysisReport.markdownReport;
  }

  return res;
}

