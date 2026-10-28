export type RiskLevel = 'KRİTİK' | 'YÜKSEK' | 'ORTA' | 'DÜŞÜK';
export type IncidentStatus = 'Yeni' | 'İnceleniyor' | 'Kapatıldı';
export type ConnectionDecision = 'ACCEPT' | 'DENY' | 'BILINMIYOR' | 'DENY / HATA';

export type NetworkZone = 'internal' | 'external' | 'loopback';
export type IpSourceType = 'direct-peer' | 'trusted-proxy-forwarded' | 'untrusted-spoofed-ignored' | 'parsed-client';
export type DetectionConfidence = 'YÜKSEK' | 'ORTA' | 'DÜŞÜK';
export type DetectionProfile = 'RELAXED' | 'BALANCED' | 'STRICT';

export interface DetectionSignal {
  code: string;
  points: number;
  label: string;
  confidence: DetectionConfidence;
  category: 'WEBSHELL' | 'SCANNER' | 'EXFILTRATION' | 'BRUTE_FORCE' | 'EXPLOIT' | 'ANOMALY' | 'INTERNAL_LATERAL';
  description: string;
}

export interface EntityContext {
  network_zone: NetworkZone;
  device?: string | null;
  user?: string | null;
  session?: string | null;
  ip_source?: IpSourceType;
  forwarded_chain?: string | null;
}

export interface NormalizedLog {
  kaynak_dosya: string;
  tarih: string | null;
  tarih_obj?: Date | null;
  ip_adresi: string | null;
  hedef_ip: string | null;
  hedef_port: number | null;
  kaynak_port: number | null;
  sunucu_ismi: string | null;
  islem_komutu: string | null;
  http_method: string | null;
  user_agent: string | null;
  byte_degeri: number | null;
  istemci_byte: number | null;
  status_code: number | null;
  baglanti_karari: ConnectionDecision;
  kullanici_adi: string | null;
  referer: string | null;
  response_time_ms: number | null;
  session_cookie: string | null;
  // Proxy / WAF / Entity Context Enriched Fields
  immediate_peer_ip?: string | null;
  forwarded_client_ip?: string | null;
  ip_source?: IpSourceType;
  forwarded_chain?: string | null;
  device?: string | null;
  network_zone?: NetworkZone;
  parse_warning?: string | null;
  weight?: number;
  count?: number | null;
  policy_name?: string | null;
  threat_type?: string | null;
  event_name?: string | null;
  log_source?: string | null;
  response_code?: string | null;
}

export interface SummaryData {
  toplam_olay: number;
  ilk_tarih: string;
  son_tarih: string;
  farkli_ip_sayisi: number;
  farkli_hedef_ip_sayisi: number;
  farkli_sunucu_sayisi: number;
  farkli_endpoint_sayisi: number;
  server_error_sayisi: number;
  auth_failure_sayisi: number;
  accept_sayisi: number;
  deny_sayisi: number;
  toplam_transfer_byte: number;
}

export interface RiskQueueItem {
  ip_adresi: string;
  sunucu_ismi: string;
  toplam_istek: number;
  farkli_endpoint_sayisi: number;
  farkli_sunucu_sayisi: number;
  farkli_kullanici_sayisi: number;
  basarili_byte: number;
  auth_hatasi: number;
  server_hatasi: number;
  hassas_endpoint: number;
  webshell_sinyali: number;
  ilk_gorulme: string;
  son_gorulme: string;
  risk_puani: number;
  risk_seviyesi: RiskLevel;
  risk_gerekcesi: string;
  ip_kategori?: string;
  ip_aciklama?: string;
  // Explainable detection & context additions
  confidence?: DetectionConfidence;
  signals?: DetectionSignal[];
  context?: EntityContext;
  device?: string | null;
  kullanici_adi?: string | null;
  network_zone?: NetworkZone;
  ip_source?: IpSourceType;
  scoring_breakdown?: Array<{ item: string; points: number; note: string }>;
  explainability_summary?: string;
}

export interface DestinationIPItem {
  hedef_ip: string;
  toplam_baglanti: number;
  erisen_kaynak_ip_sayisi: number;
  kullanilan_port_sayisi: number;
  portlar: string;
  accept_sayisi: number;
  deny_sayisi: number;
  deny_orani: number;
  toplam_transfer_byte: number;
  toplam_transfer_mb: number;
}

export interface PortItem {
  port: number;
  servis_tahmini: string;
  baglanti_sayisi: number;
  accept_sayisi: number;
  deny_sayisi: number;
  erisen_istemci_sayisi: number;
  toplam_byte: number;
  toplam_mb: number;
  hedef_port?: number;
  tahmini_servis?: string;
  istemci_sayisi?: number;
  toplam_transfer_mb?: number;
}

export interface AcceptDenyItem {
  baglanti_karari: string;
  baglanti_sayisi: number;
  oran_yuzde: number;
}

export interface CrossDayCorrelationItem {
  ip_adresi: string;
  kullanici_adi: string;
  sunucular: string;
  gun_sayisi: number;
  dosya_sayisi: number;
  toplam_istek: number;
  basarisiz_auth_sayisi: number;
  server_hata_sayisi: number;
  toplam_basarili_byte: number;
  ilk_aktivite: string;
  son_aktivite: string;
  asama_izleri: string;
  ip_kategori?: string;
}

export interface TransferDetailItem {
  kaynak_dosya: string;
  ip_adresi: string;
  kullanici_adi: string;
  sunucu_ismi: string;
  basarili_istek_sayisi: number;
  toplam_transfer_byte: number;
  toplam_transfer_mb: number;
  toplam_transfer_gb: number;
  ortalama_transfer_byte: number;
  en_buyuk_tekil_transfer: number;
  en_buyuk_tekil_transfer_mb: number;
  toplam_transfer_yuzdesi: number;
  ilk_transfer: string;
  son_transfer: string;
  basarili_istek?: number;
  ortalama_byte?: number;
  max_tekil_mb?: number;
  toplam_pay_yuzde?: number;
}

export interface LargestRequestItem {
  kaynak_dosya: string;
  tarih: string;
  ip_adresi: string;
  kullanici_adi: string;
  sunucu_ismi: string;
  islem_komutu: string;
  status_code: number | null;
  byte_degeri: number;
  transfer_mb: number;
  user_agent: string;
}

export interface WebshellItem {
  ip_adresi: string;
  sunucu_ismi: string;
  user_agent: string;
  session_cookie: string;
  istek_sayisi: number;
  hata_sayisi: number;
  server_hatasi: number;
  toplam_yanit_byte: number;
  ilk_gorulme: string;
  son_gorulme: string;
  eylem_ornekleri: string;
}

export interface WebshellTimelineItem {
  tarih: string;
  ip_adresi: string;
  sunucu_ismi: string;
  http_method: string;
  islem_komutu: string;
  status_code: number;
  byte_degeri: number;
  response_time_ms: number;
  user_agent: string;
  session_cookie: string;
  referer: string;
}

export interface BotItem {
  ip_adresi: string;
  user_agent: string;
  toplam_istek: number;
  farkli_komut_sayisi: number;
  hedef_sunucu_sayisi: number;
  hata_sayisi: number;
  hata_yuzdesi: number;
  hassas_sayisi: number;
  anormal_method_sayisi: number;
  bot_sebebi: string;
}

export interface BruteForceItem {
  ip_adresi: string;
  kullanici_adi: string;
  sunucu_ismi: string;
  status_code: number;
  basarisiz_deneme_sayisi: number;
  ilk_deneme: string;
  son_deneme: string;
}

export interface PasswordSprayingItem {
  ip_adresi: string;
  farkli_kullanici_sayisi: number;
  basarisiz_deneme_sayisi: number;
  hedef_sunucu_sayisi: number;
  hedeflenen_kullanicilar: string;
}

export interface FtpAuthItem {
  ip_adresi: string;
  kullanici_adi: string;
  session_cookie: string;
  sunucu_ismi: string;
  ftp_istek_sayisi: number;
  user_komutu: number;
  pass_komutu: number;
  auth_sonucu: number;
  ilk_gorulme: string;
  son_gorulme: string;
}

export interface FtpFileItem {
  ip_adresi: string;
  kullanici_adi: string;
  session_cookie: string;
  sunucu_ismi: string;
  islem_sayisi: number;
  yukleme_sayisi: number;
  indirme_sayisi: number;
  silme_sayisi: number;
  yeniden_adlandirma_sayisi: number;
  toplam_byte: number;
  ilk_gorulme: string;
  son_gorulme: string;
}

export interface FtpSuspiciousItem {
  tarih: string;
  ip_adresi: string;
  kullanici_adi: string;
  session_cookie: string;
  sunucu_ismi: string;
  islem_komutu: string;
  status_code: number;
  byte_degeri: number;
  referer: string;
}

export interface SuspiciousCommandItem {
  sunucu_ismi: string;
  islem_komutu: string;
  status_code: number | null;
  tekrar_sayisi: number;
  erisen_farkli_ip_sayisi: number;
}

export interface SensitiveEndpointItem {
  sunucu_ismi: string;
  islem_komutu: string;
  status_code: number | null;
  istek_sayisi: number;
  farkli_ip_sayisi: number;
}

export interface HourlyTrafficItem {
  saatlik_dilim?: string;
  toplam_istek?: number;
  basarili_istek?: number;
  hata_4xx?: number;
  hata_5xx?: number;
  saatlik_toplam_byte?: number;
  saat?: string;
  istek_sayisi?: number;
  deny_sayisi?: number;
  transfer_mb?: number;
}

export interface StatusCodeItem {
  status_code: number;
  adet: number;
}

export interface TopIPItem {
  ip_adresi: string;
  istek_sayisi: number;
  toplam_byte: number;
  sunucu_sayisi: number;
}

export interface QuarantinedLineItem {
  fileName: string;
  lineNumber: number;
  rawText: string;
  reason: string;
}

export interface ForensicQuarantineReport {
  totalLinesRead: number;
  parsedEventsCount: number;
  headerCommentLinesCount: number;
  emptyLinesCount: number;
  quarantinedCount: number;
  quarantinedLines: QuarantinedLineItem[];
  footnoteText: string;
}

export interface DetectedFormatItem {
  fileName: string;
  format: string;
  formatDisplayName: string;
  lineCount: number;
  eventCount?: number;
  headerCommentCount?: number;
  emptyLineCount?: number;
  quarantinedCount?: number;
  transferBytes?: number;
  transferMb?: number;
  transferGb?: number;
  uniqueIps?: number;
  errorCount?: number;
}

export interface RawLogTriageSummary {
  pastedAt: string;
  totalEvents: number;
  overallPosture: 'CRITICAL_THREAT' | 'SUSPICIOUS_ACTIVITY' | 'BENIGN_NORMAL' | 'MIXED_INVESTIGATION';
  postureTitle: string;
  evidenceBasedSummary: string;
  incidentCandidatesCount: number;
  overallFindings: string[];
  analystActions: string[];
  fullReportText: string;
  rawText: string;
}

export interface HuntingReport {
  summary: SummaryData;
  entity_risk_queue: RiskQueueItem[];
  risk_queue?: RiskQueueItem[];
  destination_ip_analysis: DestinationIPItem[];
  port_analysis: PortItem[];
  accept_deny_summary: AcceptDenyItem[];
  cross_day_correlation: CrossDayCorrelationItem[];
  data_transfer_details: TransferDetailItem[];
  largest_transfer_requests: LargestRequestItem[];
  webshell_and_file_management: WebshellItem[];
  webshell_activity_timeline: WebshellTimelineItem[];
  scanner_and_bots: BotItem[];
  brute_force_attempts: BruteForceItem[];
  password_spraying: PasswordSprayingItem[];
  ftp_authentication: FtpAuthItem[];
  ftp_file_operations: FtpFileItem[];
  ftp_suspicious_activity: FtpSuspiciousItem[];
  suspicious_commands: SuspiciousCommandItem[];
  sensitive_endpoints: SensitiveEndpointItem[];
  hourly_traffic: HourlyTrafficItem[];
  status_code_distribution: StatusCodeItem[];
  top_ips: TopIPItem[];
  detected_formats?: DetectedFormatItem[];
  quarantine?: ForensicQuarantineReport;
  raw_log_triage?: RawLogTriageSummary;
  auth_hatasi_sayisi?: number;
  accept_sayisi?: number;
  deny_sayisi?: number;
  bilinmeyen_sayisi?: number;
  toplam_gb?: number;
  analiz_araligi?: string;
  detection_profile?: DetectionProfile;
}

export interface IncidentNote {
  time: string;
  text: string;
}

export interface Incident {
  id: string;
  title: string;
  ip: string;
  server: string;
  username: string;
  severity: RiskLevel;
  status: IncidentStatus;
  description: string;
  notes: IncidentNote[];
  created_at: string;
  updated_at: string;
}

export interface ScopedAllowlistRule {
  id: string;
  scope: {
    ip?: string;
    cidr?: string;
    device?: string;
    user?: string;
    endpoint?: string;
    method?: string;
    detection_type?: string;
    network_zone?: NetworkZone;
  };
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt?: string | null;
}

export interface AllowlistData {
  ips: string[];
  cidrs: string[];
  service_accounts: string[];
  trusted_servers: string[];
  scoped_rules?: ScopedAllowlistRule[];
}

export interface IoCItem {
  type: 'IP' | 'Port' | 'URL/Path' | 'User-Agent' | string;
  value: string;
  description: string;
}

export interface MitreAttackItem {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  evidence: string;
}

export interface ThreatActorFinding {
  ip: string;
  riskScore: number;
  threatLevel: RiskLevel;
  reason: string;
  targetedServers: string;
  transferredMb: number;
  exfiltratedMb?: number;
  attackStage: string;
}

export interface FirewallRuleCommand {
  platform: 'iptables' | 'FortiGate' | 'Palo Alto' | 'Nginx / WAF' | string;
  command: string;
  description: string;
}

export interface CustomerEmailResult {
  emailSubject: string;
  emailGreeting: string;
  emailBody: string;
  emailClosing: string;
  companyName: string;
  analystName: string;
}

export interface AiSocAnalysisResult {
  threatLevel: RiskLevel;
  executiveSummary: string;
  attackNarrative: string;
  mitreAttacks: MitreAttackItem[];
  threatActors: ThreatActorFinding[];
  technicalDetails: string;
  iocList: IoCItem[];
  recommendedActions: string[];
  firewallRules?: FirewallRuleCommand[];
  emailSubject?: string;
  emailGreeting?: string;
  emailBody?: string;
  emailClosing?: string;
  customerEmail?: CustomerEmailResult;
  modelUsed?: string;
  fallbackActive?: boolean;
  fallbackNotice?: string;
}

export type PolicyTechnicalStatus =
  | 'BLOCK_GOZLENDI' // A — BLOCK'a geçiş gözlendi (Before ALERT ağırlıklı, After BLOCK ağırlıklı)
  | 'ALERT_DEVAM_EDIYOR' // B — ALERT devam ediyor (After döneminde ALERT olayları hâlâ mevcut)
  | 'BLOCK_GOZLENMEDI' // C — BLOCK gözlenmedi (After döneminde ilgili signature/rule mevcut fakat BLOCK yok)
  | 'LOGLARDA_GOZLENMEDI' // D — Sonraki dönemde gözlenmedi (Before'da mevcut, After'da yok)
  | 'KISMI_DEGISIM' // Kısmi değişim (hem alert hem block)
  | 'YENI_GORULEN_EVENT' // Yeni görülen event (Before'da yok, After'da var)
  | 'DEVAM_EDEN_GOZLEM' // Gözlem devam ediyor (Action alanı yokken sayı değişimi)
  | 'YETERLI_VERI_YOK'; // E — Yeterli veri yok

export interface PolicySignatureImpact {
  policyId: string;
  policyName?: string;
  signatureId: string;
  name: string;
  category: 'SQLi' | 'XSS' | 'RCE / Log4j' | 'Path Traversal' | 'Webshell' | 'Brute Force' | 'Bot / Scanner' | 'Sensitive Access' | 'Özel Kural' | 'Diğer';
  cveOrRef?: string;
  eventName?: string;
  threatType?: string;
  logSource?: string;
  // Observation counts
  beforeCount?: number;
  afterCount?: number;
  delta?: number;
  changePct?: number | null;
  // Action Availability Flag
  actionDataAvailable?: boolean;
  // Period A (Before / Baseline)
  periodA_total: number;
  periodA_alerted: number;
  periodA_blocked: number;
  periodA_blockRate: number;
  // Period B (After / Hardened)
  periodB_total: number;
  periodB_alerted: number;
  periodB_blocked: number;
  periodB_blockRate: number;
  // Response distributions for this specific event
  beforeResponses?: Record<string, number>;
  afterResponses?: Record<string, number>;
  // Transition & Technical Classification (5+ Durum)
  actionTransition: 'ALERT_TO_BLOCK' | 'STRENGTHENED' | 'MAINTAINED_BLOCK' | 'NEW_DETECTION' | 'NO_CHANGE' | 'NOT_OBSERVED_AFTER';
  actionChangeLabel: string; // 'ALERT → BLOCK' | 'Kısmi değişim' | 'Değişiklik gözlenmedi' | 'Sonraki dönemde gözlenmedi' | 'Yeni imza' | 'N/A (Action Yok)'
  isContinuingInAfter: 'Evet' | 'Hayır' | 'Yeni';
  technicalStatus: PolicyTechnicalStatus;
  statusLabel: string; // 'BLOCK gözleniyor' | 'ALERT devam ediyor' | 'BLOCK gözlenmedi' | 'Loglarda gözlenmedi' | 'Kısmi değişim' | 'Yeni görülen kayıt' | 'Gözlem devam ediyor'
  forensicInterpretation: string;
  blockRateDelta: number;
  preventedAttemptsCount: number;
  savedBandwidthBytes: number;
  protectionStatus: 'TUMU_BLOKLANDI' | 'TAM_KORUMA' | 'YUKSEK_ETKINLIK' | 'INCELEME_GEREKLI';
  // Target Hosts Breakdown under this Policy + Signature
  targetHosts?: {
    host: string;
    beforeAlert: number;
    beforeBlock: number;
    afterAlert: number;
    afterBlock: number;
  }[];
  trafficBeforeMb?: number | null;
  trafficAfterMb?: number | null;
}

export interface ProtectedServerThreatDetail {
  ruleOrAttack: string;
  signatureId: string;
  category: string;
  periodA_attacksAllowed: number;
  periodB_attacksBlocked: number;
}

export interface ProtectedServerSummary {
  server: string;
  periodA_attacksAllowed: number;
  periodB_attacksBlocked: number;
  protectionRate?: number | null;
  threats: ProtectedServerThreatDetail[];
}

export interface PeriodSummaryMetrics {
  label: string;
  totalRequests: number;
  blockedRequests: number;
  allowedRequests: number;
  alertedRequests?: number;
  otherActionRequests?: number;
  blockRate: number;
  totalBytes: number;
  blockedBytes: number;
  hasByteData: boolean;
  startDate?: string | null;
  endDate?: string | null;
  totalDays: number;
  dailyAverageRequests: number;
  dailyAverageBlocks: number;
  // Normalized Period Metrics
  periodStart?: string | null;
  periodEnd?: string | null;
  periodDays?: number;
  hasCountData?: boolean;
  totalCount?: number | null;
  dailyAverageCount?: number | null;
  isBackendLogIncluded: boolean;
  uniqueAttackIps: number;
  serverErrors5xx: number;
  authFailures: number;
  criticalThreatIps: number;
  highThreatIps: number;
}

export interface PeriodDataQuality {
  totalRows: number;
  parsedRows: number;
  rejectedRows: number;
  aggregateCount: number;
  missingPolicy: number;
  missingEvent: number;
  missingAction: number;
  missingResponse: number;
  invalidCount: number;
  warnings: string[];
}

export interface PeriodParsingDiagnostic {
  fileName: string;
  fileType?: string;
  sheetName?: string;
  headerFound?: boolean;
  totalLines: number;
  parsedRowsCount: number;
  rejectedRowsCount?: number;
  rejectionReasons?: string[];
  normalizedRecordsCount?: number;
  aggregateObservationCount?: number;
  detectedFormat: string;
  detectedColumns: string[];
  isF5SchemaDetected: boolean;
  actionDataAvailable?: boolean;
  columnStatusList?: Array<{ name: string; canonicalKey: string; present: boolean; rawHeaderName?: string }>;
  columnMapping: {
    policyCol?: string | null;
    threatCol?: string | null;
    eventCol?: string | null;
    logSourceCol?: string | null;
    responseCol?: string | null;
    destinationCol?: string | null;
    portCol?: string | null;
    timeCol?: string | null;
    lowLevelCol?: string | null;
    countCol?: string | null;
    actionCol?: string | null;
    bytesCol?: string | null;
  };
  unmatchedExpectedColumns: string[];
  sampleParsedValues?: {
    samplePolicy?: string;
    sampleThreat?: string;
    sampleResponse?: string;
    sampleDestination?: string;
    sampleCount?: number;
  };
  warningOrError?: string | null;
}

export interface PolicyComparisonResult {
  periodA: PeriodSummaryMetrics;
  periodB: PeriodSummaryMetrics;
  periodALabel: string;
  periodBLabel: string;
  analyzedAt: string;
  isDemo?: boolean;
  actionDataAvailable: boolean;
  totalObservationsA: number;
  totalObservationsB: number;
  responseDistribution: {
    periodA: Record<string, number>;
    periodB: Record<string, number>;
  };
  policyComparison: Array<{
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
  }>;
  dataQuality: {
    periodA: PeriodDataQuality;
    periodB: PeriodDataQuality;
  };
  diagnostics?: {
    periodA: PeriodParsingDiagnostic[];
    periodB: PeriodParsingDiagnostic[];
  };
  // Overall Deltas
  blockRateDelta: number;
  blockRatePercentagePointsDelta: number;
  blockRateRelativeChangePct: number | null;
  dailyAverageChangePct: number | null;
  periodDaysDifferent: boolean;
  periodDurationWarning: string | null;
  attackBlockedDeltaCount: number;
  preventedTrafficMb: number | null;
  serverErrorReductionPct: number | null;
  criticalThreatReductionPct: number;
  // Signatures & Rule Matrix (POLICY + SIGNATURE)
  signatureImpacts: PolicySignatureImpact[];
  // Continuing and Not-Observed breakdown
  continuingSignatures: {
    alertContinuing: PolicySignatureImpact[];
    blockObserved: PolicySignatureImpact[];
    partialChange: PolicySignatureImpact[];
  };
  notObservedSignatures: PolicySignatureImpact[];
  newObservedSignatures: PolicySignatureImpact[];
  // Protected Servers & Endpoints (Multi-Dimensional HOST + SIGNATURE/RULE)
  protectedServers: ProtectedServerSummary[];
  // Executive Narrative
  executiveSummary: string;
  keyFindings: string[];
  recommendations: string[];
  footnotes: string[];
  // Chronological Inversion Detection
  chronologicalInversionDetected?: boolean;
  chronologicalInversionWarning?: string | null;
}

export interface MultiPeriodEntry {
  periodId: string;
  label: string;
  fileName: string;
  periodStart?: string | null;
  periodEnd?: string | null;
  periodDays: number;
  totalRequests: number;
  dailyAverageCount: number;
  blockRate?: number | null;
  blockedRequests?: number;
  alertedRequests?: number;
  eventsCount: number;
  actionDataAvailable: boolean;
}

export interface MultiPeriodSignatureTrend {
  policyId: string;
  signatureId: string;
  name: string;
  threatType: string;
  counts: Record<string, number>; // periodId -> count
  deltas: Record<string, number>; // periodId -> delta from previous period
  overallTrend: 'INCREASING' | 'DECREASING' | 'STABLE' | 'DISAPPEARED' | 'NEW';
  trendLabel: string;
}

export interface MultiPeriodComparisonResult {
  periods: MultiPeriodEntry[];
  signatures: MultiPeriodSignatureTrend[];
  totalObservationHistory: { periodLabel: string; totalRequests: number; dailyAverage: number }[];
  analyzedAt: string;
  executiveSummary: string;
}

