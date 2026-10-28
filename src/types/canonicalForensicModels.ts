/**
 * CANONICAL FORENSIC DATA MODELS
 * Immutable single source of truth for evidence, normalization, AI claims, correlation, and SOC reporting.
 *
 * GLOBAL INVARIANTS:
 * - NO_EVIDENCE -> NO_FACT
 * - NO_EVIDENCE -> NO_CLAIM
 * - UNKNOWN != BENIGN (UNKNOWN = UNKNOWN)
 * - AI_CLAIM -> MUST_HAVE_EVIDENCE
 * - TRAFFIC -> MUST_HAVE_REAL_BYTES (or NOT_COMPUTED)
 * - BACKEND_IMPACT -> MUST_HAVE_BACKEND_EVIDENCE
 * - CORRELATION -> MUST_HAVE_CONCRETE_LINK (COMMON_HOST required)
 * - SYSTEM_ACCOUNT -> NOT_AUTOMATICALLY_TRUSTED (trusted = false)
 * - 4624 -> SUCCESSFUL_LOGON_OBSERVED (never automatically AUTHORIZED_ACTIVITY)
 */

export type ForensicVerdict =
  | 'BENIGN_EXPECTED'
  | 'OBSERVED_SECURITY_EVENT'
  | 'SUSPICIOUS_ACTIVITY'
  | 'BLOCKED_ATTACK_ATTEMPT'
  | 'POTENTIAL_COMPROMISE'
  | 'CONFIRMED_COMPROMISE'
  | 'INCONCLUSIVE';

export type ConfidenceStandard =
  | 'CONFIRMED'
  | 'HIGH_CONFIDENCE'
  | 'SUSPICIOUS'
  | 'INCONCLUSIVE'
  | 'BENIGN_EXPECTED';

export type EvidenceSourceType = 'RAW_LOG' | 'DERIVED' | 'AI_INTERPRETATION';

export type EvidenceConfidence = 'EXACT' | 'DERIVED' | 'INFERRED';

export interface SourceSpan {
  startChar: number;
  endChar: number;
  startLine?: number;
  endLine?: number;
}

export interface EvidenceRecord {
  id: string; // e.g. "EV-00001"
  eventId: string; // e.g. "EVT-001"
  fieldName: string; // e.g. "sourceIp", "user", "commandLine"
  sourceType: EvidenceSourceType;
  rawValue: unknown;
  normalizedValue?: unknown;
  sourceFile?: string;
  sourceSpan?: SourceSpan;
  rawSpanText?: string;
  timestamp?: string | null;
  confidence: EvidenceConfidence;
  provenance: {
    source: string;
    extractionMethod: string;
    parserVersion: string;
  };
}

export interface IsolatedEventRecord {
  eventIndex: number;
  eventId: string; // "EVT-001"
  rawText: string;
  sourceFile: string;
  sourceSpan: SourceSpan;
  timestamp: string | null;
  timestampMs: number | null;
  host: string | null;
  actorUser: string | null;
  subjectUser: string | null;
  sourceIp: string | null;
  sourcePort: number | null;
  destIp: string | null;
  destPort: number | null;
  process: string | null;
  parentProcess: string | null;
  commandLine: string | null;
  logonId: string | null;
  sessionId: string | null;
  logonType: number | null;
  serviceName: string | null;
  serviceFile: string | null;
  action: string | null;
  outcome: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN';
  securityDeviceAction: 'BLOCK' | 'DENY' | 'DROP' | 'RESET' | 'NOT_PRESENT';
  httpStatus: number | null;
  httpMethod: string | null;
  httpUri: string | null;
  bytes: number | null;
  trafficMb: number | null;
  trafficStatus: 'COMPUTED' | 'NOT_COMPUTED';
  winEventId: number | null;
  winEventName: string | null;
  verdict: ForensicVerdict;
  verdictReason: string;
  mitreTechnique?: string;
  evidenceIds: string[];
}

export interface CorrelationLink {
  sourceEventIndex: number;
  targetEventIndex: number;
  linkType:
    | 'SAME_LOGON_ID'
    | 'SAME_SESSION_ID'
    | 'AUTH_TRANSITION_4625_TO_4624'
    | 'PRIVILEGE_ASSIGNMENT_4624_TO_4672'
    | 'PROCESS_EXECUTION_4672_TO_4688'
    | 'PERSISTENCE_SERVICE_INSTALL_4688_TO_7045'
    | 'DEFENSE_EVASION_LOG_CLEAR_4688_TO_1102'
    | 'PARENT_CHILD_PROCESS_TREE'
    | 'SEQUENTIAL_COMMAND_TOOLCHAIN';
  evidenceIds: string[];
  reason: string;
  strength: 'STRONG' | 'MODERATE';
}

export interface CanonicalIncident {
  id: string; // "INCIDENT-01"
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  verdict: ForensicVerdict;
  confidence: ConfidenceStandard;
  sharedHost: string;
  eventIndices: number[];
  evidenceIds: string[];
  timeWindow: {
    start: string | null;
    end: string | null;
    durationMinutes: number | null;
  };
  whyCorrelated: string[]; // Explicit forensic links
  correlationLinks: CorrelationLink[];
  affectedIdentities: string[];
  sourceIps: string[];
  destinations: string[];
  processChain: string[];
  mitreMappings: Array<{
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    evidenceIds: string[];
    reason: string;
  }>;
  narrative: string;
  alternativeHypotheses: Array<{
    hypothesis: string;
    explanation: string;
    supportingEvidenceIds: string[];
    missingEvidence: string[];
    likelihood: 'PLAUSIBLE' | 'UNLIKELY' | 'UNKNOWN';
  }>;
  falsePositiveAssessment: {
    isFalsePositiveCandidate: boolean;
    benignExplanation?: string;
    missingEvidenceRequired?: string[];
  };
  actions: {
    observedActions: string[]; // Truly observed in telemetry (e.g. "Firewall dropped connection")
    recommendedActions: string[]; // Guidance for SOC analyst (e.g. "Isolate host DC01")
  };
}

export interface AIClaimRecord {
  id: string;
  claim: string;
  referencedEntities: {
    ips: string[];
    hosts: string[];
    users: string[];
    processes: string[];
    bytes: number[];
  };
  evidenceIds: string[];
  reasoning: string;
  alternativeExplanation?: string;
  validationStatus: 'PENDING' | 'ACCEPTED' | 'REJECTED_AI_CLAIM';
  rejectionReason?: string;
}

export interface AuditTrailEntry {
  timestamp: string;
  stage:
    | 'INPUT_RECEIVED'
    | 'PARSER_STARTED'
    | 'PARSER_COMPLETED'
    | 'EVIDENCE_REGISTERED'
    | 'DETERMINISTIC_VALIDATION_COMPLETED'
    | 'AI_ANALYSIS_STARTED'
    | 'AI_ANALYSIS_COMPLETED'
    | 'AI_CLAIM_VALIDATION_COMPLETED'
    | 'CORRELATION_COMPLETED'
    | 'REPORT_GENERATED';
  details: string;
  metadata?: Record<string, unknown>;
}

export interface CanonicalSocReport {
  analysisId: string;
  generatedAt: string;
  analysisHash: string;
  parserVersion: string;
  correlationVersion: string;
  aiModel: string;
  aiAnalysisStatus: 'SUCCESS' | 'AI_ANALYSIS_UNAVAILABLE' | 'PARTIAL_ANALYSIS';
  aiFailureReason?: string;

  executiveSummary: {
    overallPosture: 'CRITICAL_THREAT' | 'SUSPICIOUS_ACTIVITY' | 'BENIGN_NORMAL' | 'INCONCLUSIVE';
    postureTitle: string;
    summaryNarrative: string;
    eventCount: number;
    importantEventCount: number;
    incidentCount: number;
    evidenceCount: number;
  };

  dataQuality: {
    rawLinesCount: number;
    parsedEventsCount: number;
    parseFailuresCount: number;
    unparsedLines: string[];
    missingFieldSummaries: string[];
    analysisLimitations: string[];
  };

  incidents: CanonicalIncident[];
  standaloneSecurityEvents: IsolatedEventRecord[];
  blockedAttacks: IsolatedEventRecord[];
  potentialCompromises: CanonicalIncident[];
  confirmedCompromises: CanonicalIncident[];
  falsePositiveCandidates: Array<{
    eventIndex: number;
    reason: string;
    missingEvidence: string[];
  }>;

  evidenceRegistrySummary: {
    totalEvidenceRecords: number;
    rawEvidenceCount: number;
    derivedEvidenceCount: number;
    inferredEvidenceCount: number;
  };

  aiInterpretation: {
    status: 'ACTIVE' | 'UNAVAILABLE';
    validatedClaims: AIClaimRecord[];
    rejectedClaims: AIClaimRecord[];
    deepReasoningNarrative: string;
  };

  recommendedResponse: {
    observedActions: string[];
    recommendedActions: string[];
  };

  limitations: {
    whatIsUnknown: string[];
    whatIsMissing: string[];
    notComputableMetrics: string[];
  };

  auditTrail: AuditTrailEntry[];
}
