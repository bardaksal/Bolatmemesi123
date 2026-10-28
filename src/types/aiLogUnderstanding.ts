import { EvidenceStatus, UniversalEvidence } from './investigationEvidence';
import { UnifiedDecisionResult } from '../services/unifiedDecisionEngine';
import { WholeLogSummary } from '../services/socCorrelationEngine';

export type FormatConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface FormatAssessment {
  format: string; // e.g. "Windows Security", "Sysmon", "Linux auth", "Apache", "Nginx", "IIS", "CEF", "LEEF", "JSON", "key=value", "application_multiline", "UNKNOWN"
  confidence: FormatConfidence;
  detectedCharacteristics?: string[];
  multilineDetected?: boolean;
}

export interface SourceSpan {
  start: number;
  end: number;
}

export interface AiField {
  name: string;
  value: string;
  status: EvidenceStatus;
  sourceSpan?: SourceSpan;
}

export interface AiRecord {
  recordIndex: number;
  rawStart: number;
  rawEnd: number;
  rawText: string;
  boundaryConfidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  multilineJustification?: string;
  fields: AiField[];
}

export interface AiLogStructureResponse {
  analysisVersion: string;
  formatAssessment: FormatAssessment;
  records: AiRecord[];
  unparsedSpans: Array<{
    start: number;
    end: number;
    text: string;
    reason?: string;
  }>;
  warnings: string[];
}

export type FieldValidationDecision = 'ACCEPTED' | 'REJECTED' | 'UNCERTAIN';

export interface FieldValidationResult {
  fieldName: string;
  value: string;
  claimedStatus: EvidenceStatus;
  validatedStatus: EvidenceStatus;
  decision: FieldValidationDecision;
  sourceSpanValid: boolean;
  foundInRawSpan: boolean;
  claimedSourceSpan?: SourceSpan;
  resolvedSourceSpan?: SourceSpan;
  rejectionReason?: string;
  isCrossEventContaminated: boolean;
  isHallucinated: boolean;
}

export type RecordSpanIntegrity = 'VALID' | 'OUT_OF_BOUNDS' | 'OVERLAPPING' | 'TEXT_MISMATCH';

export interface RecordValidationResult {
  recordIndex: number;
  rawStart: number;
  rawEnd: number;
  rawText: string;
  spanIntegrity: RecordSpanIntegrity;
  recordStatus: 'ACCEPTED' | 'REJECTED' | 'UNCERTAIN';
  fields: FieldValidationResult[];
  acceptedFieldsCount: number;
  rejectedFieldsCount: number;
  hallucinatedFieldsCount: number;
  crossContaminatedFieldsCount: number;
  reasons: string[];
}

export interface LogUnderstandingValidationReport {
  inputLength: number;
  totalCandidateRecords: number;
  acceptedRecordsCount: number;
  rejectedRecordsCount: number;
  uncertainRecordsCount: number;
  validatedRecords: RecordValidationResult[];
  hasOverlappingRecords: boolean;
  hallucinationsDetected: number;
  crossEventContaminationsDetected: number;
  overallValidationStatus: 'PASS' | 'PARTIAL' | 'FAIL';
  provenanceAdherenceRate: number; // 0 - 100 %
  summaryMarkdown: string;
}

export interface FullLogUnderstandingPipelineResult {
  rawInput: string;
  rawLinesCount: number;
  aiResponse: AiLogStructureResponse;
  validationReport: LogUnderstandingValidationReport;
  universalEvidences: UniversalEvidence[];
  deterministicDecisions: UnifiedDecisionResult[];
  secondaryCorrelation?: WholeLogSummary;
  pipelineStatus: 'SUCCESS' | 'ANALYSIS_INCOMPLETE' | 'VALIDATION_FAILED';
  errorMessage?: string;
}

// =============================================================================
// PHASE 4.5 — TRUE AI LOG ANALYSIS ENGINE CONTRACTS
// =============================================================================

export type SemanticFieldType =
  | 'TIMESTAMP'
  | 'ACTOR_USER'
  | 'SUBJECT_USER'
  | 'SOURCE_ENDPOINT'
  | 'SOURCE_PORT'
  | 'DESTINATION_ENDPOINT'
  | 'DESTINATION_PORT'
  | 'HOST'
  | 'PROCESS'
  | 'PARENT_PROCESS'
  | 'COMMAND_LINE'
  | 'HTTP_REQUEST_URI'
  | 'HTTP_METHOD'
  | 'HTTP_STATUS'
  | 'SECURITY_DEVICE_ACTION' // e.g. BLOCK, DENY, DROP, RESET in Fortinet, WAF, Firewall
  | 'AUTHENTICATION_OUTCOME' // e.g. SUCCESS, FAILURE (invalid user, failed password)
  | 'ACTION'
  | 'OUTCOME'
  | 'EVENT_TYPE' // e.g. LOGON, PROCESS_CREATION, SERVICE_INSTALLATION, AUDIT_LOG_CLEAR, FILE_CREATE, NETWORK_SHARE, OBJECT_ACCESS, HTTP_REQUEST
  | 'EVENT_ID'
  | 'SERVICE_NAME'
  | 'SERVICE_FILE'
  | 'SUB_STATUS'
  | 'LOGON_TYPE'
  | 'NETWORK_INFO'
  | 'UNKNOWN_FIELD';

export interface AiSemanticField {
  field: string;
  value: string;
  semanticType: SemanticFieldType;
  status: EvidenceStatus;
  rawSpan?: SourceSpan;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence?: string;
}

export type HypothesisStatus =
  | 'CONFIRMED'
  | 'UNCONFIRMED'
  | 'NOT_ESTABLISHED'
  | 'BLOCKED_ATTEMPT'
  | 'BENIGN_ROUTINE'
  | 'INSUFFICIENT_DATA';

export interface ForensicHypothesis {
  hypothesisId: string;
  hypothesis: string;
  observedFacts: string[];
  requiredEvidence: string[];
  status: HypothesisStatus;
  reasoning: string;
}

export interface AiSemanticEvent {
  recordIndex: number;
  rawStart: number;
  rawEnd: number;
  rawText: string;
  boundaryConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  logFormatAndVendor: {
    vendorOrSource: string;
    format: string;
    isSecurityDevice: boolean;
  };
  eventType: string;
  fields: AiSemanticField[];
  hypothesis?: ForensicHypothesis;
  verdict: 'BENIGN' | 'SUSPICIOUS_ANOMALY' | 'MALICIOUS_ATTEMPT' | 'COMPROMISED' | 'BLOCKED' | 'UNCERTAIN' | 'ANALYSIS_INCOMPLETE';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  confidenceReason: string;
}

export interface AiSemanticLogResponse {
  analysisVersion: string;
  engine: 'AI_SEMANTIC_LOG_ENGINE';
  formatAssessment: FormatAssessment;
  records: AiSemanticEvent[];
  unparsedSpans: Array<{
    start: number;
    end: number;
    text: string;
    reason?: string;
  }>;
  warnings: string[];
}

export interface SemanticForensicPipelineResult {
  rawInput: string;
  rawLinesCount: number;
  aiResponse: AiSemanticLogResponse;
  validationReport: LogUnderstandingValidationReport;
  universalEvidences: UniversalEvidence[];
  hypotheses: ForensicHypothesis[];
  deterministicDecisions: UnifiedDecisionResult[];
  secondaryCorrelation?: WholeLogSummary;
  pipelineStatus: 'SUCCESS' | 'ANALYSIS_INCOMPLETE' | 'VALIDATION_FAILED';
  errorMessage?: string;
}

