export type EvidenceStatus =
  | 'OBSERVED'       // Directly and explicitly present in the raw source
  | 'DERIVED'        // Transparently transformed or parsed through strict rule
  | 'UNCERTAIN'      // Ambiguity in reading, parsing, or OCR interpretation
  | 'NOT_PRESENT'    // Confirmed absent from examined telemetry
  | 'NOT_ASSESSED';  // Not yet reliably assessed or extracted

export type ExtractionMethod =
  | 'DIRECT_KEY_VALUE'
  | 'REGEX'
  | 'DELIMITED_COLUMN'
  | 'JSON_KEY'
  | 'VISUAL_READING'
  | 'OCR_TEXT'
  | 'DERIVED_TRANSLATION'
  | 'HEURISTIC';

export type SourceType =
  | 'TEXT_LOG'
  | 'STRUCTURED_JSON'
  | 'DELIMITED_ROW'
  | 'SCREENSHOT_OCR'
  | 'SCREENSHOT_VISUAL'
  | 'USER_NOTE'
  | 'COMMAND_LINE';

export interface FieldObservation<T = string | number | null> {
  value: T;
  rawValue?: string | null;
  status: EvidenceStatus;
  sourceType: SourceType;
  sourceReference?: string;
  extractionMethod: ExtractionMethod;
  supportingEvidence?: string[];
  conflicts?: Array<{ source: string; conflictingValue: string }>;
}

export type InputAdmissibilityType =
  | 'SECURITY_EVIDENCE'
  | 'POSSIBLE_SECURITY_EVIDENCE'
  | 'NON_SECURITY_INPUT'
  | 'INSUFFICIENT_DATA';

export interface InputAdmissibility {
  classification: InputAdmissibilityType;
  isSecurityEvidence: boolean;
  confidence: 'KESİN' | 'YÜKSEK' | 'ORTA' | 'DÜŞÜK' | 'BELİRSİZ';
  reason: string;
  detectedSignals: string[];
}

export interface UniversalEvidence {
  admissibility: InputAdmissibility;
  rawContent: string;

  // Identity & Actor
  actor: FieldObservation<string | null>;
  subjectUser: FieldObservation<string | null>;

  // Endpoints
  sourceEndpoint: {
    ip: FieldObservation<string | null>;
    port: FieldObservation<number | null>;
    host: FieldObservation<string | null>;
  };
  destinationEndpoint: {
    ip: FieldObservation<string | null>;
    port: FieldObservation<number | null>;
    host: FieldObservation<string | null>;
  };

  // Actions & Outcomes
  action: FieldObservation<string | null>;
  outcome: FieldObservation<'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN'>;
  timestamp: FieldObservation<string | null>;

  // Process & Execution
  process: {
    name: FieldObservation<string | null>;
    pid: FieldObservation<number | null>;
    commandLine: FieldObservation<string | null>;
    parentProcess: FieldObservation<string | null>;
  };

  // Telemetry & Details
  telemetry: {
    protocol: FieldObservation<string | null>;
    httpStatus: FieldObservation<number | null>;
    wafAction: FieldObservation<string | null>;
    errorCode: FieldObservation<string | null>;
    errorDescription: FieldObservation<string | null>;
    rawPayload: FieldObservation<string | null>;
    eventId: FieldObservation<number | null>;
    eventName: FieldObservation<string | null>;
    logonType: FieldObservation<number | null>;
    subStatus: FieldObservation<string | null>;
    serviceName: FieldObservation<string | null>;
  };

  // Preserved raw fields
  unparsedFields: Record<string, string>;
}

export type HypothesisSupportStatus =
  | 'SUPPORTED_BY_EVIDENCE'
  | 'UNPROVEN_POSSIBILITY'
  | 'CONTRADICTED_BY_EVIDENCE'
  | 'INSUFFICIENT_EVIDENCE';

export interface DynamicHypothesis {
  id: string;
  title: string;
  statement: string;
  type: 'ATTACK_SCENARIO' | 'BENIGN_EXPLANATION' | 'SYSTEM_FAULT' | 'AUTHORIZED_ADMIN';
  supportStatus: HypothesisSupportStatus;
  observedSupportingFacts: string[];
  observedContradictingFacts: string[];
  missingEvidenceRequired: string[];
  nextVerificationSteps: string[];
}

export interface TailoredInvestigationStep {
  stepNumber: number;
  category: 'AUTHENTICATION' | 'PRIVILEGE' | 'PROCESS_EXECUTION' | 'PERSISTENCE' | 'DEFENSE_EVASION' | 'NETWORK_LATERAL' | 'DEVICE_IDENTIFICATION';
  title: string;
  objective: string;
  targetEntities: { host?: string | null; user?: string | null; ip?: string | null; timeWindow?: string | null };
  logsToCheck: string[];
  fieldsToCheck: string[];
  groundedQuestions: string[];
  pivotingGuidance: string;
}
