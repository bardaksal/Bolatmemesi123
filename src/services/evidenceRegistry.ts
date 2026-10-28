/**
 * IMMUTABLE FORENSIC EVIDENCE REGISTRY
 *
 * Implements Rule 5 & 6:
 * - Immutable single registry of all facts extracted from raw logs and deterministic derivations.
 * - Every piece of data has an exact ID, eventId, rawSpan, provenance, and confidence standard.
 * - AI cannot claim facts not present in this registry.
 */

import {
  EvidenceRecord,
  EvidenceConfidence,
  EvidenceSourceType,
  SourceSpan,
  AIClaimRecord,
} from '../types/canonicalForensicModels';

export class EvidenceRegistry {
  private records: Map<string, EvidenceRecord> = new Map();
  private ipIndex: Set<string> = new Set();
  private hostIndex: Set<string> = new Set();
  private userIndex: Set<string> = new Set();
  private processIndex: Set<string> = new Set();
  private commandIndex: Set<string> = new Set();
  private eventIndexMap: Map<string, EvidenceRecord[]> = new Map();
  private counter: number = 0;

  /**
   * Resets the registry for a new analysis session.
   */
  public clear(): void {
    this.records.clear();
    this.ipIndex.clear();
    this.hostIndex.clear();
    this.userIndex.clear();
    this.processIndex.clear();
    this.commandIndex.clear();
    this.eventIndexMap.clear();
    this.counter = 0;
  }

  /**
   * Generates a deterministic, sequential Evidence ID (e.g. EV-00001).
   */
  private generateId(): string {
    this.counter++;
    return `EV-${String(this.counter).padStart(5, '0')}`;
  }

  /**
   * Registers a piece of verified evidence.
   */
  public register(params: {
    eventId: string;
    fieldName: string;
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
      parserVersion?: string;
    };
  }): EvidenceRecord {
    const id = this.generateId();
    const record: EvidenceRecord = {
      id,
      eventId: params.eventId,
      fieldName: params.fieldName,
      sourceType: params.sourceType,
      rawValue: params.rawValue,
      normalizedValue: params.normalizedValue ?? params.rawValue,
      sourceFile: params.sourceFile,
      sourceSpan: params.sourceSpan,
      rawSpanText: params.rawSpanText,
      timestamp: params.timestamp,
      confidence: params.confidence,
      provenance: {
        source: params.provenance.source,
        extractionMethod: params.provenance.extractionMethod,
        parserVersion: params.provenance.parserVersion || '3.0.0-forensic',
      },
    };

    // Immutably store
    this.records.set(id, Object.freeze(record));

    // Update indexes for instantaneous verification
    const strVal = String(params.rawValue ?? '').trim().toLowerCase();
    if (strVal && strVal !== '-' && strVal !== 'null' && strVal !== 'undefined') {
      const field = params.fieldName.toLowerCase();
      if (field.includes('ip') || field === 'source_endpoint' || field === 'destination_endpoint') {
        this.ipIndex.add(strVal);
      } else if (field.includes('host') || field.includes('computer') || field === 'server') {
        this.hostIndex.add(strVal);
      } else if (field.includes('user') || field.includes('account')) {
        this.userIndex.add(strVal);
      } else if (field.includes('process') || field.includes('image')) {
        this.processIndex.add(strVal);
      } else if (field.includes('command') || field.includes('uri') || field.includes('url')) {
        this.commandIndex.add(strVal);
      }
    }

    if (!this.eventIndexMap.has(params.eventId)) {
      this.eventIndexMap.set(params.eventId, []);
    }
    this.eventIndexMap.get(params.eventId)!.push(record);

    return record;
  }

  public getRecord(id: string): EvidenceRecord | undefined {
    return this.records.get(id);
  }

  public getRecordsForEvent(eventId: string): EvidenceRecord[] {
    return this.eventIndexMap.get(eventId) || [];
  }

  public getAllRecords(): EvidenceRecord[] {
    return Array.from(this.records.values());
  }

  public count(): number {
    return this.records.size;
  }

  // Verification Methods for AI Claim Validator
  public hasIp(ip: string): boolean {
    if (!ip) return false;
    const clean = ip.trim().toLowerCase();
    if (this.ipIndex.has(clean)) return true;
    for (const rec of this.records.values()) {
      if (String(rec.rawValue).toLowerCase().includes(clean)) return true;
    }
    return false;
  }

  public hasHost(host: string): boolean {
    if (!host) return false;
    const clean = host.trim().toLowerCase();
    if (this.hostIndex.has(clean)) return true;
    for (const rec of this.records.values()) {
      if (String(rec.rawValue).toLowerCase().includes(clean)) return true;
    }
    return false;
  }

  public hasUser(user: string): boolean {
    if (!user) return false;
    const clean = user.trim().toLowerCase();
    if (this.userIndex.has(clean)) return true;
    for (const rec of this.records.values()) {
      if (String(rec.rawValue).toLowerCase().includes(clean)) return true;
    }
    return false;
  }

  public hasProcess(proc: string): boolean {
    if (!proc) return false;
    const clean = proc.trim().toLowerCase();
    if (this.processIndex.has(clean)) return true;
    for (const rec of this.records.values()) {
      if (String(rec.rawValue).toLowerCase().includes(clean)) return true;
    }
    return false;
  }

  public validateAiClaim(claim: AIClaimRecord): {
    isValid: boolean;
    rejectionReason?: string;
  } {
    // 1. Evidence ID verification
    if (!claim.evidenceIds || claim.evidenceIds.length === 0) {
      return {
        isValid: false,
        rejectionReason: 'REJECTED_AI_CLAIM: Claim does not reference any Evidence IDs in the registry.',
      };
    }

    for (const evId of claim.evidenceIds) {
      if (!this.records.has(evId)) {
        return {
          isValid: false,
          rejectionReason: `REJECTED_AI_CLAIM: Claim references non-existent Evidence ID "${evId}".`,
        };
      }
    }

    // 2. Referenced IP verification
    for (const ip of claim.referencedEntities.ips) {
      if (!this.hasIp(ip)) {
        return {
          isValid: false,
          rejectionReason: `REJECTED_AI_CLAIM: Claim references IP "${ip}" which does not exist in raw evidence.`,
        };
      }
    }

    // 3. Referenced Host verification
    for (const host of claim.referencedEntities.hosts) {
      if (!this.hasHost(host)) {
        return {
          isValid: false,
          rejectionReason: `REJECTED_AI_CLAIM: Claim references Host "${host}" which does not exist in raw evidence.`,
        };
      }
    }

    // 4. Referenced User verification
    for (const user of claim.referencedEntities.users) {
      if (!this.hasUser(user)) {
        return {
          isValid: false,
          rejectionReason: `REJECTED_AI_CLAIM: Claim references User "${user}" which does not exist in raw evidence.`,
        };
      }
    }

    return { isValid: true };
  }
}

export const globalEvidenceRegistry = new EvidenceRegistry();
