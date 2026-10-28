import { ParserDiagnosticReport } from './quickTriageHelper';

export type ForensicVerdict =
  | 'LIKELY_FALSE_POSITIVE'
  | 'BLOCKED_ATTACK_ATTEMPT'
  | 'SUSPICIOUS_ANOMALY'
  | 'POTENTIAL_COMPROMISE'
  | 'AUTHORIZED_ACTIVITY'
  | 'UNKNOWN'
  | 'NOT_ASSESSED';

export type CorrelationStrength = 'HIGH' | 'MEDIUM' | 'LOW';

export interface CorrelatedEventInput {
  index: number; // 1-based index (e.g. 1, 2, ..., 62)
  rawText: string;
  isWindows: boolean;
  eventId: number | null;
  eventName: string;
  timestamp: string | null;
  timestampMs: number | null;
  host: string;
  user: string;
  sourceIp: string;
  destIp: string;
  process: string;
  parentProcess: string;
  commandLine: string;
  logonId: string;
  logonType: number | null;
  logonTypeDesc: string;
  serviceName: string;
  serviceFile: string;
  subStatus: string;
  subStatusDesc: string;
  status: string;
  action: string;
  filePath: string;
  verdict: ForensicVerdict;
  confidence?: number;
  confidenceLabel?: string;
  verdictBadge: {
    text: string;
    badgeClasses: string;
    cardClasses: string;
    iconBgClasses: string;
    iconType: string;
  };
  threatTitle: string;
  summaryReason: string;
  mitreTechnique?: string;
  sourceIpCorrelationEligible?: boolean;
  evidence: string[];
}

export interface IncidentCandidate {
  id: string; // e.g. "INCIDENT-01"
  incidentId?: string; // Section 24 alias
  title: string;
  eventIds?: number[]; // Section 24 eventIds
  eventIndices: number[]; // 1-based indices (e.g. [18, 19, 23, 24])
  correlationType?: string; // Section 24 correlationType
  observedLinks?: string[]; // Section 24 observedLinks
  independentEvidenceLinks?: string[]; // Section 24 independentEvidenceLinks
  supportingEvidence?: string[]; // Section 24 supportingEvidence
  missingEvidence?: string[]; // Section 24 missingEvidence
  hypotheses?: string[]; // Section 24 hypotheses
  confirmedFacts?: string[]; // Section 24 confirmedFacts
  confirmedAttack?: boolean; // Section 28 & 29
  credentialSprayingConfirmed?: boolean;
  bruteForceConfirmed?: boolean;
  compromiseConfirmed?: boolean;
  confidence?: number;
  verdict?: string; // Section 24 verdict
  sharedHost: string;
  sharedUser: string;
  sharedIp: string;
  timeWindow: string;
  correlationStrength: CorrelationStrength;
  correlationEvidence: string[]; // Explicit forensic evidence list (e.g. "- Same host: DC01", "- Same user: Administrator")
  contributingFactors: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  narrative: string;
  mitreTechniques: string[];
  sequence: {
    eventIndex: number;
    eventId: number | null;
    timestamp: string;
    action: string;
    verdict: string;
  }[];
}

export interface WholeLogSummary {
  totalEvents: number;
  rawLinesCount: number;
  parsedRecordsCount: number;
  normalizedEventsCount: number;
  uncorrelatedEventsCount: number;
  breakdown: {
    critical: number;
    suspicious: number;
    anomaly: number;
    benign: number;
    falsePositive: number;
    unknown: number;
  };
  incidentCandidates: IncidentCandidate[];
  incidentEventsCount: number;
  uncorrelatedImportantEvents: number[]; // indices of critical/suspicious/anomaly events not in any incident
  falsePositiveCandidates: number[]; // indices of FP candidate events not in any incident
  benignEventsCount: number; // count of benign events not in any incident
  unknownEventsCount: number; // count of unknown/unassessed events not in any incident
  overallPosture: 'CRITICAL_THREAT' | 'SUSPICIOUS_ACTIVITY' | 'BENIGN_NORMAL' | 'MIXED_INVESTIGATION';
  postureTitle: string;
  postureJustification: string;
  evidenceBasedSummary: string;
  overallFindings: string[];
  analystActions: string[];
  parserDiagnostic?: ParserDiagnosticReport;
}

/**
 * Extracts timestamp and millisecond epoch if available from raw log text.
 */
export function extractEventTimestamp(text: string): { timestampStr: string | null; timestampMs: number | null } {
  // 1. ISO 8601: 2026-09-19T10:00:12
  const isoMatch = text.match(/\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b/i);
  if (isoMatch) {
    const parsed = Date.parse(isoMatch[1]);
    return {
      timestampStr: isoMatch[1],
      timestampMs: isNaN(parsed) ? null : parsed,
    };
  }

  // 2. Windows SystemTime: SystemTime='2026-09-19T10:00:12.123456Z'
  const sysTimeMatch = text.match(/SystemTime=["']?([^"'>\s]+)["']?/i);
  if (sysTimeMatch) {
    const parsed = Date.parse(sysTimeMatch[1]);
    return {
      timestampStr: sysTimeMatch[1],
      timestampMs: isNaN(parsed) ? null : parsed,
    };
  }

  // 3. Syslog / Date time: Sep 19 10:00:12 or 19/Sep/2026:10:00:12
  const syslogMatch = text.match(/\b([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b/);
  if (syslogMatch) {
    return {
      timestampStr: syslogMatch[1],
      timestampMs: null, // lacks year, relative sequence will be preserved
    };
  }

  // 4. Simple Time: 10:00:12
  const timeOnly = text.match(/\b(\d{2}:\d{2}:\d{2})\b/);
  if (timeOnly) {
    return {
      timestampStr: timeOnly[1],
      timestampMs: null,
    };
  }

  return { timestampStr: null, timestampMs: null };
}

/**
 * Secondary Correlation Engine:
 * Analyzes N independent events and discovers TRUE incidents based on:
 * - Shared Host
 * - Shared User / Account
 * - Temporal Proximity / Sequential Continuity
 * - Process execution & Parent-Child chains
 * - Attack progression (Auth -> Execution -> Persistence/Privilege -> Defense Evasion)
 *
 * GUARANTEES:
 * - Co-occurrence (merely being in the same file) is NEVER treated as correlation.
 * - Unrelated hosts/users (e.g. DC01 Admin vs LAPTOP01 UserA) remain strictly isolated.
 * - Strength is expressed qualitatively (HIGH / MEDIUM / LOW) with contributing factors.
 */
export function runSecondaryCorrelation(
  events: CorrelatedEventInput[],
  rawLinesCount?: number,
  parserDiagnostic?: ParserDiagnosticReport
): WholeLogSummary {
  const totalEvents = events.length;
  const rawLines = rawLinesCount ?? totalEvents;

  const isExtremeCollapse = rawLines >= 10 && totalEvents <= 2;
  const hasContaminatedEvents = events.some((e) => e.verdict === 'NOT_ASSESSED');
  const isParserFail = parserDiagnostic && parserDiagnostic.parserIntegrity === 'FAIL';

  // HARD STOP CONDITION: If parser integrity fails, extreme collapse occurs, or contamination is present, DO NOT produce security verdicts or correlations
  if (isParserFail || isExtremeCollapse || hasContaminatedEvents) {
    return {
      totalEvents,
      rawLinesCount: rawLines,
      parsedRecordsCount: totalEvents,
      normalizedEventsCount: totalEvents,
      uncorrelatedEventsCount: totalEvents,
      breakdown: {
        critical: 0,
        suspicious: 0,
        anomaly: 0,
        benign: 0,
        falsePositive: 0,
        unknown: totalEvents,
      },
      incidentCandidates: [],
      incidentEventsCount: 0,
      uncorrelatedImportantEvents: [],
      falsePositiveCandidates: [],
      benignEventsCount: 0,
      unknownEventsCount: totalEvents,
      overallPosture: 'MIXED_INVESTIGATION',
      postureTitle: 'ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI',
      postureJustification: 'ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI: Olay sınırları ve alan bütünlüğü doğrulanamadığı için güvenlik kararı ve korelasyon üretilmemiştir (HARD_STOP).',
      evidenceBasedSummary: 'ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI',
      overallFindings: [
        '• Kanıta Dayalı Özet: ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI',
        '• Güvenlik Duruşu Gerekçesi: ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI: Olay sınırları ve alan bütünlüğü doğrulanamadığı için adli güvenlik kararı, korelasyon veya meşruiyet üretilmemiştir.',
        `• Adli Dağılım: 0 Kritik, 0 Şüpheli, 0 Anomali, 0 FP Adayı, 0 Meşru, ${totalEvents} Değerlendirilmedi/Belirsiz.`,
      ],
      analystActions: [
        'Ham log dosyasındaki olay sınırlarını, satır yapısını ve ayrıştırma parametrelerini kontrol ediniz.',
        'Ayrıştırma tanılama raporundaki (PARSER DIAGNOSTIC REPORT) hata detaylarını inceleyiniz.',
      ],
      parserDiagnostic,
    };
  }

  const breakdown = {
    critical: 0,
    suspicious: 0,
    anomaly: 0,
    benign: 0,
    falsePositive: 0,
    unknown: 0,
  };

  events.forEach((ev) => {
    if (ev.verdict === 'POTENTIAL_COMPROMISE') breakdown.critical++;
    else if (ev.verdict === 'BLOCKED_ATTACK_ATTEMPT') breakdown.suspicious++;
    else if (ev.verdict === 'SUSPICIOUS_ANOMALY') breakdown.anomaly++;
    else if (ev.verdict === 'AUTHORIZED_ACTIVITY') breakdown.benign++;
    else if (ev.verdict === 'LIKELY_FALSE_POSITIVE') breakdown.falsePositive++;
    else breakdown.unknown++;
  });

  const incidentCandidates: IncidentCandidate[] = [];
  const assignedEventIndices = new Set<number>();

  // Helper: Detect attacker tools, high-risk commands, or malicious event indicators
  // STRICT: Event ID alone (e.g. 1102, 7045), subStatus alone (0xC0000064), or benign recon (whoami) NEVER trigger attack indicator!
  const isAttackIndicator = (ev: CorrelatedEventInput): boolean => {
    if (
      ev.verdict === 'POTENTIAL_COMPROMISE' ||
      ev.verdict === 'BLOCKED_ATTACK_ATTEMPT'
    ) {
      return true;
    }
    if (ev.verdict === 'SUSPICIOUS_ANOMALY') {
      const text = `${ev.process} ${ev.commandLine} ${ev.serviceName} ${ev.serviceFile}`.toLowerCase();
      const suspiciousKeywords = [
        '-enc', 'bypass', 'downloadstring', 'vssadmin delete', 'certutil -urlcache',
        'mimikatz', 'psexec', 'rundll32 javascript', 'invoke-expression', 'iex('
      ];
      return suspiciousKeywords.some((kw) => text.includes(kw));
    }
    return false;
  };

  // Helper: Determine if two events on the SAME host have a verified CAUSAL or BEHAVIORAL link
  const areHostEventsCausallyLinked = (
    a: CorrelatedEventInput,
    b: CorrelatedEventInput
  ): { linked: boolean; evidence?: string } => {
    // 1. Host check (must be on the same non-generic host)
    const aHost = (a.host || '').trim().toLowerCase();
    const bHost = (b.host || '').trim().toLowerCase();
    if (!aHost || !bHost || aHost !== bHost || aHost === 'windows endpoint' || aHost === 'bilinmiyor' || aHost === '-') {
      return { linked: false };
    }

    // 2. Boundary: If timestamps exist and distance is > 45 minutes, reject direct link
    if (a.timestampMs !== null && b.timestampMs !== null) {
      const diffMin = Math.abs(a.timestampMs - b.timestampMs) / 60000;
      if (diffMin > 45) return { linked: false };
    }

    // 3. Event #3 Guard: Type 2 Local Interactive Logon Isolation
    // Local interactive session without IP CANNOT link to external IP network attempts unless they share an exact non-zero Logon Session ID!
    const aIsLocalType2 = a.eventId === 4624 && a.logonType === 2;
    const bIsLocalType2 = b.eventId === 4624 && b.logonType === 2;
    const aHasRemoteIp = a.sourceIp && a.sourceIp !== '-' && a.sourceIp !== '127.0.0.1' && a.sourceIp !== '::1';
    const bHasRemoteIp = b.sourceIp && b.sourceIp !== '-' && b.sourceIp !== '127.0.0.1' && b.sourceIp !== '::1';

    const aLogon = (a.logonId || '').trim();
    const bLogon = (b.logonId || '').trim();
    const hasValidLogonId =
      aLogon &&
      bLogon &&
      aLogon !== '0x0' &&
      bLogon !== '0x0' &&
      aLogon !== '-' &&
      bLogon !== '-' &&
      aLogon.toLowerCase() !== 'bilinmiyor';

    // If one is Type 2 local and the other is remote IP, and no matching LogonId -> REJECT!
    if ((aIsLocalType2 && bHasRemoteIp) || (bIsLocalType2 && aHasRemoteIp)) {
      if (!hasValidLogonId || aLogon !== bLogon) {
        return { linked: false };
      }
    }

    // Link Type A: Exact same non-zero Logon Session ID (at least one is execution/auth/privilege/indicator)
    if (hasValidLogonId && aLogon === bLogon) {
      const hasActivity =
        a.eventId === 4688 ||
        b.eventId === 4688 ||
        a.eventId === 4624 ||
        b.eventId === 4624 ||
        a.eventId === 4672 ||
        b.eventId === 4672 ||
        isAttackIndicator(a) ||
        isAttackIndicator(b);
      if (hasActivity) {
        return { linked: true, evidence: `Same Logon Session ID (${aLogon})` };
      }
    }

    // Link Type B: Direct Process Parent-Child relationship
    const aProc = (a.process || '').toLowerCase();
    const bProc = (b.process || '').toLowerCase();
    const aParent = (a.parentProcess || '').toLowerCase();
    const bParent = (b.parentProcess || '').toLowerCase();
    if (aProc && bParent && (bParent.endsWith(aProc) || aProc.endsWith(bParent))) {
      return { linked: true, evidence: `Process Parent-Child: ${a.process} → ${b.process}` };
    }
    if (bProc && aParent && (aParent.endsWith(bProc) || bProc.endsWith(aParent))) {
      return { linked: true, evidence: `Process Parent-Child: ${b.process} → ${a.process}` };
    }

    // Link Type C: Authentication Sequence (4625 Failed Logon -> 4624 Successful Logon)
    // REQUIRES: Same user AND Same source IP (or both local)!
    const aUser = (a.user || '').trim().toLowerCase();
    const bUser = (b.user || '').trim().toLowerCase();
    const isSameUser = aUser && bUser && aUser !== '-' && aUser !== 'bilinmiyor' && aUser === bUser;

    if (isSameUser) {
      if ((a.eventId === 4625 && b.eventId === 4624) || (a.eventId === 4624 && b.eventId === 4625)) {
        // Source IP agreement check
        const sameIp = a.sourceIp === b.sourceIp;
        const bothLocal = !aHasRemoteIp && !bHasRemoteIp;
        if (sameIp || bothLocal) {
          return {
            linked: true,
            evidence: `Sequential auth transition: Failed logon (4625) followed by successful logon (4624) for ${a.user}`,
          };
        }
      }

      // Link Type D: Sequential recon/attacker toolchain under same user with tight time window
      if (isAttackIndicator(a) && isAttackIndicator(b)) {
        if ((a.eventId === 4688 || a.commandLine) && (b.eventId === 4688 || b.commandLine)) {
          return {
            linked: true,
            evidence: `Sequential command-line execution: ${(a.process || a.commandLine).slice(0, 35)} → ${(b.process || b.commandLine).slice(0, 35)}`,
          };
        }
      }
    }

    // Link Type E: Process Execution (4688) leading to Persistence (7045/4697) or Defense Evasion (1102/104)
    // MUST have execution (4688) + same user/logonId within <= 15 minutes!
    const isExecA = a.eventId === 4688;
    const isExecB = b.eventId === 4688;
    const isEvasionOrPersistenceB = b.eventId === 1102 || b.eventId === 104 || b.eventId === 7045 || b.eventId === 4697;
    const isEvasionOrPersistenceA = a.eventId === 1102 || a.eventId === 104 || a.eventId === 7045 || a.eventId === 4697;

    if (isExecA && isEvasionOrPersistenceB && isSameUser) {
      if (a.timestampMs === null || b.timestampMs === null) {
        // Rule 8: Timestamp yoksa chronological correlation yapılamaz
        return { linked: false };
      }
      const diffMin = Math.abs(a.timestampMs - b.timestampMs) / 60000;
      if (diffMin <= 15) {
        const desc = b.eventId === 1102 || b.eventId === 104
          ? 'Security audit log cleared following process execution'
          : `Windows service installed (${b.serviceName || 'Service'}) following execution`;
        return { linked: true, evidence: desc };
      }
    }

    if (isExecB && isEvasionOrPersistenceA && isSameUser) {
      if (a.timestampMs === null || b.timestampMs === null) {
        // Rule 8: Timestamp yoksa chronological correlation yapılamaz
        return { linked: false };
      }
      const diffMin = Math.abs(a.timestampMs - b.timestampMs) / 60000;
      if (diffMin <= 15) {
        const desc = a.eventId === 1102 || a.eventId === 104
          ? 'Security audit log cleared following process execution'
          : `Windows service installed (${a.serviceName || 'Service'}) following execution`;
        return { linked: true, evidence: desc };
      }
    }

    // Otherwise, NOT causally linked!
    // Temporal proximity alone or mere host co-occurrence NEVER establishes correlation.
    return { linked: false };
  };

  // --- Rule Set 1: Same Host Context Clusters ---
  const hostGroups: Record<string, CorrelatedEventInput[]> = {};

  events.forEach((ev) => {
    const host = (ev.host || '').trim();
    const hostLower = host.toLowerCase();
    if (
      !host ||
      hostLower === 'bilgisayar' ||
      hostLower === 'windows endpoint' ||
      hostLower === 'bilinmiyor' ||
      hostLower === '-' ||
      hostLower === 'unknown'
    ) {
      return;
    }

    if (!hostGroups[host]) hostGroups[host] = [];
    hostGroups[host].push(ev);
  });

  let incCounter = 1;

  for (const [hostName, hostEvents] of Object.entries(hostGroups)) {
    if (hostEvents.length < 2) continue; // Single event cannot form a multi-event incident

    const hasAnyThreatIndicator = hostEvents.some((e) => isAttackIndicator(e));
    if (!hasAnyThreatIndicator) {
      continue; // Skip: Routine/benign events remain strictly isolated from incidents
    }

    // Build Adjacency Matrix of Causal / Behavioral Links
    const n = hostEvents.length;
    const adj: number[][] = Array.from({ length: n }, () => []);
    const pairEvidence: Record<string, string> = {};

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const linkCheck = areHostEventsCausallyLinked(hostEvents[i], hostEvents[j]);
        if (linkCheck.linked) {
          adj[i].push(j);
          adj[j].push(i);
          if (linkCheck.evidence) {
            pairEvidence[`${i}_${j}`] = linkCheck.evidence;
          }
        }
      }
    }

    // Find Connected Components (clusters of transitively linked events)
    const visited = new Array<boolean>(n).fill(false);

    for (let i = 0; i < n; i++) {
      if (visited[i]) continue;

      const componentIndices: number[] = [];
      const queue = [i];
      visited[i] = true;

      while (queue.length > 0) {
        const curr = queue.shift()!;
        componentIndices.push(curr);
        for (const neighbor of adj[curr]) {
          if (!visited[neighbor]) {
            visited[neighbor] = true;
            queue.push(neighbor);
          }
        }
      }

      // Incident candidate requires AT LEAST 2 causally linked events
      if (componentIndices.length < 2) continue;

      const clusterEvents = componentIndices.map((idx) => hostEvents[idx]);

      // Ensure the cluster contains at least one threat/attack indicator
      const clusterHasThreat = clusterEvents.some((e) => isAttackIndicator(e));
      if (!clusterHasThreat) continue;

      // Compile Forensic Evidence List
      const evidenceList: string[] = [];
      evidenceList.push(`- Same host: ${hostName}`);

      // Collect user context
      const knownUsers = Array.from(
        new Set(
          clusterEvents
            .map((e) => (e.user || '').trim())
            .filter((u) => u && u !== '-' && u !== 'bilinmiyor' && u !== 'unknown')
        )
      );
      if (knownUsers.length === 1) {
        evidenceList.push(`- Same user: ${knownUsers[0]}`);
      } else if (knownUsers.length > 1) {
        evidenceList.push(`- Target accounts involved: ${knownUsers.join(', ')}`);
      }

      // Collect pair evidence descriptions
      const uniquePairEvidences = new Set<string>();
      for (let ci = 0; ci < componentIndices.length; ci++) {
        for (let cj = ci + 1; cj < componentIndices.length; cj++) {
          const idxA = Math.min(componentIndices[ci], componentIndices[cj]);
          const idxB = Math.max(componentIndices[ci], componentIndices[cj]);
          const key = `${idxA}_${idxB}`;
          if (pairEvidence[key]) {
            uniquePairEvidences.add(pairEvidence[key]);
          }
        }
      }
      uniquePairEvidences.forEach((evStr) => evidenceList.push(`- ${evStr}`));

      // Check Shared Logon Session ID
      const validLogonIds = Array.from(
        new Set(
          clusterEvents
            .map((e) => (e.logonId || '').trim())
            .filter((l) => l && l !== '0x0' && l !== '-' && l.toLowerCase() !== 'bilinmiyor')
        )
      );
      if (validLogonIds.length === 1 && !uniquePairEvidences.has(`Same Logon Session ID (${validLogonIds[0]})`)) {
        evidenceList.push(`- Same Logon ID / Session ID: ${validLogonIds[0]}`);
      }

      // Time Window calculation
      const validTimes = clusterEvents.map((g) => g.timestampMs).filter((t): t is number => t !== null);
      let timeWindowStr = 'Sıralı Olay Akışı';
      if (validTimes.length >= 2) {
        const minT = Math.min(...validTimes);
        const maxT = Math.max(...validTimes);
        const diffMinutes = Math.round((maxT - minT) / 60000);
        timeWindowStr = `${diffMinutes} minutes (${new Date(minT).toLocaleTimeString('tr-TR')} - ${new Date(maxT).toLocaleTimeString('tr-TR')})`;
        evidenceList.push(`- Time window: ${diffMinutes} minutes`);
      } else {
        const timestamps = clusterEvents.map((g) => g.timestamp).filter(Boolean);
        if (timestamps.length > 0) {
          timeWindowStr = `${timestamps[0]} - ${timestamps[timestamps.length - 1]}`;
          evidenceList.push('- Chronological sequence: Contiguous events in log stream');
        }
      }

      // Mark assigned events
      const indices = clusterEvents.map((g) => g.index);
      indices.forEach((idx) => assignedEventIndices.add(idx));

      // Correlation Strength Rule:
      // HIGH requires at least 2 independent strong forensic links
      // MEDIUM requires 1 strong forensic link
      // LOW for weaker relationships
      const strongLinksCount = uniquePairEvidences.size + (validLogonIds.length === 1 ? 1 : 0);
      let strength: CorrelationStrength = strongLinksCount >= 2 ? 'HIGH' : strongLinksCount === 1 ? 'MEDIUM' : 'LOW';

      // Severity Determination (Strict Evidence Grounding)
      const hasCompromise = clusterEvents.some((e) => e.verdict === 'POTENTIAL_COMPROMISE');
      const hasBlockedAttack = clusterEvents.some((e) => e.verdict === 'BLOCKED_ATTACK_ATTEMPT');
      const hasMaliciousIndicator = clusterEvents.some((e) => isAttackIndicator(e));

      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      if (hasCompromise) {
        severity = 'CRITICAL';
      } else if (hasBlockedAttack || (hasMaliciousIndicator && strength === 'HIGH')) {
        severity = 'HIGH';
      } else if (hasMaliciousIndicator || clusterEvents.some((e) => e.verdict === 'SUSPICIOUS_ANOMALY')) {
        severity = 'MEDIUM';
      } else {
        severity = 'LOW';
      }

      // Mitre ATT&CK techniques - strictly evidence-backed
      const mitres = new Set<string>();
      if (clusterEvents.some((e) => e.eventId === 1102 || e.eventId === 104)) {
        mitres.add('T1070.001 (Clear Event Logs)');
      }
      const failedCount = clusterEvents.filter((e) => e.eventId === 4625).length;
      if (failedCount >= 5) {
        mitres.add('T1110 (Brute Force Adayı)');
      }
      clusterEvents.forEach((g) => {
        if (g.mitreTechnique) mitres.add(g.mitreTechnique);
      });

      const id = `INCIDENT-${String(incCounter).padStart(2, '0')}`;
      incCounter++;

      const primaryUser = knownUsers[0] || (clusterEvents[0].user !== '-' ? clusterEvents[0].user : 'Sistem Süreçleri');
      const sample = clusterEvents[0];

      incidentCandidates.push({
        id,
        title: `${hostName} Üzerinde ${primaryUser} Hesabıyla İlişkili Olay Zinciri`,
        eventIndices: indices,
        sharedHost: hostName,
        sharedUser: primaryUser,
        sharedIp: sample.sourceIp !== '-' ? sample.sourceIp : 'Uç Nokta İçi',
        timeWindow: timeWindowStr,
        correlationStrength: strength,
        correlationEvidence: evidenceList,
        contributingFactors: evidenceList.map((e) => `+ ${e.replace(/^- /, '')}`),
        severity,
        narrative: `${hostName} hedefinde ${clusterEvents.length} adet ilişkili olay; ${evidenceList.slice(0, 3).map((e) => e.replace(/^- /, '')).join('; ')} adli kanıtlarıyla doğrulanmıştır.`,
        mitreTechniques: Array.from(mitres),
        sequence: clusterEvents.map((g) => ({
          eventIndex: g.index,
          eventId: g.eventId,
          timestamp: g.timestamp || 'Saat Yok',
          action: g.commandLine || g.process || g.serviceName || g.eventName,
          verdict: g.verdictBadge.text,
        })),
      });
    }
  }

  // --- Rule Set 2: Source IP / Cross-Host or Remote Authentication Sequence ---
  const sourceIpGroups: Record<string, CorrelatedEventInput[]> = {};
  events.forEach((ev) => {
    const ip = (ev.sourceIp || '').trim();
    if (!ip || ip === '-' || ip === 'bilinmiyor' || ip === '127.0.0.1' || ip === '::1') return;
    if (assignedEventIndices.has(ev.index)) return;

    if (!sourceIpGroups[ip]) sourceIpGroups[ip] = [];
    sourceIpGroups[ip].push(ev);
  });

  for (const [ip, ipEvents] of Object.entries(sourceIpGroups)) {
    if (ipEvents.length < 2) continue;

    const failedAuthEvents = ipEvents.filter((e) => e.eventId === 4625);
    const successAuthEvents = ipEvents.filter((e) => e.eventId === 4624);
    const hasAuthTransition = failedAuthEvents.length > 0 && successAuthEvents.length > 0;
    const hasSuspiciousAttack = ipEvents.some(
      (e) =>
        e.verdict === 'POTENTIAL_COMPROMISE' ||
        e.verdict === 'BLOCKED_ATTACK_ATTEMPT' ||
        isAttackIndicator(e)
    );
    const targets = Array.from(new Set(ipEvents.map((e) => e.host).filter(Boolean)));
    const targetUsers = Array.from(new Set(ipEvents.map((e) => e.user).filter((u) => u && u !== '-' && u !== 'bilinmiyor')));

    // Minimum correlation condition requires AT LEAST 2 independent forensic linkages:
    // Link 1: Verified Source IP
    // Link 2: Verified Auth Transition (4625 -> 4624) OR 3+ distinct target accounts (Spraying candidate) OR multi-host attack indicator
    const isMultiEndpoint = targets.length >= 2;
    const isCredentialSprayingCandidate = targetUsers.length >= 3 && failedAuthEvents.length >= 3;
    const hasTwoIndependentForensicLinks =
      (hasAuthTransition) ||
      (isCredentialSprayingCandidate) ||
      (isMultiEndpoint && hasSuspiciousAttack);

    if (hasTwoIndependentForensicLinks) {
      const indices = ipEvents.map((e) => e.index);
      indices.forEach((idx) => assignedEventIndices.add(idx));

      const evidenceList: string[] = [
        `- Same source IP: ${ip}`,
        `- Sequential authentication attempts: ${ipEvents.length} connection attempts`,
      ];

      // Check if any event has Logon Type 2 with IP (Event #3 semantic inconsistency)
      const hasType2WithIp = ipEvents.some((e) => e.eventId === 4624 && e.logonType === 2);
      if (hasType2WithIp) {
        evidenceList.push(`- Type 2 (Yerel İnteraktif) oturum kaydında harici IP yer almaktadır (Field Observation: UNCERTAIN)`);
      }

      if (isMultiEndpoint) {
        evidenceList.push(`- Multi-destination scope: ${targets.join(', ')} (Çoklu hedef erişimi; tek başına Lateral Movement kanıtı değildir)`);
      }

      if (isCredentialSprayingCandidate) {
        evidenceList.push(`- Multi-user credential spraying: Accounts targeted: ${targetUsers.join(', ')}`);
      } else if (targetUsers.length === 1) {
        evidenceList.push(`- Single target account: ${targetUsers[0]} (Authentication Sequence)`);
      } else {
        evidenceList.push(`- Target accounts: ${targetUsers.join(', ')}`);
      }

      if (hasAuthTransition) {
        evidenceList.push(`- Auth transition: Failed logon (4625) followed by successful logon (4624)`);
      }

      const id = `INCIDENT-${String(incCounter).padStart(2, '0')}`;
      incCounter++;

      const matchingLogonIds = Array.from(new Set(ipEvents.map((e) => (e.logonId || '').trim()).filter((l) => l && l !== '-' && l !== '0x0')));
      const strongLinks = (hasAuthTransition ? 1 : 0) + (matchingLogonIds.length === 1 ? 1 : 0) + (isMultiEndpoint ? 1 : 0);
      const strength: CorrelationStrength = (strongLinks >= 2 && isCredentialSprayingCandidate) ? 'HIGH' : 'MEDIUM';

      // Confirmed vs Hypothesis Evaluation:
      const confirmedAttack = isCredentialSprayingCandidate || (isMultiEndpoint && hasSuspiciousAttack);
      const credentialSprayingConfirmed = isCredentialSprayingCandidate;
      const bruteForceConfirmed = failedAuthEvents.length >= 10;
      const compromiseConfirmed = false;

      let incidentTitle = '';
      let correlationType = 'AUTHENTICATION_ANOMALY';
      let incidentVerdict = 'INVESTIGATION_CANDIDATE';
      let incidentSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

      if (credentialSprayingConfirmed) {
        incidentTitle = `${ip} Kaynaklı Parola Püskürtme (Credential Spraying)`;
        correlationType = 'CREDENTIAL_SPRAYING';
        incidentVerdict = 'SUSPICIOUS_ANOMALY';
        incidentSeverity = 'HIGH';
      } else if (isMultiEndpoint && hasSuspiciousAttack) {
        incidentTitle = `${ip} Kaynaklı Çoklu Uç Nokta Kimlik Doğrulama Dizisi`;
        correlationType = 'MULTI_ENDPOINT_ANOMALY';
        incidentVerdict = 'SUSPICIOUS_ANOMALY';
        incidentSeverity = 'MEDIUM';
      } else {
        // Routine or small failure sequence (e.g. 2 failures + 1 success)
        incidentTitle = `${ip}: Kimlik Doğrulama Dizisi (Korelasyon Adayı — Teyit Gerekli)`;
        correlationType = 'AUTHENTICATION_ANOMALY';
        incidentVerdict = 'INVESTIGATION_CANDIDATE';
        incidentSeverity = ipEvents.length >= 8 ? 'MEDIUM' : 'LOW';
      }

      // Mitre techniques - ONLY if strictly evidenced!
      const mitres: string[] = [];
      if (credentialSprayingConfirmed) {
        mitres.push('T1110.003 (Credential Spraying)');
      } else if (bruteForceConfirmed) {
        mitres.push('T1110 (Brute Force Adayı)');
      }

      const confirmedFactsList: string[] = [
        `${ip} kaynak IP adresi ile ilişkili ${ipEvents.length} adet oturum kaydı`,
        ...ipEvents.map((e) => `Event #${e.index}: ${e.eventName} (${e.user || 'Kullanıcı'}, Durum: ${e.subStatus || e.status || e.verdictBadge.text})`),
      ];

      const hypothesesList: string[] = [
        'Kimlik doğrulama anomalisi / olası yetkisiz erişim denemesi',
        'Yetkili kullanıcının klavye yazım hatası ve ardından doğru parola ile oturum açması',
        'Eski parola saklayan otomatik istemci veya servis yazılımı kaynaklı tekrar denemesi',
      ];

      const missingEvidenceList: string[] = [];
      if (hasType2WithIp) {
        missingEvidenceList.push('Type 2 yerel oturumundaki kaynak IP adresinin uzaktan kimlik doğrulama kaynağı olduğuna dair bağımsız kanıt (Field Observation: UNCERTAIN)');
      }
      if (!credentialSprayingConfirmed) {
        missingEvidenceList.push('Parola püskürtme (Credential Spraying) teyidi için gereken 3+ farklı hesap ve sistematik püskürtme deseni (Yetersiz hedef çeşitliliği)');
      }
      if (!bruteForceConfirmed) {
        missingEvidenceList.push('Kaba kuvvet (Brute Force) tespiti için gereken sayıda ardışık deneme veya hesap kilitlenmesi (Mevcut deneme sayısı düşüktür)');
      }
      missingEvidenceList.push('Başarılı oturum sonrasında sistemin ele geçirildiğine (compromise) dair oturum içi şüpheli süreç veya eylem kaydı');

      const independentEvidenceLinksList: string[] = [
        `Ortak kaynak IP adresi (${ip})`,
      ];
      if (hasAuthTransition) {
        independentEvidenceLinksList.push('Kimlik doğrulama geçişi: 4625 başarısız oturum ardından 4624 başarılı oturum');
      }
      if (isMultiEndpoint) {
        independentEvidenceLinksList.push(`Çoklu hedef uç nokta: ${targets.join(', ')}`);
      }

      incidentCandidates.push({
        id,
        incidentId: id,
        title: incidentTitle,
        eventIds: indices,
        eventIndices: indices,
        correlationType,
        observedLinks: evidenceList,
        independentEvidenceLinks: independentEvidenceLinksList,
        supportingEvidence: [
          `${ip} adresinden ${targetUsers.join(', ')} hesaplarına yönelik ${ipEvents.length} adet oturum denemesi ve adli bağlantı`,
        ],
        missingEvidence: missingEvidenceList,
        hypotheses: hypothesesList,
        confirmedFacts: confirmedFactsList,
        confirmedAttack,
        credentialSprayingConfirmed,
        bruteForceConfirmed,
        compromiseConfirmed,
        confidence: confirmedAttack ? 80 : 55,
        verdict: incidentVerdict,
        sharedHost: targets.join(', ') || 'Windows Endpoint',
        sharedUser: targetUsers.join(', ') || 'Belirtilmemiş',
        sharedIp: ip,
        timeWindow: `${ipEvents[0].timestamp || 'Zaman Yok'} - ${ipEvents[ipEvents.length - 1].timestamp || 'Zaman Yok'}`,
        correlationStrength: strength,
        correlationEvidence: evidenceList,
        contributingFactors: evidenceList.map((e) => `+ ${e.replace(/^- /, '')}`),
        severity: incidentSeverity,
        narrative: `${ip} adresinden gerçekleştirilen ${ipEvents.length} adet işlemde ortak kaynak IP ve kimlik doğrulama dizisi gözlenmiştir. Mevcut kanıtlar kesin saldırı (brute force/spraying) iddialarını doğrulamamakta olup adli teyit gerektirmektedir.`,
        mitreTechniques: mitres,
        sequence: ipEvents.map((g) => ({
          eventIndex: g.index,
          eventId: g.eventId,
          timestamp: g.timestamp || 'Saat Yok',
          action: `${g.eventName} [Hedef: ${g.host || 'Bilinmiyor'}]`,
          verdict: g.verdictBadge.text,
        })),
      });
    }
  }

  // ============================================================================
  // MUTUALLY EXCLUSIVE MATHEMATICAL EVENT COUNTING
  // GUARANTEE: Total Events === incidentEventsCount + uncorrelatedEventsCount
  // ============================================================================
  const incidentEventIndicesSet = new Set<number>();
  incidentCandidates.forEach((inc) => {
    inc.eventIndices.forEach((idx) => incidentEventIndicesSet.add(idx));
  });
  const incidentEventsCount = incidentEventIndicesSet.size;
  const uncorrelatedEventsCount = totalEvents - incidentEventsCount;

  const uncorrelatedImportantEvents: number[] = [];
  const falsePositiveCandidates: number[] = [];
  let benignEventsCount = 0;
  let unknownEventsCount = 0;

  events.forEach((ev) => {
    if (incidentEventIndicesSet.has(ev.index)) return; // Already accounted in incidentEventsCount!

    if (
      ev.verdict === 'POTENTIAL_COMPROMISE' ||
      ev.verdict === 'BLOCKED_ATTACK_ATTEMPT' ||
      ev.verdict === 'SUSPICIOUS_ANOMALY'
    ) {
      uncorrelatedImportantEvents.push(ev.index);
    } else if (ev.verdict === 'LIKELY_FALSE_POSITIVE') {
      falsePositiveCandidates.push(ev.index);
    } else if (ev.verdict === 'AUTHORIZED_ACTIVITY') {
      benignEventsCount++;
    } else {
      unknownEventsCount++;
    }
  });

  // Security Posture Determination
  const hasHighStrengthIncident = incidentCandidates.some((i) => i.correlationStrength === 'HIGH');
  const hasCriticalIncident = incidentCandidates.some((i) => i.severity === 'CRITICAL');
  const hasHighSeverityIncident = incidentCandidates.some((i) => i.severity === 'HIGH');

  const criticalUncorrelatedCount = uncorrelatedImportantEvents.filter((idx) => {
    const ev = events.find((e) => e.index === idx);
    return ev?.verdict === 'POTENTIAL_COMPROMISE';
  }).length;

  const suspiciousUncorrelatedCount = uncorrelatedImportantEvents.filter((idx) => {
    const ev = events.find((e) => e.index === idx);
    return ev?.verdict === 'BLOCKED_ATTACK_ATTEMPT' || ev?.verdict === 'SUSPICIOUS_ANOMALY';
  }).length;

  // 1. Evidence-Based Summary Sentence (Mathematically Consistent)
  let evidenceBasedSummary = '';
  if (incidentCandidates.length > 0) {
    evidenceBasedSummary = `${rawLines} ham log satırı alındı. ${totalEvents} yapılandırılmış olay kaydı ayrıştırıldı. ${incidentEventsCount} olay ${incidentCandidates.length} adli zincirde (incident) korele edildi; ${uncorrelatedEventsCount} olay bağımsız niteliktedir (${uncorrelatedImportantEvents.length} bağımsız şüpheli/anomali, ${falsePositiveCandidates.length} yanlış alarm adayı, ${benignEventsCount} meşru/beklenen, ${unknownEventsCount} belirsiz).`;
  } else if (uncorrelatedImportantEvents.length > 0) {
    evidenceBasedSummary = `${rawLines} ham log satırı alındı. ${totalEvents} yapılandırılmış olay kaydı ayrıştırıldı. Olaylar arasında çoklu korelasyon zinciri saptanmadı; ${uncorrelatedImportantEvents.length} bağımsız şüpheli/anomali, ${falsePositiveCandidates.length} yanlış alarm adayı, ${benignEventsCount} meşru/beklenen, ${unknownEventsCount} belirsiz niteliğindedir.`;
  } else {
    if (unknownEventsCount > 0) {
      evidenceBasedSummary = `${rawLines} ham log satırı alındı. ${totalEvents} yapılandırılmış olay kaydı ayrıştırıldı. Ayrıştırılan olayların ${benignEventsCount} adedi meşru/beklenen operasyonel kayıt niteliğindedir; ${unknownEventsCount} adet olay ise telemetri/bağlam eksikliği sebebiyle belirsizdir (herhangi bir saldırı veya istismar emaresi saptanmamıştır).`;
    } else {
      evidenceBasedSummary = `${rawLines} ham log satırı alındı. ${totalEvents} yapılandırılmış olay kaydı ayrıştırıldı. Olayların tamamı (${benignEventsCount} meşru, ${falsePositiveCandidates.length} FP adayı) beklenen operasyonel kayıt niteliğindedir.`;
    }
  }

  // 2. Posture & Transparent Forensic Rationale
  let overallPosture: WholeLogSummary['overallPosture'] = 'BENIGN_NORMAL';
  let postureTitle = 'Meşru / Rutin Güvenlik Duruşu';
  let postureJustification = '';

  if (hasCriticalIncident || (hasHighStrengthIncident && hasHighSeverityIncident)) {
    overallPosture = 'CRITICAL_THREAT';
    postureTitle = 'Doğrulanmış Çoklu Olay Saldırı Zinciri / Aktif Tehdit';
    const topInc = incidentCandidates.find((i) => i.severity === 'CRITICAL') || incidentCandidates[0];
    postureJustification = `Gerekçe: Bu karar mekanik bir risk kuralı veya basit bir sayaç kopyalaması değildir. ${topInc.sharedHost} üzerinde ${topInc.timeWindow} penceresinde ardışık kanıtlarla (${topInc.correlationEvidence.slice(0, 3).map((e) => e.replace(/^- /, '')).join('; ')}) doğrulanan ${topInc.id} saldırı zincirine dayanmaktadır.`;
  } else if (incidentCandidates.length > 0 || criticalUncorrelatedCount > 0) {
    if (criticalUncorrelatedCount > 0) {
      overallPosture = 'CRITICAL_THREAT';
      postureTitle = 'İzole Kritik Güvenlik Olayları Tespit Edildi';
      postureJustification = `Gerekçe: Olaylar arasında ortak bir saldırı zinciri (incident) oluşturacak çoklu korelasyon bağı tespit edilmemiştir; ancak #${uncorrelatedImportantEvents.join(', #')} numaralı bağımsız olaylarda doğrudan kritik istismar/anomali saptandığı için izole yüksek risk kararı verilmiştir.`;
    } else {
      const allIncidentsAreCandidates = incidentCandidates.every(
        (i) => i.verdict === 'INVESTIGATION_CANDIDATE' || i.confirmedAttack === false || i.severity === 'LOW'
      );
      if (allIncidentsAreCandidates) {
        overallPosture = 'MIXED_INVESTIGATION';
        postureTitle = 'Kanıtlar Kesin Saldırıyı Doğrulamıyor — İnceleme Gerekli';
        postureJustification = `Gerekçe: Olay kümesinde tespit edilen ${incidentCandidates.length} adet korelasyon adayı (${incidentCandidates.map((i) => i.id).join(', ')}) kanıta dayalı bir adli hipotezdir; brute force, credential spraying veya sistem ihlali (compromise) doğrulanmamıştır. Bu sebeple kesin saldırı yerine adli inceleme ve teyit gerektiren anomali duruşu benimsenmiştir.`;
      } else {
        overallPosture = 'SUSPICIOUS_ACTIVITY';
        postureTitle = 'İnceleme Gerektiren Şüpheli Aktivite Zinciri';
        postureJustification = `Gerekçe: ${incidentCandidates.length} adet korelasyon adayı (${incidentCandidates.map((i) => i.id).join(', ')}) şüpheli davranış ve ardışık adli kanıtlar içermektedir; aktif adli teyit önerilir.`;
      }
    }
  } else if (suspiciousUncorrelatedCount > 0 || breakdown.anomaly > 0) {
    overallPosture = 'MIXED_INVESTIGATION';
    postureTitle = 'Münferit Anomaliler / İzole İnceleme Duruşu';
    const anomalyCount = suspiciousUncorrelatedCount > 0 ? suspiciousUncorrelatedCount : breakdown.anomaly;
    postureJustification = `Gerekçe: Olaylar arasında bir saldırı zinciri kurulmamış; yalnızca ${anomalyCount} adet bağımsız olayda şüpheli anomali veya inceleme gerektiren durum gözlenmiştir.`;
  } else if (unknownEventsCount > 0) {
    overallPosture = 'BENIGN_NORMAL';
    postureTitle = 'Tehdit Saptanmadı (Belirsiz Telemetri Mevcut)';
    postureJustification = `Gerekçe: İncelenen olaylar arasında teyit edilmiş bir saldırı sekansı veya kötü amaçlı tehdit göstergesi saptanmamıştır; ancak ${unknownEventsCount} adet olay yetersiz telemetri veya adli bağlam sebebiyle belirsiz olarak değerlendirilmiştir.`;
  } else {
    overallPosture = 'BENIGN_NORMAL';
    postureTitle = 'Meşru ve Beklenen Sistem Duruşu';
    postureJustification = 'Gerekçe: İncelenen tüm olaylarda yetkili idari işlemler veya olağan sistem günlükleri teyit edilmiştir; herhangi bir saldırı sekansı veya izole tehdit göstergesi saptanmamıştır.';
  }

  // Generate Overall Findings Narrative
  const overallFindings: string[] = [];
  overallFindings.push(`• Kanıta Dayalı Özet: ${evidenceBasedSummary}`);
  overallFindings.push(`• Güvenlik Duruşu Gerekçesi: ${postureJustification}`);
  overallFindings.push(`• Adli Dağılım: ${breakdown.critical} Kritik, ${breakdown.suspicious} Şüpheli, ${breakdown.anomaly} Anomali, ${breakdown.falsePositive} FP Adayı, ${breakdown.benign} Meşru, ${breakdown.unknown} Belirsiz.`);

  if (incidentCandidates.length > 0) {
    incidentCandidates.forEach((inc) => {
      overallFindings.push(`• [${inc.id}] ${inc.title} (Olaylar: #${inc.eventIndices.join(', #')} | Güç: ${inc.correlationStrength} | Seviye: ${inc.severity})`);
    });
  } else {
    overallFindings.push('• Çoklu olayları birleştiren doğrulanmış bir saldırı zinciri saptanmamıştır; olaylar adli açıdan bağımsız karakterdedir.');
  }

  if (uncorrelatedImportantEvents.length > 0) {
    overallFindings.push(`• Zincirlere dahil olmayan bağımsız önemli/şüpheli olaylar: #${uncorrelatedImportantEvents.join(', #')}`);
  }

  // Analyst Verification Actions (Section 27 - Targeted by missing evidence)
  const analystActions: string[] = [];

  const hasEvent104Unobserved = events.some((e) => e.eventId === 104);
  if (hasEvent104Unobserved) {
    analystActions.push('Kanal Bilgisi Eksik (Event 104): Olay günlüğü temizleme kaydının hangi kanala (System/Application/Security) ait olduğunu wevtutil veya Olay Görüntüleyicisi üzerinden doğrulayınız.');
  }

  const hasEvent1102 = events.some((e) => e.eventId === 1102);
  if (hasEvent1102) {
    analystActions.push('Güvenlik Günlüğü Sıfırlama (Event 1102): Sistem yöneticisi bakım kayıtlarını ve aynı zaman aralığında wevtutil.exe çağrısı olup olmadığını doğrulayınız.');
  }

  const hasType2WithIp = events.some((e) => e.eventId === 4624 && e.logonType === 2 && e.sourceIp !== '-');
  if (hasType2WithIp) {
    analystActions.push('Çelişkili Oturum Semantiği: Type 2 (Yerel İnteraktif) oturum kaydındaki harici kaynak IP adresini ham olay kaydı ve ağ günlüğü ile teyit ediniz.');
  }

  const hasMissingProcessParent = events.some((e) => (e.eventId === 4688 || e.eventId === 1) && !e.parentProcess);
  if (hasMissingProcessParent) {
    analystActions.push('Eksik Üst Süreç (Parent PID): Süreç yürütmeleri için EDR / Sysmon üzerinden çağıran üst süreç ve tam komut satırı ağacını sorgulayınız.');
  }

  const hasServiceInstall = events.some((e) => e.eventId === 7045 || e.eventId === 4697);
  if (hasServiceInstall) {
    analystActions.push('Servis Doğrulama (Event 7045): Yeni servis kurulumları için BT Değişiklik Yönetimi (Change Ticket) ve ikili dosya dijital imzasını doğrulayınız.');
  }

  if (incidentCandidates.length > 0) {
    incidentCandidates.forEach((inc) => {
      analystActions.push(`[${inc.id}] ${inc.sharedHost} üzerinde ${inc.sharedUser} hesabı için LogonId oturum bağımsızlığı sorgusu ve uç nokta telemetri teyidi gerçekleştiriniz.`);
    });
  }

  if (analystActions.length === 0) {
    analystActions.push('Mevcut log kümesinde aktif sömürü veya zincirleme saldırı emaresi görülmemiştir; rutin izleme statüsünde arşivlenebilir.');
  }

  return {
    totalEvents,
    rawLinesCount: rawLines,
    parsedRecordsCount: totalEvents,
    normalizedEventsCount: totalEvents,
    uncorrelatedEventsCount,
    breakdown,
    incidentCandidates,
    incidentEventsCount,
    uncorrelatedImportantEvents,
    falsePositiveCandidates,
    benignEventsCount,
    unknownEventsCount,
    overallPosture,
    postureTitle,
    postureJustification,
    evidenceBasedSummary,
    overallFindings,
    analystActions,
  };
}

/**
 * Generates the strictly ordered 6-stage SOC report requested by user:
 * 1. DOSYA / LOG ÖZETİ
 * 2. EVENT-BY-EVENT ANALYSIS
 * 3. CORRELATION ANALYSIS (Incident Candidates)
 * 4. UNCORRELATED IMPORTANT EVENTS
 * 5. WHOLE-LOG SUMMARY
 * 6. ANALYST ACTIONS
 */
export function generateComprehensive6StageReport(
  events: CorrelatedEventInput[],
  summary: WholeLogSummary,
  fileLabel = 'Analiz Edilen Log Dosyası',
  parserDiagnostic?: ParserDiagnosticReport
): string {
  const lines: string[] = [];
  const diag = parserDiagnostic || summary.parserDiagnostic;
  const isHardStop = summary.postureTitle.includes('ANALİZ TAMAMLANAMADI') || diag?.parserIntegrity === 'FAIL';

  // ============================================================================
  // 1. DOSYA / LOG ÖZETİ
  // ============================================================================
  lines.push('================================================================================');
  lines.push('1. DOSYA / LOG ÖZETİ');
  lines.push('================================================================================');
  lines.push(`Dosya / Kaynak: ${fileLabel}`);
  lines.push(`• Ham Satır Sayısı (Raw Log Lines): ${summary.rawLinesCount ?? summary.totalEvents}`);
  lines.push(`• Ayrıştırılabilen Olay Kaydı Sayısı (Parsed Event Records): ${summary.parsedRecordsCount ?? summary.totalEvents}`);
  lines.push(`• Normalize Edilmiş Benzersiz Olay Sayısı (Normalized Events): ${summary.normalizedEventsCount ?? summary.totalEvents}`);
  lines.push(`• Korelasyon Olay Zinciri Sayısı (Incident Candidates): ${isHardStop ? 0 : summary.incidentCandidates.length} adet`);
  lines.push(`• Korelasyona Dahil Olmayan Bağımsız Olay Sayısı (Uncorrelated Events): ${summary.uncorrelatedEventsCount ?? summary.uncorrelatedImportantEvents.length} adet`);
  lines.push(`• Adli Dağılım: ${summary.breakdown.critical} Kritik | ${summary.breakdown.suspicious} Şüpheli | ${summary.breakdown.anomaly} Anomali | ${summary.breakdown.falsePositive} FP Adayı | ${summary.breakdown.benign} Meşru | ${summary.breakdown.unknown} Belirsiz`);
  lines.push(`• Kanıta Dayalı Bütünsel Özet: ${summary.evidenceBasedSummary}`);
  lines.push(`Genel Güvenlik Duruşu: ${
    isHardStop
      ? 'ANALİZ TAMAMLANAMADI — EVENT PARSE BÜTÜNLÜĞÜ DOĞRULANAMADI'
      : summary.overallPosture === 'CRITICAL_THREAT'
      ? 'KRİTİK TEHDİT / AKTİF MÜDAHALE GEREKLİ'
      : summary.overallPosture === 'SUSPICIOUS_ACTIVITY'
      ? 'ŞÜPHELİ AKTİVİTE / İNCELEME GEREKLİ'
      : summary.overallPosture === 'MIXED_INVESTIGATION'
      ? 'ANOMALİ / DİKKAT GEREKTİREN DURUM'
      : 'MEŞRU / BEKLENEN ETKİNLİK'
  } [${summary.postureTitle}]`);
  lines.push(`Duruş Gerekçesi (Forensic Rationale): ${summary.postureJustification}`);
  lines.push('');

  // ============================================================================
  // 2. EVENT-BY-EVENT ANALYSIS
  // ============================================================================
  lines.push('================================================================================');
  lines.push('2. EVENT-BY-EVENT ANALYSIS (OLAY BAZINDA ADLİ AYRIŞTIRMA)');
  lines.push('================================================================================');
  lines.push('Her olay bağımsız bir adli nesne olarak incelenmiş, alanlar komşu olaylardan kopyalanmamıştır:');
  lines.push('');

  events.forEach((ev) => {
    lines.push(`--------------------------------------------------------------------------------`);
    lines.push(`[EVENT #${ev.index}] ${ev.isWindows && ev.eventId ? `Event ID ${ev.eventId} - ${ev.eventName}` : ev.threatTitle}`);
    lines.push(`  • Verdict: ${ev.verdictBadge.text}`);
    lines.push(`  • Hedef Host: ${ev.host || 'Bilinmiyor / Uygulanamaz'}`);
    lines.push(`  • Kullanıcı / Hesap: ${ev.user || 'Bilinmiyor / Uygulanamaz'}`);
    if (ev.isWindows) {
      if (ev.eventId === 4688 || ev.eventId === 1) {
        lines.push(`  • Yürütülen Süreç: ${ev.commandLine || ev.process || 'Belirtilmemiş'}`);
        lines.push(`  • Üst Süreç (Parent): ${ev.parentProcess || 'Belirtilmemiş'}`);
        lines.push(`  • Oturum Türü: Uygulanamaz (Süreç oluşturma)`);
        lines.push(`  • Ağ Kaynak IP: Uygulanamaz (Uç nokta içi)`);
      } else if (ev.eventId === 7045 || ev.eventId === 4697) {
        lines.push(`  • Servis Adı: ${ev.serviceName || 'Belirtilmemiş'}`);
        lines.push(`  • Servis Dosyası: ${ev.serviceFile || 'Belirtilmemiş'}`);
        lines.push(`  • Oturum Türü: Uygulanamaz (Servis kurulumu)`);
      } else {
        lines.push(`  • Oturum Türü: ${ev.logonTypeDesc}`);
        lines.push(`  • Hata Kodu / Neden: ${ev.subStatus ? `${ev.subStatus} (${ev.subStatusDesc})` : ev.status || 'Normal Akış'}`);
        lines.push(`  • Kaynak IP: ${ev.sourceIp !== '-' ? ev.sourceIp : 'Bilinmiyor / Uygulanamaz'}`);
      }
    } else {
      lines.push(`  • Kaynak IP: ${ev.sourceIp !== '-' ? ev.sourceIp : 'Bilinmiyor'}`);
      lines.push(`  • Hedef IP: ${ev.destIp !== '-' ? ev.destIp : 'Bilinmiyor'}`);
    }
    if (ev.mitreTechnique) {
      lines.push(`  • MITRE ATT&CK: ${ev.mitreTechnique}`);
    }
    lines.push(`  • Gerekçe: ${ev.summaryReason}`);
  });
  lines.push('');

  // ============================================================================
  // 3. CORRELATION ANALYSIS (INCIDENT CANDIDATES)
  // ============================================================================
  lines.push('================================================================================');
  lines.push('3. CORRELATION ANALYSIS (İLİŞKİLİ OLAY ZİNCİRLERİ)');
  lines.push('================================================================================');
  if (summary.incidentCandidates.length === 0) {
    lines.push('Log dosyasında çoklu olayları birleştiren doğrulanmış bir saldırı zinciri tespit edilmemiştir.');
    lines.push('Olaylar aynı dosyada bulunmakla birlikte adli bağlamları (host, kullanıcı, IP, zaman) birbirinden bağımsızdır.');
  } else {
    summary.incidentCandidates.forEach((inc) => {
      lines.push(`--------------------------------------------------------------------------------`);
      lines.push(`[${inc.id}] ${inc.title}`);
      lines.push(`Events: #${inc.eventIndices.join(', #')}`);
      lines.push('');
      lines.push('Evidence:');
      inc.correlationEvidence.forEach((evLine) => {
        lines.push(evLine.startsWith('- ') ? evLine : `- ${evLine}`);
      });
      lines.push('');
      lines.push(`Correlation Strength: ${inc.correlationStrength}`);
      lines.push(`Severity: ${inc.severity}`);
      lines.push(`Ortak Host: ${inc.sharedHost} | Ortak Kullanıcı: ${inc.sharedUser} | Zaman: ${inc.timeWindow}`);
      if (inc.mitreTechniques.length > 0) {
        lines.push(`Korele MITRE ATT&CK Matrisi: ${inc.mitreTechniques.join(', ')}`);
      }
      lines.push('Olay Akış Sırası (Chronological Sequence):');
      inc.sequence.forEach((s) => {
        lines.push(`  - [#${s.eventIndex}] ${s.timestamp} | ${s.action} -> [${s.verdict}]`);
      });
    });
  }
  lines.push('');

  // ============================================================================
  // 4. UNCORRELATED IMPORTANT EVENTS
  // ============================================================================
  lines.push('================================================================================');
  lines.push('4. UNCORRELATED IMPORTANT EVENTS (İLİŞKİSİZ ÖNEMLİ / ŞÜPHELİ OLAYLAR)');
  lines.push('================================================================================');
  if (summary.uncorrelatedImportantEvents.length === 0) {
    lines.push('Olay zincirleri dışında kalan münferit kritik/şüpheli olay bulunmamaktadır.');
  } else {
    lines.push('Aşağıdaki olaylar kendi başlarına şüpheli veya inceleme gerektiren nitelikte olup,');
    lines.push('diğer olaylarla host, kullanıcı veya süreç bağı tespit edilemediği için bağımsız tutulmuştur:');
    lines.push('');
    summary.uncorrelatedImportantEvents.forEach((idx) => {
      const ev = events.find((e) => e.index === idx);
      if (ev) {
        lines.push(`• [Olay #${ev.index}] ${ev.threatTitle} (Verdict: ${ev.verdictBadge.text})`);
        lines.push(`   Host: ${ev.host || 'Bilinmiyor'} | Kullanıcı: ${ev.user || 'Bilinmiyor'} | IP: ${ev.sourceIp}`);
        lines.push(`   Neden: ${ev.summaryReason}`);
      }
    });
  }
  lines.push('');

  // ============================================================================
  // 5. WHOLE-LOG SUMMARY
  // ============================================================================
  lines.push('================================================================================');
  lines.push('5. WHOLE-LOG SUMMARY (BÜTÜNSEL LOG DEĞERLENDİRMESİ)');
  lines.push('================================================================================');
  summary.overallFindings.forEach((f) => lines.push(f));
  lines.push('');

  // ============================================================================
  // 6. ANALYST ACTIONS
  // ============================================================================
  lines.push('================================================================================');
  lines.push('6. ANALYST ACTIONS (DOĞRULANMASI GEREKEN ADIMLAR VE TEYİTLER)');
  lines.push('================================================================================');
  summary.analystActions.forEach((act, i) => lines.push(`${i + 1}. ${act}`));
  lines.push('');
  lines.push('SOC Güvenlik Operasyonları Merkezi');
  lines.push('');

  // ============================================================================
  // EVENT ACCOUNTING & PARSER DIAGNOSTIC REPORT (SECTION 10 REQUIREMENT)
  // ============================================================================
  lines.push('================================================================================');
  lines.push('EVENT ACCOUNTING');
  lines.push('-----------------');
  lines.push(`Raw Lines:                 ${summary.rawLinesCount ?? summary.totalEvents}`);
  lines.push(`Parsed Events:              ${summary.parsedRecordsCount ?? summary.totalEvents}`);
  lines.push(`Normalized Events:          ${summary.normalizedEventsCount ?? summary.totalEvents}`);
  lines.push(`Unique Parsed Events:       ${summary.totalEvents}`);
  lines.push(`Incident Candidates:          ${isHardStop ? 0 : summary.incidentCandidates.length}`);
  lines.push(`Events in Incidents:          ${isHardStop ? 0 : summary.incidentEventsCount}`);
  lines.push(`Uncorrelated Events:          ${summary.uncorrelatedEventsCount}`);
  lines.push('');
  lines.push('CHECK:');
  const parsedPass =
    (summary.parsedRecordsCount ?? summary.totalEvents) === (summary.normalizedEventsCount ?? summary.totalEvents) &&
    (summary.normalizedEventsCount ?? summary.totalEvents) === summary.totalEvents;
  const bucketSum =
    summary.breakdown.critical +
    summary.breakdown.suspicious +
    summary.breakdown.anomaly +
    summary.breakdown.falsePositive +
    summary.breakdown.benign +
    summary.breakdown.unknown;
  const bucketPass = bucketSum === summary.totalEvents;
  const membershipPass = (isHardStop ? 0 : summary.incidentEventsCount) + summary.uncorrelatedEventsCount === summary.totalEvents;

  lines.push(`Parsed + normalization invariant = ${parsedPass ? 'PASS' : 'FAIL'}`);
  lines.push(`Verdict bucket sum = ${bucketPass ? 'PASS' : 'FAIL'}`);
  lines.push(`Incident membership accounting = ${membershipPass ? 'PASS' : 'FAIL'}`);
  lines.push(`Duplicate event detection = ${diag?.duplicateIdentity || 'PASS'}`);
  lines.push(`Field provenance = ${diag?.fieldProvenance || (isHardStop ? 'FAIL' : 'PASS')}`);
  lines.push(`(Doğrulama: Events in Incidents [${isHardStop ? 0 : summary.incidentEventsCount}] + Uncorrelated Events [${summary.uncorrelatedEventsCount}] = ${summary.totalEvents})`);
  lines.push('================================================================================');

  if (diag) {
    lines.push('');
    lines.push('--------------------------------------------------');
    lines.push('PARSER DIAGNOSTIC REPORT');
    lines.push('--------------------------------------------------');
    lines.push(`Raw Lines: ${diag.rawLinesCount}`);
    lines.push(`Candidate Event Boundaries: ${diag.candidateBoundariesCount}`);
    lines.push(`Parsed Events: ${diag.parsedEventsCount}`);
    lines.push(`Normalized Events: ${diag.normalizedEventsCount}`);
    lines.push(`Unparsed Records: ${diag.unparsedRecordsCount}`);
    lines.push(`Duplicate Records Dropped: ${diag.duplicateRecordsCount}`);
    lines.push(`Cross-Event Contamination: ${diag.crossEventContamination}`);
    lines.push(`Field Provenance Integrity: ${diag.fieldProvenance}`);
    lines.push(`Duplicate Identity Integrity: ${diag.duplicateIdentity}`);
    lines.push(`Multiline Handling: ${diag.multilineHandling}`);
    lines.push(`Event Boundary Integrity: ${diag.eventBoundaryIntegrity}`);
    lines.push(`Parser Completeness: ${diag.parserCompleteness}`);
    lines.push(`Unmatched Line Accounting: ${diag.unmatchedLineAccounting}`);
    lines.push(`Overall Parser Integrity: ${diag.parserIntegrity}`);
    lines.push('--------------------------------------------------');
    if (diag.failures && diag.failures.length > 0) {
      lines.push('FAIL DETAYLARI:');
      diag.failures.forEach((f) => {
        lines.push(`- Fail Sebebi: ${f.reason} [Kontrol: ${f.check}]`);
        lines.push(`  Fail Eden Satır Numaraları: ${f.lineNumbers.join(', ')}`);
        lines.push(`  Fail Eden Raw Text Snippet: ${f.snippet.replace(/\n/g, ' ')}`);
      });
      lines.push('--------------------------------------------------');
    }
  }

  return lines.join('\n');
}
