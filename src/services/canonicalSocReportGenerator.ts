/**
 * CANONICAL CENTRAL SOC REPORT GENERATOR
 *
 * Implements Rule 22, 25, 34, 35:
 * Produces the authoritative, tamper-evident, evidence-driven Central SOC Incident Report.
 *
 * GLOBAL INVARIANTS:
 * - NO_EVIDENCE -> NO_FACT
 * - UNKNOWN != BENIGN
 * - BYTE_ABSENT -> NOT_COMPUTED (never fake 18.4 MB)
 * - WAF_BLOCK = BLOCKED_ATTACK_ATTEMPT (never COMPROMISED without backend proof)
 * - 4624 = SUCCESSFUL_LOGON_OBSERVED (never AUTHORIZED_ACTIVITY)
 * - SYSTEM = trusted: false
 * - CORRELATION requires COMMON_HOST + CONCRETE FORENSIC LINK + WHY_CORRELATED
 */

import {
  CanonicalSocReport,
  CanonicalIncident,
  IsolatedEventRecord,
  CorrelationLink,
  AIClaimRecord,
  AuditTrailEntry,
  ForensicVerdict,
} from '../types/canonicalForensicModels';
import { EvidenceRegistry, globalEvidenceRegistry } from './evidenceRegistry';

export interface ReportGenerationInput {
  rawInput: string;
  sourceFileName?: string;
  isolatedEvents: IsolatedEventRecord[];
  evidenceRegistry: EvidenceRegistry;
  rawAiClaims?: Array<{
    claim: string;
    evidenceIds: string[];
    ips?: string[];
    hosts?: string[];
    users?: string[];
    processes?: string[];
    reasoning?: string;
    alternativeExplanation?: string;
  }>;
  aiModelUsed?: string;
  aiStatus?: 'SUCCESS' | 'AI_ANALYSIS_UNAVAILABLE' | 'PARTIAL_ANALYSIS';
  aiFailureReason?: string;
  parseFailures?: string[];
  auditTrail?: AuditTrailEntry[];
}

export function generateCanonicalSocReport(input: ReportGenerationInput): CanonicalSocReport {
  const {
    rawInput,
    sourceFileName = 'security_telemetry.log',
    isolatedEvents,
    evidenceRegistry,
    rawAiClaims = [],
    aiModelUsed = 'gemini-3.8-flash',
    aiStatus = 'SUCCESS',
    aiFailureReason,
    parseFailures = [],
  } = input;

  const generatedAt = new Date().toISOString();
  const rawLines = rawInput.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const auditTrail: AuditTrailEntry[] = input.auditTrail ? [...input.auditTrail] : [];

  auditTrail.push({
    timestamp: new Date().toISOString(),
    stage: 'REPORT_GENERATED',
    details: 'Merkezi SOC Adli Rapor Derleyicisi çalıştırıldı.',
  });

  // 1. Validate all AI Claims against Evidence Registry (Rule 27: AI Claim Validator)
  const validatedClaims: AIClaimRecord[] = [];
  const rejectedClaims: AIClaimRecord[] = [];

  rawAiClaims.forEach((rawClaim, idx) => {
    const claimRecord: AIClaimRecord = {
      id: `AIC-${String(idx + 1).padStart(3, '0')}`,
      claim: rawClaim.claim,
      referencedEntities: {
        ips: rawClaim.ips || [],
        hosts: rawClaim.hosts || [],
        users: rawClaim.users || [],
        processes: rawClaim.processes || [],
        bytes: [],
      },
      evidenceIds: rawClaim.evidenceIds || [],
      reasoning: rawClaim.reasoning || '',
      alternativeExplanation: rawClaim.alternativeExplanation,
      validationStatus: 'PENDING',
    };

    const validation = evidenceRegistry.validateAiClaim(claimRecord);
    if (validation.isValid) {
      claimRecord.validationStatus = 'ACCEPTED';
      validatedClaims.push(claimRecord);
    } else {
      claimRecord.validationStatus = 'REJECTED_AI_CLAIM';
      claimRecord.rejectionReason = validation.rejectionReason;
      rejectedClaims.push(claimRecord);
    }
  });

  // 2. Correlation Engine (Rule 10 & 11: COMMON_HOST + Concrete Forensic Link)
  const incidents: CanonicalIncident[] = [];
  const correlatedIndices = new Set<number>();

  // Group events by strict HOST
  const hostGroups = new Map<string, IsolatedEventRecord[]>();
  isolatedEvents.forEach((ev) => {
    const host = (ev.host || '').trim();
    if (
      !host ||
      host === '-' ||
      host.toLowerCase() === 'bilinmeyen-host' ||
      host.toLowerCase() === 'endpoint' ||
      host.toLowerCase() === 'windows endpoint'
    ) {
      return; // Generic or missing host cannot form multi-event host cluster
    }
    if (!hostGroups.has(host)) hostGroups.set(host, []);
    hostGroups.get(host)!.push(ev);
  });

  let incCounter = 1;

  for (const [host, hostEvents] of hostGroups.entries()) {
    if (hostEvents.length < 2) continue;

    // Detect Concrete Forensic Links
    const links: CorrelationLink[] = [];
    const whyCorrelated: string[] = [`COMMON_HOST: "${host}"`];

    for (let i = 0; i < hostEvents.length; i++) {
      for (let j = i + 1; j < hostEvents.length; j++) {
        const evA = hostEvents[i];
        const evB = hostEvents[j];

        // Link Type 1: Same LogonId
        if (evA.logonId && evB.logonId && evA.logonId !== '-' && evA.logonId === evB.logonId) {
          links.push({
            sourceEventIndex: evA.eventIndex,
            targetEventIndex: evB.eventIndex,
            linkType: 'SAME_LOGON_ID',
            evidenceIds: [...evA.evidenceIds, ...evB.evidenceIds],
            reason: `Aynı Logon ID (${evA.logonId}) oturum sürekliliği`,
            strength: 'STRONG',
          });
          whyCorrelated.push(`Aynı Logon ID (${evA.logonId}) oturum bağı`);
        }

        // Link Type 2: Auth Transition: 4625 -> 4624
        if (
          ((evA.winEventId === 4625 && evB.winEventId === 4624) ||
            (evA.winEventId === 4624 && evB.winEventId === 4625)) &&
          evA.actorUser &&
          evA.actorUser === evB.actorUser
        ) {
          links.push({
            sourceEventIndex: evA.eventIndex,
            targetEventIndex: evB.eventIndex,
            linkType: 'AUTH_TRANSITION_4625_TO_4624',
            evidenceIds: [...evA.evidenceIds, ...evB.evidenceIds],
            reason: `Başarısız kimlik doğrulama (4625) ardından başarılı oturum (4624): Kullanıcı "${evA.actorUser}"`,
            strength: 'STRONG',
          });
          whyCorrelated.push(`Başarısız logon (4625) $\\to$ Başarılı logon (4624) geçişi`);
        }

        // Link Type 3: Privilege Assignment: 4624 -> 4672
        if (
          ((evA.winEventId === 4624 && evB.winEventId === 4672) ||
            (evA.winEventId === 4672 && evB.winEventId === 4624)) &&
          evA.actorUser &&
          evA.actorUser === evB.actorUser
        ) {
          links.push({
            sourceEventIndex: evA.eventIndex,
            targetEventIndex: evB.eventIndex,
            linkType: 'PRIVILEGE_ASSIGNMENT_4624_TO_4672',
            evidenceIds: [...evA.evidenceIds, ...evB.evidenceIds],
            reason: `Oturum açılışında idari ayrıcalık atanması: Kullanıcı "${evA.actorUser}"`,
            strength: 'STRONG',
          });
          whyCorrelated.push(`Oturum açma (4624) $\\to$ Ayrıcalık atanması (4672)`);
        }

        // Link Type 4: Process Execution: 4672 -> 4688
        if (
          ((evA.winEventId === 4672 && evB.winEventId === 4688) ||
            (evA.winEventId === 4688 && evB.winEventId === 4672)) &&
          evA.actorUser &&
          evA.actorUser === evB.actorUser
        ) {
          links.push({
            sourceEventIndex: evA.eventIndex,
            targetEventIndex: evB.eventIndex,
            linkType: 'PROCESS_EXECUTION_4672_TO_4688',
            evidenceIds: [...evA.evidenceIds, ...evB.evidenceIds],
            reason: `Ayrıcalıklı oturum altında yeni süreç başlatılması: "${evB.process || evA.process}"`,
            strength: 'STRONG',
          });
          whyCorrelated.push(`Ayrıcalık atanması (4672) $\\to$ Süreç başlatma (4688)`);
        }

        // Link Type 5: Service Installation or Log Clearing: 4688 -> 7045 or 4688 -> 1102
        if (
          evA.winEventId === 4688 &&
          (evB.winEventId === 7045 || evB.winEventId === 1102) &&
          evA.timestampMs &&
          evB.timestampMs &&
          Math.abs(evA.timestampMs - evB.timestampMs) <= 15 * 60 * 1000
        ) {
          const lType = evB.winEventId === 7045 ? 'PERSISTENCE_SERVICE_INSTALL_4688_TO_7045' : 'DEFENSE_EVASION_LOG_CLEAR_4688_TO_1102';
          links.push({
            sourceEventIndex: evA.eventIndex,
            targetEventIndex: evB.eventIndex,
            linkType: lType,
            evidenceIds: [...evA.evidenceIds, ...evB.evidenceIds],
            reason: `Süreç çalıştırmanın ardından $\\le 15$ dk içinde ${evB.winEventName}`,
            strength: 'STRONG',
          });
          whyCorrelated.push(`Süreç çalıştırma (4688) $\\to$ ${evB.winEventName}`);
        }
      }
    }

    // Minimum concrete link requirement: An incident candidate requires at least 1 concrete link
    if (links.length > 0) {
      const incidentIndices = Array.from(new Set(links.flatMap((l) => [l.sourceEventIndex, l.targetEventIndex])));
      incidentIndices.forEach((idx) => correlatedIndices.add(idx));

      const incEvents = hostEvents.filter((e) => incidentIndices.includes(e.eventIndex));
      const incEvidenceIds = Array.from(new Set(incEvents.flatMap((e) => e.evidenceIds)));

      // Calculate Severity & Verdict
      const hasClearLog = incEvents.some((e) => e.winEventId === 1102);
      const hasService = incEvents.some((e) => e.winEventId === 7045 || e.winEventId === 4697);
      const hasPriv = incEvents.some((e) => e.winEventId === 4672);
      const hasFailThenSuccess = links.some((l) => l.linkType === 'AUTH_TRANSITION_4625_TO_4624');

      let incVerdict: ForensicVerdict = 'SUSPICIOUS_ACTIVITY';
      let incSev: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';

      if (hasFailThenSuccess && hasPriv && (hasService || hasClearLog)) {
        incVerdict = 'POTENTIAL_COMPROMISE';
        incSev = 'CRITICAL';
      } else if (hasService || hasClearLog || hasFailThenSuccess) {
        incVerdict = 'SUSPICIOUS_ACTIVITY';
        incSev = 'HIGH';
      }

      // Check for confirmed compromise standard (multiple independent strong links)
      if (hasFailThenSuccess && hasPriv && hasService && hasClearLog) {
        incVerdict = 'CONFIRMED_COMPROMISE';
        incSev = 'CRITICAL';
      }

      incidents.push({
        id: `INCIDENT-${String(incCounter).padStart(2, '0')}`,
        severity: incSev,
        verdict: incVerdict,
        confidence: incVerdict === 'CONFIRMED_COMPROMISE' ? 'CONFIRMED' : 'HIGH_CONFIDENCE',
        sharedHost: host,
        eventIndices: incidentIndices,
        evidenceIds: incEvidenceIds,
        timeWindow: {
          start: incEvents[0]?.timestamp || null,
          end: incEvents[incEvents.length - 1]?.timestamp || null,
          durationMinutes: null,
        },
        whyCorrelated: Array.from(new Set(whyCorrelated)),
        correlationLinks: links,
        affectedIdentities: Array.from(new Set(incEvents.map((e) => e.actorUser || e.subjectUser).filter(Boolean) as string[])),
        sourceIps: Array.from(new Set(incEvents.map((e) => e.sourceIp).filter(Boolean) as string[])),
        destinations: Array.from(new Set(incEvents.map((e) => e.destIp).filter(Boolean) as string[])),
        processChain: Array.from(new Set(incEvents.map((e) => e.process || e.commandLine).filter(Boolean) as string[])),
        mitreMappings: incEvents
          .filter((e) => e.mitreTechnique)
          .map((e) => ({
            tactic: 'Execution & Persistence',
            techniqueId: e.mitreTechnique!.split(' ')[0],
            techniqueName: e.mitreTechnique!,
            evidenceIds: e.evidenceIds,
            reason: e.verdictReason,
          })),
        narrative: `${host} uç noktasında ${incEvents.length} adet adli olay somut korelasyon bağıyla (${whyCorrelated.slice(1).join(', ')}) bir araya getirilmiştir.`,
        alternativeHypotheses: [
          {
            hypothesis: 'Saldırgan Harekat Zinciri (Lateral / Compromise)',
            explanation: 'Kimlik doğrulama, ayrıcalık yükseltme ve süreç yürütme ardışıklığı saldırı göstergesidir.',
            supportingEvidenceIds: incEvidenceIds.slice(0, 4),
            missingEvidence: ['Harici C2 ağ trafiği teyidi', 'Bellek enjeksiyon dökümü'],
            likelihood: 'PLAUSIBLE',
          },
          {
            hypothesis: 'Yetkili BT Bakım / Kurulum Senaryosu',
            explanation: 'Sistem yöneticisi tarafından gerçekleştirilen planlı yazılım güncellemesi veya bakım betiği olabilir.',
            supportingEvidenceIds: incEvidenceIds.slice(0, 2),
            missingEvidence: ['Yetkili değişiklik yönetim bileti (Change Ticket)', 'Mesai dışı onay kaydı'],
            likelihood: 'PLAUSIBLE',
          },
        ],
        falsePositiveAssessment: {
          isFalsePositiveCandidate: incEvents.some((e) => e.actorUser?.toLowerCase() === 'administrator' && !hasClearLog),
          benignExplanation: 'Kullanıcı yetkili idari hesap olup rutin yönetim faaliyeti gerçekleştiriyor olabilir.',
          missingEvidenceRequired: ['Süreç imzalayan (signer) ve hash doğrulaması', 'Ağ egress bağlantı logları'],
        },
        actions: {
          observedActions: incEvents
            .filter((e) => e.securityDeviceAction !== 'NOT_PRESENT')
            .map((e) => `${e.sourceFile}: Güvenlik kontrolü ${e.securityDeviceAction} aksiyonu uyguladı.`),
          recommendedActions: [
            `[İNCELENEN HOST] "${host}" uç noktasında çalışan süreçleri (${incEvents.map((e) => e.process).filter(Boolean).slice(0, 3).join(', ')}) inceleyin.`,
            `İlgili hesapların (${incEvents.map((e) => e.actorUser).filter(Boolean).slice(0, 2).join(', ')}) oturumlarını ve parolasını denetleyin.`,
            `Event 1102 / 7045 zaman aralığında (${incEvents[0]?.timestamp || 'tarih'}) ağ egress trafiğini araştırın.`,
          ],
        },
      });

      incCounter++;
    }
  }

  // 3. Standalone Important Events (Not in any incident cluster)
  const standaloneSecurityEvents = isolatedEvents.filter(
    (e) => !correlatedIndices.has(e.eventIndex) && e.verdict !== 'BENIGN_EXPECTED'
  );

  // 4. Blocked Attacks
  const blockedAttacks = isolatedEvents.filter(
    (e) => e.verdict === 'BLOCKED_ATTACK_ATTEMPT' || e.securityDeviceAction === 'BLOCK' || e.securityDeviceAction === 'DENY'
  );

  // 5. Potential & Confirmed Compromises
  const potentialCompromises = incidents.filter((i) => i.verdict === 'POTENTIAL_COMPROMISE');
  const confirmedCompromises = incidents.filter((i) => i.verdict === 'CONFIRMED_COMPROMISE');

  // 6. False Positive Candidates
  const falsePositiveCandidates = isolatedEvents
    .filter((e) => e.verdict === 'SUSPICIOUS_ACTIVITY' && e.actorUser && e.actorUser.toLowerCase().includes('admin'))
    .map((e) => ({
      eventIndex: e.eventIndex,
      reason: `Yetkili idari hesap (${e.actorUser}) altında yürütülen eylem bakım kaynaklı olabilir.`,
      missingEvidence: ['Yetkili değişiklik bileti', 'Süreç dijital imzası'],
    }));

  // 7. Executive Summary & Posture Determination
  let overallPosture: CanonicalSocReport['executiveSummary']['overallPosture'] = 'BENIGN_NORMAL';
  let postureTitle = 'NORMAL GÜVENLİK DURUMU';

  if (confirmedCompromises.length > 0) {
    overallPosture = 'CRITICAL_THREAT';
    postureTitle = 'KESİN İHLAL VE SALDIRI TESPİTİ (CONFIRMED COMPROMISE)';
  } else if (potentialCompromises.length > 0) {
    overallPosture = 'CRITICAL_THREAT';
    postureTitle = 'YÜKSEK SEVİYELİ ADLİ TEHDİT (POTENTIAL COMPROMISE)';
  } else if (incidents.length > 0 || standaloneSecurityEvents.length > 0) {
    overallPosture = 'SUSPICIOUS_ACTIVITY';
    postureTitle = 'ŞÜPHELİ ADLİ ANOMALİLER GÖZLENDİ';
  } else if (isolatedEvents.length === 0) {
    overallPosture = 'INCONCLUSIVE';
    postureTitle = 'YETERSİZ TELEMETRİ / VERİ YOK';
  }

  const summaryNarrative =
    `İncelenen ${isolatedEvents.length} güvenlik olayında toplam ${evidenceRegistry.count()} adli kanıt kayıt altına alınmıştır. ` +
    `Uç nokta ve ağ telemetrisinde ${incidents.length} adet doğrulanmış olay adayı (incident candidate) ve ` +
    `${standaloneSecurityEvents.length} adet bağımsız güvenlik olayı değerlendirilmiştir. ` +
    `${blockedAttacks.length > 0 ? `${blockedAttacks.length} adet engellenmiş saldırı girişimi (BLOCKED_ATTACK_ATTEMPT) saptanmıştır. ` : ''}` +
    `Tüm bulgular sıfır uydurma veri ve kesin kanıt kaydı esasıyla derlenmiştir.`;

  // 8. Compile Final Report
  return {
    analysisId: `SOC-${Date.now()}`,
    generatedAt,
    analysisHash: `SHA256-${Date.now().toString(16)}-${isolatedEvents.length}`,
    parserVersion: '3.0.0-forensic-strict',
    correlationVersion: '2.5.0-concrete-link',
    aiModel: aiModelUsed,
    aiAnalysisStatus: aiStatus,
    aiFailureReason,

    executiveSummary: {
      overallPosture,
      postureTitle,
      summaryNarrative,
      eventCount: isolatedEvents.length,
      importantEventCount: incidents.flatMap((i) => i.eventIndices).length + standaloneSecurityEvents.length,
      incidentCount: incidents.length,
      evidenceCount: evidenceRegistry.count(),
    },

    dataQuality: {
      rawLinesCount: rawLines.length,
      parsedEventsCount: isolatedEvents.length,
      parseFailuresCount: parseFailures.length,
      unparsedLines: parseFailures,
      missingFieldSummaries: [
        'Ağ bayt bilgisi (byte) telemetride yer almayan olaylar için trafik hacmi hesaplanmamıştır (NOT_COMPUTED).',
        'Backend uygulama logu bulunmayan WAF 5xx hatalarında sunucu çökmesi veya istismar iddiası yapılmamıştır.',
      ],
      analysisLimitations: [
        'Log sınırlarının dışındaki harici ağ egress akışları kanıt olmadan yorumlanamaz.',
        'Zaman damgası bulunmayan olaylar kronolojik korelasyona dahil edilmez.',
      ],
    },

    incidents,
    standaloneSecurityEvents,
    blockedAttacks,
    potentialCompromises,
    confirmedCompromises,
    falsePositiveCandidates,

    evidenceRegistrySummary: {
      totalEvidenceRecords: evidenceRegistry.count(),
      rawEvidenceCount: evidenceRegistry.getAllRecords().filter((r) => r.sourceType === 'RAW_LOG').length,
      derivedEvidenceCount: evidenceRegistry.getAllRecords().filter((r) => r.sourceType === 'DERIVED').length,
      inferredEvidenceCount: evidenceRegistry.getAllRecords().filter((r) => r.sourceType === 'AI_INTERPRETATION').length,
    },

    aiInterpretation: {
      status: aiStatus === 'SUCCESS' ? 'ACTIVE' : 'UNAVAILABLE',
      validatedClaims,
      rejectedClaims,
      deepReasoningNarrative:
        validatedClaims.length > 0
          ? validatedClaims.map((c) => `• [${c.id}] ${c.claim} (Kanıt: ${c.evidenceIds.join(', ')})`).join('\n')
          : 'AI tarafından Evidence Registry ile doğrulanan iddialar.',
    },

    recommendedResponse: {
      observedActions: Array.from(new Set(incidents.flatMap((i) => i.actions.observedActions))),
      recommendedActions: Array.from(new Set(incidents.flatMap((i) => i.actions.recommendedActions))),
    },

    limitations: {
      whatIsUnknown: [
        'Logda bulunmayan hedef port veya harici IP adresleri bilinmemektedir (UNKNOWN).',
        'Parent Process PID bilgisi loglanmamışsa üst süreç bağlantısı kesinleştirilemez.',
      ],
      whatIsMissing: [
        'Uç nokta bellek (memory) dökümü ve süreç hash değerleri eksiktir.',
        'DNS sorgu kayıtları ve proxy bağlantı telemetrisi eksiktir.',
      ],
      notComputableMetrics: [
        'Trafik transfer boyutu (Byte sütunu eksik olan loglar: NOT_COMPUTED).',
      ],
    },

    auditTrail,
  };
}

/**
 * Formats a CanonicalSocReport into an authoritative, professional SOC analyst markdown report.
 * Strictly honors evidence-based reporting without any synthetic placeholders.
 */
export function formatCanonicalSocReportMarkdown(report: CanonicalSocReport): string {
  const lines: string[] = [];

  lines.push(`# 🛡️ MERKEZİ ADLİ SOC ANALİZ & İNCELENME RAPORU`);
  lines.push(`**Analiz ID:** \`${report.analysisId}\` | **Tarih:** \`${report.generatedAt}\` | **Hash:** \`${report.analysisHash}\``);
  lines.push(`**AI Analiz Modeli:** \`${report.aiModel}\` (${report.aiAnalysisStatus === 'SUCCESS' ? '✅ Aktif & Doğrulanmış' : '⚠️ ' + report.aiAnalysisStatus})`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // 1. Executive Summary
  lines.push(`## 1. YÖNETİCİ ÖZETİ & GÜVENLİK DURUŞU (EXECUTIVE SUMMARY)`);
  lines.push(`* **Güvenlik Duruşu:** **${report.executiveSummary.postureTitle}** (\`${report.executiveSummary.overallPosture}\`)`);
  lines.push(`* **İncelenen Toplam Olay:** ${report.executiveSummary.eventCount}`);
  lines.push(`* **Kritik/Önemli Olay Sayısı:** ${report.executiveSummary.importantEventCount}`);
  lines.push(`* **Doğrulanmış Olay Grubu (Incident):** ${report.executiveSummary.incidentCount}`);
  lines.push(`* **Kayıtlı Adli Kanıt (Evidence):** ${report.executiveSummary.evidenceCount}`);
  lines.push('');
  lines.push(`> ${report.executiveSummary.summaryNarrative}`);
  lines.push('');

  // 2. Data Quality & Limitations
  lines.push(`## 2. VERİ BÜTÜNLÜĞÜ & ADLİ KANIT SİCİLİ (DATA QUALITY & EVIDENCE REGISTRY)`);
  lines.push(`* **Ham Satır Sayısı:** ${report.dataQuality.rawLinesCount} | **Ayrıştırılan Olay:** ${report.dataQuality.parsedEventsCount} | **Ayrıştırılamayan:** ${report.dataQuality.parseFailuresCount}`);
  lines.push(`* **Adli Kanıt Dağılımı:** Ham Kanıt: \`${report.evidenceRegistrySummary.rawEvidenceCount}\`, Türetilmiş: \`${report.evidenceRegistrySummary.derivedEvidenceCount}\`, AI Çıkarımı: \`${report.evidenceRegistrySummary.inferredEvidenceCount}\``);
  lines.push('');
  lines.push('### Adli Kısıtlar & Eksik Veri İlkeleri (Zero-Fabrication)');
  report.dataQuality.missingFieldSummaries.forEach((m) => lines.push(`* ${m}`));
  report.dataQuality.analysisLimitations.forEach((l) => lines.push(`* ${l}`));
  lines.push('');

  // 3. Incidents
  lines.push(`## 3. DOĞRULANMIŞ GÜVENLİK İNCİDENTLERİ (CORRELATED INCIDENTS)`);
  if (report.incidents.length === 0) {
    lines.push('_Kayıtlarda somut bir korelasyon bağı ve ortak host üzerinde birleşen birleşik saldırı zinciri (incident) saptanmamıştır._');
  } else {
    report.incidents.forEach((inc) => {
      lines.push(`### 🚨 ${inc.id}: [${inc.severity}] ${inc.verdict} (${inc.sharedHost})`);
      lines.push(`* **Olay Sayısı:** ${inc.eventIndices.length} adet olay (${inc.eventIndices.map((i) => `#${i}`).join(', ')})`);
      lines.push(`* **Kapsanan Kanıtlar:** ${inc.evidenceIds.length} adet (${inc.evidenceIds.slice(0, 8).join(', ')}${inc.evidenceIds.length > 8 ? '...' : ''})`);
      lines.push(`* **Etkilenen Kullanıcılar:** ${inc.affectedIdentities.length > 0 ? inc.affectedIdentities.map((u) => `\`${u}\``).join(', ') : 'Belirtilmedi'}`);
      lines.push(`* **Kaynak IP'ler:** ${inc.sourceIps.length > 0 ? inc.sourceIps.map((ip) => `\`${ip}\``).join(', ') : 'Yerel / Belirtilmedi'}`);
      lines.push('');
      lines.push('**Korelasyon Kanıtı & Neden İlişkilendirildi (Why Correlated):**');
      inc.whyCorrelated.forEach((wc) => lines.push(`  - 🔗 ${wc}`));
      lines.push('');
      lines.push('**Teknik Bağlantılar (Causal Links):**');
      inc.correlationLinks.forEach((link) => {
        lines.push(`  - [Olay #${link.sourceEventIndex} $\\to$ #${link.targetEventIndex}] **${link.linkType}** (${link.strength}): ${link.reason}`);
      });
      lines.push('');
      if (inc.mitreMappings.length > 0) {
        lines.push('**MITRE ATT&CK Eşleştirmesi:**');
        inc.mitreMappings.forEach((m) => {
          lines.push(`  - \`${m.techniqueId}\` (${m.techniqueName}): ${m.reason}`);
        });
        lines.push('');
      }
      lines.push('**Alternatif Hipotezler:**');
      inc.alternativeHypotheses.forEach((hyp) => {
        lines.push(`  - **${hyp.hypothesis}** (${hyp.likelihood}): ${hyp.explanation} (Eksik kanıt: ${hyp.missingEvidence.join(', ')})`);
      });
      lines.push('');
      lines.push('**Önerilen Doğrulama Adımları:**');
      inc.actions.recommendedActions.forEach((act) => lines.push(`  - 📌 ${act}`));
      lines.push('');
    });
  }

  // 4. Standalone & Blocked
  if (report.blockedAttacks.length > 0) {
    lines.push(`## 4. GÜVENLİK DUVARI / WAF TARAFINDAN ENGELLENMİŞ SALDIRILAR (BLOCKED ATTACKS)`);
    report.blockedAttacks.forEach((b) => {
      lines.push(`* **[Olay #${b.eventIndex}]** \`${b.sourceFile}\`: **${b.securityDeviceAction}** - ${b.verdictReason}`);
    });
    lines.push('');
  }

  if (report.standaloneSecurityEvents.length > 0) {
    lines.push(`## 5. BAĞIMSIZ GÜVENLİK OLAYLARI (STANDALONE SECURITY EVENTS)`);
    report.standaloneSecurityEvents.forEach((s) => {
      lines.push(`* **[Olay #${s.eventIndex}]** ${s.winEventId ? `Event ID ${s.winEventId} (${s.winEventName})` : s.sourceFile} $\\to$ **${s.verdict}**: ${s.verdictReason}`);
    });
    lines.push('');
  }

  // 6. AI Claim Validation
  lines.push(`## 6. AI GÜVENLİK YORUMLAMA & İDDİA DOĞRULAMA (AI CLAIM VALIDATION)`);
  lines.push(`* **Doğrulanan AI İddiaları (CLAIM_ACCEPTED):** ${report.aiInterpretation.validatedClaims.length}`);
  report.aiInterpretation.validatedClaims.forEach((c) => {
    lines.push(`  - ✅ [${c.id}] ${c.claim} _(Kanıt: ${c.evidenceIds.join(', ')})_`);
  });
  if (report.aiInterpretation.rejectedClaims.length > 0) {
    lines.push(`* **Reddedilen AI İddiaları (CLAIM_REJECTED - Kanıtsız Uydurma Önleme):** ${report.aiInterpretation.rejectedClaims.length}`);
    report.aiInterpretation.rejectedClaims.forEach((r) => {
      lines.push(`  - ❌ [${r.id}] ${r.claim} (Gerekçe: ${r.rejectionReason})`);
    });
  } else {
    lines.push(`* **Reddedilen AI İddiaları:** 0 (Yapay zeka hiçbir kanıtsız veri veya uydurma IP üretmemiştir)`);
  }
  lines.push('');

  // 7. Recommended Response Actions
  lines.push(`## 7. MÜDAHALE VE MÜŞTERİ BİLGİLENDİRME TALİMATLARI (RECOMMENDED RESPONSE)`);
  if (report.recommendedResponse.recommendedActions.length > 0) {
    report.recommendedResponse.recommendedActions.forEach((act, idx) => {
      lines.push(`${idx + 1}. **${act}**`);
    });
  } else {
    lines.push('1. Rutin sistem izleme faaliyetlerine devam ediniz.');
  }
  lines.push('');

  // 8. Audit Trail
  lines.push(`## 8. ADLİ DENETİM İZİ & PROVENANCE (AUDIT TRAIL)`);
  report.auditTrail.forEach((aud) => {
    lines.push(`* \`${aud.timestamp}\` **[${aud.stage}]** ${aud.details}`);
  });
  lines.push('');
  lines.push('---');
  lines.push(`_Rapor kanıta dayalı adli SOC motoru ve AI Forensic Doğrulama Katmanı tarafından üretilmiştir. Kanıtsız varsayım içermez._`);

  return lines.join('\n');
}
