import {
  UniversalEvidence,
  DynamicHypothesis,
  SourceType,
} from '../types/investigationEvidence';
import { NormalizedLog } from '../types';
import {
  WindowsEventDetails,
  CrossEventCorrelation,
  buildCrossEventCorrelations,
  extractWindowsDetails,
  generateTailoredExtraInfo,
  auditEventContamination,
} from './quickTriageHelper';
import {
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
  getFormatDisplayName,
  FileFormatState,
} from './streamingParser';
import { extractUniversalEvidence } from './universalEvidenceExtractor';
import {
  synthesizeDynamicHypotheses,
} from './dynamicHypothesisEngine';

export type ForensicVerdict =
  | 'LIKELY_FALSE_POSITIVE'
  | 'BLOCKED_ATTACK_ATTEMPT'
  | 'SUSPICIOUS_ANOMALY'
  | 'POTENTIAL_COMPROMISE'
  | 'AUTHORIZED_ACTIVITY'
  | 'UNKNOWN'
  | 'NOT_ASSESSED';

export interface UnifiedDecisionBadge {
  text: string;
  badgeClasses: string;
  cardClasses: string;
  iconBgClasses: string;
  iconType: 'shieldCheck' | 'shieldAlert' | 'alertTriangle' | 'shield' | 'info';
}

export interface UnifiedDecisionResult {
  parsedLog: NormalizedLog | null;
  detectedFormat: string;
  verdict: ForensicVerdict;
  verdictBadge: UnifiedDecisionBadge;
  confidence: number;
  confidenceLabel: string;
  threatTitle: string;
  summaryReason: string;
  deepForensics: string[];
  customerResponseText: string;
  requiredExtraInfo: string[];
  rawKeyValues: Record<string, string>;
  winDetails: WindowsEventDetails;
  correlations: CrossEventCorrelation[];
  action: string;
  isBlocked: boolean;
  universalEvidence: UniversalEvidence;
  dynamicHypotheses: DynamicHypothesis[];
  provenFacts: string[];
  unprovenHypotheses: string[];
  missingInformation: string[];
  dataIntegrityGuarded: boolean;
}

export interface UnifiedDecisionParams {
  rawLine: string;
  eventIndex?: number;
  formatState?: FileFormatState | null;
  parsedLog?: NormalizedLog | null;
  allWinDetails?: WindowsEventDetails[];
  sourceType?: SourceType;
  universalEvidence?: UniversalEvidence;
  semanticFormat?: string;
}

/**
 * UNIFIED DECISION ENGINE:
 * Implements the single decision spine:
 * INPUT -> FORMAT/SOURCE DETECTION -> EVIDENCE EXTRACTION (UniversalEvidence)
 *       -> OBSERVED/DERIVED/UNCERTAIN FACTS -> DYNAMIC HYPOTHESIS
 *       -> EVIDENCE SUFFICIENCY CHECK -> FINAL DECISION (ForensicVerdict)
 */
export function evaluateUnifiedDecision(params: UnifiedDecisionParams): UnifiedDecisionResult {
  const {
    rawLine,
    eventIndex = 0,
    allWinDetails = [],
    sourceType = 'TEXT_LOG',
    universalEvidence: providedEvidence,
  } = params;

  const line = rawLine;
  const trimmed = line.trim();

  // 1. FORMAT / SOURCE DETECTION
  let state = params.formatState;
  let parsed = params.parsedLog;

  if (!state && !providedEvidence) {
    state = initializeFormatState(`pasted_log_${eventIndex + 1}.log`);
    feedSampleLine(state, line);
  }
  if (parsed === undefined && !providedEvidence && state) {
    parsed = parseLineToNormalizedLog(line, state);
  }

  // Key-value extraction strictly for this event
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=(".*?"|\S+)/g;
  const kvDict: Record<string, string> = {};
  let match: RegExpExecArray | null;
  while ((match = kvRegex.exec(line)) !== null) {
    const k = match[1].toLowerCase();
    let v = match[2];
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    kvDict[k] = v;
  }

  // Windows Event Details
  const winDetails = extractWindowsDetails(line, kvDict, parsed);

  // Cross-event correlations
  const correlations = buildCrossEventCorrelations(
    eventIndex,
    allWinDetails.length > 0 ? allWinDetails : [winDetails]
  );

  const lowLine = line.toLowerCase();
  let formatName = state ? getFormatDisplayName(state.format) : (params.semanticFormat || 'Evrensel Telemetri');
  if (winDetails.isWindowsEvent) {
    formatName = 'Windows Güvenlik Olay Günlüğü';
  }

  // 2. EVIDENCE EXTRACTION (UniversalEvidence) - Use provided AI evidence directly if present
  const universalEvidence = providedEvidence || extractUniversalEvidence(line, parsed, sourceType);

  // STRICT ATTRIBUTIONS (Driven authoritatively by UniversalEvidence when available)
  const targetHost =
    universalEvidence.destinationEndpoint.host.value ||
    (winDetails.isWindowsEvent
      ? (winDetails.computer || winDetails.workstation || 'Windows Endpoint')
      : (kvDict.http_host || parsed?.sunucu_ismi || kvDict.host || ''));

  const srcIp =
    universalEvidence.sourceEndpoint.ip.value ||
    (winDetails.isWindowsEvent
      ? (winDetails.sourceIp !== 'Bilinmiyor' && winDetails.sourceIp !== '-' ? winDetails.sourceIp : '-')
      : (parsed?.ip_adresi || kvDict.src || kvDict.srcip || kvDict.sourceip || 'Bilinmiyor'));

  const dstIp =
    universalEvidence.destinationEndpoint.ip.value ||
    (winDetails.isWindowsEvent
      ? '-'
      : (parsed?.hedef_ip || kvDict.dst || kvDict.dstip || kvDict.destinationip || 'Bilinmiyor'));

  const dstPort =
    universalEvidence.destinationEndpoint.port.value
      ? String(universalEvidence.destinationEndpoint.port.value)
      : (winDetails.isWindowsEvent
          ? ''
          : (parsed?.hedef_port ? String(parsed.hedef_port) : kvDict.dst_port || kvDict.dstport || kvDict.destinationport || ''));

  const logTime =
    universalEvidence.timestamp.value ||
    parsed?.tarih ||
    (kvDict.date && kvDict.time ? `${kvDict.date} ${kvDict.time}` : kvDict.date || kvDict.time || 'Log zamanı');

  // 3. OBSERVED / DERIVED / UNCERTAIN FACTS & DYNAMIC HYPOTHESIS
  const dynamicSynth = synthesizeDynamicHypotheses(universalEvidence);
  const { hypotheses: dynamicHypotheses, provenFacts, unprovenHypotheses, missingEvidence: missingInformation } = dynamicSynth;

  // Real security action explicitly extracted from log (never fabricated from HTTP status code)
  const rawExplicitAction =
    kvDict.action ||
    kvDict.act ||
    kvDict.device_action ||
    kvDict.waf_action ||
    kvDict.policy_action ||
    kvDict.disposition ||
    kvDict.aksiyon ||
    kvDict.karar ||
    (universalEvidence.telemetry.wafAction.status === 'OBSERVED' ? universalEvidence.telemetry.wafAction.value : null) ||
    (universalEvidence.action.status === 'OBSERVED' && /drop|deny|block|reject|reset|prevent|blocked/i.test(universalEvidence.action.value || '') ? universalEvidence.action.value : null);

  const hasExplicitAction = Boolean(
    rawExplicitAction &&
    rawExplicitAction.trim() &&
    !['unknown', 'empty', 'undefined', 'none', '-'].includes(rawExplicitAction.toLowerCase().trim())
  );

  const isServerAuthOrDaemonLog = Boolean(
    /sshd|sudo|postfix|smtpd|pam/i.test(lowLine) ||
    /failed password|connection closed by invalid user|sasl.*failed|invalid user/i.test(lowLine)
  );

  const isWebServerAccessLog = Boolean(
    (state && (state.isApacheNginx || state.isW3C || /apache|nginx|w3c|iis/i.test(state.formatDisplayName))) ||
    universalEvidence.telemetry.httpStatus.value !== null ||
    universalEvidence.telemetry.rawPayload.value?.startsWith('/')
  );

  const pureFirewallDecision =
    !isWebServerAccessLog && !isServerAuthOrDaemonLog && (parsed?.baglanti_karari === 'DENY' || parsed?.baglanti_karari === 'ACCEPT')
      ? parsed.baglanti_karari
      : '';

  const isExplicitSecDevAction = Boolean(
    universalEvidence.telemetry.wafAction.status === 'OBSERVED' &&
    universalEvidence.telemetry.wafAction.value &&
    !isServerAuthOrDaemonLog
  );

  const wafAction = isExplicitSecDevAction
    ? universalEvidence.telemetry.wafAction.value!.trim()
    : (hasExplicitAction && !isServerAuthOrDaemonLog
        ? rawExplicitAction!.trim()
        : (winDetails.isWindowsEvent
            ? (parsed?.baglanti_karari || 'Denetlendi')
            : (pureFirewallDecision || 'Belirtilmemiş')));

  const sigSubclass = kvDict.signature_subclass || kvDict.attack || kvDict.sig_name || kvDict.msg || (winDetails.isWindowsEvent ? winDetails.eventName : 'Güvenlik İmzası');
  const sigId = kvDict.signature_id || kvDict.sig_id || (winDetails.eventId ? String(winDetails.eventId) : '');
  const deviceId = winDetails.isWindowsEvent
    ? (winDetails.computer || 'Windows Güvenlik Alt Sistemi')
    : (kvDict.device_id || kvDict.devname || kvDict.devid || kvDict.hostname || 'Güvenlik Cihazı');
  const countryStr = kvDict.srccountry ? ` (${kvDict.srccountry})` : '';
  const requestUrl = universalEvidence.telemetry.rawPayload.value || parsed?.islem_komutu || kvDict.http_url || kvDict.url || kvDict.uri || winDetails.commandLine || '';
  const matchedPattern = kvDict.matched_pattern || '';
  const clientLevel = kvDict.client_level || '';
  const threatWeight = parseInt(kvDict.history_threat_weight || '0', 10);
  const httpRefer = kvDict.http_refer || '';

  // 4. EVIDENCE SUFFICIENCY & VERIFICATION
  // Determine blocking status: ONLY explicit BLOCK/DENY/DROP/REJECT/RESET/CLOSE from a verified security device action
  // SSH server auth failure, Postfix SASL failure, HTTP 401/403 are NEVER security device blocks!
  const isBlocked = !isServerAuthOrDaemonLog && (isExplicitSecDevAction || hasExplicitAction)
    ? /^(?:drop|deny|block|reject|reset|close|prevent|blocked|engellendi)$/i.test(wafAction) ||
      /\b(?:drop|deny|block|reject|reset|close|prevent|engellendi)\b/i.test(wafAction)
    : (!isServerAuthOrDaemonLog && pureFirewallDecision === 'DENY');

  const isAlertOnly = hasExplicitAction && !isServerAuthOrDaemonLog && /^(?:alert|alarm|alarmed|monitor|learning|log|logged|uyari)$/i.test(wafAction);

  let verdict: ForensicVerdict = 'UNKNOWN';
  let confidence = 75;
  let confidenceLabel = 'Orta Düzey İnceleme';
  let threatTitle = 'Güvenlik Olayı İncelendi';
  let summaryReason = '';
  const deepForensics: string[] = [];
  let attackVector = 'GENERIC';

  // 5. DECISION ENGINE (Forensic Classification)

  // Check 0: Cross-Event Contamination Hard Stop
  const contaminationCheck = auditEventContamination(rawLine);
  if (contaminationCheck.hasContamination) {
    verdict = 'NOT_ASSESSED';
    confidence = 0;
    confidenceLabel = 'Değerlendirilmedi (Çapraz Kontaminasyon)';
    threatTitle = 'ANALİZ TAMAMLANAMADI — ÇAPRAZ OLAY KONTAMİNASYONU';
    summaryReason = `Gözlenen Kanıt (Observed Evidence): Olay metninde birden fazla bağımsız log kaydına ait verilerin (Event ID, sağlayıcı veya bağlam) aynı olay sınırına karıştığı tespit edilmiştir (${contaminationCheck.details.join('; ')}). Adli İlke: Çapraz kontaminasyona uğramış olaylardan güvenlik hükmü (Meşru, Anomali, Şüpheli) üretilemez.`;
    deepForensics.push(
      'Adli Sınır Denetimi: Çapraz olay kontaminasyonu saptandı.',
      ...contaminationCheck.details.map((d) => `Kontaminasyon Detayı: ${d}`)
    );
  }
  // Non-security input check
  else if (!universalEvidence.admissibility.isSecurityEvidence) {
    verdict = 'UNKNOWN';
    confidence = 30;
    confidenceLabel = 'Güvenlik Telemetrisi Bulunamadı';
    threatTitle = 'Geçersiz / Güvenlik Dışı Girdi';
    summaryReason = universalEvidence.admissibility.reason || 'Sağlanan girdi geçerli bir güvenlik telemetrisi veya log kaydı içermemektedir.';
    deepForensics.push(
      'Girdi Doğrulama: Güvenlik göstergesi tespit edilemedi.',
      `Sınıflandırma: ${universalEvidence.admissibility.classification}`
    );
  }
  // 5.1 WINDOWS SECURITY AUDITING LOGS
  else if (winDetails.isWindowsEvent) {
    if (winDetails.eventId === 4625) {
      attackVector = 'WINDOWS_4625';
      if (winDetails.subStatus === '0XC000006A') {
        verdict = 'LIKELY_FALSE_POSITIVE';
        confidence = 85;
        confidenceLabel = 'Hatalı Parola (Doğrulama Bekliyor)';
        threatTitle = 'Windows Event 4625: Hatalı Parola ile Başarısız Oturum (0xC000006A)';
        summaryReason = `Gözlenen Kanıt (Observed): Doğru kullanıcı hesabı (${winDetails.targetUser ? `"${winDetails.targetUser}"` : 'ilgili hesap'}) için hatalı parola girişi sebebiyle başarısız oturum (0xC000006A), Kaynak: ${srcIp}. Yorum (Interpretation): Parola uyumsuzluğu sonucu kimlik doğrulama reddi. Olası Açıklamalar (Hypotheses): Kullanıcı yazım hatası, güncellenmemiş eski kimlik bilgisi, arka plan otomatik istemcisi veya yetkisiz denemedir. Tek başına kaba kuvvet (Brute Force) kanıtı değildir.`;
      } else if (winDetails.subStatus === '0XC0000064') {
        verdict = 'LIKELY_FALSE_POSITIVE';
        confidence = 85;
        confidenceLabel = 'Tanımsız Kullanıcı (Doğrulama Bekliyor)';
        threatTitle = 'Windows Event 4625: Tanımsız Kullanıcı ile Başarısız Oturum (0xC0000064)';
        summaryReason = `Gözlenen Kanıt (Observed): Active Directory veya yerel etki alanında tanımlı olmayan kullanıcı adıyla (${winDetails.targetUser ? `"${winDetails.targetUser}"` : 'Bilinmeyen'}) başarısız oturum açma (0xC0000064), Kaynak: ${srcIp}. Yorum (Interpretation): Tanımsız kullanıcı sebebiyle kimlik doğrulama reddi. Olası Açıklamalar (Hypotheses): Kullanıcı yazım hatası, eski istemci konfigürasyonu, otomatik servis denemesi veya yetkisiz denemedir. Tek başına parola püskürtme (Credential Spraying) veya saldırı kanıtı değildir.`;
      } else if (winDetails.subStatus === '0XC0000234') {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 90;
        confidenceLabel = 'Güvenlik Koruması Tetiklendi';
        threatTitle = 'Güvenlik Uyarısı: Windows Event 4625 - Hesap Kilitlendi (Lockout)';
        summaryReason = `Gözlenen Kanıt: Hedef hesap (${winDetails.targetUser ? `"${winDetails.targetUser}"` : 'ilgili hesap'}) çok sayıda ardışık başarısız oturum denemesi sonucu Active Directory güvenlik politikası gereği kilitlenmiştir (0xC0000234). Yorum: Güvenlik kilitleme mekanizması devreye girmiştir. Belirsizlik: Kilitlenmenin otomatik bir servis mi yoksa kaba kuvvet denemesi mi olduğu teyit edilmelidir.`;
      } else {
        verdict = 'LIKELY_FALSE_POSITIVE';
        confidence = 78;
        confidenceLabel = 'Başarısız Oturum Denemesi';
        threatTitle = `Windows Event 4625: Başarısız Oturum Açma ${winDetails.subStatus ? `(${winDetails.subStatus})` : ''}`;
        summaryReason = `Gözlenen Kanıt: Oturum açma isteği Windows güvenlik katmanı tarafından reddedilmiştir. Hata kodu: ${winDetails.subStatus || 'Bilinmiyor'} ${winDetails.subStatusDesc ? `(${winDetails.subStatusDesc})` : ''}. Yorum: Standart kimlik doğrulama reddi. Belirsizlik: Tekil başarısız oturum tek başına kaba kuvvet (brute force) saldırısı değildir.`;
      }

      deepForensics.push(
        `Olay Kimliği: Event ID 4625 - ${winDetails.eventName}`,
        `Hedef Kullanıcı: ${winDetails.targetUser || 'Bilinmiyor'}`,
        `Oturum Türü: ${winDetails.logonTypeDesc}`,
        `Hata Kodu & Anlamı: ${winDetails.subStatus || 'Belirtilmemiş'} ${winDetails.subStatusDesc ? `(${winDetails.subStatusDesc})` : ''}`,
        `Kaynak Cihaz / Host: ${winDetails.workstation || winDetails.computer || 'Bilinmiyor'}`,
        `Kaynak IP: ${srcIp}${winDetails.sourcePort ? ':' + winDetails.sourcePort : ''}`
      );
      if (winDetails.mitreTechnique) {
        deepForensics.push(`MITRE ATT&CK Tekniği: ${winDetails.mitreTechnique}`);
      }
    } else if (winDetails.eventId === 4624) {
      attackVector = 'WINDOWS_4624';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 90;
      confidenceLabel = winDetails.logonType === 2 && winDetails.sourceIp && winDetails.sourceIp !== '-'
        ? 'Yerel İnteraktif Oturum (Kaynak IP Çelişkili)'
        : (winDetails.logonType === 10 ? 'Uzak Masaüstü Oturumu' : 'Meşru Oturum Akışı');
      threatTitle = winDetails.logonType === 10
        ? 'Uzak Masaüstü Oturumu: Windows Event 4624 - Başarılı RDP Girişi (Type 10)'
        : (winDetails.logonType === 2
          ? 'Yerel Oturum: Windows Event 4624 - Başarılı İnteraktif Giriş (Type 2)'
          : 'Normal Güvenlik Olayı: Windows Event 4624 - Başarılı Oturum Açma');

      if (winDetails.logonType === 2 && winDetails.sourceIp && winDetails.sourceIp !== '-') {
        summaryReason = `Gözlenen Kanıt (Observed): Logon Type 2 (Yerel İnteraktif) başarılı oturum açma (Kullanıcı: "${winDetails.targetUser || 'Kullanıcı'}", Host: "${winDetails.computer || targetHost || 'Windows Endpoint'}"). Yorum (Interpretation): Yerel konsol/klavye interaktif oturumu başlatılmıştır. Belirsizlik (Uncertainty): Telemetride ağ kaynak IP adresi (${winDetails.sourceIp}) yer almaktadır; yerel interaktif oturum semantiği ile harici ağ IP'si çelişmektedir (Field Observation: UNCERTAIN). Bu IP adresi uzaktan kimlik doğrulama korelasyonuna doğrudan dahil edilemez (correlationEligible = false).`;
      } else if (winDetails.logonType === 10) {
        summaryReason = `Gözlenen Kanıt (Observed): Hedef sistemde RDP (Logon Type 10) üzerinden "${winDetails.targetUser || 'Kullanıcı'}" hesabı ile başarılı oturum açılmıştır. Yorum (Interpretation): RDP standart yönetim protokolüdür. Belirsizlik (Uncertainty): Tek başına saldırı veya ihlal kanıtı değildir; yetkili erişim bağlamında değerlendirilmelidir.`;
      } else {
        summaryReason = `Gözlenen Kanıt (Observed): Hedef sistemde başarılı kimlik doğrulaması (${winDetails.logonTypeDesc}) tamamlanmıştır (Kullanıcı: "${winDetails.targetUser || 'Kullanıcı'}"). Yorum (Interpretation): Oturum başlatma işlemi tamamlanmıştır. Belirsizlik (Uncertainty): Tek başına saldırı kanıtı değildir.`;
      }

      deepForensics.push(
        `Olay Kimliği: Event ID 4624 - ${winDetails.eventName}`,
        `Oturum Açan Hesap: ${winDetails.targetUser || 'Bilinmiyor'}`,
        `Oturum Türü: ${winDetails.logonTypeDesc}`,
        `Kaynak Cihaz / IP: ${winDetails.workstation || srcIp}`,
        `Hedef Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`
      );
    } else if (winDetails.eventId === 4672) {
      attackVector = 'WINDOWS_4672';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 88;
      confidenceLabel = 'İdari Ayrıcalık Gözlendi (Bağlam Gerekli)';
      threatTitle = 'Windows Event 4672: Özel Ayrıcalık Atandı (Observed Admin Privilege)';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Oturum açılışında özel güvenlik hakları (SeSecurityPrivilege vb.) atanması kaydedilmiştir (Kullanıcı: "${winDetails.targetUser || winDetails.subjectUser || 'Kullanıcı'}"). Yorum (Interpretation): İdari ayrıcalık ataması gözlemlenmiştir (OBSERVED ADMINISTRATIVE PRIVILEGE ASSIGNMENT). Belirsizlik/Bağlam (Uncertainty): Tek başına yetki yükseltme (Privilege Escalation) kanıtı değildir; yetkili hesapların rutin oturum açmasında standart işletim sistemi davranışıdır. Güvenlik etkisi oturum içi eylemlerin bağlamını gerektirir (NOT DETERMINED / CONTEXT REQUIRED).`;

      deepForensics.push(
        `Olay Kimliği: Event ID 4672 - ${winDetails.eventName}`,
        `Kullanıcı Hesabı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar (Host): ${winDetails.computer || targetHost || 'Windows Endpoint'}`,
        'Epistemik Sınıf: OBSERVED ADMINISTRATIVE PRIVILEGE ASSIGNMENT',
        'Adli Not: Event 4672 tek başına yetki yükseltme kanıtı değildir; yetkili hesapların oturum açmasında standart olarak üretilir. Güvenlik etkisi bağlam gerektirir (NOT DETERMINED / CONTEXT REQUIRED).'
      );
    } else if (winDetails.eventId === 4688 || winDetails.eventId === 1) {
      attackVector = winDetails.eventId === 1 ? 'SYSMON_1' : 'WINDOWS_4688';
      const cmdLow = (winDetails.commandLine + ' ' + winDetails.processName).toLowerCase();
      const runningUser = winDetails.subjectUser || winDetails.targetUser || 'SYSTEM';
      const endpointHost = winDetails.computer || 'Windows Endpoint';

      const procLow = (winDetails.processName || '').toLowerCase();
      const parentLow = (winDetails.parentProcess || '').toLowerCase();

      const isMalformedProcess =
        cmdLow.includes('/admin/reports/panel.aspx') ||
        (winDetails.processName.startsWith('/') && !winDetails.processName.toLowerCase().endsWith('.exe'));

      const isSvchostAnomaly =
        procLow.includes('svchost.exe') &&
        (parentLow.includes('cmd.exe') ||
          parentLow.includes('powershell.exe') ||
          parentLow.includes('explorer.exe') ||
          (winDetails.commandLine.trim().length > 0 && !cmdLow.includes('-k')));

      const isDataReconnaissance =
        (cmdLow.includes('get-childitem') || cmdLow.includes('dir ') || cmdLow.includes('ls ')) &&
        (cmdLow.includes('\\users\\') || cmdLow.includes('\\documents') || cmdLow.includes('\\appdata') || cmdLow.includes('\\desktop') || cmdLow.includes('\\shares\\'));

      const isSuspiciousProc =
        isSvchostAnomaly ||
        isDataReconnaissance ||
        (cmdLow.includes('powershell') && (cmdLow.includes('-enc') || cmdLow.includes('bypass') || cmdLow.includes('downloadstring') || cmdLow.includes('iex'))) ||
        cmdLow.includes('vssadmin delete') ||
        (cmdLow.includes('certutil') && (cmdLow.includes('-urlcache') || cmdLow.includes('-split'))) ||
        cmdLow.includes('mimikatz') ||
        cmdLow.includes('psexec') ||
        (cmdLow.includes('rundll32') && cmdLow.includes('javascript'));

      if (isMalformedProcess) {
        verdict = 'UNKNOWN';
        confidence = 50;
        confidenceLabel = 'Alan Semantiği Belirsiz (Uyumsuz Süreç)';
        threatTitle = 'Uyumsuz Süreç Gözlemi: /admin/reports/panel.aspx (Field Semantics Uncertain)';
        summaryReason = 'Gözlenen Kanıt (Observed Evidence): Event ID 4688 kaydında süreç alanı olarak "/admin/reports/panel.aspx" gözlenmiştir. Yorum (Interpretation): Windows işletim sistemi yerel yürütülebilir ikili dosyası (.exe/.dll) formatıyla uyumsuz, ayrıştırılamamış veya aktarım sırasında bozulmuş alan semantiğidir (UNPARSED / MALFORMED PROCESS OBSERVATION). Belirsizlik (Uncertainty): Alanın URL, web kabuğu (webshell) veya betik yolu olduğu kanıtlanmamıştır; ham değer "/admin/reports/panel.aspx" olarak muhafaza edilmiştir. Tek başına meşru veya zararlı olarak yorumlanamaz.';
      } else if (isSvchostAnomaly) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 88;
        confidenceLabel = 'Süreç Anomalisi (svchost.exe)';
        threatTitle = 'Şüpheli Süreç Anomalisi: svchost.exe Olağandışı Yürütme/Üst Süreç';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): "svchost.exe" süreci olağandışı bir üst süreç (${winDetails.parentProcess || 'Bilinmiyor'}) veya olağandışı parametre ile yürütülmüştür ("${winDetails.commandLine || winDetails.processName}") (Kullanıcı: ${runningUser}, Host: ${endpointHost}). Yorum (Interpretation): Meşru svchost.exe yalnızca services.exe tarafından "-k" parametresiyle başlatılır; bu yürütme deseni süreç gizleme (Process Masquerading) veya kod enjeksiyonu anomalisi ile uyumludur. Belirsizlik (Uncertainty): Tam dosya yolu, ikili dosya hash değeri ve PID bilgisi uç noktada doğrulanmalıdır.`;
      } else if (isDataReconnaissance) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'Veri/Dizin Keşfi (Reconnaissance)';
        threatTitle = 'Şüpheli Veri Keşfi: Kullanıcı Dizinleri Listelendi';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Uç noktada kullanıcı profil dizinlerini ("${winDetails.commandLine || winDetails.processName}") sorgulayan/listeleyen süreç yürütülmüştür (Kullanıcı: ${runningUser}, Host: ${endpointHost}). Yorum (Interpretation): Dosya ve dizin keşfi (T1083 File and Directory Discovery) deseni ile uyumludur. Belirsizlik (Uncertainty): Yetkili bir yedekleme/yönetim betiği olabileceği gibi saldırganın hedef veri tespiti faaliyeti de olabilir; yürütme amacı uç nokta bağlamında doğrulanmalıdır.`;
      } else if (cmdLow.includes('wevtutil')) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'Günlük Yönetim Aracı (Bağlamsal Anomali)';
        threatTitle = 'Sistem Komutu: wevtutil.exe (Olay Günlüğü Yönetimi)';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): "wevtutil.exe" komutu/süreci yürütülmüştür (Kullanıcı: ${runningUser}, Host: ${endpointHost}). Yorum (Interpretation): Windows olay günlüğü yapılandırma ve temizleme aracıdır. Belirsizlik (Uncertainty): Event 1102 ile yakın zaman aralığında yer almakla birlikte, doğrudan PID/Parent PID veya oturum bağı kanıtlanmadan otomatik saldırı zinciri oluşturulamaz; korelasyon adayı olarak işaretlenmiştir.`;
      } else if (cmdLow.includes('whoami')) {
        verdict = 'AUTHORIZED_ACTIVITY';
        confidence = 85;
        confidenceLabel = 'Sistem Keşif Komutu (whoami)';
        threatTitle = 'Sistem Komutu: whoami.exe (Kullanıcı Keşfi)';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): "whoami.exe" komutu/süreci yürütülmüştür (Kullanıcı: ${runningUser}). Yorum (Interpretation): Yerleşik kullanıcı ve grup kimlik bilgisi sorgulama aracıdır (System Owner/User Discovery). Belirsizlik (Uncertainty): T1059 komut yorumlayıcı tekniği otomatik atanmamıştır; keşif amaçlı saldırgan davranışı olabileceği gibi yönetimsel denetim veya kurulum betiği de olabilir.`;
      } else if (isSuspiciousProc) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'Şüpheli Komut / LOLBAS Deseni (Doğrulama Bekliyor)';
        threatTitle = 'Şüpheli Komut/Süreç Anomalisi: Zararlı/LOLBAS Deseni';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Uç noktada yetki kontrolü veya kod gizleme tekniklerinde sık kullanılan şüpheli bir komut yürütülmüştür: ${winDetails.commandLine || winDetails.processName}. Yorum (Interpretation): LOLBAS veya kod yürütme anomalisi tespit edilmiştir. Belirsizlik (Uncertainty): Bu komut saldırgan faaliyeti olabileceği gibi yetkili BT personeli veya otomatik yönetim araçları tarafından da çalıştırılmış olabilir. İlgili hesabın ve zamanlamanın teyidi gereklidir.`;
      } else {
        verdict = 'AUTHORIZED_ACTIVITY';
        confidence = 85;
        confidenceLabel = 'Süreç Yürütme Gözlendi';
        threatTitle = `Süreç Yürütme: ${winDetails.processName ? winDetails.processName.split('\\').pop() : (winDetails.eventId === 1 ? 'Sysmon Event 1' : 'Windows Event 4688')}`;
        summaryReason = `Gözlenen Kanıt (Observed Evidence): ${winDetails.processName || 'Süreç'} ${winDetails.commandLine ? `("${winDetails.commandLine}")` : ''} yürütülmüştür (Kullanıcı: ${runningUser}, Host: ${endpointHost}). Yorum (Interpretation): Süreç yürütme davranışı rutin işletim sistemi veya yönetim araçları ile uyumludur. Belirsizlik (Uncertainty): Üst süreç ${winDetails.parentProcess ? `(${winDetails.parentProcess})` : 'mevcut değildir'}. Süreç veya komut adı tek başına kesin meşruiyet veya saldırı kanıtı oluşturmaz; yürütme amacı uç nokta bağlamında doğrulanmalıdır.`;
      }

      deepForensics.push(
        `Olay Kimliği: ${winDetails.eventId === 1 ? 'Sysmon Event 1' : 'Event ID 4688'} - ${winDetails.eventName}`,
        `Hedef Bilgisayar (Host): ${endpointHost}`,
        `Çalıştıran Hesap: ${runningUser}`,
        `Yürütülen Komut / Süreç: ${winDetails.commandLine || winDetails.processName || 'Belirtilmemiş'}`,
        `Üst Süreç (Parent): ${winDetails.parentProcess || 'Belirtilmemiş'}`
      );
    } else if (winDetails.eventId === 4663) {
      attackVector = 'WINDOWS_4663';
      const rawTextLow = line.toLowerCase();
      const hasSensitiveTarget = rawTextLow.includes('sam') || rawTextLow.includes('lsass') || rawTextLow.includes('ntds.dit');

      const hasRoutineObjectName =
        rawTextLow.includes('object name:') ||
        rawTextLow.includes('objectname:') ||
        rawTextLow.includes('object name :') ||
        rawTextLow.includes('access mask:') ||
        rawTextLow.includes('accessmask:');

      if (hasSensitiveTarget) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 82;
        confidenceLabel = 'Kritik Nesne Erişimi';
        threatTitle = 'Kritik Nesne Erişimi: Windows Event 4663 - Hassas Sistem Dosyası';
        summaryReason = 'Gözlenen Kanıt (Observed Evidence): Kritik kimlik bilgisi veya sistem dosyasına doğrudan erişim girişimi gözlenmiştir. Yorum (Interpretation): Hassas nesne erişim anomalisi. Belirsizlik (Uncertainty): Erişim maskesi ve çağıran süreç amacı uç noktada teyit edilmelidir.';
      } else if (hasRoutineObjectName) {
        verdict = 'AUTHORIZED_ACTIVITY';
        confidence = 85;
        confidenceLabel = 'Rutin Nesne Erişimi Gözlendi';
        threatTitle = 'Nesne Erişimi: Windows Event 4663 (Belgelenmiş Nesne)';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Nesne erişim telemetrisi kaydedilmiştir (Event ID 4663, Kullanıcı: ${winDetails.subjectUser || winDetails.targetUser || 'Bilinmiyor'}). Yorum (Interpretation): Nesne adı ve erişim maskesi telemetride gözlenmiş olup rutin operasyonel akış ile uyumludur. Belirsizlik (Uncertainty): Tek başına kötü amaçlılık veya ihlal kanıtı değildir.`;
      } else {
        verdict = 'UNKNOWN';
        confidence = 65;
        confidenceLabel = 'Yetersiz Nesne Bağlamı';
        threatTitle = 'Nesne Erişimi: Windows Event 4663 (Yetersiz Kanıt)';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Windows nesne erişim telemetrisi kaydedilmiştir (Event ID 4663, Kullanıcı: ${winDetails.subjectUser || winDetails.targetUser || 'Bilinmiyor'}). Yorum (Interpretation): Nesne erişim denemesi gözlenmiştir. Belirsizlik (Uncertainty): ObjectName ve AccessMask gibi kritik alanlar telemetride yer almadığı için güvenlik etkisi adli açıdan belirlenemez (INSUFFICIENT_EVIDENCE / BELİRSİZ).`;
      }

      deepForensics.push(
        `Olay Kimliği: Event ID 4663 - ${winDetails.eventName}`,
        `Kullanıcı: ${winDetails.subjectUser || winDetails.targetUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || 'Windows Endpoint'}`,
        'Adli Not: Event 4663 tek başına kötü amaçlılık kanıtı değildir; nesne ve erişim maskesi incelenmelidir.'
      );
    } else if (winDetails.eventId === 5140 || winDetails.eventId === 5145) {
      attackVector = 'WINDOWS_SHARE_ACCESS';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 85;
      confidenceLabel = 'Ağ Paylaşım Erişimi';
      threatTitle = `Ağ Paylaşım Erişimi: Windows Event ${winDetails.eventId}`;
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Ağ paylaşımına erişim olayı kaydedilmiştir (Event ID ${winDetails.eventId}, Kullanıcı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}). Yorum (Interpretation): Ağ paylaşım oturumu gözlenmiştir. Belirsizlik (Uncertainty): Tek başına kötü amaçlılık göstergesi değildir; hedef paylaşım ve kullanıcı hesabı doğrulanmalıdır.`;

      deepForensics.push(
        `Olay Kimliği: Event ID ${winDetails.eventId} - ${winDetails.eventName}`,
        `Kullanıcı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || 'Windows Endpoint'}`
      );
    } else if (winDetails.eventId === 4634) {
      attackVector = 'WINDOWS_4634';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 90;
      confidenceLabel = 'Meşru Oturum Kapatma';
      threatTitle = 'Oturum Kapatma: Windows Event 4634 - Normal Logoff';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Oturum kapatma (logoff) telemetrisi kaydedilmiştir (Kullanıcı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}). Yorum (Interpretation): Standart oturum sonlandırma işlemidir. Belirsizlik (Uncertainty): Tek başına kötü amaçlılık veya saldırı göstergesi değildir.`;

      deepForensics.push(
        `Olay Kimliği: Event ID 4634 - ${winDetails.eventName}`,
        `Kullanıcı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || 'Windows Endpoint'}`
      );
    } else if (winDetails.eventId === 5156) {
      attackVector = 'WINDOWS_5156';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 85;
      confidenceLabel = 'Ağ Bağlantı İzni (Permitted)';
      threatTitle = 'Windows Filtreleme Platformu: Event 5156 - Bağlantıya İzin Verildi';
      summaryReason = 'Gözlenen Kanıt (Observed Evidence): Windows Filtreleme Platformu ağ bağlantısına izin vermiştir (Permitted). Yorum (Interpretation): İzin verilmiş ağ bağlantısı telemetrisidir (Network Connection Permitted). Belirsizlik (Uncertainty): Tek başına meşru veya kötü amaçlı olarak sınıflandırılamaz (Security Verdict: NOT DETERMINED). Kaynak/hedef IP, port ve uygulama detayları telemetride eksikse ağ davranışı tam olarak değerlendirilememiştir.';

      deepForensics.push(
        `Olay Kimliği: Event ID 5156 - ${winDetails.eventName}`,
        `Bilgisayar: ${winDetails.computer || 'Windows Endpoint'}`,
        'Adli Not: 5156 tek başına meşru veya kötü amaçlı sayılamaz; ağ davranışı tam olarak değerlendirilmelidir.'
      );
    } else if (winDetails.eventId === 11) {
      attackVector = 'SYSMON_11';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 85;
      confidenceLabel = 'Dosya Oluşturma Olayı';
      threatTitle = 'Dosya Oluşturuldu: Sysmon Event 11';
      summaryReason = 'Gözlenen Kanıt (Observed Evidence): Dosya oluşturma olayı (Sysmon Event 11) kaydedilmiştir. Yorum (Interpretation): Dosya sistemi yazma eylemi gözlenmiştir. Belirsizlik (Uncertainty): Ağ transferi, URL indirmesi veya harici araç aktarımı kanıtı bulunmadığı için T1105 Ingress Tool Transfer tekniği desteklenmez (T1105 = NOT_SUPPORTED / NOT_ASSESSED).';

      deepForensics.push(
        'Olay Kimliği: Sysmon Event 11 (File Create)',
        `Hedef Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`,
        'Adli Not: Dosya oluşturma olayı tek başına T1105 Ingress Tool Transfer değildir; harici indirme veya ağ bağlantısı kanıtı aranmalıdır.'
      );
    } else if (winDetails.eventId === 4104) {
      attackVector = 'POWERSHELL_4104';
      const rawLow = line.toLowerCase();
      const isBenignCmdlet =
        rawLow.includes('get-childitem') ||
        rawLow.includes('get-item') ||
        rawLow.includes('get-process') ||
        rawLow.includes('get-service') ||
        rawLow.includes('dir ');

      const isSuspiciousScript =
        rawLow.includes('-enc') ||
        rawLow.includes('downloadstring') ||
        rawLow.includes('bypass') ||
        rawLow.includes('invoke-expression') ||
        rawLow.includes('iex(') ||
        rawLow.includes('frombase64string');

      if (isSuspiciousScript) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'Şüpheli PowerShell Betiği';
        threatTitle = 'Şüpheli PowerShell Script Bloğu: Event 4104';
        summaryReason = 'Gözlenen Kanıt: PowerShell script bloğunda kod gizleme, indirme veya çalıştırma teknikleri tespit edilmiştir. Yorum: Yetkisiz betik yürütme anomalisi adayıdır. Belirsizlik: Çağıran kullanıcı ve betik kaynağı uç noktada teyit edilmelidir.';
      } else if (isBenignCmdlet) {
        verdict = 'AUTHORIZED_ACTIVITY';
        confidence = 85;
        confidenceLabel = 'Rutin PowerShell Sorgusu';
        threatTitle = 'PowerShell Script Yürütme: Event 4104 (Rutin Komut)';
        summaryReason = 'Gözlenen Kanıt (Observed Evidence): PowerShell script bloğunda rutin sorgu içeriği gözlenmiştir. Yorum (Interpretation): Rutin sistem sorgusu niteliğindedir (Observed Benign Command). Belirsizlik (Uncertainty): Tek başına kötü amaçlılık göstermez; yürütme bağlamı uç noktada doğrulanmalıdır.';
      } else {
        verdict = 'UNKNOWN';
        confidence = 70;
        confidenceLabel = 'Script İçeriği Değerlendirilmedi';
        threatTitle = 'PowerShell Script Blok Kaydı: Event 4104 (İçerik Yok)';
        summaryReason = 'Gözlenen Kanıt (Observed Evidence): PowerShell script blok telemetrisi kaydedilmiştir (Event ID 4104). Yorum (Interpretation): Script yürütme olayı gözlenmiştir. Belirsizlik (Uncertainty): Script blok içeriği ham telemetride yer almadığı için içerik değerlendirilememiştir (SCRIPT_CONTENT_NOT_ASSESSED). Tek başına meşru veya zararlı olarak kesinleştirilemez.';
      }

      deepForensics.push(
        'Olay Kimliği: Event ID 4104 (Script Block Logging)',
        `Bilgisayar: ${winDetails.computer || 'Windows Endpoint'}`
      );
    } else if (winDetails.eventId === 1102) {
      attackVector = 'WINDOWS_1102';
      verdict = 'SUSPICIOUS_ANOMALY';
      confidence = 88;
      confidenceLabel = 'Adli Anomali (İnceleme Gerektirir)';
      threatTitle = 'Güvenlik Günlüğü Sıfırlandı: Windows Event 1102 (Adli Anomali)';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Windows Güvenlik Olay Günlüğü sıfırlanmıştır (Event ID 1102, Kullanıcı: ${winDetails.subjectUser || 'Yönetici'}). Yorum (Interpretation): Savunma aşma (T1070.001) tekniği ile uyumlu adli bir anomalidir. Belirsizlik (Uncertainty): Günlüğün saldırgan tarafından iz gizleme amacıyla mı yoksa yetkili yönetici tarafından planlı bakım amacıyla mı sıfırlandığı doğrulanmamıştır (Hipotez: Yetkili bakım vs Saldırgan faaliyeti).`;

      deepForensics.push(
        `Olay Kimliği: 1102 (${winDetails.eventName})`,
        `Eylemi Yapan Kullanıcı: ${winDetails.subjectUser || 'Yönetici Hesabı'}`,
        `Hedef Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`,
        'Adli Not: Günlük temizleme olayı tek başına saldırgan aktivitesi kanıtı değildir; yetkili bakım teyidi ve ek kanıt aranmalıdır.'
      );
    } else if (winDetails.eventId === 104) {
      attackVector = 'WINDOWS_104';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 85;
      confidenceLabel = 'Sistem/Uygulama Günlüğü Temizlendi';
      threatTitle = 'Olay Günlüğü Temizlendi: Windows Event 104 (System / App)';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Olay günlüğü temizleme telemetrisi (Event ID 104) kaydedilmiştir (Kullanıcı: ${winDetails.subjectUser || 'Yönetici'}). Yorum (Interpretation): Sistem veya uygulama günlüğünün temizlendiğini gösterir; Güvenlik denetim günlüğü (Security Audit Log) değildir. Belirsizlik (Uncertainty): Günlük kanalı (Channel) ham veride gözlenmemiştir (Channel = NOT OBSERVED). Bu nedenle T1070.001 tekniği atanmamıştır (ATT&CK = NOT_ASSESSED).`;

      deepForensics.push(
        `Olay Kimliği: 104 (${winDetails.eventName})`,
        `Eylemi Yapan Kullanıcı: ${winDetails.subjectUser || 'Yönetici Hesabı'}`,
        `Hedef Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`,
        'Adli Not: Event 104 Security denetim günlüğü değildir. Kanal bilgisi gözlenmediği için T1070.001 tekniği atanmaz (ATT&CK = NOT_ASSESSED).'
      );
    } else if (winDetails.eventId === 7045 || winDetails.eventId === 4697) {
      attackVector = 'WINDOWS_7045';
      const svfLow = ((winDetails.serviceFile || '') + ' ' + (winDetails.serviceName || '')).toLowerCase();
      const isSuspiciousService =
        svfLow.includes('powershell') ||
        svfLow.includes('cmd.exe') ||
        svfLow.includes('\\appdata\\') ||
        svfLow.includes('\\temp\\') ||
        svfLow.includes('\\public\\') ||
        svfLow.includes('certutil') ||
        svfLow.includes('-enc') ||
        svfLow.includes('mimikatz');

      if (isSuspiciousService) {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'Şüpheli Servis Dosya Yolu';
        threatTitle = 'Şüpheli Servis Kurulumu: Windows Event 7045 (Anormal Yol / LOLBAS)';
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Sisteme kaydedilen yeni servisin ("${winDetails.serviceName}") ikili dosya yolu (${winDetails.serviceFile}) şüpheli yürütme deseni veya geçici dizin konumu içermektedir. Yorum (Interpretation): Yetkisiz kalıcılık veya şüpheli servis kurulum anomalisi. Belirsizlik (Uncertainty): Servisin meşru BT yazılımı olup olmadığı değişiklik yönetimi ile teyit edilmelidir.`;
      } else {
        verdict = 'AUTHORIZED_ACTIVITY';
        confidence = 85;
        confidenceLabel = 'Yeni Servis Kurulumu Gözlendi';
        threatTitle = `Yeni Servis Kurulumu: Windows Event 7045 (${winDetails.serviceName || 'Servis'})`;
        summaryReason = `Gözlenen Kanıt (Observed Evidence): Sisteme yeni bir servis kaydedilmiştir: Servis Adı: "${winDetails.serviceName || 'Servis'}", İkili Dosya: "${winDetails.serviceFile || 'Belirtilmemiş'}" (Kullanıcı: ${winDetails.subjectUser || 'Bilinmiyor'}). Yorum (Interpretation): Yeni servis kurulumu gözlenmiştir (New Service Installation Observed). Belirsizlik/Eksik Kanıt (Uncertainty): Tek başına kötü amaçlı kalıcılık (Persistence) saldırısı kanıtı değildir. Eksik kanıtlar: Değişiklik yönetim bileti (Change Ticket), ikili dosya dijital imzası/hash teyidi ve servis ile ilişkili 4688 süreç oluşturma kaydı.`;
      }

      deepForensics.push(
        `Servis İsmi: ${winDetails.serviceName || 'Bilinmiyor'}`,
        `Servis Dosya Yolu: ${winDetails.serviceFile || 'Bilinmiyor'}`,
        `Kuran Hesap: ${winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`,
        'Adli Not: 7045 olayı tek başına kötü amaçlı kalıcılık saldırısı kanıtı değildir; meşru yazılım veya servis kurulumu da olabilir.'
      );
    } else if (winDetails.eventId === 4720 || winDetails.eventId === 4728 || winDetails.eventId === 4732) {
      attackVector = 'WINDOWS_ACCOUNT_MGMT';
      verdict = 'SUSPICIOUS_ANOMALY';
      confidence = 82;
      confidenceLabel = 'Yetkili Hesap Yönetim Eylemi';
      threatTitle = `Windows Event ${winDetails.eventId}: Kullanıcı / Yetkili Grup Değişikliği`;
      summaryReason = `Active Directory veya yerel hesap veritabanında kritik kimlik/grup değişikliği yapılmıştır (${winDetails.eventName}). Yetkili değişiklik yönetim kaydı (Change Request) aranmalıdır.`;
      deepForensics.push(
        `Olay: ${winDetails.eventName}`,
        `İlgili Hesap: ${winDetails.targetUser || 'Bilinmiyor'}`,
        `İşlemi Yapan Hesap: ${winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || targetHost || 'Windows Endpoint'}`
      );
    } else {
      attackVector = 'WINDOWS_GENERIC';
      verdict = 'AUTHORIZED_ACTIVITY';
      confidence = 80;
      confidenceLabel = 'Standart Uç Nokta Telemetrisi';
      threatTitle = `Windows Olay Kaydı: Event ${winDetails.eventId || 'Telemetrisi'}`;
      summaryReason = 'Uç nokta olay telemetrisi gözlenmiştir; olayda bilinen bir saldırı göstergesi veya anomali tespit edilmemiştir.';
      deepForensics.push(
        `Olay ID: ${winDetails.eventId || 'Bilinmiyor'}`,
        `Olay Adı: ${winDetails.eventName}`,
        `Kullanıcı: ${winDetails.targetUser || winDetails.subjectUser || 'Bilinmiyor'}`,
        `Bilgisayar: ${winDetails.computer || winDetails.workstation || 'Bilinmiyor'}`
      );
    }
  }
  // 5.2 WEB / WAF / FIREWALL HEURISTICS
  else {
    const isOwaLogin =
      lowLine.includes('/owa/auth/logon.aspx') ||
      lowLine.includes('replacecurrent=1') ||
      (lowLine.includes('logon.aspx') && lowLine.includes('url=https'));

    const isRfiSignature =
      lowLine.includes('rfi injection') ||
      lowLine.includes('060140003') ||
      lowLine.includes('remote file inclusion');

    const isSameHost = Boolean(targetHost && requestUrl.toLowerCase().includes(targetHost.toLowerCase()));
    const isEcpTarget = requestUrl.toLowerCase().includes('/ecp');
    const isClientFlagged = clientLevel.toLowerCase() === 'malicious' || threatWeight > 1000;

    if (isOwaLogin && isRfiSignature) {
      attackVector = 'OWA_RFI_FALSE_POSITIVE';
      verdict = 'LIKELY_FALSE_POSITIVE';
      confidence = isClientFlagged ? 84 : 88;
      confidenceLabel = isClientFlagged
        ? 'Muhtemel FP (IP İtibar Uyarısı Var - Teyit Şart)'
        : 'Yüksek Olasılık (Personel Teyidi Bekliyor)';
      threatTitle = 'Muhtemel Yanlış Alarm (FP Adayı): Exchange OWA/ECP Oturum Yönlendirmesi';
      summaryReason =
        `WAF RFI imza kuralı (${sigId ? `ID: ${sigId}` : 'RFI Signature'}), istekteki "url=" parametresini Uzaktan Dosya Ekleme (RFI) atağı olarak yorumlamıştır. İstek aynı hosta ("${targetHost || 'Dahili Host'}") ve standart Exchange yönetim paneline (${isEcpTarget ? '/ecp' : 'dahili servis'}) işaret ettiği için meşru Exchange kimlik doğrulama akışıyla güçlü uyum göstermektedir.` +
        (isClientFlagged
          ? ` DİKKAT: Güvenlik cihazı bu kaynak IP için client_level="${clientLevel}" (Geçmiş Tehdit Ağırlığı: ${threatWeight}) kaydetmiştir. Bu nedenle olay peşinen kapatılmamalı; isteği yapan IP'nin personelin ev/mobil interneti olup olmadığı ve bu saatte oturum açıp açmadığı doğrulanmalıdır.`
          : ` Olay yüksek olasılıkla yanlış alarmdır; ancak kaynak IP'nin kurumsal personele ait olduğu doğrulanmalıdır.`);

      deepForensics.push(
        sigId ? `Tetiklenen İmza: ID ${sigId} (${sigSubclass})` : `Tetiklenen İmza: ${sigSubclass}`,
        matchedPattern ? `Eşleşen Parametre Deseni: "${matchedPattern}"` : requestUrl ? `İstek URL'si: "${requestUrl}"` : 'İstek parametresi incelendi.',
        isSameHost
          ? `Host Uyumu: İstek hedefi ("${targetHost}") ile parametre yönlendirmesi aynı dahili hosttur (Dışarıya RFI çağrısı saptanmamıştır).`
          : 'Host Analizi: İstek parametresindeki yönlendirme adresi incelenmiştir.',
        isEcpTarget ? 'Yönlendirme Hedefi: Microsoft Exchange ECP (Exchange Control Panel) yönetim portalı.' : 'Yönlendirme Hedefi: Standart web oturum açma sayfası.',
        isClientFlagged
          ? `Cihaz İtibar Uyarısı: Kaynak IP için client_level="${clientLevel}" ve threat_weight=${threatWeight} kaydı bulunmaktadır.`
          : 'Cihaz İtibarı: Kaynak IP için olağandışı risk ağırlığı bildirilmemiştir.',
        `HTTP Referer: ${httpRefer || 'Belirtilmemiş'}`,
        `WAF Aksiyonu: "${wafAction}". ${isAlertOnly ? 'Trafik engellenmemiş (Alert modunda); oturum açma işlemi tamamlanmış olabilir.' : 'WAF bağlantıyı engellemiştir.'}`
      );
    } else if (
      lowLine.includes('jndi:') ||
      lowLine.includes('ldap://') ||
      lowLine.includes('dns://') ||
      lowLine.includes('${jndi')
    ) {
      attackVector = 'LOG4J';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 94;
        confidenceLabel = 'Saldırı Girişimi Engellendi';
        threatTitle = 'Engellenmiş Saldırı Girişimi: Log4j / JNDI İstismar Denemesi';
        summaryReason =
          `Saldırgan Log4j (CVE-2021-44228) uzaktan kod yürütme istismar payloadı göndermiştir. Ancak güvenlik katmanı (${wafAction}) isteği engelleyerek sunucuya ulaşmasını durdurmuştur. Başarılı sömürü veya dış bağlantı kanıtı saptanmamıştır.`;
      } else {
        verdict = 'POTENTIAL_COMPROMISE';
        confidence = 92;
        confidenceLabel = 'Kritik İstismar Şüphesi (Adli Alarm)';
        threatTitle = 'Kritik Adli Tehdit: Log4j / JNDI İstismar İsteği';
        const statusNote = parsed?.status_code
          ? (parsed.status_code === 200
              ? ' (HTTP 200 tek başına uzaktan kod yürütmenin başarılı olduğunu kanıtlamaz; giden LDAP/DNS bağlantıları teyit edilmelidir)'
              : parsed.status_code === 403
              ? ' (HTTP 403 tek başına WAF engellemesi kanıtı değildir)'
              : ` (HTTP ${parsed.status_code})`)
          : '';
        const actionNote = hasExplicitAction
          ? `Güvenlik katmanı aksiyonu: "${wafAction}".`
          : 'Logda açık bir WAF/güvenlik cihazı engelleme aksiyonu saptanmamıştır.';
        summaryReason =
          `Log4j istismar payloadı tespit edilmiştir. ${actionNote}${statusNote} Sunucunun bu isteğe yanıtı ve sunucudan dışarıya LDAP/DNS (389/53/1099) giden bağlantı kurulup kurulmadığı acilen adli inceleme gerektirir.`;
      }
      deepForensics.push(
        'İstismar Türü: Apache Log4j (CVE-2021-44228) JNDI Injection',
        `Saldırı Aksiyonu: ${hasExplicitAction ? `"${wafAction}"` : 'Belirtilmemiş (Aksiyon Alanı Yok)'}. ${isBlocked ? 'İstek engellendiği için sömürü gerçekleşmemiştir.' : 'Açık engelleme kanıtı yoktur; sunucu yanıtı ve dış bağlantılar incelenmelidir.'}`,
        `Kaynak IP: ${srcIp}${countryStr}`
      );
    } else if (
      /time[-_\s]?out|zaman[-_\s]?a[sş][ıi]m[ıi]|aged[-_\s]?out/i.test(
        line + ' ' + (kvDict.reason || '')
      )
    ) {
      attackVector = 'TIMEOUT';
      verdict = 'SUSPICIOUS_ANOMALY';
      confidence = 85;
      confidenceLabel = 'Bağlantı Hatası / Zaman Aşımı';
      threatTitle = 'Bağlantı Zaman Aşımı (Session Timeout / Aged Out)';
      summaryReason =
        'Olay bir bağlantı zaman aşımıdır (Timeout). QRadar veya güvenlik duvarları bunu izin kuralı sebebiyle "Success" olarak gösterse de, çift yönlü veri akışı tamamlanmamış bir başarısız bağlantı durumudur. Hedef servisin o sırada ayakta olup olmadığı veya güvenlik duvarının paketleri sessizce düşürüp düşürmediği kontrol edilmelidir.';
      deepForensics.push(
        'Oturum zaman aşımına uğramıştır. Veri transferi ya hiç olmamış (SYN paketinde kalmış) ya da sunucu yanıt vermeden bağlantı düşmüştür.',
        'Korelasyon Motoru Durumu: 408 / DENY / HATA olarak sınıflandırılmıştır.'
      );
    } else if (
      lowLine.includes('webshell') ||
      lowLine.includes('cmd=') ||
      lowLine.includes('whoami') ||
      lowLine.includes('eval(') ||
      lowLine.includes('base64_decode')
    ) {
      attackVector = 'COMMAND_INJECTION_WEBSHELL';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 90;
        confidenceLabel = 'Zararlı Kod Çağrısı Engellendi';
        threatTitle = 'Engellenmiş Saldırı: Komut Enjeksiyonu / Webshell Girişimi Engellendi';
        summaryReason =
          `Sistem komutları (whoami, cmd) veya zararlı PHP/ASP yürütme fonksiyonları içeren şüpheli istek parametresi tespit edilmiş, güvenlik katmanı tarafından engellenmiştir (${wafAction}).`;
      } else {
        verdict = 'POTENTIAL_COMPROMISE';
        confidence = 90;
        confidenceLabel = 'Yüksek İstismar Riski';
        threatTitle = 'Yüksek Tehdit: Webshell / Komut Enjeksiyonu Çalıştırma Şüphesi';
        const statusNote = parsed?.status_code
          ? (parsed.status_code === 200
              ? ' (HTTP 200 tek başına komutun çalıştığını kanıtlamaz; süreç ve komut çıktısı doğrulanmalıdır)'
              : parsed.status_code === 403
              ? ' (HTTP 403 tek başına WAF engellemesi kanıtı değildir)'
              : ` (HTTP ${parsed.status_code})`)
          : '';
        const actionNote = hasExplicitAction
          ? `Uygulanan Aksiyon: "${wafAction}".`
          : 'Açık WAF engelleme aksiyonu bulunmamaktadır.';
        summaryReason =
          `Zararlı komut veya webshell çağrısı içeren istek tespit edilmiştir. ${actionNote}${statusNote} Sunucu dosya sisteminde bu dosyanın bulunup bulunmadığı ve çalışıp çalışmadığı doğrulanmalıdır.`;
      }
      deepForensics.push(
        `İstek Komutu: ${parsed?.islem_komutu || requestUrl || 'Bilinmiyor'}`,
        `Uygulanan Aksiyon: ${hasExplicitAction ? wafAction : 'Belirtilmemiş'}`,
        `Kaynak IP: ${srcIp}${countryStr}`
      );
    } else if (
      lowLine.includes('union select') ||
      (lowLine.includes('union') && lowLine.includes('select')) ||
      lowLine.includes('or 1=1') ||
      lowLine.includes('waitfor delay') ||
      lowLine.includes('information_schema')
    ) {
      attackVector = 'SQL_INJECTION';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 92;
        confidenceLabel = 'SQLi Atağı Engellendi';
        threatTitle = 'Engellenmiş Saldırı: SQL Enjeksiyonu Denemesi (SQLi Engellendi)';
        summaryReason =
          `İstek parametrelerinde veritabanı manipülasyonu amaçlı SQL enjeksiyon dizgisi tespit edilmiş, güvenlik cihazı tarafından engellenmiştir (${wafAction}). Veritabanına ulaşılmamıştır.`;
      } else {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 85;
        confidenceLabel = 'İnceleme Gerektiren İstek';
        threatTitle = 'Şüpheli İstek: SQL Enjeksiyonu Göstergesi Tespit Edildi';
        const statusNote = parsed?.status_code
          ? (parsed.status_code === 200
              ? ' (HTTP 200 yanıtı tek başına saldırının başarılı olduğunu kanıtlamaz; uygulamanın yanıt gövdesi ve veritabanı logları doğrulanmalıdır)'
              : parsed.status_code === 403
              ? ' (HTTP 403 yanıtı tek başına WAF engellemesi olduğunu kanıtlamaz; web sunucusu yetki reddi olabilir)'
              : ` (HTTP ${parsed.status_code} yanıt kodu gözlendi)`)
          : '';
        const actionNote = hasExplicitAction
          ? `Güvenlik cihazı aksiyonu: "${wafAction}" (engellenmemiş).`
          : 'Logda açık bir WAF/güvenlik cihazı engelleme aksiyonu bulunmamaktadır.';
        summaryReason =
          `İstek parametrelerinde SQL enjeksiyon deseni saptanmıştır. ${actionNote}${statusNote} Veritabanı sorgu logları ve uygulama davranışı adli olarak incelenmelidir.`;
      }
      deepForensics.push(
        `Tetiklenen Desen: ${matchedPattern || requestUrl || 'SQL Syntax'}`,
        `Güvenlik Aksiyonu: ${hasExplicitAction ? wafAction : 'Belirtilmemiş (Aksiyon Alanı Yok)'}`,
        `Kaynak IP: ${srcIp} -> Hedef: ${dstIp}${dstPort ? ':' + dstPort : ''}`
      );
    } else if (
      lowLine.includes('<script') ||
      lowLine.includes('javascript:') ||
      lowLine.includes('onerror=') ||
      lowLine.includes('onload=')
    ) {
      attackVector = 'XSS';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 90;
        confidenceLabel = 'XSS İsteği Engellendi';
        threatTitle = 'Engellenmiş Saldırı: Siteler Arası Betik Çalıştırma (XSS Engellendi)';
        summaryReason =
          `İstemci tarafında zararlı JavaScript yürütmeyi hedefleyen XSS payloadı tespit edilmiş ve güvenlik katmanı tarafından engellenmiştir (${wafAction}).`;
      } else {
        verdict = 'SUSPICIOUS_ANOMALY';
        confidence = 80;
        confidenceLabel = 'Şüpheli Web İsteği';
        threatTitle = 'Şüpheli Aktivite: Olası XSS Girişimi';
        const statusNote = parsed?.status_code
          ? (parsed.status_code === 200
              ? ' (HTTP 200 tek başına script yürütüldüğünü kanıtlamaz; sayfa sanitizasyonu incelenmelidir)'
              : parsed.status_code === 403
              ? ' (HTTP 403 tek başına WAF engellemesi kanıtı değildir)'
              : ` (HTTP ${parsed.status_code})`)
          : '';
        const actionNote = hasExplicitAction
          ? `Aksiyon: "${wafAction}".`
          : 'Açık WAF engelleme aksiyonu bulunmamaktadır.';
        summaryReason = `XSS kalıbı içeren istek tespit edilmiştir. ${actionNote}${statusNote} Sayfa çıktısının filtrelenip filtrelenmediği teyit edilmelidir.`;
      }
      deepForensics.push(
        `İstek Detayı: ${requestUrl || 'XSS Payload'}`,
        `Aksiyon: ${hasExplicitAction ? wafAction : 'Belirtilmemiş'}`,
        `Kaynak IP: ${srcIp}${countryStr}`
      );
    } else if (
      lowLine.includes('../') ||
      lowLine.includes('..\\') ||
      lowLine.includes('/etc/passwd') ||
      lowLine.includes('windows/win.ini')
    ) {
      attackVector = 'PATH_TRAVERSAL';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 92;
        confidenceLabel = 'Dizin Atlama Engellendi';
        threatTitle = 'Engellenmiş Saldırı: Dizin Atlama / Dosya Okuma Engellendi (Path Traversal)';
        summaryReason =
          `Uygulama kök dizini dışındaki sistem dosyalarını okumayı amaçlayan dizin atlama deseni yakalanmış ve engellenmiştir (${wafAction}).`;
      } else {
        verdict = 'POTENTIAL_COMPROMISE';
        confidence = 88;
        confidenceLabel = 'Dosya Erişim Şüphesi';
        threatTitle = 'Kritik İstismar Şüphesi: Dizin Atlama (Path Traversal / LFI)';
        const statusNote = parsed?.status_code
          ? (parsed.status_code === 200
              ? ' (HTTP 200 tek başına dosyanın okunduğunu kanıtlamaz; dönen yanıt boyutu ve içeriği doğrulanmalıdır)'
              : parsed.status_code === 403
              ? ' (HTTP 403 tek başına WAF engellemesi kanıtı değildir; dosya sistemi izin reddi olabilir)'
              : ` (HTTP ${parsed.status_code})`)
          : '';
        const actionNote = hasExplicitAction
          ? `Aksiyon: "${wafAction}".`
          : 'Açık WAF engelleme aksiyonu bulunmamaktadır.';
        summaryReason = `Sistem dosyalarına erişim içeren istek tespit edilmiştir. ${actionNote}${statusNote} Sunucunun dosya içeriği döndürüp döndürmediği acilen araştırılmalıdır.`;
      }
      deepForensics.push(
        `Hedeflenen Dosya / Yol: ${requestUrl || 'Sistem Dosyası'}`,
        `Aksiyon: ${hasExplicitAction ? wafAction : 'Belirtilmemiş'}`,
        `Kaynak IP: ${srcIp}${countryStr}`
      );
    } else if (lowLine.includes('sshd') || lowLine.includes('failed password') || lowLine.includes('connection closed by invalid user')) {
      attackVector = 'LINUX_SSH';
      verdict = 'LIKELY_FALSE_POSITIVE';
      confidence = 85;
      confidenceLabel = 'SSH Kimlik Doğrulama Reddi';
      threatTitle = 'SSH: Hatalı Parola veya Geçersiz Kullanıcı (Sunucu Kimlik Doğrulama Reddi)';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): SSH sunucusu oturum açma isteğini hatalı kimlik bilgisi sebebiyle reddetmiştir (Kaynak IP: ${srcIp}, Kullanıcı: ${universalEvidence.actor.value || 'Bilinmiyor'}). Yorum (Interpretation): Sunucu seviyesinde standart kimlik doğrulama başarısızlığıdır. Güvenlik cihazı (Firewall/WAF) engelleme kararı (DENY) DEĞİLDİR. Belirsizlik (Uncertainty): Tekil başarısız oturum tek başına kaba kuvvet (Brute Force) kanıtı değildir.`;
      deepForensics.push(
        `Olay: SSH Sunucu Kimlik Doğrulama Telemetrisi`,
        `Kullanıcı: ${universalEvidence.actor.value || 'Bilinmiyor'}`,
        `Kaynak IP: ${srcIp}`,
        `Adli Saptama: Güvenlik cihazı engellemesi (Firewall/WAF DENY) DEĞİLDİR.`,
        `PROVENANCE: FINAL DECISION (${verdict}) → EVIDENCE (${threatTitle}) → SEMANTIC INTERPRETATION (${attackVector}) → RAW SPAN`
      );
    } else if (lowLine.includes('postfix') || lowLine.includes('smtpd') || lowLine.includes('sasl login authentication failed')) {
      attackVector = 'MAIL_AUTH';
      verdict = 'LIKELY_FALSE_POSITIVE';
      confidence = 85;
      confidenceLabel = 'E-posta Kimlik Doğrulama Reddi';
      threatTitle = 'Postfix / SMTPD: SASL Kimlik Doğrulama Başarısızlığı';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Postfix e-posta sunucusunda SASL kimlik doğrulama reddi kaydedilmiştir (Kaynak IP: ${srcIp}). Yorum (Interpretation): E-posta sunucu seviyesinde kimlik doğrulama başarısızlığıdır; güvenlik cihazı (Firewall/WAF) engelleme kararı (DENY) DEĞİLDİR.`;
      deepForensics.push(
        `Olay: Postfix / SMTPD Telemetrisi`,
        `Kaynak IP: ${srcIp}`,
        `Adli Saptama: Güvenlik cihazı engellemesi (DENY) DEĞİLDİR.`,
        `PROVENANCE: FINAL DECISION (${verdict}) → EVIDENCE (${threatTitle}) → SEMANTIC INTERPRETATION (${attackVector}) → RAW SPAN`
      );
    } else if (universalEvidence.telemetry.httpStatus.value === 401 || (parsed?.status_code === 401 && !isBlocked)) {
      attackVector = 'HTTP_401';
      verdict = 'LIKELY_FALSE_POSITIVE';
      confidence = 80;
      confidenceLabel = 'Yetkilendirme Hatası (HTTP 401)';
      threatTitle = 'Web / API Yetkilendirme Hatası: HTTP 401 Unauthorized';
      summaryReason = `Gözlenen Kanıt (Observed Evidence): Web/API isteği HTTP 401 (Unauthorized) kimlik doğrulama/yetki reddi koduyla yanıtlanmıştır. Yorum (Interpretation): Uygulama katmanında kimlik doğrulama eksikliği veya yetki reddidir; güvenlik cihazı (WAF/Firewall) engelleme kararı (BLOCK/DENY) DEĞİLDİR.`;
      deepForensics.push(
        `HTTP Yanıtı: 401 Unauthorized`,
        `Kaynak: ${srcIp} -> Hedef: ${targetHost || dstIp}`,
        `Adli Saptama: Güvenlik cihazı engellemesi (WAF Block) DEĞİLDİR.`,
        `PROVENANCE: FINAL DECISION (${verdict}) → EVIDENCE (${threatTitle}) → SEMANTIC INTERPRETATION (${attackVector}) → RAW SPAN`
      );
    } else {
      attackVector = 'GENERIC';
      if (isBlocked) {
        verdict = 'BLOCKED_ATTACK_ATTEMPT';
        confidence = 70;
        confidenceLabel = 'Cihaz Tarafından Engellendi';
        threatTitle = parsed?.islem_komutu
          ? `Engellenen Olay: ${parsed.islem_komutu.slice(0, 60)}`
          : 'Güvenlik Cihazı Tarafından Engellenen İstek';
        summaryReason = `Log başarıyla ayrıştırıldı. Güvenlik cihazı engelleme kararı uygulamıştır (${wafAction}).`;
      } else {
        const isErrorStatus = (universalEvidence.telemetry.httpStatus.value && universalEvidence.telemetry.httpStatus.value >= 400) ||
          (parsed?.status_code && parsed.status_code >= 400);
        const statusCodeVal = universalEvidence.telemetry.httpStatus.value || parsed?.status_code;
        if (isErrorStatus) {
          verdict = 'SUSPICIOUS_ANOMALY';
          confidence = 60;
          confidenceLabel = 'Hata Kodu İncelemesi';
          threatTitle = `Web Yanıt Anomalisi (HTTP ${statusCodeVal})`;
          summaryReason = `İstek HTTP ${statusCodeVal} durum koduyla sonuçlanmıştır. HTTP ${statusCodeVal} tek başına WAF engellemesi kanıtı değildir (web sunucusu yetki reddi veya kaynak kısıtlaması olabilir). Saldırı veya engelleme teyidi için ek telemetri gereklidir.`;
        } else {
          verdict = 'UNKNOWN';
          confidence = 50;
          confidenceLabel = 'Belirsiz / Ek Delil Gerekli';
          threatTitle = 'Belirsiz Telemetri: Yetersiz Güvenlik Kanıtı (Çekimserlik)';
          summaryReason = 'Sağlanan log satırında doğrudan bir saldırı deseni veya güvenlik engelleme kaydı saptanmamıştır. Kesin bir güvenlik verdikti üretmek için ek telemetri gereklidir.';
        }
      }
      deepForensics.push(
        `Kaynak: ${srcIp} -> Hedef: ${dstIp}${dstPort ? ':' + dstPort : ''}`,
        `Aksiyon: ${hasExplicitAction ? wafAction : 'Belirtilmemiş'}`,
        `PROVENANCE: FINAL DECISION (${verdict}) → EVIDENCE (${threatTitle}) → SEMANTIC INTERPRETATION (${attackVector}) → RAW SPAN`
      );
    }
  }

  // 6. EXTRA INFO QUESTIONS & BADGE CREATION
  const requiredExtraInfo = generateTailoredExtraInfo({
    isWindows: winDetails.isWindowsEvent,
    winDetails,
    attackVector,
    srcIp,
    dstIp,
    dstPort,
    logTime,
    targetHost,
    requestUrl,
    wafAction,
    sigSubclass,
    matchedPattern,
  });

  let verdictBadge: UnifiedDecisionBadge = {
    text: 'ŞÜPHELİ / İNCELEME GEREKTİRİR',
    badgeClasses: 'bg-amber-100 text-amber-900 border border-amber-300',
    cardClasses: 'bg-amber-50/70 border-amber-200',
    iconBgClasses: 'bg-amber-500 text-white',
    iconType: 'alertTriangle',
  };

  if (verdict === 'LIKELY_FALSE_POSITIVE') {
    verdictBadge = {
      text: 'MUHTEMEL YANLIŞ ALARM (FP ADAYI)',
      badgeClasses: 'bg-emerald-100 text-emerald-900 border border-emerald-300',
      cardClasses: 'bg-emerald-50/70 border-emerald-200',
      iconBgClasses: 'bg-emerald-600 text-white',
      iconType: 'shieldCheck',
    };
  } else if (verdict === 'BLOCKED_ATTACK_ATTEMPT') {
    verdictBadge = {
      text: 'ENGELLENMİŞ SALDIRI GİRİŞİMİ',
      badgeClasses: 'bg-blue-100 text-blue-900 border border-blue-300',
      cardClasses: 'bg-blue-50/70 border-blue-200',
      iconBgClasses: 'bg-blue-600 text-white',
      iconType: 'shieldAlert',
    };
  } else if (verdict === 'POTENTIAL_COMPROMISE') {
    verdictBadge = {
      text: 'KRİTİK ADLİ TEHDİT / SÖMÜRÜ ŞÜPHESİ',
      badgeClasses: 'bg-rose-100 text-rose-900 border border-rose-300',
      cardClasses: 'bg-rose-50/70 border-rose-200',
      iconBgClasses: 'bg-rose-600 text-white',
      iconType: 'shieldAlert',
    };
  } else if (verdict === 'AUTHORIZED_ACTIVITY') {
    verdictBadge = {
      text: 'MEŞRU / BEKLENEN ETKİNLİK',
      badgeClasses: 'bg-slate-100 text-slate-800 border border-slate-300',
      cardClasses: 'bg-slate-50 border-slate-200',
      iconBgClasses: 'bg-slate-600 text-white',
      iconType: 'shield',
    };
  } else if (verdict === 'UNKNOWN') {
    verdictBadge = {
      text: 'BELİRSİZ / ÇEKİMSER (YETERSİZ KANIT)',
      badgeClasses: 'bg-zinc-100 text-zinc-800 border border-zinc-300',
      cardClasses: 'bg-zinc-50 border-zinc-200',
      iconBgClasses: 'bg-zinc-500 text-white',
      iconType: 'info',
    };
  } else if (verdict === 'NOT_ASSESSED') {
    verdictBadge = {
      text: 'DEĞERLENDİRİLMEDİ (ÇAPRAZ KONTAMİNASYON)',
      badgeClasses: 'bg-zinc-800 text-zinc-200 border border-zinc-600',
      cardClasses: 'bg-zinc-900 border-zinc-700',
      iconBgClasses: 'bg-zinc-700 text-white',
      iconType: 'info',
    };
  }

  // 7. CUSTOMER RESPONSE TEXT GENERATION
  const correlationBlock = correlations.length > 0
    ? `\n■ KORELASYON İLİŞKİSİ: Bu olay, analizdeki ${correlations.map(c => `#${c.sourceEventId} (${c.eventType || c.correlationReason})`).join(', ')} ile ilişkilendirilmiştir.`
    : '';

  let customerResponseText = '';
  if (winDetails.isWindowsEvent) {
    if (winDetails.eventId === 7045) {
      customerResponseText = `Merhaba,

İlettiğiniz Windows Güvenlik Olayı (Event ID ${winDetails.eventId} - ${winDetails.eventName}) L3 Güvenlik Operasyonları (SOC) ekibimiz tarafından incelenmiştir.

■ ADLİ DEĞERLENDİRME: ${threatTitle}
■ VERDİKT: ${verdictBadge.text}
■ GÜVEN / OLASILIK: ${confidenceLabel} (%${confidence})
■ SERVİS ADI: ${winDetails.serviceName || 'Bilinmiyor'}
■ SERVİS DOSYA YOLU: ${winDetails.serviceFile || 'Bilinmiyor'}
■ KURAN HESAP: ${winDetails.subjectUser || 'Bilinmiyor'}
■ HEDEF BİLGİSAYAR: ${winDetails.computer || 'Windows Endpoint'}${correlationBlock}

■ ADLİ ANALİZ VE GEREKÇE:
${summaryReason}

■ TESPİT EDİLEN ADLİ BULGULAR:
${deepForensics.map((f) => '• ' + f).join('\n')}

■ MÜŞTERİDEN TEYİT TALEP EDİLEN BİLGİLER:
${requiredExtraInfo.map((info, i) => `${i + 1}. ${info}`).join('\n')}

Bilgilerinize sunarız.
SOC Güvenlik Operasyonları Merkezi`;
    } else {
      customerResponseText = `Merhaba,

İlettiğiniz Windows Güvenlik Olayı (${winDetails.eventId ? `Olay ID: ${winDetails.eventId} - ${winDetails.eventName}` : 'Güvenlik Günlüğü'}) L3 Güvenlik Operasyonları (SOC) ekibimiz tarafından incelenmiştir.

■ ADLİ DEĞERLENDİRME: ${threatTitle}
■ VERDİKT: ${verdictBadge.text}
■ GÜVEN / OLASILIK: ${confidenceLabel} (%${confidence})
■ İLGİLİ HESAP / KULLANICI: ${winDetails.targetUser || winDetails.subjectUser || 'Belirtilmemiş'}
■ HEDEF BİLGİSAYAR / ETKİ ALANI: ${winDetails.computer || winDetails.workstation || 'Windows Endpoint'}
■ OTURUM TÜRÜ: ${winDetails.logonTypeDesc}
■ HATA KODU & TEKNİK NEDEN: ${winDetails.subStatus ? `${winDetails.subStatus} (${winDetails.subStatusDesc})` : winDetails.status || 'Normal Akış / Başarılı'}
■ KAYNAK IP / İŞ İSTASYONU: ${srcIp}${countryStr}${correlationBlock}

■ ADLİ ANALİZ VE GEREKÇE:
${summaryReason}

■ TESPİT EDİLEN ADLİ BULGULAR:
${deepForensics.map((f) => '• ' + f).join('\n')}

■ MÜŞTERİDEN TEYİT TALEP EDİLEN BİLGİLER:
${requiredExtraInfo.map((info, i) => `${i + 1}. ${info}`).join('\n')}

Bilgilerinize sunarız.
SOC Güvenlik Operasyonları Merkezi`;
    }
  } else if (verdict === 'LIKELY_FALSE_POSITIVE') {
    customerResponseText = `Merhaba,

İlettiğiniz güvenlik uyarısı (Cihaz: ${deviceId}, Kural: ${sigSubclass}${sigId ? ` [ID: ${sigId}]` : ''}) L3 Güvenlik Operasyonları (SOC) ekibimiz tarafından incelenmiştir.

■ ADLİ DEĞERLENDİRME: MUHTEMEL YANLIŞ ALARM (FP ADAYI)
■ GÜVEN / OLASILIK: ${confidenceLabel} (%${confidence})
■ TETİKLENEN KURAL: ${sigSubclass}${sigId ? ` (ID: ${sigId})` : ''}
■ İLGİLİ KAYNAK IP: ${srcIp}${countryStr}
■ HEDEF SERVİS: ${targetHost || (dstIp !== 'Bilinmiyor' ? dstIp + (dstPort ? ':' + dstPort : '') : 'Web Portalı')}

■ TEKNİK ADLİ GEREKÇE:
${summaryReason}

■ TESPİT EDİLEN ADLİ BULGULAR:
${deepForensics.map((f) => '• ' + f).join('\n')}

■ KESİNLEŞTİRME İÇİN MÜŞTERİDEN TALEP EDİLEN TEYİT:
${requiredExtraInfo.map((info, i) => `${i + 1}. ${info}`).join('\n')}

Bilgilerinize sunarız.
SOC Güvenlik Operasyonları Merkezi`;
  } else if (verdict === 'BLOCKED_ATTACK_ATTEMPT') {
    customerResponseText = `Merhaba,

İlettiğiniz güvenlik log kaydı (Cihaz: ${deviceId}) L3 Güvenlik Operasyonları (SOC) ekibimiz tarafından incelenmiştir.

■ ADLİ DEĞERLENDİRME: ENGELLENMİŞ SALDIRI GİRİŞİMİ (GÜVENLİK CİHAZI ENGELLEDİ)
■ GÜVEN / OLASILIK: ${confidenceLabel} (%${confidence})
■ KAYNAK ADRESİ: ${srcIp}${countryStr}
■ HEDEF SERVİS: ${targetHost || dstIp}${dstPort ? ':' + dstPort : ''}
■ UYGULANAN AKSİYON: ${wafAction} (İstek başarıyla engellenmiştir)

■ ÖZET ANALİZ SONUCU:
${summaryReason}

■ TESPİT EDİLEN ADLİ BULGULAR:
${deepForensics.map((f) => '• ' + f).join('\n')}

■ GEREKLİ KONTROL & TEYİT TALEBİ:
${requiredExtraInfo.map((info, i) => `${i + 1}. ${info}`).join('\n')}

Bilgilerinize sunarız.
SOC Güvenlik Operasyonları Merkezi`;
  } else {
    customerResponseText = `Merhaba,

İlettiğiniz güvenlik log kaydı (Cihaz: ${deviceId}) SOC analiz uzmanlarımız tarafından incelenmiştir.

■ ADLİ DEĞERLENDİRME: ${verdictBadge.text}
■ GÜVEN / OLASILIK: ${confidenceLabel} (%${confidence})
■ KAYNAK ADRESİ: ${srcIp}${countryStr}
■ HEDEF SERVİS: ${targetHost || dstIp}${dstPort ? ':' + dstPort : ''}
■ UYGULANAN AKSİYON: ${wafAction}

■ ÖZET ANALİZ SONUCU:
${summaryReason}

■ TESPİT EDİLEN ADLİ BULGULAR:
${deepForensics.map((f) => '• ' + f).join('\n')}

■ MÜŞTERİDEN TALEP EDİLEN BİLGİLER:
${requiredExtraInfo.map((info, i) => `${i + 1}. ${info}`).join('\n')}

Bilgilerinize sunarız.
SOC Güvenlik Operasyonları Merkezi`;
  }

  return {
    parsedLog: parsed,
    detectedFormat: formatName,
    verdict,
    verdictBadge,
    confidence,
    confidenceLabel,
    threatTitle,
    summaryReason,
    deepForensics,
    customerResponseText,
    requiredExtraInfo,
    rawKeyValues: kvDict,
    winDetails,
    correlations,
    action: hasExplicitAction ? wafAction : (pureFirewallDecision || ''),
    isBlocked,
    universalEvidence,
    dynamicHypotheses,
    provenFacts,
    unprovenHypotheses,
    missingInformation,
    dataIntegrityGuarded: true,
  };
}
