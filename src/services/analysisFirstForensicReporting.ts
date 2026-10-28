import { ObservedFromImage, StructuredTableRow } from './imageForensicService';
import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
  HttpRequestDetails,
} from './httpRequestAnalyzer';

export type ForensicSecurityVerdict =
  | 'MEŞRU / BEKLENEN ETKİNLİK'
  | 'BİLGİ AMAÇLI / GÜVENLİK SONUCU YOK'
  | 'ŞÜPHELİ ETKİNLİK'
  | 'MUHTEMEL YANLIŞ ALARM'
  | 'ENGELLENMİŞ SALDIRI GİRİŞİMİ'
  | 'SALDIRI BELİRTİSİ'
  | 'SALDIRI BAŞARISI KANITLANMADI'
  | 'YETERSİZ KANIT';

export interface AnalysisFirstObservedFacts {
  sourceIp: string;
  destinationIp: string;
  timestamp: string;
  deviceOrPlatform: string;
  requestOrCommand: string;
  action: string;
  statusCode: string;
  userOrAccount: string;
  hostOrEndpoint: string;
}

export interface AnalysisFirstSecurityInterpretation {
  whatIsSeen: string;
  whatMightHaveHappened: string;
  securityMeaning: string;
  supportingEvidence: string[];
}

export interface AnalysisFirstForensicReport {
  executiveSummary: string;
  securityVerdict: ForensicSecurityVerdict;
  verdictRationale: string;
  observedFacts: AnalysisFirstObservedFacts;
  securityInterpretation: AnalysisFirstSecurityInterpretation;
  unprovenAspects: string[];
  recommendedInvestigationSteps: string[];
  markdownReport: string;
}

/**
 * Determines whether a payload contains known malicious exploitation patterns
 */
function detectMaliciousPayloadPattern(str: string): { isMalicious: boolean; type?: string } {
  if (!str) return { isMalicious: false };
  const lower = str.toLowerCase();

  if (
    lower.includes('/etc/passwd') ||
    lower.includes('../') ||
    lower.includes('..\\') ||
    lower.includes('%2e%2e%2f') ||
    lower.includes('/winnt/') ||
    lower.includes('/windows/system32/')
  ) {
    return { isMalicious: true, type: 'Dizin Atlama (Path Traversal / LFI)' };
  }

  if (
    lower.includes('union select') ||
    lower.includes('union%20select') ||
    lower.includes('or 1=1') ||
    lower.includes("or '1'='1") ||
    lower.includes('information_schema') ||
    lower.includes('sleep(') ||
    lower.includes('waitfor delay')
  ) {
    return { isMalicious: true, type: 'SQL Enjeksiyonu (SQLi)' };
  }

  if (
    lower.includes('<script') ||
    lower.includes('javascript:') ||
    lower.includes('onerror=') ||
    lower.includes('onload=') ||
    lower.includes('<svg')
  ) {
    return { isMalicious: true, type: 'Siteler Arası Betik Çalıştırma (XSS)' };
  }

  if (
    lower.includes('powershell') &&
    (lower.includes('-enc') || lower.includes('downloadstring') || lower.includes('bypass') || lower.includes('iex'))
  ) {
    return { isMalicious: true, type: 'Zararlı PowerShell / LOLBAS Yürütme' };
  }

  if (lower.includes('certutil') && (lower.includes('-urlcache') || lower.includes('-split'))) {
    return { isMalicious: true, type: 'LOLBAS Dosya İndirme (certutil)' };
  }

  return { isMalicious: false };
}

/**
 * Generates an analysis-first forensic report strictly from observed evidence.
 * Follows the fundamental product principle: SYSTEM IMPLEMENTATION != ANALYSIS RESULT
 */
export function generateAnalysisFirstReport(params: {
  observed?: ObservedFromImage | null;
  observedFromImage?: ObservedFromImage | null;
  observedTelemetry?: any;
  visualPlatform?: string;
  platformFamily?: string;
  confidence?: string | number;
  structuredTableRows?: StructuredTableRow[];
  fallbackLimitation?: any;
  rawOcrText?: string;
  [key: string]: any;
}): AnalysisFirstForensicReport {
  const observed = params.observed || params.observedFromImage || params.observedTelemetry || null;
  const visualPlatform = params.visualPlatform || params.platformFamily || (params as any).visualPlatformName;
  const fallbackLimitation = params.fallbackLimitation;

  // Case B: Fallback / Pixel data could not be inspected
  if (fallbackLimitation || !observed || (!observed.sourceIp && !observed.commandLine && !observed.action && !observed.status && !observed.eventId && !observed.rawMessage)) {
    const isNoText = fallbackLimitation?.errorCode === 'NO_TEXT_DETECTED';
    const reasonText = isNoText
      ? 'Görselde okunabilir güvenlik telemetrisi veya metin karakteri tespit edilemedi.'
      : 'Görsel üzerinde doğrulanabilir güvenlik telemetrisi veya olay alanı okunamadı.';

    return {
      executiveSummary: `Görüntü üzerinde güvenli bir şekilde okunabilen bir ağ veya sistem telemetri kaydı tespit edilememiştir. ${reasonText} Bu nedenle güvenlik açısından kesin bir olay değerlendirmesi yapılamamıştır.`,
      securityVerdict: 'YETERSİZ KANIT',
      verdictRationale: 'Görselde adli analizi destekleyecek doğrulanabilir telemetri alanı bulunmamaktadır.',
      observedFacts: {
        sourceIp: 'NOT OBSERVED',
        destinationIp: 'NOT OBSERVED',
        timestamp: 'NOT OBSERVED',
        deviceOrPlatform: visualPlatform || 'NOT OBSERVED',
        requestOrCommand: 'NOT OBSERVED',
        action: 'NOT OBSERVED',
        statusCode: 'NOT OBSERVED',
        userOrAccount: 'NOT OBSERVED',
        hostOrEndpoint: 'NOT OBSERVED',
      },
      securityInterpretation: {
        whatIsSeen: 'Görselde okunabilir güvenlik olayı veya ağ kaydı verisi saptanamadı.',
        whatMightHaveHappened: 'Görüntü düşük çözünürlüklü, boş, güvenlik kaydı içermeyen bir arayüz veya okunamayan bir grafik formatında olabilir.',
        securityMeaning: 'Mevcut görsel üzerinden herhangi bir saldırı veya normal aktivite kanıtı türetilemez.',
        supportingEvidence: [],
      },
      unprovenAspects: [
        'Herhangi bir güvenlik ihlali veya istismar kanıtlanmamıştır.',
        'Kaynak veya hedef sistem kimliği belirlenememiştir.',
        'Ağ veya sistem üzerinde bir etkinlik gerçekleştiği kanıtlanmamıştır.',
      ],
      recommendedInvestigationSteps: [
        'Daha yüksek çözünürlüklü bir ekran görüntüsü sağlayın veya ham SIEM/Syslog metin kaydını sisteme yapıştırın.',
        'İlgili zaman aralığı için doğrudan SIEM veya Firewall arayüzünden olay sorgusu gerçekleştirin.',
      ],
      markdownReport: renderAnalysisFirstMarkdown({
        executiveSummary: `Görüntü üzerinde güvenli bir şekilde okunabilen bir ağ veya sistem telemetri kaydı tespit edilememiştir. ${reasonText}`,
        securityVerdict: 'YETERSİZ KANIT',
        verdictRationale: 'Doğrulanabilir telemetri alanı bulunmamaktadır.',
        observedFacts: {
          sourceIp: 'NOT OBSERVED',
          destinationIp: 'NOT OBSERVED',
          timestamp: 'NOT OBSERVED',
          deviceOrPlatform: visualPlatform || 'NOT OBSERVED',
          requestOrCommand: 'NOT OBSERVED',
          action: 'NOT OBSERVED',
          statusCode: 'NOT OBSERVED',
          userOrAccount: 'NOT OBSERVED',
          hostOrEndpoint: 'NOT OBSERVED',
        },
        securityInterpretation: {
          whatIsSeen: 'Okunabilir telemetri alanı saptanamadı.',
          whatMightHaveHappened: 'Görsel güvenlik verisi içermiyor veya çözünürlük yetersiz.',
          securityMeaning: 'Herhangi bir saldırı veya olay kanıtı türetilemez.',
          supportingEvidence: [],
        },
        unprovenAspects: [
          'Güvenlik ihlali kanıtlanmadı.',
          'Kaynak ve hedef kimliği kanıtlanmadı.',
        ],
        recommendedInvestigationSteps: [
          'Daha yüksek çözünürlüklü görsel veya ham log sağlayın.',
        ],
      }),
    };
  }

  // 1. Extract Observed Facts strictly (zero fabrication)
  const sourceIp = observed.sourceIp || 'NOT OBSERVED';
  const destinationIp = observed.destinationIp || 'NOT OBSERVED';
  const timestamp = observed.timestamp || 'NOT OBSERVED';
  const deviceOrPlatform = visualPlatform || 'Güvenlik Cihazı / Günlük Kaydı';

  // HTTP Request Semantic Detection
  let httpInfo: HttpRequestDetails | null = observed.httpRequest || null;
  let requestOrCommand = observed.commandLine || 'NOT OBSERVED';

  if (!httpInfo) {
    if (requestOrCommand !== 'NOT OBSERVED' && isHttpRequestPattern(requestOrCommand)) {
      httpInfo = parseHttpRequestSemantics(requestOrCommand);
    } else if (observed.rawMessage && isHttpRequestPattern(observed.rawMessage)) {
      httpInfo = parseHttpRequestSemantics(observed.rawMessage);
    }
  }

  // If requestOrCommand was an HTTP request, format cleanly as HTTP request
  if (httpInfo) {
    requestOrCommand = `${httpInfo.method} ${httpInfo.requestUri} ${httpInfo.protocol}`;
  }

  const actionRaw = observed.action || 'NOT OBSERVED';
  const statusCode = observed.status || 'NOT OBSERVED';
  const userOrAccount = observed.username || 'NOT OBSERVED';
  const hostOrEndpoint = observed.host || 'NOT OBSERVED';

  // Normalization of action
  const isBlocked = actionRaw !== 'NOT OBSERVED' && /\b(blocked|deny|drop|reject|reset|prevent)\b/i.test(actionRaw);
  const isAlert = actionRaw !== 'NOT OBSERVED' && /\b(alert|alarm|monitor|log)\b/i.test(actionRaw);
  const isAllow = actionRaw !== 'NOT OBSERVED' && /\b(allow|allowed|pass|accept)\b/i.test(actionRaw);

  const combinedSearchText = [
    requestOrCommand !== 'NOT OBSERVED' ? requestOrCommand : '',
    observed.rawMessage || (observed as any).rawText || '',
    params.rawOcrText || '',
    ...(params.structuredTableRows || []).map((r) => `${r.ruleOrEvent} ${r.action} ${r.sourceIp}`),
    ...((params as any).ocrEvidenceLines || []).map((l: any) => l.text || ''),
  ].join(' ');

  const payloadCheck = detectMaliciousPayloadPattern(combinedSearchText);

  // Multi-request analysis across structuredTableRows and raw text (e.g. F5 table)
  const tableRows = params.structuredTableRows || [];
  const rawRequestMatches = (combinedSearchText.match(/\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+[^\s\r\n]+/gi) || []);
  const uniqueRequests = Array.from(new Set(rawRequestMatches.map((m) => m.toLowerCase())));
  const hasMultipleRequests = tableRows.length > 1 || uniqueRequests.length > 1;
  const isF5 = (deviceOrPlatform || '').toLowerCase().includes('f5') || combinedSearchText.toLowerCase().includes('f5');

  // Check observed attack vectors in traffic
  const observedAttackVectors: string[] = [];
  const lowerSearch = combinedSearchText.toLowerCase();

  if (lowerSearch.includes('/etc/passwd') || lowerSearch.includes('passwd')) {
    observedAttackVectors.push('/etc/passwd erişim denemeleri');
  }
  if (lowerSearch.includes('../') || lowerSearch.includes('..\\') || lowerSearch.includes('%2e%2e%2f') || lowerSearch.includes('..%2f')) {
    observedAttackVectors.push('path traversal dizileri');
  }
  if (lowerSearch.includes('union select') || lowerSearch.includes('union%20select') || lowerSearch.includes('or 1=1') || lowerSearch.includes("or '1'='1") || lowerSearch.includes('information_schema')) {
    observedAttackVectors.push('SQL injection benzeri parametreler');
  }
  if (lowerSearch.includes('/druid/indexer') || lowerSearch.includes('/actuator') || lowerSearch.includes('/solr') || lowerSearch.includes('/cgi-bin') || lowerSearch.includes('/admin') || lowerSearch.includes('/manager')) {
    observedAttackVectors.push('hassas yönetim endpoint\'lerine erişim');
  }
  if (/\bpost\b/i.test(combinedSearchText) && (lowerSearch.includes('/sampler') || lowerSearch.includes('/v1/') || lowerSearch.includes('/api/'))) {
    observedAttackVectors.push('uygulama servislerine yönelik şüpheli POST istekleri');
  }
  if (lowerSearch.includes('<script') || lowerSearch.includes('javascript:') || lowerSearch.includes('onerror=')) {
    observedAttackVectors.push('Siteler arası betik çalıştırma (XSS) parametreleri');
  }

  const allTableRowsBlocked = tableRows.length > 0 && tableRows.every((r) => !r.action || /\b(blocked|deny|drop|reject|reset|prevent)\b/i.test(r.action));

  // 2. Strict Security Verdict Classification
  // Fundamental Principles:
  // - MALICIOUS PAYLOAD != ATTACK SUCCESS
  // - HTTP 403 != WAF BLOCK
  // - BLOCKED != COMPROMISED
  // - REQUEST != COMMAND EXECUTION
  let securityVerdict: ForensicSecurityVerdict;
  let verdictRationale: string;

  if (hasMultipleRequests && (allTableRowsBlocked || isBlocked)) {
    securityVerdict = 'ENGELLENMİŞ SALDIRI GİRİŞİMİ';
    verdictRationale = `${isF5 ? 'F5 WAF' : 'Güvenlik cihazı'} gelen tüm şüpheli istekleri engellemiştir (Aksiyon: ${actionRaw !== 'NOT OBSERVED' ? actionRaw : 'blocked'}).`;
  } else if (httpInfo) {
    if (isBlocked) {
      securityVerdict = 'ENGELLENMİŞ SALDIRI GİRİŞİMİ';
      verdictRationale = `Güvenlik cihazı ${httpInfo.targetTechnology} endpoint'ine (${httpInfo.endpoint}) yönelen HTTP isteğini engellemiştir (Aksiyon: ${actionRaw}).`;
    } else if (payloadCheck.isMalicious || httpInfo.isKnownVulnerabilityTarget) {
      securityVerdict = 'SALDIRI BAŞARISI KANITLANMADI';
      verdictRationale = `Görüntüde ${httpInfo.targetTechnology} (${httpInfo.endpoint}) yoluna yönelik istek yer almaktadır; ancak hedef sistemin bu isteği başarıyla işlediğine veya sistemin ele geçirildiğine dair kanıt bulunmamaktadır.`;
    } else if (statusCode === '403') {
      securityVerdict = 'ŞÜPHELİ ETKİNLİK';
      verdictRationale = 'Web sunucusu HTTP 403 (Erişim Reddedildi) yanıtı dönmüştür; ancak bu durum tek başına bir WAF engellemesi veya sistem ihlali kanıtı oluşturmaz.';
    } else {
      securityVerdict = 'BİLGİ AMAÇLI / GÜVENLİK SONUCU YOK';
      verdictRationale = `Görüntülenen kayıt ${httpInfo.targetTechnology} endpoint'ine iletilen standart bir HTTP işlemidir.`;
    }
  } else if (payloadCheck.isMalicious && isBlocked) {
    securityVerdict = 'ENGELLENMİŞ SALDIRI GİRİŞİMİ';
    verdictRationale = `Görüntüde ${payloadCheck.type} niteliğinde şüpheli bir istek deseni gözlemlenmiş; ancak güvenlik cihazı isteği engellemiştir (Aksiyon: ${actionRaw}).`;
  } else if (payloadCheck.isMalicious && !isBlocked) {
    securityVerdict = 'SALDIRI BAŞARISI KANITLANMADI';
    verdictRationale = `Görüntüde ${payloadCheck.type} deseni içeren bir istek yer almaktadır; ancak hedef sistemin bu isteği başarıyla işlediğine veya sistemin ele geçirildiğine dair kanıt bulunmamaktadır.`;
  } else if (observed.eventId === '4688' && payloadCheck.isMalicious) {
    securityVerdict = 'SALDIRI BELİRTİSİ';
    verdictRationale = `Uç noktada şüpheli/zararlı komut çalıştırma etkinliği (${payloadCheck.type}) gözlemlenmiştir.`;
  } else if (observed.eventId === '4625') {
    securityVerdict = 'ŞÜPHELİ ETKİNLİK';
    verdictRationale = `Kullanıcı (${userOrAccount}) için başarısız kimlik doğrulama anomalisi gözlemlenmiştir.`;
  } else if (statusCode === '403' && !isBlocked) {
    securityVerdict = 'ŞÜPHELİ ETKİNLİK';
    verdictRationale = 'Web sunucusu HTTP 403 (Erişim Reddedildi) yanıtı dönmüştür; ancak bu durum tek başına bir WAF engellemesi veya sistem ihlali kanıtı oluşturmaz.';
  } else if (isBlocked) {
    securityVerdict = 'ENGELLENMİŞ SALDIRI GİRİŞİMİ';
    verdictRationale = `Güvenlik cihazı isteği engellemiştir (${actionRaw}).`;
  } else if (isAlert) {
    securityVerdict = 'ŞÜPHELİ ETKİNLİK';
    verdictRationale = 'Güvenlik cihazı kural tetiklemesi ile uyarı (ALERT) üretmiştir.';
  } else if (isAllow) {
    securityVerdict = 'BİLGİ AMAÇLI / GÜVENLİK SONUCU YOK';
    verdictRationale = 'Görüntülenen ağ veya sistem trafiği meşru/izin verilmiş bağlantı kaydı niteliğindedir.';
  } else {
    securityVerdict = 'BİLGİ AMAÇLI / GÜVENLİK SONUCU YOK';
    verdictRationale = 'Görüntülenen telemetri standart işlem veya genel olay kaydıdır.';
  }

  // 3. Executive Summary (2-5 sentences describing the event, strictly analyst-focused)
  let executiveSummary = '';

  if (hasMultipleRequests && (allTableRowsBlocked || isBlocked)) {
    const vectorsText = observedAttackVectors.length > 0
      ? `\n\nGözlenen istekler arasında:\n${observedAttackVectors.map((v) => `- ${v}`).join('\n')}\n\n`
      : ' ';
    executiveSummary = `${isF5 ? 'F5 WAF' : 'Güvenlik cihazı'} ekranında${sourceIp !== 'NOT OBSERVED' ? ` aynı kaynak IP'den (${sourceIp})` : ''} gelen çok sayıda HTTP isteği görülüyor. İsteklerin tamamı 'blocked' olarak işaretlenmiş.${vectorsText}Bu örüntü normal uygulama trafiğinden ziyade otomatik saldırı/tarama faaliyetiyle uyumludur.\n\n${isF5 ? 'WAF' : 'Güvenlik'} kayıtlarında isteklerin engellendiği açıkça görüldüğü için:\nSONUÇ: ENGELLENMİŞ SALDIRI GİRİŞİMİ\n\nAncak bu ekran görüntüsü tek başına: hedef sistemde komut çalıştırıldığını, sunucunun ele geçirildiğini, dosyanın gerçekten okunduğunu veya veri sızdırıldığını kanıtlamaz.`;
  } else if (httpInfo) {
    const tech = httpInfo.targetTechnology || 'web servisi';
    if (isBlocked) {
      executiveSummary = `${sourceIp !== 'NOT OBSERVED' ? `${sourceIp} kaynaklı bir ` : ''}HTTP ${httpInfo.method} isteği ${tech}'ın ${httpInfo.endpoint} endpoint'ine yönelmiştir. ${isF5 ? 'F5 kaydında istek blocked olarak görülmektedir. ' : actionRaw !== 'NOT OBSERVED' ? `Güvenlik cihazı kaydında istek '${actionRaw}' olarak görülmektedir. ` : ''}Bu nedenle mevcut kanıt isteğin güvenlik cihazı tarafından engellendiğini desteklemektedir.\n\nSONUÇ: ENGELLENMİŞ SALDIRI GİRİŞİMİ\n\nAncak bu ekran görüntüsü tek başına: hedef sistemde komut çalıştırıldığını, sunucunun ele geçirildiğini, dosyanın gerçekten okunduğunu veya veri sızdırıldığını kanıtlamaz. Görüntü tek başına endpoint üzerinde komut çalıştırıldığını, işlemin başarıyla gerçekleştirildiğini veya hedef sistemin ele geçirildiğini kanıtlamamaktadır.`;
    } else {
      executiveSummary = `${sourceIp !== 'NOT OBSERVED' ? `${sourceIp} kaynaklı bir ` : ''}HTTP ${httpInfo.method} isteği ${tech}'ın ${httpInfo.endpoint} endpoint'ine yönelmiştir. Görüntü tek başına endpoint üzerinde komut çalıştırıldığını, işlemin başarıyla gerçekleştirildiğini veya hedef sistemin ele geçirildiğini kanıtlamamaktadır.`;
    }
  } else if (isBlocked && payloadCheck.isMalicious) {
    executiveSummary = `Görüntüde bir güvenlik cihazına ait ağ trafiği ve erişim kontrol kaydı görülmektedir. Kaynak ${sourceIp !== 'NOT OBSERVED' ? `IP ${sourceIp}` : 'tarafından'} hedef sisteme yönelik ${payloadCheck.type} niteliğinde bir istek iletilmiştir. Mevcut görüntü, isteğin güvenlik katmanı tarafından engellendiğini (${actionRaw}) göstermektedir. Ancak görüntü tek başına hedef sistemde komut çalıştırıldığını, dosyanın okunduğunu veya sistemin ele geçirildiğini kanıtlamamaktadır.`;
  } else if (payloadCheck.isMalicious && !isBlocked) {
    executiveSummary = `Görüntüde hedef sisteme yönelik ${payloadCheck.type} içeren bir ağ isteği kaydı görülmektedir. ${sourceIp !== 'NOT OBSERVED' ? `Kaynak IP ${sourceIp} olarak kaydedilmiştir.` : ''} Görüntü tek başına hedef sistemin bu isteği başarıyla çalıştırdığını veya yanıt verdiğini kanıtlamamaktadır. Olayın başarılı bir saldırıya dönüşüp dönüşmediği ek sunucu ve veri tabanı günlükleriyle incelenmelidir.`;
  } else if (observed.eventId === '4688') {
    executiveSummary = `Görüntüde bir uç nokta üzerinde işletim sistemi süreç oluşturma (Process Creation) telemetrisi görülmektedir. Çalıştırılan süreç ${observed.processName || 'işlem'} olup komut satırında ${requestOrCommand !== 'NOT OBSERVED' ? requestOrCommand : 'parametreler'} gözlemlenmiştir. Bu kayıt, komutun çağrıldığını gösterir ancak uç noktanın kalıcı olarak ele geçirildiğini veya veri sızdırıldığını kanıtlamaz.`;
  } else if (observed.eventId === '4625') {
    executiveSummary = `Görüntüde bir işletim sistemine ait başarısız oturum açma (Logon Failure) kaydı görülmektedir. ${userOrAccount !== 'NOT OBSERVED' ? `Hedef hesap ${userOrAccount} olarak kaydedilmiştir.` : ''} Hata kodu ${statusCode} olup olayın münferit bir parola hatası mı yoksa parola deneme atağı mı olduğu diğer zaman kayıtları incelenmeden doğrulanamaz. Hesabın ele geçirildiği kanıtlanmamıştır.`;
  } else {
    executiveSummary = `Görüntüde ${deviceOrPlatform} arayüzüne ait bir güvenlik ve telemetri kaydı görülmektedir. ${sourceIp !== 'NOT OBSERVED' ? `Kayıtta kaynak adres ${sourceIp} olarak yer almaktadır.` : ''} Mevcut telemetri belirli bir olay kaydını göstermekte olup tek başına geniş kapsamlı bir güvenlik ihlali oluşturmamaktadır.`;
  }

  // 4. Security Interpretation
  let whatIsSeen = '';
  let whatMightHaveHappened = '';
  let securityMeaning = '';

  if (hasMultipleRequests && (allTableRowsBlocked || isBlocked)) {
    whatIsSeen = `${isF5 ? 'F5 WAF' : 'Güvenlik cihazı'} arayüzünde aynı kaynak IP'den (${sourceIp !== 'NOT OBSERVED' ? sourceIp : 'şüpheli adres'}) gelen ve tamamı 'blocked' olarak işaretlenmiş çoklu HTTP istekleri görülmektedir.`;
    whatMightHaveHappened = 'Otomatik bir saldırı veya tarama aracı, hedef web uygulamasındaki olası zafiyetleri istismar etmek amacıyla ardışık denemelerde bulunmuştur.';
    securityMeaning = 'WAF güvenlik kuralları etkin şekilde devreye girmiş ve istekleri hedef uygulamaya ulaşmadan sınırda durdurmuştur. Hedef sistem doğrudan etkilenmemiş görünmektedir; ancak kaynak IP\'nin diğer sistemlere yönelik trafiği kontrol edilmelidir.';
  } else if (httpInfo) {
    whatIsSeen = `${sourceIp !== 'NOT OBSERVED' ? `Kaynak ${sourceIp} tarafından iletilen ` : ''}${httpInfo.protocol} protokolüyle '${httpInfo.method} ${httpInfo.requestUri}' isteği görülmektedir.${actionRaw !== 'NOT OBSERVED' ? ` Aksiyon: ${actionRaw}.` : ''}`;
    whatMightHaveHappened = `Dış bir kaynak veya otomatik tarama aracı ${httpInfo.targetTechnology} ${httpInfo.endpoint} endpoint'ine yönelik bir veri veya bağlantı isteği iletmiştir.`;
    securityMeaning = isBlocked
      ? `Güvenlik cihazı isteği engellemiştir (${actionRaw}). İsteğin hedef sunucuya erişimi durdurulmuş olup sistem doğrudan etkilenmemiş görünmektedir.`
      : `Hedef endpoint'e yönelik bir HTTP isteği gözlemlenmiştir; ancak hedef uygulamanın bu isteği işlediğini veya istismar edildiğini kanıtlamamaktadır.`;
  } else {
    whatIsSeen = isBlocked
      ? `Güvenlik cihazında kaynak ${sourceIp !== 'NOT OBSERVED' ? sourceIp : 'adresten'} gelen ve '${actionRaw}' olarak işaretlenmiş bir ağ kaydı görülmektedir.`
      : requestOrCommand !== 'NOT OBSERVED'
      ? `Güvenlik günlüğünde '${requestOrCommand}' içeriğine sahip bir işlem kaydı görülmektedir.`
      : `Güvenlik platformunda (${deviceOrPlatform}) belirli bir zaman damgasına ait olay kaydı görülmektedir.`;

    whatMightHaveHappened = payloadCheck.isMalicious
      ? `Dış bir kaynak veya otomatik tarama aracı hedef sunucu üzerindeki olası zafiyetleri istismar etmek amacıyla istek göndermiş olabilir.`
      : observed.eventId === '4625'
      ? `Kullanıcı parolasını yanlış girmiş veya yetkisiz bir taraf kimlik doğrulama denemesinde bulunmuş olabilir.`
      : `Sistem bileşenleri arasında standart bir ağ iletişimi veya rutin yönetim işlemi gerçekleşmiş olabilir.`;

    securityMeaning = isBlocked
      ? `Güvenlik kontrolleri etkin bir şekilde devreye girmiş ve isteği durdurmuştur. Hedef sistem doğrudan etkilenmemiş görünmektedir.`
      : payloadCheck.isMalicious
      ? `Şüpheli desen sunucuya ulaşmış olabilir; ancak hedef uygulamanın zafiyeti barındırıp barındırmadığı ve yanıt kodu doğrulanmalıdır.`
      : `Mevcut kanıtlar tek başına doğrudan bir tehdit veya veri sızıntısı olduğunu göstermemektedir.`;
  }

  const supportingEvidence: string[] = [];
  if (sourceIp !== 'NOT OBSERVED') supportingEvidence.push(`Kaynak IP: ${sourceIp}`);
  if (actionRaw !== 'NOT OBSERVED') supportingEvidence.push(`Güvenlik Aksiyonu: ${actionRaw}`);
  if (requestOrCommand !== 'NOT OBSERVED') supportingEvidence.push(`Gözlemlenen İstek: ${requestOrCommand}`);
  if (statusCode !== 'NOT OBSERVED') supportingEvidence.push(`Durum / Hata Kodu: ${statusCode}`);
  if (userOrAccount !== 'NOT OBSERVED') supportingEvidence.push(`Kullanıcı Hesabı: ${userOrAccount}`);
  if (tableRows.length > 0) supportingEvidence.push(`${tableRows.length} adet olay tablosu kaydı`);
  if (supportingEvidence.length === 0) supportingEvidence.push('Görüntüdeki olay paneli ve satır kaydı');

  // 5. Unproven Aspects (Crucial: What is NOT proven)
  const unprovenAspects: string[] = [];
  unprovenAspects.push('Hedef sistemde komut çalıştırıldığını kanıtlamaz (komut çalıştırıldığı kanıtlanmadı).');
  unprovenAspects.push('Sunucunun ele geçirildiğini kanıtlamaz (sunucu ele geçirilmedi veya ele geçirildiği kanıtlanmadı).');
  unprovenAspects.push('Dosyanın gerçekten okunduğunu kanıtlamaz (dosyanın okunduğu kanıtlanmadı).');
  unprovenAspects.push('Veri sızdırıldığını kanıtlamaz (veri sızıntısı kanıtlanmadı).');
  unprovenAspects.push('Saldırının başarıyla sonuçlandığını kanıtlamaz.');

  if (httpInfo) {
    unprovenAspects.push(`${httpInfo.targetTechnology} sunucusunun kesin olarak zarar gördüğü kanıtlanmadı.`);
    unprovenAspects.push('İşlemin başarıyla gerçekleştirildiği veya hedef sistemin ele geçirildiği kanıtlanmadı.');
  }
  if (!isBlocked && statusCode !== 'NOT OBSERVED') {
    unprovenAspects.push(`HTTP ${statusCode} yanıtının bir güvenlik duvarı engellemesi olduğu kanıtlanmadı.`);
  }
  if (sourceIp !== 'NOT OBSERVED' && !httpInfo) {
    unprovenAspects.push('Kaynak IP adresinin kurum içi yetkili bir test mi yoksa gerçek saldırgan mı olduğu kanıtlanmadı.');
  }
  if (userOrAccount !== 'NOT OBSERVED') {
    unprovenAspects.push('Hesabın ele geçirildiği (compromised) kanıtlanmadı.');
  }

  // 6. Recommended Investigation Steps
  const recommendedInvestigationSteps: string[] = [];
  if (httpInfo || hasMultipleRequests) {
    recommendedInvestigationSteps.push('WAF veya web sunucusu erişim loglarında bu isteklere dönülen HTTP yanıt kodunu (200, 403, 500 vb.) ve boyutunu kontrol edin.');
    recommendedInvestigationSteps.push('Hedef sunucuda süreç oluşturma (Process Creation) kayıtlarını inceleyerek anormal alt süreç veya komut çalıştırılmadığını teyit edin.');
  }
  if (sourceIp !== 'NOT OBSERVED') {
    recommendedInvestigationSteps.push(`SIEM / Firewall üzerinde kaynak IP (${sourceIp}) için son 24 saatlik trafik hacmini ve diğer hedeflere yönelik bağlantılarını sorgulayın.`);
  }
  if (!httpInfo && payloadCheck.isMalicious) {
    recommendedInvestigationSteps.push('Hedef web sunucusu erişim loglarında (Access Logs) bu isteğe dönülen gerçek HTTP yanıt kodunu ve yanıt boyutunu kontrol edin.');
    recommendedInvestigationSteps.push('Uygulama sunucusunda ilgili dizin veya veritabanı hata günlüklerini inceleyerek istismar izi arayın.');
  }
  if (observed.eventId === '4688' && observed.host) {
    recommendedInvestigationSteps.push(`Host (${observed.host}) üzerinde Sysmon Event 3 (Network Connection) loglarını inceleyerek dış bağlantı kurulup kurulmadığını doğrulayın.`);
  }
  if (recommendedInvestigationSteps.length === 0) {
    recommendedInvestigationSteps.push('İlgili sistemin zaman çizelgesi loglarını SIEM üzerinden korele edin.');
  }

  const observedFacts: AnalysisFirstObservedFacts = {
    sourceIp,
    destinationIp,
    timestamp,
    deviceOrPlatform,
    requestOrCommand,
    action: actionRaw,
    statusCode,
    userOrAccount,
    hostOrEndpoint,
  };

  const securityInterpretation: AnalysisFirstSecurityInterpretation = {
    whatIsSeen,
    whatMightHaveHappened,
    securityMeaning,
    supportingEvidence,
  };

  const reportObj = {
    executiveSummary,
    securityVerdict,
    verdictRationale,
    observedFacts,
    securityInterpretation,
    unprovenAspects,
    recommendedInvestigationSteps,
  };

  const markdownReport = renderAnalysisFirstMarkdown(reportObj as any);

  return {
    ...reportObj,
    markdownReport,
  };
}

/**
 * Formats the analysis report as clean, professional security analyst markdown.
 * Purely security focused, zero pipeline or implementation jargon.
 */
export function renderAnalysisFirstMarkdown(report: {
  executiveSummary: string;
  securityVerdict: ForensicSecurityVerdict;
  verdictRationale: string;
  observedFacts: AnalysisFirstObservedFacts;
  securityInterpretation: AnalysisFirstSecurityInterpretation;
  unprovenAspects: string[];
  recommendedInvestigationSteps: string[];
}): string {
  const { executiveSummary, securityVerdict, verdictRationale, observedFacts, securityInterpretation, unprovenAspects, recommendedInvestigationSteps } = report;

  return `# Görsel Güvenlik Analizi

## 1. Analiz Özeti
${executiveSummary}

## 2. Gözlemlenen Bulgular (Observed Facts)
* **Kaynak IP:** ${observedFacts.sourceIp}
* **Hedef IP:** ${observedFacts.destinationIp}
* **Zaman Damgası:** ${observedFacts.timestamp}
* **Cihaz / Platform:** ${observedFacts.deviceOrPlatform}
* **İstek / Komut:** ${observedFacts.requestOrCommand}
* **Aksiyon (Action):** ${observedFacts.action}
* **Durum Kodu / Hata:** ${observedFacts.statusCode}
* **Kullanıcı / Hesap:** ${observedFacts.userOrAccount}

## 3. Olayın Anlamı ve Güvenlik Yorumu (Security Interpretation)
* **Ne Görülüyor?:** ${securityInterpretation.whatIsSeen}
* **Ne Olmuş Olabilir?:** ${securityInterpretation.whatMightHaveHappened}
* **Güvenlik Açısından Anlamı:** ${securityInterpretation.securityMeaning}
* **Destekleyen Kanıtlar:**
${securityInterpretation.supportingEvidence.map((e) => `  - ${e}`).join('\n')}

## 4. Güvenlik Değerlendirmesi
* **Kategori:** ${securityVerdict}
* **Gerekçe:** ${verdictRationale}

## 5. Kanıt ve Yorum Ayrımı
* **Gözlemlenen Gerçekler:** ${securityInterpretation.supportingEvidence.join(', ')}
* **Güvenlik Yorumu:** ${securityInterpretation.securityMeaning}

## 6. Kanıtlanmayanlar
${unprovenAspects.map((u) => `* ${u}`).join('\n')}

## 7. Önerilen İnceleme Adımları
${recommendedInvestigationSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}
`;
}
