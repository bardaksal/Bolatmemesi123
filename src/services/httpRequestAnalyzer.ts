/**
 * HTTP Request Semantic Analyzer & Classifier
 * 
 * Fundamental Principles:
 * 1. HTTP REQUEST ≠ COMMAND
 *    - GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS + HTTP/1.0, HTTP/1.1, HTTP/2
 *    - NEVER classified as commandLine, process, executedCommand, binaryExecution
 * 2. COMMAND ANALYZER ROUTING PROTECTION
 *    - When HTTP_REQUEST is detected, commandExplainer / binary execution analyzers must NOT be called
 * 3. NO "BU KOMUT SİSTEMDE SORUN ÇIKARTIR MI?"
 *    - Directly generate security analyst assessment for the HTTP request
 * 4. NO "BELİRTİLEN İKİLİ SİSTEM ÜZERİNDE YÜRÜTÜLMEKTEDİR"
 *    - HTTP URIs are not binaries. No "yürütüldü", "çalıştırıldı", "binary çalıştı", "komut çalıştırıldı"
 *      unless actual OS process creation telemetry exists.
 * 5. DRUID & KNOWN ENDPOINT SEMANTICS:
 *    - Identify Apache Druid sampler/indexer endpoint without hallucinating attack success.
 *    - Endpoint presence ≠ Attack success.
 */

export interface HttpRequestDetails {
  type: 'HTTP_REQUEST';
  method: string;
  requestUri: string;
  protocol: string;
  endpoint: string;
  query: string;
  targetTechnology?: string;
  targetTechnologyContext?: string;
  isKnownVulnerabilityTarget?: boolean;
}

export interface HttpRequestSecurityAnalysis {
  isHttpRequest: true;
  method: string;
  endpoint: string;
  query: string;
  protocol: string;
  targetTechnology: string;
  summary: string;
  whatIsSeen: string;
  securityMeaning: string;
  supportingEvidence: string[];
  unprovenAspects: string[];
  recommendedSteps: string[];
}

const HTTP_METHOD_REGEX = /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/i;
const PROTOCOL_INDICATOR_REGEX = /\bHTTP\/[0-9\.]+\b/i;

/**
 * Detects whether a string is an HTTP request pattern and NOT an OS command line.
 */
export function isHttpRequestPattern(input: string): boolean {
  if (!input) return false;
  const trimmed = input.trim();

  // Explicit HTTP request pattern: e.g. "POST /druid/indexer/v1/sampler?for=connect HTTP/1.1"
  if (HTTP_METHOD_REGEX.test(trimmed)) {
    // Check if followed by a URI starting with / or http
    if (/\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?:\/|https?:\/\/)/i.test(trimmed)) {
      return true;
    }
  }

  // Protocol indicators: e.g. "GET /test HTTP/1.1"
  if (PROTOCOL_INDICATOR_REGEX.test(trimmed) && trimmed.includes('/')) {
    return true;
  }

  // Pure URI path passed mistakenly as command
  if (trimmed.startsWith('/') && (trimmed.includes('?') || trimmed.includes('/v1/') || trimmed.includes('/api/'))) {
    return true;
  }

  return false;
}

/**
 * Identifies technology context from known web application endpoints.
 */
export function identifyEndpointTechnology(endpoint: string): {
  technology: string;
  context: string;
  isKnownExploitTarget: boolean;
} {
  const lower = (endpoint || '').toLowerCase();

  if (lower.includes('/druid/indexer') || lower.includes('/druid/v2') || lower.includes('/druid/coordinator')) {
    return {
      technology: 'Apache Druid',
      context: 'Apache Druid veri işleme ve indeksleme (sampler/indexer) endpoint\'i',
      isKnownExploitTarget: true,
    };
  }

  if (lower.includes('/solr/')) {
    return {
      technology: 'Apache Solr',
      context: 'Apache Solr arama ve indeksleme servisi endpoint\'i',
      isKnownExploitTarget: true,
    };
  }

  if (lower.includes('/actuator/')) {
    return {
      technology: 'Spring Boot Actuator',
      context: 'Spring Boot operasyonel metrik ve yönetim endpoint\'i',
      isKnownExploitTarget: true,
    };
  }

  if (lower.includes('/cgi-bin/')) {
    return {
      technology: 'CGI-BIN Script Environment',
      context: 'Ortak Ağ Geçidi Arayüzü (CGI) betik çalıştırma dizini',
      isKnownExploitTarget: true,
    };
  }

  if (lower.includes('/geoserver/')) {
    return {
      technology: 'GeoServer',
      context: 'GeoServer coğrafi veri sunucusu endpoint\'i',
      isKnownExploitTarget: true,
    };
  }

  if (lower.includes('/wp-admin') || lower.includes('/wp-content') || lower.includes('/wp-json')) {
    return {
      technology: 'WordPress',
      context: 'WordPress içerik yönetim sistemi yönetim ve API arayüzü',
      isKnownExploitTarget: false,
    };
  }

  if (lower.includes('/autodiscover') || lower.includes('/owa')) {
    return {
      technology: 'Microsoft Exchange',
      context: 'Microsoft Exchange Web Access / Otomatik Keşif servisi',
      isKnownExploitTarget: true,
    };
  }

  return {
    technology: 'Web Uygulama Sunucusu',
    context: 'Standart web uygulaması API veya sayfa endpoint\'i',
    isKnownExploitTarget: false,
  };
}

/**
 * Strictly parses an HTTP request string into structured semantic components.
 * Example:
 *   "POST /druid/indexer/v1/sampler?for=connect HTTP/1.1"
 * Returns:
 *   type: "HTTP_REQUEST"
 *   method: "POST"
 *   requestUri: "/druid/indexer/v1/sampler?for=connect"
 *   protocol: "HTTP/1.1"
 *   endpoint: "/druid/indexer/v1/sampler"
 *   query: "for=connect"
 */
export function parseHttpRequestSemantics(input: string): HttpRequestDetails | null {
  if (!input) return null;
  const trimmed = input.trim();

  // Pattern A: Method + URI + Optional Protocol (e.g. "POST /druid/indexer/v1/sampler?for=connect HTTP/1.1")
  const match = trimmed.match(
    /\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\r\n\|]+)(?:\s+(HTTP\/[0-9\.]+))?/i
  );

  let method = 'GET';
  let requestUri = '';
  let protocol = 'HTTP/1.1';

  if (match) {
    method = match[1].toUpperCase();
    requestUri = match[2];
    protocol = match[3] ? match[3].toUpperCase() : 'HTTP/1.1';
  } else if (trimmed.startsWith('/')) {
    requestUri = trimmed.split(/\s+/)[0];
    const protoMatch = trimmed.match(/\bHTTP\/[0-9\.]+\b/i);
    if (protoMatch) protocol = protoMatch[0].toUpperCase();
  } else {
    return null;
  }

  // Parse endpoint and query parameters
  const [endpoint, ...queryParts] = requestUri.split('?');
  const query = queryParts.join('?');

  const techInfo = identifyEndpointTechnology(endpoint);

  return {
    type: 'HTTP_REQUEST',
    method,
    requestUri,
    protocol,
    endpoint,
    query,
    targetTechnology: techInfo.technology,
    targetTechnologyContext: techInfo.context,
    isKnownVulnerabilityTarget: techInfo.isKnownExploitTarget,
  };
}

/**
 * Generates an analysis-first security interpretation of an observed HTTP request.
 * Strictly adheres to forensic boundaries:
 * - NO command execution claims
 * - NO binary claims
 * - Endpoint presence != Attack success
 */
export function analyzeHttpRequestSecurity(
  details: HttpRequestDetails,
  context?: {
    sourceIp?: string | null;
    action?: string | null;
    statusCode?: string | null;
    deviceOrPlatform?: string | null;
  }
): HttpRequestSecurityAnalysis {
  const sourceIp = context?.sourceIp && context.sourceIp !== 'NOT OBSERVED' ? context.sourceIp : null;
  const action = context?.action && context.action !== 'NOT OBSERVED' ? context.action : null;
  const isBlocked = action ? /\b(blocked|deny|drop|reject|reset|prevent)\b/i.test(action) : false;

  const tech = details.targetTechnology || 'Web Uygulaması';
  const techContext = details.targetTechnologyContext || 'Web servisi';

  // 1. Executive Summary & Meaning
  let summary = '';
  if (sourceIp && isBlocked) {
    summary = `${sourceIp} kaynaklı bir HTTP ${details.method} isteği ${tech}'ın ${details.endpoint} endpoint'ine yönelmiştir. Güvenlik cihazı kaydında istek '${action}' olarak görülmektedir. Bu nedenle mevcut kanıt isteğin güvenlik cihazı tarafından engellendiğini desteklemektedir. Görüntü tek başına endpoint üzerinde komut çalıştırıldığını, işlemin başarıyla gerçekleştirildiğini veya hedef sistemin ele geçirildiğini kanıtlamamaktadır.`;
  } else if (sourceIp && !isBlocked) {
    summary = `${sourceIp} kaynaklı bir HTTP ${details.method} isteği ${tech}'ın ${details.endpoint} endpoint'ine iletilmiştir. Mevcut görüntü isteğin hedef sistem tarafından işlendiğini veya yanıt kodunu doğrudan içermemektedir. Görüntü tek başına hedef sistemde komut çalıştırıldığını veya zafiyetin istismar edildiğini kanıtlamamaktadır.`;
  } else if (isBlocked) {
    summary = `Hedef sistemdeki ${tech} endpoint'ine (${details.endpoint}) yönelik HTTP ${details.method} isteği güvenlik cihazı tarafından engellenmiştir (${action || 'BLOCKED'}). Görüntü tek başına hedef sistemin etkilendiğini kanıtlamamaktadır.`;
  } else {
    summary = `${tech} endpoint'ine (${details.endpoint}) yönelik bir HTTP ${details.method} isteği gözlemlenmiştir. Görüntü tek başına işlemin hedef sunucu tarafından çalıştırıldığını veya başarılı olduğunu kanıtlamamaktadır.`;
  }

  // 2. What is Seen
  const whatIsSeen = `${sourceIp ? `Kaynak ${sourceIp} tarafından ` : ''}${details.protocol} protokolüyle iletilen '${details.method} ${details.requestUri}' isteği görülmektedir.${action ? ` İstek aksiyonu: ${action}.` : ''}`;

  // 3. Security Meaning
  let securityMeaning = '';
  if (isBlocked) {
    securityMeaning = `Güvenlik katmanı isteği durdurmuştur (Aksiyon: ${action}). İsteğin ${details.endpoint} yoluna erişimi engellenmiş olup hedef sistem bu istekten doğrudan etkilenmemiş görünmektedir.`;
  } else if (details.isKnownVulnerabilityTarget) {
    securityMeaning = `Hedeflenen endpoint (${details.endpoint}), ${tech} mimarisinde geçmişte zafiyet taramalarına veya istismar girişimlerine konu olmuş bir arayüzdür. Ancak bu isteğin başarılı olduğu yalnızca sunucu yanıt kodları ve süreç logları incelenerek doğrulanabilir.`;
  } else {
    securityMeaning = `Mevcut kayıt belirli bir web endpoint'ine yönelik HTTP isteğini göstermektedir. Doğrudan bir ihlal veya zafiyet istismarı kanıtı içermemektedir.`;
  }

  // 4. Supporting Evidence
  const supportingEvidence: string[] = [
    `HTTP Metodu: ${details.method}`,
    `Hedef URI: ${details.requestUri}`,
    `Protokol: ${details.protocol}`,
  ];
  if (sourceIp) supportingEvidence.push(`Kaynak IP: ${sourceIp}`);
  if (action) supportingEvidence.push(`Güvenlik Aksiyonu: ${action}`);
  if (details.query) supportingEvidence.push(`Sorgu Parametresi: ${details.query}`);

  // 5. Unproven Aspects
  const unprovenAspects: string[] = [
    'Endpoint üzerinde komut çalıştırıldığı kanıtlanmadı.',
    'İşlemin hedef sistem tarafından başarıyla gerçekleştirildiği kanıtlanmadı.',
    'Hedef sistemin ele geçirildiği veya veri sızdırıldığı kanıtlanmadı.',
  ];
  if (details.isKnownVulnerabilityTarget) {
    unprovenAspects.push(`${tech} servisinin bu zafiyeti barındırdığı veya etkilendiği kanıtlanmadı.`);
  }

  // 6. Recommended Next Steps
  const recommendedSteps: string[] = [
    'Web sunucusu veya WAF erişim loglarında bu isteğe dönülen HTTP durum kodunu (örn. 200 OK, 403 Forbidden, 500 Error) kontrol edin.',
    'Hedef uygulama sunucusunda süreç oluşturma (Process Creation) loglarını inceleyerek anormal alt süreç başlatılıp başlatılmadığını teyit edin.',
  ];
  if (sourceIp) {
    recommendedSteps.push(`SIEM üzerinde ${sourceIp} kaynaklı diğer HTTP isteklerini ve hedefleri korele edin.`);
  }

  return {
    isHttpRequest: true,
    method: details.method,
    endpoint: details.endpoint,
    query: details.query,
    protocol: details.protocol,
    targetTechnology: tech,
    summary,
    whatIsSeen,
    securityMeaning,
    supportingEvidence,
    unprovenAspects,
    recommendedSteps,
  };
}
