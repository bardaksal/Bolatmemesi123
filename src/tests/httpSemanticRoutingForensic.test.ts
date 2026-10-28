import assert from 'assert';
import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
  analyzeHttpRequestSecurity,
} from '../services/httpRequestAnalyzer';
import { explainCommand } from '../services/commandExplainer';
import { parseSecurityFieldsFromOcrText } from '../services/realPixelVisionService';
import { generateAnalysisFirstReport } from '../services/analysisFirstForensicReporting';

console.log('================================================================');
console.log('🛡️ PHASE 3.6 — HTTP REQUEST SEMANTIC ROUTING ACCEPTANCE TESTS');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: HTTP REQUEST ≠ COMMAND Classification
// -----------------------------------------------------------------------------
console.log('\n--- TEST 1: HTTP Request Doğru Semantik Ayrıştırma ---');

const druidRaw = 'POST /druid/indexer/v1/sampler?for=connect HTTP/1.1';
assert.strictEqual(isHttpRequestPattern(druidRaw), true, 'T1.1: Druid POST isteği HTTP request olarak tanınmalı');

const parsed = parseHttpRequestSemantics(druidRaw);
assert.ok(parsed !== null, 'T1.2: Ayrıştırma başarılı olmalı');
assert.strictEqual(parsed?.type, 'HTTP_REQUEST', 'T1.3: Type HTTP_REQUEST olmalı');
assert.strictEqual(parsed?.method, 'POST', 'T1.4: Method POST olmalı');
assert.strictEqual(parsed?.requestUri, '/druid/indexer/v1/sampler?for=connect', 'T1.5: requestUri doğru olmalı');
assert.strictEqual(parsed?.protocol, 'HTTP/1.1', 'T1.6: protocol HTTP/1.1 olmalı');
assert.strictEqual(parsed?.endpoint, '/druid/indexer/v1/sampler', 'T1.7: endpoint /druid/indexer/v1/sampler olmalı');
assert.strictEqual(parsed?.query, 'for=connect', 'T1.8: query for=connect olmalı');
assert.strictEqual(parsed?.targetTechnology, 'Apache Druid', 'T1.9: targetTechnology Apache Druid olmalı');

console.log('✅ [PASS] T1: HTTP_REQUEST doğru ayrıştırıldı (Method, URI, Protocol, Endpoint, Query, Technology).');

// -----------------------------------------------------------------------------
// TEST 2: F5 Big-IP Blocked Log OCR Parser & Semantic Routing
// -----------------------------------------------------------------------------
console.log('\n--- TEST 2: OCR Metninde HTTP Request ve F5 Blocked Semantiği ---');

const f5SampleText = `
Source IP: 185.123.105.51
F5 Request Status: blocked
Full Request: POST /druid/indexer/v1/sampler?for=connect HTTP/1.1
`;

const parsedOcr = parseSecurityFieldsFromOcrText(f5SampleText, {
  valid: true,
  format: 'png',
  byteLength: 45000,
  sha256Hash: 'a1b2c3d4e5f6',
});

assert.strictEqual(parsedOcr.observedFromImage.sourceIp, '185.123.105.51', 'T2.1: Kaynak IP 185.123.105.51 olmalı');
assert.strictEqual(parsedOcr.observedFromImage.action, 'DENY', 'T2.2: Action DENY normalize edilmeli');
assert.strictEqual(parsedOcr.observedFromImage.status, 'blocked', 'T2.3: Status blocked olmalı');
assert.strictEqual(parsedOcr.observedFromImage.commandLine, null, 'T2.4: commandLine KESİNLİKLE NULL olmalı (HTTP is NOT a command)');
assert.strictEqual(parsedOcr.observedFromImage.processName, null, 'T2.5: processName KESİNLİKLE NULL olmalı');
assert.ok(parsedOcr.observedFromImage.httpRequest, 'T2.6: httpRequest nesnesi oluşturulmuş olmalı');
assert.strictEqual(parsedOcr.observedFromImage.httpRequest?.method, 'POST', 'T2.7: httpRequest.method POST olmalı');
assert.strictEqual(parsedOcr.observedFromImage.httpRequest?.endpoint, '/druid/indexer/v1/sampler', 'T2.8: endpoint doğru olmalı');

console.log('✅ [PASS] T2: OCR çıktısında HTTP isteği asla commandLine veya process olarak etiketlenmiyor.');

// -----------------------------------------------------------------------------
// TEST 3: "Belirtilen İkili Sistem Üzerinde Yürütülmektedir" ve "Bu Komut Sorun Çıkartır mı" YASAK
// -----------------------------------------------------------------------------
console.log('\n--- TEST 3: İkili / Binary Yürütme Hatalı İfadelerin Engellenmesi ---');

// If command explainer is called directly with HTTP string (defense-in-depth)
const exp = explainCommand(druidRaw);
assert.strictEqual(
  exp.willCauseTroubleText.includes('ikili sistem üzerinde yürütülmektedir'),
  false,
  'T3.1: "ikili sistem üzerinde yürütülmektedir" ifadesi tamamen temizlenmiş olmalı'
);
assert.strictEqual(
  exp.summary.includes('ikili (binary) değil'),
  true,
  'T3.2: HTTP isteği olduğu ve işletim sistemi ikilisi olmadığı açıkça belirtilmeli'
);

const rep = parsedOcr.analysisReport;
assert.ok(rep, 'T3.3: Analysis report mevcut olmalı');
const markdownReport = rep?.markdownReport || '';
assert.strictEqual(
  markdownReport.includes('ikili sistem üzerinde yürütülmektedir'),
  false,
  'T3.4: Raporda "ikili sistem üzerinde yürütülmektedir" olmamalı'
);
assert.strictEqual(
  markdownReport.includes('Bu Komut Sistemde Sorun Çıkartır mı?'),
  false,
  'T3.5: Raporda "Bu Komut Sistemde Sorun Çıkartır mı?" sorusu bulunmamalı'
);

console.log('✅ [PASS] T3: "İkili sistem üzerinde yürütülmektedir" ve "Bu Komut Sorun Çıkartır mı" ifadeleri engellendi.');

// -----------------------------------------------------------------------------
// TEST 4: Gerçek Görsel Analiz Değerlendirmesi & Druid Endpoint Anlamı
// -----------------------------------------------------------------------------
console.log('\n--- TEST 4: Apache Druid Sampler / F5 Blocked Analist Değerlendirmesi ---');

const repSummary = rep?.executiveSummary || '';
console.log('\nÜretilen Özet:\n' + repSummary + '\n');

assert.ok(repSummary.includes('185.123.105.51'), 'T4.1: Özette 185.123.105.51 yer almalı');
assert.ok(repSummary.includes('POST'), 'T4.2: Özette HTTP POST yer almalı');
assert.ok(repSummary.includes('/druid/indexer/v1/sampler'), 'T4.3: Özette endpoint yer almalı');
assert.ok(repSummary.includes('Apache Druid'), 'T4.4: Özette teknoloji bağlamı (Apache Druid) yer almalı');
assert.ok(repSummary.includes('engellendiğini') || repSummary.includes('blocked'), 'T4.5: Özette engellendiği belirtilmeli');
assert.ok(
  repSummary.includes('Görüntü tek başına endpoint üzerinde komut çalıştırıldığını') ||
  repSummary.includes('başarıyla gerçekleştirildiğini veya hedef sistemin ele geçirildiğini kanıtlamamaktadır'),
  'T4.6: Özette istismarın kanıtlanmadığı kesin olarak belirtilmeli'
);

assert.strictEqual(rep?.securityVerdict, 'ENGELLENMİŞ SALDIRI GİRİŞİMİ', 'T4.7: Güvenlik kategorisi ENGELLENMİŞ SALDIRI GİRİŞİMİ olmalı');

const unproven = rep?.unprovenAspects || [];
assert.ok(
  unproven.some((u) => u.includes('komut çalıştırıldığı kanıtlanmadı')),
  'T4.8: Kanıtlanmayanlarda komut çalıştırıldığı kanıtlanmadı maddesi bulunmalı'
);
assert.ok(
  unproven.some((u) => u.includes('başarıyla gerçekleştirildiği veya hedef sistemin ele geçirildiği kanıtlanmadı')),
  'T4.9: Kanıtlanmayanlarda saldırı başarısının kanıtlanmadığı bulunmalı'
);

console.log('✅ [PASS] T4: Druid ve F5 analiz-odaklı analist çıktısı ve kanıtlanmayanlar tam uyumlu.');

// -----------------------------------------------------------------------------
// TEST 5: HTTP Request Security Analyzer Doğrudan Doğrulama
// -----------------------------------------------------------------------------
console.log('\n--- TEST 5: HTTP Request Security Analyzer Modülü ---');

const analysis = analyzeHttpRequestSecurity(parsed!, {
  sourceIp: '185.123.105.51',
  action: 'blocked',
  deviceOrPlatform: 'F5 BIG-IP ASM',
});

assert.strictEqual(analysis.isHttpRequest, true, 'T5.1: isHttpRequest true olmalı');
assert.strictEqual(analysis.method, 'POST', 'T5.2: Method POST olmalı');
assert.strictEqual(analysis.endpoint, '/druid/indexer/v1/sampler', 'T5.3: Endpoint doğru olmalı');
assert.strictEqual(analysis.query, 'for=connect', 'T5.4: Query doğru olmalı');
assert.ok(analysis.summary.includes('Apache Druid'), 'T5.5: Summary Apache Druid içermeli');
assert.ok(analysis.unprovenAspects.length >= 3, 'T5.6: En az 3 adet kanıtlanmayan madde içermeli');

console.log('✅ [PASS] T5: HTTP Request Security Analyzer modülü başarıyla doğrulandı.');

console.log('\n================================================================');
console.log('🎉 TÜM PHASE 3.6 HTTP REQUEST SEMANTIC ROUTING TESTLERİ BAŞARIYLA GEÇTİ!');
console.log('================================================================');
