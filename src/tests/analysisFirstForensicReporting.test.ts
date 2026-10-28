import assert from 'assert';
import {
  generateAnalysisFirstReport,
  renderAnalysisFirstMarkdown,
} from '../services/analysisFirstForensicReporting';

console.log('================================================================');
console.log('🛡️ PHASE 3.5 — ANALYSIS-FIRST FORENSIC REPORTING ACCEPTANCE TESTS');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: Executive Summary Does NOT Contain System Implementation Jargon
// -----------------------------------------------------------------------------
console.log('\n--- TEST 1: Analiz Özeti İç Çalışma Mekanizması / Motor Anlatmıyor ---');

const blockedReport = generateAnalysisFirstReport({
  observed: {
    eventId: null,
    provider: null,
    timestamp: '2026-10-13 14:02:11',
    host: null,
    username: null,
    sourceIp: '185.123.105.51',
    destinationIp: null,
    port: '443',
    processName: null,
    parentProcess: null,
    commandLine: null,
    action: 'blocked',
    status: null,
    rawMessage: 'GET /cgi-bin/../../../../etc/passwd HTTP/1.1 | blocked',
  },
  visualPlatform: 'F5 BIG-IP ASM',
  confidence: 'KESİN',
});

const lowerSummary = blockedReport.executiveSummary.toLowerCase();
assert.strictEqual(lowerSummary.includes('tesseract'), false, 'T1.1: Tesseract kelimesi içermemeli');
assert.strictEqual(lowerSummary.includes('pixel ocr'), false, 'T1.2: Pixel OCR kelimesi içermemeli');
assert.strictEqual(lowerSummary.includes('sha-256'), false, 'T1.3: SHA-256 hash içermemeli');
assert.strictEqual(lowerSummary.includes('model pipeline'), false, 'T1.4: Model pipeline içermemeli');
assert.strictEqual(lowerSummary.includes('yerel ocr'), false, 'T1.5: Yerel ocr kelimesi içermemeli');
assert.ok(blockedReport.executiveSummary.length > 50, 'T1.6: Anlamlı bir olay özeti içermeli');
console.log('✅ [PASS] T1: Analiz özeti teknik implementasyon yerine güvenlik olayını anlatıyor.');

// -----------------------------------------------------------------------------
// TEST 2: Strict Verdict & Security Evaluation (Blocked vs Success)
// -----------------------------------------------------------------------------
console.log('\n--- TEST 2: Güvenlik Değerlendirmesi: Engellenmiş İstek vs Saldırı Başarısı ---');

// Case A: Malicious Payload + Blocked -> ENGELLENMİŞ SALDIRI GİRİŞİMİ
assert.strictEqual(
  blockedReport.securityVerdict,
  'ENGELLENMİŞ SALDIRI GİRİŞİMİ',
  'T2.1: WAF tarafından engellenen istek ENGELLENMİŞ SALDIRI GİRİŞİMİ olmalı'
);

// Case B: Malicious Payload + HTTP 200 (Not Blocked) -> SALDIRI BAŞARISI KANITLANMADI
const unblockedReport = generateAnalysisFirstReport({
  observed: {
    eventId: null,
    provider: null,
    timestamp: '2026-10-13 14:00:00',
    host: null,
    username: null,
    sourceIp: '192.168.1.50',
    destinationIp: '10.0.0.10',
    port: '80',
    processName: null,
    parentProcess: null,
    commandLine: null,
    action: null,
    status: '200',
    rawMessage: 'GET /vuln.php?id=1 UNION SELECT null,password FROM users HTTP/1.1',
  },
  visualPlatform: 'Nginx Access Log',
  confidence: 'YÜKSEK',
});

assert.strictEqual(
  unblockedReport.securityVerdict,
  'SALDIRI BAŞARISI KANITLANMADI',
  'T2.2: İstek 200 dönse bile saldırı başarılı kabul edilmemeli (SALDIRI BAŞARISI KANITLANMADI)'
);
console.log('✅ [PASS] T2: Malicious Payload != Attack Success ilkesi doğrulandı.');

// -----------------------------------------------------------------------------
// TEST 3: HTTP 403 != WAF Block Ayrımı
// -----------------------------------------------------------------------------
console.log('\n--- TEST 3: HTTP 403 Tek Başına WAF Block Değildir ---');

const forbiddenReport = generateAnalysisFirstReport({
  observed: {
    eventId: null,
    provider: null,
    timestamp: '2026-10-13 13:55:00',
    host: null,
    username: null,
    sourceIp: '10.10.10.25',
    destinationIp: null,
    port: '80',
    processName: null,
    parentProcess: null,
    commandLine: null,
    action: null,
    status: '403',
    rawMessage: 'GET /admin HTTP/1.1 403',
  },
  visualPlatform: 'Apache Access Log',
});

assert.notStrictEqual(
  forbiddenReport.securityVerdict,
  'ENGELLENMİŞ SALDIRI GİRİŞİMİ',
  'T3.1: HTTP 403 tek başına WAF BLOCK veya ENGELLENMİŞ SALDIRI GİRİŞİMİ olamaz'
);
assert.strictEqual(
  forbiddenReport.securityVerdict,
  'ŞÜPHELİ ETKİNLİK',
  'T3.2: HTTP 403 ŞÜPHELİ ETKİNLİK olarak sınıflandırılmalı'
);
console.log('✅ [PASS] T3: HTTP 403 != WAF Block ilkesi doğrulandı.');

// -----------------------------------------------------------------------------
// TEST 4: Observed Facts: Sıfır Halüsinasyon & Eksik Alanlar NOT OBSERVED
// -----------------------------------------------------------------------------
console.log('\n--- TEST 4: Gözlemlenen Bulgular & Eksik Alanlar Kesinlikle NOT OBSERVED ---');

const obsFacts = blockedReport.observedFacts;
assert.strictEqual(obsFacts.sourceIp, '185.123.105.51', 'T4.1: Gerçek okunan IP yer almalı');
assert.strictEqual(obsFacts.destinationIp, 'NOT OBSERVED', 'T4.2: Görüntüde olmayan Hedef IP NOT OBSERVED olmalı');
assert.strictEqual(obsFacts.userOrAccount, 'NOT OBSERVED', 'T4.3: Görüntüde olmayan Kullanıcı NOT OBSERVED olmalı');
assert.strictEqual(obsFacts.statusCode, 'NOT OBSERVED', 'T4.4: Görüntüde olmayan Status NOT OBSERVED olmalı');
assert.strictEqual(obsFacts.action, 'blocked', 'T4.5: Görüntüdeki aksiyon blocked olarak korunmalı');
console.log('✅ [PASS] T4: Eksik alanlar kesinlikle uydurulmuyor ve NOT OBSERVED olarak veriliyor.');

// -----------------------------------------------------------------------------
// TEST 5: Kanıtlanmayanlar (What is NOT Proven) Bölümü
// -----------------------------------------------------------------------------
console.log('\n--- TEST 5: Kanıtlanmayanlar Açıkça Belirtilmeli ---');

const unproven = blockedReport.unprovenAspects;
assert.ok(unproven.length >= 2, 'T5.1: En az 2 kanıtlanmayan unsur bulunmalı');
const hasSuccessNotProven = unproven.some((u) => u.toLowerCase().includes('başarı') || u.toLowerCase().includes('kanıtlanmadı'));
const hasCommandNotProven = unproven.some((u) => u.toLowerCase().includes('komut') || u.toLowerCase().includes('çalıştırıldı'));
const hasFileNotProven = unproven.some((u) => u.toLowerCase().includes('dosya') || u.toLowerCase().includes('okundu'));

assert.ok(hasSuccessNotProven, 'T5.2: Saldırının başarılı olduğu kanıtlanmadı ifadesi yer almalı');
assert.ok(hasCommandNotProven, 'T5.3: Komut çalıştırıldığı kanıtlanmadı ifadesi yer almalı');
assert.ok(hasFileNotProven, 'T5.4: Dosyanın okunduğu kanıtlanmadı ifadesi yer almalı');
console.log('✅ [PASS] T5: Kanıtlanmayanlar bölümü saldırı başarı iddialarını net bir şekilde çürütüyor.');

// -----------------------------------------------------------------------------
// TEST 6: Markdown Rapor Yapısı Doğrulaması (# Görsel Güvenlik Analizi)
// -----------------------------------------------------------------------------
console.log('\n--- TEST 6: Standart Rapor Yapısı Doğrulaması ---');

const md = blockedReport.markdownReport;
assert.ok(md.includes('# Görsel Güvenlik Analizi'), 'T6.1: Ana başlık # Görsel Güvenlik Analizi olmalı');
assert.ok(md.includes('## 1. Analiz Özeti'), 'T6.2: ## 1. Analiz Özeti bulunmalı');
assert.ok(md.includes('## 2. Gözlemlenen Bulgular'), 'T6.3: ## 2. Gözlemlenen Bulgular bulunmalı');
assert.ok(md.includes('## 3. Olayın Anlamı ve Güvenlik Yorumu'), 'T6.4: ## 3. Olayın Anlamı bulunmalı');
assert.ok(md.includes('## 4. Güvenlik Değerlendirmesi'), 'T6.5: ## 4. Güvenlik Değerlendirmesi bulunmalı');
assert.ok(md.includes('## 5. Kanıt ve Yorum Ayrımı'), 'T6.6: ## 5. Kanıt ve Yorum Ayrımı bulunmalı');
assert.ok(md.includes('## 6. Kanıtlanmayanlar'), 'T6.7: ## 6. Kanıtlanmayanlar bulunmalı');
assert.ok(md.includes('## 7. Önerilen İnceleme Adımları'), 'T6.8: ## 7. Önerilen İnceleme Adımları bulunmalı');
console.log('✅ [PASS] T6: Markdown raporu kullanıcı odaklı yeni yapıya eksiksiz uyuyor.');

// -----------------------------------------------------------------------------
// TEST 7: Fallback Durumunda Yetersiz Kanıt Sınıflandırması
// -----------------------------------------------------------------------------
console.log('\n--- TEST 7: Görsel Verisi Okunamadığında YETERSİZ KANIT ---');

const fallbackReport = generateAnalysisFirstReport({
  observed: null,
  visualPlatform: 'Bilinmeyen Arayüz',
  fallbackLimitation: {
    modelCallFailed: true,
    ocrNotAvailableLocally: false,
    errorCode: 'NO_TEXT_DETECTED',
  },
});

assert.strictEqual(fallbackReport.securityVerdict, 'YETERSİZ KANIT', 'T7.1: Okunamayan görsel YETERSİZ KANIT olmalı');
assert.strictEqual(fallbackReport.observedFacts.sourceIp, 'NOT OBSERVED', 'T7.2: IP uydurulmamalı (NOT OBSERVED)');
assert.ok(fallbackReport.executiveSummary.includes('güvenli bir şekilde okunabilen'), 'T7.3: Dürüst sınırlama açıklaması sunulmalı');
console.log('✅ [PASS] T7: Fallback durumu taklit yapmadan dürüstçe YETERSİZ KANIT bildiriyor.');

console.log('\n================================================================');
console.log('🎉 TÜM PHASE 3.5 ANALYSIS-FIRST FORENSIC REPORTING TESTLERİ GEÇTİ');
console.log('================================================================');
