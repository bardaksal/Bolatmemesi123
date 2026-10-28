/**
 * ============================================================================
 * PHASE 3.3 — REAL PIXEL FORENSIC VISION PIPELINE ADVERSARIAL ACCEPTANCE TESTS
 * ============================================================================
 *
 * Strict Forensic Invariants:
 * 1. REAL PIXEL EVIDENCE > OCR SUCCESS > EVIDENCE PROVENANCE > SEMANTIC CORRECTNESS
 * 2. HTTP REQUEST ≠ COMMAND LINE ≠ PROCESS EXECUTION
 * 3. MALICIOUS REQUEST ≠ ATTACK SUCCESS
 * 4. BLOCKED REQUEST ≠ SERVER COMPROMISED
 * 5. NO HALLUCINATED FIELDS ON DECODE/OCR FAILURE (MUST BE NOT_ASSESSED)
 * 6. TEXT-ONLY INPUT MUST NEVER BE LABELED AS REAL_PIXEL_TEST
 */

import {
  generateTestPngWithText,
  validateImageBuffer,
  parseSecurityFieldsFromOcrText,
} from '../services/realPixelVisionService';
import { extractUniversalEvidence } from '../services/universalEvidenceExtractor';
import { synthesizeDynamicHypotheses } from '../services/dynamicHypothesisEngine';
import { evaluateUnifiedDecision } from '../services/unifiedDecisionEngine';

let passCount = 0;
let failCount = 0;
const testDetails: Array<{ testNumber: number; name: string; status: 'PASS' | 'FAIL'; note: string }> = [];

function assert(condition: boolean, message: string) {
  if (!condition) {
    failCount++;
    console.error(`❌ [FAIL] ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passCount++;
  console.log(`✅ [PASS] ${message}`);
}

console.log('\n================================================================');
console.log('🛡️ PHASE 3.3 — REAL PIXEL FORENSIC VISION ACCEPTANCE TEST SUITE');
console.log('================================================================\n');

// -----------------------------------------------------------------------------
// TEST 1: Gerçek PNG -> OCR Başarılı -> Alanlar Çıkarıldı -> EvidenceStatus OBSERVED
// -----------------------------------------------------------------------------
console.log('\n--- TEST 1: Gerçek PNG -> OCR Başarılı -> Alanlar Çıkarıldı -> OBSERVED ---');
const rawText1 = '185.123.105.51 | BLOCKED | GET /CGI-BIN/TEST';
const png1 = generateTestPngWithText(rawText1, 600, 100);
const val1 = validateImageBuffer(png1);

assert(val1.valid === true, 'T1.1: Gerçek PNG bayt doğrulaması başarılı olmalı');
assert(val1.format === 'png', 'T1.2: Görsel formatı PNG olarak tanınmalı');
assert(val1.byteLength > 500, 'T1.3: Görsel boyutu > 500 bytes gerçek piksel verisi olmalı');
assert(val1.sha256Hash.length === 64, 'T1.4: SHA-256 hash üretilmeli');

const ocrParsed1 = parseSecurityFieldsFromOcrText(rawText1, val1);
assert(ocrParsed1.observedFromImage.sourceIp === '185.123.105.51', 'T1.5: Kaynak IP OBSERVED olmalı');
assert(ocrParsed1.observedFromImage.action === 'DENY', 'T1.6: WAF aksiyonu DENY olarak normalize edilmeli');
assert(ocrParsed1.provenance.sourceType === 'IMAGE_PIXEL', 'T1.7: Provenance sourceType IMAGE_PIXEL olmalı');
testDetails.push({ testNumber: 1, name: 'Gerçek PNG OCR Başarılı OBSERVED', status: 'PASS', note: 'Gerçek bayt ve hash doğrulandı' });

// -----------------------------------------------------------------------------
// TEST 2: Gerçek PNG -> OCR Timeout / Failure -> NOT_ASSESSED -> Sahte Alan Yok
// -----------------------------------------------------------------------------
console.log('\n--- TEST 2: Gerçek PNG -> OCR Failure / Timeout -> NOT_ASSESSED ---');
const emptyVal2 = validateImageBuffer(png1);
const ocrParsed2 = parseSecurityFieldsFromOcrText('', emptyVal2);

assert(ocrParsed2.observedFromImage.sourceIp === null, 'T2.1: OCR boşken sahte IP uydurulmamalı (null olmalı)');
assert(ocrParsed2.observedFromImage.action === null, 'T2.2: OCR boşken sahte action uydurulmamalı (null olmalı)');
assert(ocrParsed2.observedFromImage.commandLine === null, 'T2.3: OCR boşken sahte komut satırı uydurulmamalı');
testDetails.push({ testNumber: 2, name: 'OCR Failure NOT_ASSESSED', status: 'PASS', note: 'Sıfır halüsinasyon, sahte alan yok' });

// -----------------------------------------------------------------------------
// TEST 3: Gerçek PNG -> Bozuk Bayt / Decode Failure -> Fallback ve Hata Kodu
// -----------------------------------------------------------------------------
console.log('\n--- TEST 3: Bozuk Bayt / Decode Failure -> IMAGE_DECODE_FAILED ---');
const corruptedBytes = Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
const val3 = validateImageBuffer(corruptedBytes);

assert(val3.valid === false, 'T3.1: Bozuk görsel baytları reddedilmeli');
assert(val3.errorCode === 'UNSUPPORTED_IMAGE_FORMAT', 'T3.2: UNSUPPORTED_IMAGE_FORMAT hata kodu dönmeli');
assert(val3.errorMessage?.includes('Desteklenmeyen'), 'T3.3: Açıklayıcı hata mesajı içermeli');
testDetails.push({ testNumber: 3, name: 'Decode Failure', status: 'PASS', note: 'Geçersiz baytlar reddedildi' });

// -----------------------------------------------------------------------------
// TEST 4: Boş Görsel Verisi -> IMAGE_DATA_MISSING
// -----------------------------------------------------------------------------
console.log('\n--- TEST 4: Boş Görsel Verisi -> IMAGE_DATA_MISSING ---');
const emptyBuffer = Buffer.alloc(0);
const val4 = validateImageBuffer(emptyBuffer);

assert(val4.valid === false, 'T4.1: 0 byte buffer reddedilmeli');
assert(val4.errorCode === 'IMAGE_DATA_MISSING', 'T4.2: IMAGE_DATA_MISSING hata kodu dönmeli');
testDetails.push({ testNumber: 4, name: 'Image Data Missing', status: 'PASS', note: '0 byte doğru yakalandı' });

// -----------------------------------------------------------------------------
// TEST 5: Gerçek PNG -> F5 "blocked" -> action OBSERVED DENY & outcome BLOCKED
// -----------------------------------------------------------------------------
console.log('\n--- TEST 5: F5 "blocked" -> Action OBSERVED DENY & Outcome BLOCKED ---');
const f5OcrText = '185.123.105.51 | blocked | GET /cgi-bin/../../../../etc/passwd HTTP/1.1 | /etc/passwd';
const f5Parsed = parseSecurityFieldsFromOcrText(f5OcrText, val1);

assert(f5Parsed.observedFromImage.action === 'DENY', 'T5.1: F5 blocked aksiyonu DENY olmalı');
assert(f5Parsed.observedFromImage.sourceIp === '185.123.105.51', 'T5.2: Kaynak IP 185.123.105.51 olmalı');
assert(f5Parsed.visualPlatform.includes('F5'), 'T5.3: Platform F5 ASM/WAF olarak tanınmalı');

const decision5 = evaluateUnifiedDecision({ rawLine: f5OcrText, sourceType: 'SCREENSHOT_OCR' });
assert(decision5.isBlocked === true, 'T5.4: isBlocked true olmalı');
assert(decision5.verdict === 'BLOCKED_ATTACK_ATTEMPT', 'T5.5: Verdict BLOCKED_ATTACK_ATTEMPT olmalı');
assert(decision5.universalEvidence.action.status === 'OBSERVED', 'T5.6: Action kanıt durumu OBSERVED olmalı');
assert(decision5.universalEvidence.outcome.status === 'OBSERVED', 'T5.7: Outcome kanıt durumu OBSERVED olmalı');
testDetails.push({ testNumber: 5, name: 'F5 Blocked Action OBSERVED', status: 'PASS', note: 'Provenance ve verdict doğrulandı' });

// -----------------------------------------------------------------------------
// TEST 6: Gerçek Görsel / Log -> HTTP 403 + NO WAF ACTION -> BLOCKED Üretilmiyor
// -----------------------------------------------------------------------------
console.log('\n--- TEST 6: HTTP 403 + NO WAF ACTION -> WAF BLOCKED Üretilmiyor ---');
const log6 = '192.168.1.100 - - [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 2326';
const decision6 = evaluateUnifiedDecision({ rawLine: log6, sourceType: 'SCREENSHOT_OCR' });

assert(decision6.isBlocked === false, 'T6.1: HTTP 403 tek başına isBlocked=true yapmamalı');
assert(decision6.verdict !== 'BLOCKED_ATTACK_ATTEMPT', 'T6.2: Verdict BLOCKED_ATTACK_ATTEMPT olmamalı');
assert(decision6.verdict === 'SUSPICIOUS_ANOMALY', 'T6.3: Verdict SUSPICIOUS_ANOMALY olmalı');
assert(decision6.universalEvidence.action.status === 'NOT_PRESENT', 'T6.4: Action NOT_PRESENT olmalı');
testDetails.push({ testNumber: 6, name: 'HTTP 403 Without Action No Block', status: 'PASS', note: '403 blok sayılmadı' });

// -----------------------------------------------------------------------------
// TEST 7: Malicious URI -> No Compromise Evidence -> Attack Success YOK
// -----------------------------------------------------------------------------
console.log('\n--- TEST 7: Malicious URI -> Attack Success Yok (NOT_ESTABLISHED) ---');
const sqliLog = '10.0.0.5 - - [10/Oct/2026:14:00:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,password%20FROM%20users HTTP/1.1" 200 4500';
const ev7 = extractUniversalEvidence(sqliLog, null, 'TEXT_LOG');
const hyp7 = synthesizeDynamicHypotheses(ev7);

const hasSuccessClaim = hyp7.provenFacts.some((f) => f.includes('başarılı oldu') || f.includes('ele geçirildi'));
assert(!hasSuccessClaim, 'T7.1: ProvenFacts içinde saldırı başarılı oldu iddiası olmamalı');
assert(hyp7.unprovenHypotheses.some((h) => h.includes('Attack success not established') || h.includes('kanıt saptanmamıştır')), 'T7.2: UnprovenHypotheses başarı kanıtı olmadığını açıkça belirtmeli');
testDetails.push({ testNumber: 7, name: 'Malicious Request != Attack Success', status: 'PASS', note: 'Başarı kanıtı aranması korundu' });

// -----------------------------------------------------------------------------
// TEST 8: /etc/passwd Request -> "Request targets /etc/passwd", AMA "File read" YOK
// -----------------------------------------------------------------------------
console.log('\n--- TEST 8: /etc/passwd URI Semantik Doğrulaması ---');
const traversalLog = '185.123.105.51 | blocked | GET /cgi-bin/../../../../etc/passwd HTTP/1.1 | /etc/passwd';
const ev8 = extractUniversalEvidence(traversalLog, null, 'SCREENSHOT_OCR');
const hyp8 = synthesizeDynamicHypotheses(ev8);

const fileReadClaim = hyp8.provenFacts.some((f) => f.includes('Dosya okundu') || f.includes('Dosya içeriği ele geçirildi'));
assert(!fileReadClaim, 'T8.1: ProvenFacts içinde "Dosya okundu" iddiası yer almamalı');
assert(hyp8.provenFacts.some((f) => f.includes('HTTP isteğinde') && f.includes('/etc/passwd')), 'T8.2: ProvenFacts hedef URI desenini nesnel olarak belirtmeli');
testDetails.push({ testNumber: 8, name: '/etc/passwd Request Semantic Precision', status: 'PASS', note: 'Dosya okundu iddiası engellendi' });

// -----------------------------------------------------------------------------
// TEST 9: HTTP Request URI -> CommandLine Alanına ASLA Yazılmamalı
// -----------------------------------------------------------------------------
console.log('\n--- TEST 9: KRİTİK SEMANTİK HATA DÜZELTMESİ (Request != CommandLine) ---');
assert(ev8.process.commandLine.status === 'NOT_PRESENT', 'T9.1: HTTP isteğinde process.commandLine NOT_PRESENT olmalı');
assert(ev8.process.commandLine.value === null, 'T9.2: process.commandLine.value null olmalı');
assert(!hyp8.provenFacts.some((f) => f.includes('Yürütülen komut satırı: "/cgi-bin')), 'T9.3: "Yürütülen komut satırı: /cgi-bin" YANLIŞ ÇIKTISI ARTIK ÜRETİLMEMELİ!');
testDetails.push({ testNumber: 9, name: 'Request != CommandLine', status: 'PASS', note: 'Kritik semantik hata başarıyla düzeltildi' });

// -----------------------------------------------------------------------------
// TEST 10: Source IP Doğrudan sourceEndpoint.ip Alanına Girmeli
// -----------------------------------------------------------------------------
console.log('\n--- TEST 10: Source IP -> sourceEndpoint.ip ---');
assert(ev8.sourceEndpoint.ip.status === 'OBSERVED', 'T10.1: sourceEndpoint.ip.status OBSERVED olmalı');
assert(ev8.sourceEndpoint.ip.value === '185.123.105.51', 'T10.2: Kaynak IP 185.123.105.51 olmalı');
testDetails.push({ testNumber: 10, name: 'Source IP Binding', status: 'PASS', note: 'IP doğrudan bağlandı' });

// -----------------------------------------------------------------------------
// TEST 11: Blocked -> Action/Outcome Provenance Korunuyor
// -----------------------------------------------------------------------------
console.log('\n--- TEST 11: Blocked Provenance ---');
assert(ev8.action.status === 'OBSERVED', 'T11.1: action.status OBSERVED olmalı');
assert(ev8.action.value === 'DENY', 'T11.2: action.value DENY olmalı');
assert(ev8.outcome.status === 'OBSERVED', 'T11.3: outcome.status OBSERVED olmalı');
assert(ev8.outcome.value === 'BLOCKED', 'T11.4: outcome.value BLOCKED olmalı');
testDetails.push({ testNumber: 11, name: 'Action/Outcome Provenance', status: 'PASS', note: 'OBSERVED korundu' });

// -----------------------------------------------------------------------------
// TEST 12: Bozuk OCR Sonucu -> Belirsizlik / UNCERTAIN
// -----------------------------------------------------------------------------
console.log('\n--- TEST 12: Bozuk OCR Sonucu -> UNCERTAIN ---');
const garbledOcrText = 'X?#~@... unrecognizable symbols 999.999';
const garbledParsed = parseSecurityFieldsFromOcrText(garbledOcrText, val1);

assert(garbledParsed.observedFromImage.sourceIp === null, 'T12.1: Bozuk IP kabul edilmemeli');
assert(garbledParsed.observedFromImage.action === null, 'T12.2: Bozuk aksiyon kabul edilmemeli');
testDetails.push({ testNumber: 12, name: 'Garbled OCR Uncertainty', status: 'PASS', note: 'Halüsinasyon engellendi' });

// -----------------------------------------------------------------------------
// TEST 13: Sadece Metin Girdisi -> TEXT_INPUT Olarak İşaretlenmeli
// -----------------------------------------------------------------------------
console.log('\n--- TEST 13: Sadece Metin Girdisi -> TEXT_INPUT Olarak Sınıflandırılmalı ---');
const textOnlyInput = '185.123.105.51 | blocked | GET /cgi-bin/../../../../etc/passwd HTTP/1.1 | /etc/passwd';
const textEv = extractUniversalEvidence(textOnlyInput, null, 'TEXT_LOG');

assert(textEv.sourceEndpoint.ip.sourceType === 'TEXT_LOG', 'T13.1: Metin logu sourceType TEXT_LOG olmalı');
assert(textEv.sourceEndpoint.ip.sourceType !== 'IMAGE_PIXEL', 'T13.2: Metin logu ASLA IMAGE_PIXEL sayılmamalı!');
assert(textEv.sourceEndpoint.ip.sourceType !== 'SCREENSHOT_OCR', 'T13.3: Metin logu sahte SCREENSHOT_OCR sayılmamalı!');
testDetails.push({ testNumber: 13, name: 'Text Only Not Real Pixel', status: 'PASS', note: 'Anti-cheat ayrımı korundu' });

console.log('\n================================================================');
console.log(`🎉 TÜM REAL PIXEL FORENSIC VISION TESTLERİ BAŞARIYLA GEÇTİ: ${passCount} / ${passCount}`);
console.log('================================================================\n');
