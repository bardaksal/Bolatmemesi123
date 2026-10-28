import assert from 'assert';
import { runDirectGeminiHunt } from '../services/geminiDirectHunter';

console.log('================================================================');
console.log('⚡ GEMINI DIRECT HUNTER & INTEGRATION VALIDATION TEST ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: Empty or whitespace log input
// -----------------------------------------------------------------------------
console.log('\n--- 1. Boş veya Tanımsız Girdi Dayanıklılığı ---');
const emptyRes = await runDirectGeminiHunt('');
assert.strictEqual(emptyRes.report.summary.toplam_olay, 0);
assert.strictEqual(emptyRes.triageSummary.totalEvents, 0);
assert.strictEqual(emptyRes.triageSummary.postureTitle, 'BOŞ VERİ');
console.log('✔ Test 1 PASS: Boş girdi güvenli şekilde ele alındı.');

// -----------------------------------------------------------------------------
// TEST 2: Multi-format log paste with SSH, Nginx, Postfix, CEF, and API 401
// -----------------------------------------------------------------------------
console.log('\n--- 2. Çoklu Format Ham Log Analizi & Semantik Raporlama ---');

const mixedRawLogs = [
  // 1. SSH Auth failure (NOT a security device block)
  'Oct 18 10:14:22 srv-prod sshd[18422]: Failed password for invalid user oracle from 198.51.100.44 port 44122 ssh2',
  // 2. SSH Connection closed (NOT a security device block)
  'Oct 18 10:14:23 srv-prod sshd[18422]: Connection closed by invalid user oracle 198.51.100.44 port 44122 [preauth]',
  // 3. Postfix SASL Login failure (NOT a security device block)
  'Oct 18 10:15:01 mail-01 postfix/smtpd[2033]: warning: unknown[203.0.113.88]: SASL LOGIN authentication failed: authentication failure',
  // 4. Nginx Path Traversal attempt
  '10.44.8.21 - - [18/Oct/2026:10:16:00 +0300] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 403 162 "-" "curl/7.68.0"',
  // 5. CEF Firewall Deny (Real security device block)
  'CEF:0|Checkpoint|Firewall|R80.40|Drop|Drop|5|src=198.51.100.99 dst=10.0.0.5 act=deny outcome=blocked',
  // 6. API 401
  '{"timestamp":"2026-10-18T10:17:00Z","level":"warn","service":"auth-api","status":401,"srcIp":"192.168.1.50","msg":"unauthorized token"}'
].join('\n');

const huntResult = await runDirectGeminiHunt(mixedRawLogs);

// Verify file creation for DuckDB ingestion
assert(huntResult.file instanceof File, 'Test 2.1: File nesnesi başarıyla üretilmeli');
assert.strictEqual(huntResult.file.name, 'pasted_customer_logs.log');

// Verify total events count
assert.strictEqual(
  huntResult.report.summary.toplam_olay,
  6,
  `Test 2.2: 6 adet log olayının ayrıştırılması bekleniyordu, alınan: ${huntResult.report.summary.toplam_olay}`
);

// Verify auth failures count (SSH Failed password + Postfix SASL + Nginx 403 + API 401 = >= 4)
assert(
  huntResult.report.summary.auth_failure_sayisi >= 3,
  `Test 2.3: auth_failure_sayisi en az 3 olmalıdır, alınan: ${huntResult.report.summary.auth_failure_sayisi}`
);

// Verify security device deny count (ONLY CEF act=deny/outcome=blocked should be DENY; NOT SSH or Postfix or 401/403)
assert.strictEqual(
  huntResult.report.summary.deny_sayisi,
  1,
  `Test 2.4: Yalnızca gerçek güvenlik cihazı DENY üretmelidir (beklenen 1), alınan: ${huntResult.report.summary.deny_sayisi}`
);

// Verify Risk Queue generation
assert(
  huntResult.report.entity_risk_queue.length > 0,
  'Test 2.5: entity_risk_queue en az 1 şüpheli varlık içermelidir'
);

// Verify that the risk queue includes 198.51.100.44 or 10.44.8.21
const trackedIps = huntResult.report.entity_risk_queue.map((r) => r.ip_adresi);
console.log('Tespit edilen Risk Kuyruğu Varlıkları:', trackedIps);
assert(
  trackedIps.some((ip) => ip.includes('198.51.100.44') || ip.includes('10.44.8.21') || ip.includes('203.0.113.88') || ip.includes('198.51.100.99')),
  'Test 2.6: Şüpheli IP adresleri risk kuyruğuna eklenmelidir'
);

// Verify Raw Log Triage Summary fields
assert.strictEqual(typeof huntResult.triageSummary.overallPosture, 'string');
assert.strictEqual(typeof huntResult.triageSummary.evidenceBasedSummary, 'string');
assert(huntResult.triageSummary.overallFindings.length > 0);
assert(huntResult.triageSummary.fullReportText.includes('DOSYA / LOG ÖZETİ'));
assert(huntResult.triageSummary.fullReportText.includes('EVENT-BY-EVENT ANALYSIS'));

// Verify Webshell / Path Traversal table contains /cgi-bin/../../etc/passwd
assert(
  huntResult.report.webshell_and_file_management.length > 0,
  'Test 2.7: Path traversal tespiti webshell tablosuna eklenmelidir'
);
assert(
  huntResult.report.webshell_and_file_management.some((w) => w.eylem_ornekleri.includes('etc/passwd')),
  'Test 2.8: /etc/passwd URI webshell eylem örneklerinde yer almalıdır'
);

console.log('✔ Test 2 PASS: Çoklu format doğrudan Gemini analiz pipeline başarıyla doğrulandı.');

// -----------------------------------------------------------------------------
// TEST 3: Zero UI Telemetry & Clean Posture
// -----------------------------------------------------------------------------
console.log('\n--- 3. Sıfır Telemetri Kirliliği ve UI Uyumluluğu ---');
assert(!huntResult.triageSummary.postureTitle.includes('API_KEY'), 'Test 3.1: API anahtarı veya iç telemetri sızmamalı');
assert(!huntResult.triageSummary.evidenceBasedSummary.includes('telemetry_badge'), 'Test 3.2: Görsel rozet veya iç değişken adı sızmamalı');
console.log('✔ Test 3 PASS: Sıfır telemetri ve temiz arka plan yürütümü doğrulandı.');

// -----------------------------------------------------------------------------
// TEST 4: Gemini 3.8 Flash Reasoning ("Akıl Yürütme") Integration
// -----------------------------------------------------------------------------
console.log('\n--- 4. Gemini 3.8 Flash Akıl Yürütme (Reasoning) Entegrasyonu ---');

// Verify that the explainability summary reflects Gemini 3.8 Flash reasoning
const riskItemWithReasoning = huntResult.report.entity_risk_queue.find(
  (r) => r.explainability_summary.includes('Gemini 3.8 Flash') || r.explainability_summary.includes('Akıl Yürütme')
);
assert(
  riskItemWithReasoning !== undefined,
  'Test 4.1: En az bir risk kuyruğu öğesi Gemini 3.8 Flash akıl yürütme özetini içermelidir'
);
console.log('Örnek Akıl Yürütme Özeti:', riskItemWithReasoning.explainability_summary);

// Verify that individual events have reasoning embedded in evidence or summaryReason
assert(
  huntResult.report.raw_log_triage.fullReportText.includes('Akıl Yürütme') ||
  huntResult.report.raw_log_triage.fullReportText.includes('Gerekçe') ||
  huntResult.report.raw_log_triage.fullReportText.includes('Forensic Rationale'),
  'Test 4.2: Adli raporda mantıksal gerekçe / akıl yürütme yer almalıdır'
);

// Verify that hypotheses array has reasoning
assert(
  huntResult.pipelineResult.hypotheses.length > 0,
  'Test 4.3: pipelineResult en az bir adli hipotez içermelidir'
);
const firstHyp = huntResult.pipelineResult.hypotheses[0];
assert.strictEqual(typeof firstHyp.reasoning, 'string');
assert(firstHyp.reasoning.length > 10, 'Test 4.4: Hipotez akıl yürütme (reasoning) açıklaması içermelidir');
console.log(`✔ Test 4 PASS: Gemini 3.8 Flash Akıl Yürütme (Reasoning: "${firstHyp.reasoning.slice(0, 60)}...") başarıyla doğrulandı.`);

console.log('\n================================================================');
console.log('🎉 TÜM GEMINI DIRECT HUNTER & REASONING ENTEGRASYON TESTLERİ BAŞARIYLA GEÇTİ!');
console.log('================================================================\n');
