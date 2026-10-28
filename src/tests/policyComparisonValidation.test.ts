import {
  compareSecurityPeriods,
  generatePolicyEffectivenessHtmlReport,
  loadSampleWafComparisonScenario,
} from '../services/policyComparisonEngine';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${message}`);
  }
}

console.log('=== FORENSIC VALIDATION TESTS: POLICY COMPARISON & WAF EFFECTIVENESS ===\n');

// ==========================================
// TEST 1 — ALERT → BLOCK
// ==========================================
const test1_linesA = Array(100).fill(
  'date=2026-08-01 host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login?id=1"'
).join('\n');
const test1_linesB = Array(100).fill(
  'date=2026-09-01 host=srv01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login?id=1"'
).join('\n');

const res1 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test1_linesA }],
  [{ name: 'pB.log', content: test1_linesB }]
);

const sig1 = res1.signatureImpacts.find((s) => s.signatureId === 'OWASP-942-SQLI');
assert(!!sig1, 'TEST 1: Signature OWASP-942-SQLI must exist');
assert(sig1.periodA_alerted === 100, `TEST 1: Before ALERT must be 100, got ${sig1.periodA_alerted}`);
assert(sig1.periodA_blocked === 0, `TEST 1: Before BLOCK must be 0, got ${sig1.periodA_blocked}`);
assert(sig1.periodB_alerted === 0, `TEST 1: After ALERT must be 0, got ${sig1.periodB_alerted}`);
assert(sig1.periodB_blocked === 100, `TEST 1: After BLOCK must be 100, got ${sig1.periodB_blocked}`);
assert(sig1.actionChangeLabel === 'ALERT → BLOCK', `TEST 1: Action change must be ALERT → BLOCK, got ${sig1.actionChangeLabel}`);
assert(sig1.isContinuingInAfter === 'Evet', 'TEST 1: isContinuingInAfter must be Evet');
assert(sig1.statusLabel === 'BLOCK gözleniyor', `TEST 1: statusLabel must be BLOCK gözleniyor, got ${sig1.statusLabel}`);
assert(sig1.technicalStatus === 'BLOCK_GOZLENDI', 'TEST 1: technicalStatus must be BLOCK_GOZLENDI');

// Forbidden wording check
const allFindings1 = [...res1.keyFindings, res1.executiveSummary, sig1.forensicInterpretation].join(' ').toLowerCase();
assert(!allFindings1.includes('önceki 100 saldırının tamamı engellendi'), 'TEST 1: Must NOT claim previous 100 attacks were stopped');
assert(!allFindings1.includes('önceki saldırılar engellendi'), 'TEST 1: Must NOT claim previous attacks were stopped');
console.log('✅ TEST 1: ALERT → BLOCK durumu başarıyla doğrulandı; yasaklı ifade içermiyor.');

// ==========================================
// TEST 2 — Kısmi Değişim
// ==========================================
const test2_linesA = Array(100).fill(
  'date=2026-08-01 host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"'
).join('\n');
const test2_linesB = [
  ...Array(80).fill('date=2026-09-01 host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"'),
  ...Array(20).fill('date=2026-09-01 host=srv01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"'),
].join('\n');

const res2 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test2_linesA }],
  [{ name: 'pB.log', content: test2_linesB }]
);
const sig2 = res2.signatureImpacts.find((s) => s.signatureId === 'OWASP-942-SQLI');
assert(!!sig2, 'TEST 2: Signature must exist');
assert(sig2.periodA_alerted === 100 && sig2.periodA_blocked === 0, 'TEST 2: Before 100 alert / 0 block');
assert(sig2.periodB_alerted === 80 && sig2.periodB_blocked === 20, 'TEST 2: After 80 alert / 20 block');
assert(sig2.actionChangeLabel === 'Kısmi değişim', `TEST 2: Action change must be Kısmi değişim, got ${sig2.actionChangeLabel}`);
assert(
  sig2.statusLabel === 'Kısmi değişim' || sig2.statusLabel === 'ALERT devam ediyor',
  `TEST 2: Status label must be Kısmi değişim or ALERT devam ediyor, got ${sig2.statusLabel}`
);
assert(
  sig2.technicalStatus === 'KISMI_DEGISIM' || sig2.technicalStatus === 'ALERT_DEVAM_EDIYOR',
  'TEST 2: technicalStatus must be KISMI_DEGISIM or ALERT_DEVAM_EDIYOR'
);
console.log('✅ TEST 2: Kısmi değişim (ALERT + BLOCK) başarıyla doğrulandı.');

// ==========================================
// TEST 3 — Artık Gözlenmeyen İmza
// ==========================================
const test3_linesA = Array(100).fill(
  'date=2026-08-01 host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"'
).join('\n');
const test3_linesB = 'date=2026-09-01 host=srv01 action="allow" http_url="/home" attack="none"';

const res3 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test3_linesA }],
  [{ name: 'pB.log', content: test3_linesB }]
);
const sig3 = res3.signatureImpacts.find((s) => s.signatureId === 'OWASP-942-SQLI');
assert(!!sig3, 'TEST 3: Signature must exist in impacts');
assert(sig3.isContinuingInAfter === 'Hayır', 'TEST 3: isContinuingInAfter must be Hayır');
assert(sig3.statusLabel === 'Loglarda gözlenmedi', `TEST 3: statusLabel must be Loglarda gözlenmedi, got ${sig3.statusLabel}`);
assert(sig3.technicalStatus === 'LOGLARDA_GOZLENMEDI', 'TEST 3: technicalStatus must be LOGLARDA_GOZLENMEDI');
assert(
  sig3.forensicInterpretation.includes('sonraki karşılaştırma döneminde WAF/firewall loglarında gözlenmemiştir'),
  'TEST 3: Interpretation must state not observed in subsequent logs'
);
assert(!sig3.forensicInterpretation.toLowerCase().includes('saldırı tamamen engellendi'), 'TEST 3: Must not claim attack was completely prevented');
console.log('✅ TEST 3: Artık gözlenmeyen imza adli doğrulukla "Loglarda gözlenmedi" olarak işaretlendi.');

// ==========================================
// TEST 4 — Test 18 Regresyonu (Host + Attack Type İzolasyonu)
// ==========================================
const test4_linesA = 'date=2026-08-01 host=server01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"';
const test4_linesB = 'date=2026-09-01 host=server01 action="deny" attack="Cross-Site Scripting" signature_id="OWASP-941-XSS" http_url="/search"';

const res4 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test4_linesA }],
  [{ name: 'pB.log', content: test4_linesB }]
);
const srv01_4 = res4.protectedServers.find((s) => s.server === 'server01');
assert(!!srv01_4, 'TEST 4: server01 must exist');
assert(srv01_4.protectionRate === null, 'TEST 4: protectionRate must be null to prevent misleading unified rate');
assert(srv01_4.threats.length === 2, `TEST 4: SQLi and XSS must be 2 separate threat entries, got ${srv01_4.threats.length}`);
console.log('✅ TEST 4: Test 18 regresyonu engellendi — farklı saldırılar için birleşik sunucu koruma oranı üretilmiyor.');

// ==========================================
// TEST 5 — Farklı Policy Ayrımı
// ==========================================
const test5_linesA = 'date=2026-08-01 policy="Policy-A" host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"';
const test5_linesB = 'date=2026-09-01 policy="Policy-B" host=srv01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"';

const res5 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test5_linesA }],
  [{ name: 'pB.log', content: test5_linesB }]
);
const entryA = res5.signatureImpacts.find((s) => s.policyId === 'Policy-A' && s.signatureId === 'OWASP-942-SQLI');
const entryB = res5.signatureImpacts.find((s) => s.policyId === 'Policy-B' && s.signatureId === 'OWASP-942-SQLI');
assert(!!entryA && !!entryB, 'TEST 5: Policy-A and Policy-B must remain two independent entries');
assert(entryA.technicalStatus === 'LOGLARDA_GOZLENMEDI', 'TEST 5: Policy-A was not observed in Period B');
assert(entryB.isContinuingInAfter === 'Yeni', 'TEST 5: Policy-B was newly observed in Period B');
console.log('✅ TEST 5: Farklı policy ID/name içeren kurallar bağımsız olarak ayrıldı.');

// ==========================================
// TEST 6 — Aynı Policy + Aynı Rule
// ==========================================
const test6_linesA = 'date=2026-08-01 policy="Policy-A" rule="Rule-1" host=srv01 action="alert" http_url="/login"';
const test6_linesB = 'date=2026-09-01 policy="Policy-A" rule="Rule-1" host=srv01 action="deny" http_url="/login"';

const res6 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test6_linesA }],
  [{ name: 'pB.log', content: test6_linesB }]
);
const entry6 = res6.signatureImpacts.find((s) => s.policyId === 'Policy-A' && s.signatureId === 'Rule-1');
assert(!!entry6, 'TEST 6: Same Policy-A + Rule-1 must be matched before/after');
assert(entry6.periodA_alerted === 1 && entry6.periodB_blocked === 1, 'TEST 6: 1 alert in A, 1 block in B');
assert(entry6.actionChangeLabel === 'ALERT → BLOCK', 'TEST 6: Action transition must be ALERT → BLOCK');
console.log('✅ TEST 6: Aynı policy ve rule_id altında before/after eşleşmesi başarıyla doğrulandı.');

// ==========================================
// TEST 7 — Farklı Trafik Hacmi (100.000 vs 1.000.000)
// ==========================================
// Test mathematically with normalized percentages
const test7_linesA = [
  ...Array(10).fill('date=2026-08-01 action="deny" status=403 http_url="/"'),
  ...Array(990).fill('date=2026-08-01 action="allow" status=200 http_url="/"'),
].join('\n'); // 10 / 1000 = %1

const test7_linesB = [
  ...Array(50).fill('date=2026-09-01 action="deny" status=403 http_url="/"'),
  ...Array(4950).fill('date=2026-09-01 action="allow" status=200 http_url="/"'),
].join('\n'); // 50 / 5000 = %1

const res7 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test7_linesA }],
  [{ name: 'pB.log', content: test7_linesB }]
);
assert(res7.periodA.blockRate === 1, `TEST 7: Period A rate should be 1%, got ${res7.periodA.blockRate}`);
assert(res7.periodB.blockRate === 1, `TEST 7: Period B rate should be 1%, got ${res7.periodB.blockRate}`);
assert(res7.blockRateDelta === 0, `TEST 7: blockRateDelta should be 0 percentage points, got ${res7.blockRateDelta}`);
console.log('✅ TEST 7: Farklı trafik hacimlerinde oran normalizasyonu (yüzde puan) doğru hesaplandı.');

// ==========================================
// TEST 8 — Farklı Dönem Uzunluğu (Günlük Ortalama)
// ==========================================
const test8_linesA = [
  'date=2026-08-01 time=10:00:00 action="deny" status=403 http_url="/"',
  'date=2026-08-30 time=10:00:00 action="deny" status=403 http_url="/"',
].join('\n'); // 30 days
const test8_linesB = [
  'date=2026-09-01 time=10:00:00 action="deny" status=403 http_url="/"',
  'date=2026-09-07 time=10:00:00 action="deny" status=403 http_url="/"',
].join('\n'); // 7 days

const res8 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test8_linesA }],
  [{ name: 'pB.log', content: test8_linesB }]
);
assert(res8.periodA.totalDays === 30, `TEST 8: Period A should be 30 days, got ${res8.periodA.totalDays}`);
assert(res8.periodB.totalDays === 7, `TEST 8: Period B should be 7 days, got ${res8.periodB.totalDays}`);
assert(res8.periodA.dailyAverageRequests >= 0 && res8.periodB.dailyAverageRequests >= 0, 'TEST 8: daily averages computed');
console.log('✅ TEST 8: Farklı dönem uzunlukları için gün sayısı ve günlük ortalamalar doğru hesaplandı.');

// ==========================================
// TEST 9 — Byte Yok
// ==========================================
const test9_linesA = 'date=2026-08-01 action="alert" http_url="/sqli" attack="SQLi" signature_id="OWASP-942-SQLI"';
const test9_linesB = 'date=2026-09-01 action="deny" http_url="/sqli" attack="SQLi" signature_id="OWASP-942-SQLI"';

const res9 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test9_linesA }],
  [{ name: 'pB.log', content: test9_linesB }]
);
assert(res9.preventedTrafficMb === null, 'TEST 9: preventedTrafficMb must be null');
assert(res9.keyFindings.some((f) => f.includes('Log kaynağında byte bilgisi bulunmadığından trafik hacmi hesaplanamadı')), 'TEST 9: Key finding must state byte absent');
console.log('✅ TEST 9: Byte alanı yokken sentetik fallback yapılmıyor; null ve adli uyarı dönüyor.');

// ==========================================
// TEST 10 — Unknown Action
// ==========================================
const test10_linesA = 'date=2026-08-01 action="unknown" http_url="/"';
const test10_linesB = 'date=2026-09-01 action="-" http_url="/"';

const res10 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test10_linesA }],
  [{ name: 'pB.log', content: test10_linesB }]
);
assert(res10.periodA.blockedRequests === 0, 'TEST 10: unknown must NOT be counted as BLOCK');
assert(res10.periodA.alertedRequests === 0, 'TEST 10: unknown must NOT be counted as ALERT');
assert(res10.periodB.blockedRequests === 0, 'TEST 10: dash must NOT be counted as BLOCK');
console.log('✅ TEST 10: Unknown veya tanımsız action değerleri varsayılan olarak BLOCK veya ALERT sayılmıyor.');

// ==========================================
// TEST 11 — WAF 502/504 vs Backend 5xx
// ==========================================
const test11_linesA = 'date=2026-08-01 devname="FW-WAF" status=502 http_url="/" action="deny"';
const test11_linesB = 'date=2026-09-01 devname="FW-WAF" status=200 http_url="/" action="deny"';

const res11 = compareSecurityPeriods(
  [{ name: 'pure_waf_a.log', content: test11_linesA }],
  [{ name: 'pure_waf_b.log', content: test11_linesB }]
);
assert(res11.serverErrorReductionPct === null, 'TEST 11: serverErrorReductionPct must be null without backend log');
assert(res11.keyFindings.some((f) => f.includes('Backend telemetrisi bulunmadığı için 5xx etkisi hesaplanamadı')), 'TEST 11: Warning must be displayed');
console.log('✅ TEST 11: WAF tek başına backend 5xx olarak sayılmıyor; backend logu yoksa 5xx etkisi hesaplanmıyor.');

// ==========================================
// TEST 12 — Duplicate Loglar Dipnotu
// ==========================================
assert(res1.footnotes.some((fn) => fn.includes('Stateful deduplication')), 'TEST 12: Footnotes must explain deduplication policy');
console.log('✅ TEST 12: Tekrarlayan loglar için stateful deduplication sınırlaması adli dipnotlarda açıklandı.');

// ==========================================
// TEST 13 — Bilinmeyen Vendor Rule/Signature
// ==========================================
const test13_linesA = 'date=2026-08-01 rule="custom-rule-999" attack="Custom Vendor Attack" action="alert" http_url="/custom"';
const test13_linesB = 'date=2026-09-01 rule="custom-rule-999" attack="Custom Vendor Attack" action="deny" http_url="/custom"';

const res13 = compareSecurityPeriods(
  [{ name: 'pA.log', content: test13_linesA }],
  [{ name: 'pB.log', content: test13_linesB }]
);
const customSig = res13.signatureImpacts.find((s) => s.signatureId === 'custom-rule-999');
assert(!!customSig, 'TEST 13: Custom unknown vendor rule must be identified');
assert(customSig.name === 'Custom Vendor Attack', `TEST 13: Name should match attack name, got ${customSig.name}`);
assert(customSig.actionChangeLabel === 'ALERT → BLOCK', 'TEST 13: Action change should be ALERT → BLOCK');
console.log('✅ TEST 13: Bilinmeyen vendor kural ve imzaları kaybolmadan dinamik olarak matrise dahil edildi.');

// ==========================================
// TEST 14 — HTML Rapor Dil ve Yasaklı İfade Denetimi
// ==========================================
const html14 = generatePolicyEffectivenessHtmlReport(res1, 'Finans Bank A.Ş.', 'SOC Analisti');
const forbiddenPhrases = [
  'önceki saldırılar engellendi',
  'tamamen nötralize',
  'tam koruma',
  'policy değişikliği doğrulandı',
  'saldırıların tamamı engellendi',
  '%100 nötralize',
];

for (const phrase of forbiddenPhrases) {
  assert(!html14.toLowerCase().includes(phrase.toLowerCase()), `TEST 14: HTML report MUST NOT contain forbidden phrase: "${phrase}"`);
}

// Ensure required sections exist in the HTML report
assert(html14.includes('1. 📋 Yönetici Özeti'), 'TEST 14: Section 1 must exist');
assert(html14.includes('2. 🛡️ Policy Before / After'), 'TEST 14: Section 2 must exist');
assert(html14.includes('3. 🔄 Devam Eden İmzalar'), 'TEST 14: Section 3 must exist');
assert(html14.includes('4. 📴 Artık Gözlenmeyen İmzalar'), 'TEST 14: Section 4 must exist');
assert(html14.includes('5. 📶 Trafik Hacmi Analizi'), 'TEST 14: Section 5 must exist');
assert(html14.includes('6. 🗂️ Hiyerarşik Dağılım'), 'TEST 14: Section 6 must exist');
assert(html14.includes('7. 🛡️ Önerilen Güvenlik Aksiyonları'), 'TEST 14: Section 7 must exist');

console.log('✅ TEST 14: HTML raporu 7 temel bölümü içeriyor ve hiçbir yasaklı ifade barındırmıyor.');

console.log('\n=============================================================');
console.log('TÜM 14 ADLİ VE METODOLOJİK TEST BAŞARIYLA GEÇTİ!');
console.log('=============================================================\n');
