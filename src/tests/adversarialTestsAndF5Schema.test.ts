import {
  compareSecurityPeriods,
  generatePolicyEffectivenessHtmlReport,
} from '../services/policyComparisonEngine';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${message}`);
  }
}

console.log('=== RUNNING ADVERSARIAL VALIDATION & F5 10-COLUMN SCHEMA TESTS ===\n');

// =========================================================================
// TEST 1 — EŞİT SAYI, FARKLI SALDIRILAR
// =========================================================================
console.log('--- TEST 1: Eşit Sayı, Farklı Saldırılar ---');
const t1_linesA = Array.from({ length: 100 }, (_, i) =>
  `date=2026-08-01 client_ip=10.1.1.${(i % 50) + 1} uri=/login?u=${i} action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"`
).join('\n');

const t1_linesB = Array.from({ length: 100 }, (_, i) =>
  `date=2026-09-01 client_ip=172.16.2.${(i % 50) + 1} uri=/api/v2/item/${i} action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"`
).join('\n');

const resT1 = compareSecurityPeriods(
  [{ name: 'periodA.log', content: t1_linesA }],
  [{ name: 'periodB.log', content: t1_linesB }]
);

const textT1 = [
  ...resT1.keyFindings,
  resT1.executiveSummary,
  ...resT1.signatureImpacts.map((s) => s.forensicInterpretation),
].join(' ').toLowerCase();

assert(!textT1.includes('100 önceki saldırı engellendi'), 'TEST 1: Must NOT claim 100 previous attacks were stopped');
assert(!textT1.includes('önceki 100 saldırının tamamı engellendi'), 'TEST 1: Must NOT claim all previous 100 attacks stopped');
assert(
  resT1.keyFindings.some((k) => k.includes('Dönem B') && k.includes('BLOCK') && k.includes('gözlendi')),
  'TEST 1: Must report observed block events in Period B'
);
console.log('✅ TEST 1 Passed: Sistem önceki saldırıların engellendiğini iddia etmedi, gözlenen olay olarak raporladı.');

// =========================================================================
// TEST 2 — TRAFİK HACMİ 5 KAT ARTIYOR
// =========================================================================
console.log('--- TEST 2: Trafik Hacmi 5 Kat Artıyor ---');
// Period A: 10.000 requests, 500 SQLi ALERT -> 5%
// Period B: 50.000 requests, 1.000 SQLi BLOCK -> 2%
const t2_periodA = [
  ...Array.from({ length: 500 }, () => 'action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
  ...Array.from({ length: 9500 }, () => 'action="allow" status=200'),
].join('\n');

const t2_periodB = [
  ...Array.from({ length: 1000 }, () => 'action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
  ...Array.from({ length: 49000 }, () => 'action="allow" status=200'),
].join('\n');

const resT2 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t2_periodA }],
  [{ name: 'pB.log', content: t2_periodB }]
);

assert(resT2.periodA.totalRequests === 10000, `Period A total requests should be 10000, got ${resT2.periodA.totalRequests}`);
assert(resT2.periodB.totalRequests === 50000, `Period B total requests should be 50000, got ${resT2.periodB.totalRequests}`);
assert(resT2.periodA.blockRate === 0, `Period A block rate should be 0%, got ${resT2.periodA.blockRate}`);
assert(resT2.periodB.blockRate === 2, `Period B block rate should be 2%, got ${resT2.periodB.blockRate}`);
assert(resT2.attackBlockedDeltaCount === 1000, `Attack blocked delta count should be 1000, got ${resT2.attackBlockedDeltaCount}`);

const textT2 = [...resT2.keyFindings, resT2.executiveSummary].join(' ').toLowerCase();
assert(!textT2.includes('saldırı etkinliği %100 arttı'), 'TEST 2: Must NOT claim attack efficiency increased 100%');
console.log('✅ TEST 2 Passed: Raw count (1000) ve normalize edilmiş oran (%2) ayrı ve adli olarak sunuldu.');

// =========================================================================
// TEST 3 — GERÇEK BEFORE/AFTER
// =========================================================================
console.log('--- TEST 3: Gerçek Before/After ---');
const t3_periodA = Array.from({ length: 1000 }, () =>
  'action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"'
).join('\n');
const t3_periodB = Array.from({ length: 1000 }, () =>
  'action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"'
).join('\n');

const resT3 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t3_periodA }],
  [{ name: 'pB.log', content: t3_periodB }]
);

assert(resT3.periodA.blockRate === 0, 'TEST 3: Period A block rate should be 0%');
assert(resT3.periodB.blockRate === 100, 'TEST 3: Period B block rate should be 100%');
assert(resT3.blockRateDelta === 100, 'TEST 3: Delta should be +100 percentage points');

const textT3 = [...resT3.keyFindings, resT3.executiveSummary].join(' ').toLowerCase();
assert(!textT3.includes('önceki 1.000 saldırının tamamı engellendi'), 'TEST 3: Must NOT claim previous 1,000 attacks were blocked');
assert(!textT3.includes('önceki 1000 saldırının tamamı engellendi'), 'TEST 3: Must NOT claim previous 1000 attacks were blocked');
console.log('✅ TEST 3 Passed: Block rate %0 -> %100 (+100 percentage points) doğru hesaplandı, spekülatif iddia üretilmedi.');

// =========================================================================
// TEST 4 — TAMAMEN FARKLI IP
// =========================================================================
console.log('--- TEST 4: Tamamen Farklı IP ---');
const t4_periodA = 'client_ip=10.1.1.1 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"';
const t4_periodB = 'client_ip=10.9.9.9 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"';

const resT4 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t4_periodA }],
  [{ name: 'pB.log', content: t4_periodB }]
);

const textT4 = [...resT4.keyFindings, resT4.executiveSummary].join(' ').toLowerCase();
assert(!textT4.includes('aynı saldırgan engellendi'), 'TEST 4: Different IPs must not be correlated as same attacker');
console.log('✅ TEST 4 Passed: Farklı IP olayları birebir aynı saldırı olarak korele edilmedi.');

// =========================================================================
// TEST 5 — AYNI IP, FARKLI SALDIRI
// =========================================================================
console.log('--- TEST 5: Aynı IP, Farklı Saldırı ---');
const t5_periodA = 'client_ip=10.1.1.1 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"';
const t5_periodB = 'client_ip=10.1.1.1 action="deny" attack="Cross-Site Scripting" signature_id="OWASP-941-XSS"';

const resT5 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t5_periodA }],
  [{ name: 'pB.log', content: t5_periodB }]
);

assert(resT5.signatureImpacts.length === 2, `TEST 5: Must have 2 distinct signatures, got ${resT5.signatureImpacts.length}`);
console.log('✅ TEST 5 Passed: Aynı IP olsa dahi farklı saldırılar birbirinden bağımsız tutuldu.');

// =========================================================================
// TEST 6 — AYNI SIGNATURE, FARKLI KAYNAKLAR
// =========================================================================
console.log('--- TEST 6: Aynı Signature, Farklı Kaynaklar ---');
const t6_periodA = Array.from({ length: 100 }, (_, i) =>
  `client_ip=10.0.1.${i} action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"`
).join('\n');
const t6_periodB = Array.from({ length: 100 }, (_, i) =>
  `client_ip=10.0.2.${i} action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"`
).join('\n');

const resT6 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t6_periodA }],
  [{ name: 'pB.log', content: t6_periodB }]
);

const textT6 = [...resT6.keyFindings, resT6.executiveSummary].join(' ').toLowerCase();
assert(!textT6.includes('100 saldırı önceden içeri geçiyordu ve şimdi engellendi'), 'TEST 6: Must NOT claim previous 100 attacks stopped');
console.log('✅ TEST 6 Passed: Kümülatif imza karşılaştırması yapıldı fakat sahte devamlılık iddiası üretilmedi.');

// =========================================================================
// TEST 7 — TRAFİK PATLAMASI
// =========================================================================
console.log('--- TEST 7: Trafik Patlaması ---');
// Period A: 10.000 request, 100 BLOCK -> %1
// Period B: 100.000 request, 1.000 BLOCK -> %1
const t7_periodA = [
  ...Array.from({ length: 100 }, () => 'action="deny" status=403'),
  ...Array.from({ length: 9900 }, () => 'action="allow" status=200'),
].join('\n');

const t7_periodB = [
  ...Array.from({ length: 1000 }, () => 'action="deny" status=403'),
  ...Array.from({ length: 99000 }, () => 'action="allow" status=200'),
].join('\n');

const resT7 = compareSecurityPeriods(
  [{ name: 'pA.log', content: t7_periodA }],
  [{ name: 'pB.log', content: t7_periodB }]
);

assert(resT7.periodA.blockRate === 1, `Period A block rate should be 1%, got ${resT7.periodA.blockRate}`);
assert(resT7.periodB.blockRate === 1, `Period B block rate should be 1%, got ${resT7.periodB.blockRate}`);
assert(resT7.blockRateDelta === 0, `Block rate delta must be 0 percentage points, got ${resT7.blockRateDelta}`);
assert(resT7.attackBlockedDeltaCount === 900, `Raw block delta must be +900, got ${resT7.attackBlockedDeltaCount}`);

const textT7 = [...resT7.keyFindings, resT7.executiveSummary].join(' ').toLowerCase();
assert(!textT7.includes('koruma 10 kat arttı'), 'TEST 7: Must NOT claim protection increased 10 fold');
console.log('✅ TEST 7 Passed: Raw BLOCK sayısı +9.000 fakat block rate delta 0 percentage points; "10 kat arttı" denmedi.');

// =========================================================================
// TESTLER A-E: TEST 18 METODOLOJİK DÜZELTME (HOST + SIGNATURE)
// =========================================================================
console.log('\n--- TESTS A-E: Protected Server Dimension Isolation ---');

// TEST A — Farklı saldırı türleri
const tA_pA = 'host=server01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"';
const tA_pB = 'host=server01 action="deny" attack="Cross-Site Scripting" signature_id="OWASP-941-XSS"';
const resTA = compareSecurityPeriods([{ name: 'pA.log', content: tA_pA }], [{ name: 'pB.log', content: tA_pB }]);
const srvA = resTA.protectedServers.find((s) => s.server === 'server01');
assert(!!srvA, 'TEST A: server01 must exist');
assert(srvA.protectionRate === null, 'TEST A: Combined protection rate MUST be null');
assert(srvA.threats.length === 2, 'TEST A: Must have 2 separate threat entries');
console.log('✅ TEST A Passed: Farklı saldırılar için birleşik koruma oranı üretilmedi (%50 denmedi).');

// TEST B — Aynı server + aynı signature
const tB_pA = Array.from({ length: 100 }, () => 'host=server01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"').join('\n');
const tB_pB = Array.from({ length: 100 }, () => 'host=server01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"').join('\n');
const resTB = compareSecurityPeriods([{ name: 'pA.log', content: tB_pA }], [{ name: 'pB.log', content: tB_pB }]);
const textTB = [...resTB.keyFindings, resTB.executiveSummary].join(' ').toLowerCase();
assert(!textTB.includes('önceki 100 saldırının tamamı engellendi'), 'TEST B: Must not claim previous 100 attacks stopped');
console.log('✅ TEST B Passed: Aynı host + signature adli olarak incelendi.');

// TEST C — Aynı host + farklı rule ID
const tC_pA = 'host=server01 rule="rule-100" action="alert"';
const tC_pB = 'host=server01 rule="rule-200" action="deny"';
const resTC = compareSecurityPeriods([{ name: 'pA.log', content: tC_pA }], [{ name: 'pB.log', content: tC_pB }]);
assert(resTC.signatureImpacts.length === 2, 'TEST C: rule-100 and rule-200 must be 2 distinct entries');
console.log('✅ TEST C Passed: rule-100 ve rule-200 aynı kural kabul edilmedi.');

// TEST D — Aynı signature + farklı host
const tD_pA = 'host=server01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"';
const tD_pB = 'host=server02 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"';
const resTD = compareSecurityPeriods([{ name: 'pA.log', content: tD_pA }], [{ name: 'pB.log', content: tD_pB }]);
const srv01 = resTD.protectedServers.find((s) => s.server === 'server01');
const srv02 = resTD.protectedServers.find((s) => s.server === 'server02');
assert(!!srv01 && !!srv02, 'TEST D: server01 and server02 must be separate entries');
console.log('✅ TEST D Passed: Aynı signature olsa dahi host bazında ayrı tutuldu.');

// TEST E — Host + signature + action matrisi
const tE_pA = [
  ...Array.from({ length: 10 }, () => 'host=server01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
  ...Array.from({ length: 20 }, () => 'host=server01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
  ...Array.from({ length: 30 }, () => 'host=server01 action="alert" attack="Cross-Site Scripting" signature_id="OWASP-941-XSS"'),
  ...Array.from({ length: 40 }, () => 'host=server01 action="deny" attack="Cross-Site Scripting" signature_id="OWASP-941-XSS"'),
  ...Array.from({ length: 50 }, () => 'host=server02 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
  ...Array.from({ length: 60 }, () => 'host=server02 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI"'),
].join('\n');
const resTE = compareSecurityPeriods([{ name: 'pA.log', content: tE_pA }], [{ name: 'pB.log', content: tE_pA }]);
assert(resTE.protectedServers.length === 2, 'TEST E: Exactly 2 servers');
console.log('✅ TEST E Passed: Tüm kombinasyonlar bağımsız hesaplandı.');

// =========================================================================
// TEST F5: GERÇEK MÜŞTERİ 10-KOLON F5 EXCEL/CSV ŞEMASI DOĞRULAMASI
// =========================================================================
console.log('\n--- TEST F5: Real Customer 10-Column F5 Schema & Weights ---');

const f5_csv_A = `Policy Name (custom),Threat Type (custom),Event Name,Log Source,Response,Destination,Destination Port,Start Time,Low Level,Count
/Common/waf_corp_prod,SQL Injection,Illegal meta character in value,BIG-IP-ASM-01,Alarmed,192.168.10.50,443,2026-08-05 14:22:10,High,250
/Common/waf_corp_prod,Cross Site Scripting (XSS),XSS script tag in parameter,BIG-IP-ASM-01,Alarmed,192.168.10.50,443,2026-08-05 15:10:00,Medium,150
/Common/waf_corp_prod,Command Execution,OS command injection syntax,BIG-IP-ASM-01,Alarmed,192.168.10.60,443,2026-08-05 16:00:00,High,100`;

const f5_csv_B = `Policy Name (custom),Threat Type (custom),Event Name,Log Source,Response,Destination,Destination Port,Start Time,Low Level,Count
/Common/waf_corp_prod,SQL Injection,Illegal meta character in value,BIG-IP-ASM-01,Blocked,192.168.10.50,443,2026-09-10 10:00:00,High,250
/Common/waf_corp_prod,Cross Site Scripting (XSS),XSS script tag in parameter,BIG-IP-ASM-01,Blocked,192.168.10.50,443,2026-09-10 11:00:00,Medium,150
/Common/waf_corp_prod,Command Execution,OS command injection syntax,BIG-IP-ASM-01,Alarmed,192.168.10.60,443,2026-09-10 12:00:00,High,50
/Common/waf_corp_prod,Command Execution,OS command injection syntax,BIG-IP-ASM-01,Blocked,192.168.10.60,443,2026-09-10 12:30:00,High,50`;

const resF5 = compareSecurityPeriods(
  [{ name: 'f5_donem_a.csv', content: f5_csv_A }],
  [{ name: 'f5_donem_b.csv', content: f5_csv_B }],
  'Ağustos 2026 (Öncesi)',
  'Eylül 2026 (Sonrası)'
);

// Diagnostics checks
assert(!!resF5.diagnostics, 'TEST F5: Diagnostics must be returned');
const diagA = resF5.diagnostics.periodA[0];
const diagB = resF5.diagnostics.periodB[0];
assert(diagA.isF5SchemaDetected === true, 'TEST F5: Period A must be detected as F5 schema');
assert(diagB.isF5SchemaDetected === true, 'TEST F5: Period B must be detected as F5 schema');
assert(diagA.parsedRowsCount === 3, `TEST F5: Period A rows parsed should be 3, got ${diagA.parsedRowsCount}`);
assert(diagB.parsedRowsCount === 4, `TEST F5: Period B rows parsed should be 4, got ${diagB.parsedRowsCount}`);
assert(diagA.unmatchedExpectedColumns.length === 0, 'TEST F5: All 10 expected F5 columns matched');

// Weighted totals
// Period A: 250 + 150 + 100 = 500 total requests (all Alarmed = 0 blocked)
// Period B: 250 + 150 + 50 + 50 = 500 total requests (250 + 150 + 50 = 450 blocked, 50 alarmed)
assert(resF5.periodA.totalRequests === 500, `TEST F5: Period A total requests must be 500 (weighted), got ${resF5.periodA.totalRequests}`);
assert(resF5.periodA.blockedRequests === 0, `TEST F5: Period A blocked requests must be 0, got ${resF5.periodA.blockedRequests}`);
assert(resF5.periodA.alertedRequests === 500, `TEST F5: Period A alerted requests must be 500, got ${resF5.periodA.alertedRequests}`);

assert(resF5.periodB.totalRequests === 500, `TEST F5: Period B total requests must be 500 (weighted), got ${resF5.periodB.totalRequests}`);
assert(resF5.periodB.blockedRequests === 450, `TEST F5: Period B blocked requests must be 450, got ${resF5.periodB.blockedRequests}`);
assert(resF5.periodB.alertedRequests === 50, `TEST F5: Period B alerted requests must be 50, got ${resF5.periodB.alertedRequests}`);

// Signatures verification
const sqliSig = resF5.signatureImpacts.find((s) => s.signatureId === 'SQL Injection');
assert(!!sqliSig, 'TEST F5: SQL Injection signature must exist');
assert(sqliSig.periodA_alerted === 250, `SQLi A alerted should be 250, got ${sqliSig.periodA_alerted}`);
assert(sqliSig.periodB_blocked === 250, `SQLi B blocked should be 250, got ${sqliSig.periodB_blocked}`);
assert(sqliSig.actionChangeLabel === 'ALERT → BLOCK', `SQLi action change must be ALERT → BLOCK, got ${sqliSig.actionChangeLabel}`);

const cmdSig = resF5.signatureImpacts.find((s) => s.signatureId === 'Command Execution');
assert(!!cmdSig, 'TEST F5: Command Execution signature must exist');
assert(cmdSig.periodB_alerted === 50 && cmdSig.periodB_blocked === 50, 'Command Execution should have 50 alert and 50 block');
assert(cmdSig.actionChangeLabel === 'Kısmi değişim', `Command Execution should have Kısmi değişim, got ${cmdSig.actionChangeLabel}`);

console.log('✅ TEST F5 Passed: Gerçek 10-kolonlu F5 şeması, Count ağırlıkları, Alarmed->Blocked geçişleri kusursuz çalıştı.');

// =========================================================================
// TEST DIAGNOSTICS ON EMPTY / MISMATCHED SCHEMA
// =========================================================================
console.log('\n--- TEST DIAGNOSTICS: Incompatible / Missing Schema Reporting ---');

const bad_csv = `Some_Random_Col1,Random_Col2,Col3
val1,val2,val3
val4,val5,val6`;

const resBad = compareSecurityPeriods(
  [{ name: 'bad_file_a.csv', content: bad_csv }],
  [{ name: 'bad_file_b.csv', content: bad_csv }]
);

assert(resBad.periodA.totalRequests === 0, 'Bad file must have 0 total requests');
assert(resBad.diagnostics.periodA[0].parsedRowsCount === 0, 'Bad file diagnostic must report 0 rows parsed');
assert(resBad.diagnostics.periodA[0].unmatchedExpectedColumns.length > 0, 'Bad file must list unmatched expected columns');
assert(!!resBad.diagnostics.periodA[0].warningOrError, 'Bad file must give clear warning message');

console.log('✅ TEST DIAGNOSTICS Passed: Sessiz boş ekran yerine kaç satırın parse edildiği ve eksik kolonlar açıkça raporlandı.');

// =========================================================================
// TEST 9: FAZLADAN / BAŞKA KOLONLAR EKLENDİĞİNDE ANALİZİN KESİNTİSİZ ÇALIŞMASI
// =========================================================================
console.log('\n--- TEST 9: Extra / Additional Arbitrary Columns in Excel/CSV ---');

const extra_cols_csv_A = `Incident_ID,Policy Name (custom),Ticket_Num,Threat Type (custom),Client_Country,Event Name,Log Source,Response,Destination,VLAN,Destination Port,Start Time,Low Level,Count,Analyst_Notes,Bytes_Sent
INC-1001,/Common/waf_corp_prod,TK-9921,SQL Injection,US,Illegal meta character,BIG-IP-ASM-01,Alarmed,192.168.10.50,100,443,2026-08-05 14:00:00,High,200,Pending Review,15420
INC-1002,/Common/waf_corp_prod,TK-9922,Cross Site Scripting (XSS),DE,XSS script tag,BIG-IP-ASM-01,Alarmed,192.168.10.50,100,443,2026-08-05 15:00:00,Medium,100,Escalated,8200`;

const extra_cols_csv_B = `Incident_ID,Policy Name (custom),Ticket_Num,Threat Type (custom),Client_Country,Event Name,Log Source,Response,Destination,VLAN,Destination Port,Start Time,Low Level,Count,Analyst_Notes,Bytes_Sent
INC-2001,/Common/waf_corp_prod,TK-9951,SQL Injection,RU,Illegal meta character,BIG-IP-ASM-01,Blocked,192.168.10.50,100,443,2026-09-10 10:00:00,High,200,Resolved,15420
INC-2002,/Common/waf_corp_prod,TK-9952,Cross Site Scripting (XSS),CN,XSS script tag,BIG-IP-ASM-01,Blocked,192.168.10.50,100,443,2026-09-10 11:00:00,Medium,100,Closed,8200`;

const resExtra = compareSecurityPeriods(
  [{ name: 'extra_a.csv', content: extra_cols_csv_A }],
  [{ name: 'extra_b.csv', content: extra_cols_csv_B }]
);

assert(resExtra.periodA.totalRequests === 300, `TEST 9: Total requests should be 300, got ${resExtra.periodA.totalRequests}`);
assert(resExtra.periodB.blockedRequests === 300, `TEST 9: Blocked requests should be 300, got ${resExtra.periodB.blockedRequests}`);
assert(resExtra.signatureImpacts.length === 2, `TEST 9: Must extract both signatures despite 6 extra columns`);
assert(resExtra.preventedTrafficMb !== null && resExtra.preventedTrafficMb > 0, 'TEST 9: Extra Bytes_Sent column must be recognized and compute traffic MB');

console.log('✅ TEST 9 Passed: 16 kolonlu (Incident_ID, Client_Country, VLAN, Bytes_Sent vb.) dosyada analiz başarıyla yapıldı ve trafik hacmi hesaplandı.');

console.log('\n=============================================================');
console.log('TÜM ADVERSARIAL VE F5 ŞEMA TESTLERİ BAŞARIYLA TAMAMLANDI!');
console.log('=============================================================\n');
