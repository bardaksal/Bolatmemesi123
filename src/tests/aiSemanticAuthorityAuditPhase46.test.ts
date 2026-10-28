import assert from 'assert';
import { runAiSemanticLogPipeline } from '../services/aiSemanticLogEngine';
import { runAiLogUnderstandingPipeline } from '../services/aiLogUnderstandingEngine';
import { segmentRawTextIntoEventsWithDiagnostics } from '../services/quickTriageHelper';

console.log('================================================================');
console.log('⚡ PHASE 4.6 — AI SEMANTIC AUTHORITY AUDIT & ENGINE HARDENING ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: SSH FAILED PASSWORD & CONNECTION CLOSED BY INVALID USER
// -----------------------------------------------------------------------------
console.log('\n--- 1. SSH Telemetrisi: ASLA Security-Device DENY/BLOCK Üretmeme Testi ---');

const sshFailedLog = 'Oct 18 10:14:22 srv-prod sshd[18422]: Failed password for invalid user oracle from 198.51.100.44 port 44122 ssh2';
const sshClosedLog = 'Oct 18 10:14:23 srv-prod sshd[18422]: Connection closed by invalid user oracle 198.51.100.44 port 44122 [preauth]';

const sshFailedRes = await runAiSemanticLogPipeline({ rawInput: sshFailedLog });
const sshClosedRes = await runAiSemanticLogPipeline({ rawInput: sshClosedLog });

assert.strictEqual(sshFailedRes.deterministicDecisions.length, 1);
const sshFailedDec = sshFailedRes.deterministicDecisions[0];
assert.notStrictEqual(
  sshFailedDec.verdict,
  'BLOCKED_ATTACK_ATTEMPT',
  'Test 1.1: SSH Failed password ASLA BLOCKED_ATTACK_ATTEMPT olmamalıdır'
);
assert(
  !sshFailedDec.summaryReason.includes('Güvenlik cihazı engelleme kararı uygulamıştır'),
  'Test 1.2: SSH Failed password için güvenlik cihazı engelleme kararı iddia edilemez'
);
assert.strictEqual(sshFailedDec.isBlocked, false, 'Test 1.3: SSH Failed password isBlocked = false olmalıdır');

const sshClosedDec = sshClosedRes.deterministicDecisions[0];
assert.notStrictEqual(
  sshClosedDec.verdict,
  'BLOCKED_ATTACK_ATTEMPT',
  'Test 1.4: SSH Connection closed ASLA BLOCKED_ATTACK_ATTEMPT olmamalıdır'
);
assert.strictEqual(sshClosedDec.isBlocked, false, 'Test 1.5: SSH Connection closed isBlocked = false olmalıdır');
console.log('  ✅ [PASS] SSH Failed password ve Connection closed -> isBlocked = false, Güvenlik Cihazı DENY/BLOCK Üretilmedi.');

// -----------------------------------------------------------------------------
// TEST 2: HTTP 401 & 403 ALONE ARE NEVER WAF BLOCKS
// -----------------------------------------------------------------------------
console.log('\n--- 2. HTTP 401 & 403: Tek Başına WAF Block/Deny Olmadığını Doğrulama ---');

const http401Log = '10.0.0.5 - - [18/Oct/2026:10:00:00 +0000] "GET /api/v1/user/profile HTTP/1.1" 401 89';
const http403Log = '10.0.0.5 - - [18/Oct/2026:10:00:00 +0000] "GET /admin/dashboard HTTP/1.1" 403 145';

const http401Res = await runAiSemanticLogPipeline({ rawInput: http401Log });
const http403Res = await runAiSemanticLogPipeline({ rawInput: http403Log });

const dec401 = http401Res.deterministicDecisions[0];
assert.strictEqual(dec401.isBlocked, false, 'Test 2.1: HTTP 401 isBlocked = false olmalıdır');
assert.notStrictEqual(dec401.verdict, 'BLOCKED_ATTACK_ATTEMPT', 'Test 2.2: HTTP 401 ASLA BLOCKED_ATTACK_ATTEMPT değildir');

const dec403 = http403Res.deterministicDecisions[0];
assert.strictEqual(dec403.isBlocked, false, 'Test 2.3: HTTP 403 tek başına isBlocked = false olmalıdır');
assert.notStrictEqual(dec403.verdict, 'BLOCKED_ATTACK_ATTEMPT', 'Test 2.4: HTTP 403 tek başına BLOCKED_ATTACK_ATTEMPT değildir');
console.log('  ✅ [PASS] HTTP 401 ve 403 tek başına -> isBlocked = false, WAF Block Kararı Üretilmedi.');

// -----------------------------------------------------------------------------
// TEST 3: POSTFIX / SMTPD SASL AUTHENTICATION FAILED
// -----------------------------------------------------------------------------
console.log('\n--- 3. Postfix SASL Auth Failure: Güvenlik Cihazı Block Değildir ---');

const postfixLog = 'Oct 18 10:14:25 mail-gw postfix/smtpd[28114]: warning: unknown[198.51.100.99]: SASL LOGIN authentication failed: UGFzc3dvcmQ6';
const postfixRes = await runAiSemanticLogPipeline({ rawInput: postfixLog });

assert.strictEqual(postfixRes.deterministicDecisions.length, 1);
const postfixDec = postfixRes.deterministicDecisions[0];
assert.strictEqual(postfixDec.isBlocked, false, 'Test 3.1: Postfix SASL failure isBlocked = false olmalıdır');
assert.notStrictEqual(
  postfixDec.verdict,
  'BLOCKED_ATTACK_ATTEMPT',
  'Test 3.2: Postfix SASL failure ASLA BLOCKED_ATTACK_ATTEMPT olmamalıdır'
);
assert(
  !postfixDec.summaryReason.includes('Güvenlik cihazı engelleme kararı uygulamıştır'),
  'Test 3.3: Postfix SASL failure için güvenlik cihazı engellemesi iddia edilemez'
);
console.log('  ✅ [PASS] Postfix SASL failure -> isBlocked = false, E-posta kimlik doğrulama reddi doğru sınıflandırıldı.');

// -----------------------------------------------------------------------------
// TEST 4: SYSMON EVENT ID 1 & SYSTEMD EVENT BOUNDARY ISOLATION
// -----------------------------------------------------------------------------
console.log('\n--- 4. Sysmon Event ID 1 ile systemd/nginx Olay Sınırı İzolasyonu ---');

const mixedSysmonAndSystemd = `Microsoft-Windows-Sysmon: [1] Process Create. User: system, Image: C:\\Windows\\System32\\cmd.exe, CommandLine: cmd.exe /c echo hi, ParentImage: C:\\Windows\\explorer.exe
systemd[1]: nginx.service: Deactivated successfully.
systemd[1]: nginx.service: Activated.`;

const diag = segmentRawTextIntoEventsWithDiagnostics(mixedSysmonAndSystemd);

assert.strictEqual(
  diag.eventBoundaries.length,
  3,
  `Test 4.1: Sysmon ve 2 adet systemd satırı toplam 3 ayrı olaya ayrılmalıdır (Bulunan: ${diag.eventBoundaries.length})`
);

const sysmonEv = diag.eventBoundaries[0];
assert(
  !sysmonEv.rawText.includes('systemd') && !sysmonEv.rawText.includes('nginx.service'),
  'Test 4.2: Sysmon Event 1 içine systemd satırları KESİNLİKLE sızmamalıdır'
);
assert.strictEqual(sysmonEv.hasCrossEventContamination, false, 'Test 4.3: Sysmon olayı kontaminasyonsuz olmalıdır');
console.log('  ✅ [PASS] Sysmon Event 1 ile systemd/nginx satırları kesin olay sınırlarıyla izole edildi (3 ayrı event).');

// -----------------------------------------------------------------------------
// TEST 5: NGINX COMBINED LOG ALAN AYRIŞTIRMASI & HOST/URI ATIFLARI
// -----------------------------------------------------------------------------
console.log('\n--- 5. Nginx Combined Log: Semantik Doğru Alan Eşleştirmesi ---');

const nginxCombinedLog = 'web-03 nginx: 10.44.8.21 - - [18/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"';
const nginxRes = await runAiSemanticLogPipeline({ rawInput: nginxCombinedLog });

assert.strictEqual(nginxRes.deterministicDecisions.length, 1);
const nginxEv = nginxRes.universalEvidences[0];

assert.strictEqual(nginxEv.sourceEndpoint.ip.value, '10.44.8.21', 'Test 5.1: Kaynak IP = 10.44.8.21 olmalıdır');
assert.strictEqual(nginxEv.destinationEndpoint.host.value, 'web-03', 'Test 5.2: Hedef Host = web-03 olmalıdır');
assert.strictEqual(nginxEv.telemetry.rawPayload.value, '/index.html', 'Test 5.3: URI = /index.html olmalıdır');
assert.strictEqual(nginxEv.process.commandLine.status, 'NOT_PRESENT', 'Test 5.4: HTTP isteği için CommandLine NOT_PRESENT olmalıdır');

const correlatedNginx = nginxRes.secondaryCorrelation;
console.log('  ✅ [PASS] Nginx Combined: Source IP = 10.44.8.21, Host = web-03, URI = /index.html, CommandLine = NOT_PRESENT.');

// -----------------------------------------------------------------------------
// TEST 6: CEF ACTION=DENY / OUTCOME=BLOCKED -> VERIFIED SECURITY DEVICE ACTION
// -----------------------------------------------------------------------------
console.log('\n--- 6. CEF action=deny: Güvenlik Cihazı Aksiyonu Olarak Kabul Edilme ---');

const cefBlockLog = 'CEF:0|Fortinet|FortiGate|6.4|100|Drop packet|8|src=198.51.100.50 dst=10.0.0.1 act=deny msg="IPS Drop"';
const cefRes = await runAiSemanticLogPipeline({ rawInput: cefBlockLog });

const cefDec = cefRes.deterministicDecisions[0];
assert.strictEqual(cefDec.isBlocked, true, 'Test 6.1: CEF act=deny için isBlocked = true olmalıdır');
assert.strictEqual(cefDec.verdict, 'BLOCKED_ATTACK_ATTEMPT', 'Test 6.2: CEF act=deny için BLOCKED_ATTACK_ATTEMPT üretilmelidir');
console.log('  ✅ [PASS] CEF act=deny -> isBlocked = true, BLOCKED_ATTACK_ATTEMPT doğrulandı.');

// -----------------------------------------------------------------------------
// TEST 7: AYNI SOURCE IP FARKLI HOSTLARDA = ASLA OTOMATİK LATERAL MOVEMENT DEĞİL
// -----------------------------------------------------------------------------
console.log('\n--- 7. Aynı Kaynak IP Farklı Hostlarda: Lateral Movement / Network Sweep Etiketi Engeli ---');

const multiHostTraffic = `10.44.8.21 - - [18/Oct/2026:10:00:00 +0000] "GET /app1 HTTP/1.1" 200 100 host=web-01
10.44.8.21 - - [18/Oct/2026:10:01:00 +0000] "GET /app2 HTTP/1.1" 200 120 host=web-02`;

const multiHostRes = await runAiSemanticLogPipeline({ rawInput: multiHostTraffic });
const incidents = multiHostRes.secondaryCorrelation?.incidentCandidates || [];

for (const inc of incidents) {
  for (const evStr of inc.correlationEvidence) {
    assert(
      !evStr.includes('(Lateral Movement / Network Sweep)'),
      'Test 7.1: Çoklu host erişimi tek başına "Lateral Movement / Network Sweep" olarak etiketlenemez'
    );
  }
}
console.log('  ✅ [PASS] Çoklu hedef erişiminde peşin Lateral Movement / Network Sweep etiketi üretilmedi.');

// -----------------------------------------------------------------------------
// TEST 8: TIMESTAMP YOKSA CHRONOLOGICAL CORRELATION YAPILAMAZ
// -----------------------------------------------------------------------------
console.log('\n--- 8. Zaman Damgası Yoksa Kronolojik Korelasyon Yapmama Testi ---');

const noTimestampProcessAndClear = `Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: admin, New Process Name: C:\\Windows\\System32\\wevtutil.exe, Process Command Line: wevtutil.exe cl Security, Computer: SRV-APP01
Microsoft-Windows-Security-Auditing: [1102] The audit log was cleared. Subject: Security ID: S-1-5-18, Account Name: admin, Computer: SRV-APP01`;

const noTimeRes = await runAiSemanticLogPipeline({ rawInput: noTimestampProcessAndClear });
const noTimeIncidents = noTimeRes.secondaryCorrelation?.incidentCandidates || [];

for (const inc of noTimeIncidents) {
  for (const ev of inc.correlationEvidence) {
    assert(
      !ev.includes('Security audit log cleared following process execution'),
      'Test 8.1: Zaman damgası olmayan olaylar arasında kronolojik execution -> clear zinciri kurulamaz'
    );
  }
}
console.log('  ✅ [PASS] Zaman damgası olmayan olaylar için kronolojik korelasyon engellendi.');

// -----------------------------------------------------------------------------
// TEST 9: AI UNKNOWN ALANLAR TAHMİN EDİLEMEZ
// -----------------------------------------------------------------------------
console.log('\n--- 9. AI Tarafından Bilinmeyen Alanlar Tahmin Edilerek Doldurulamaz ---');

const unknownLog = 'CUSTOM_SERVICE_LOG: ID=9941 client=10.10.10.10 request_token="XYZ"';
const unknownRes = await runAiSemanticLogPipeline({ rawInput: unknownLog });
const unknownEvidence = unknownRes.universalEvidences[0];

assert.strictEqual(
  unknownEvidence.process.commandLine.status,
  'NOT_PRESENT',
  'Test 9.1: Logda olmayan CommandLine alanı NOT_PRESENT olmalı, tahmin edilmemelidir'
);
assert.strictEqual(
  unknownEvidence.actor.status,
  'NOT_PRESENT',
  'Test 9.2: Logda olmayan Kullanıcı adı NOT_PRESENT olmalı, tahmin edilmemelidir'
);
console.log('  ✅ [PASS] Bilinmeyen alanlar NOT_PRESENT olarak korundu, tahmin edilmedi.');

// -----------------------------------------------------------------------------
// TEST 10: RAPOR BÜTÜNLÜĞÜ: RAW LINES COUNT TUTARLILIĞI
// -----------------------------------------------------------------------------
console.log('\n--- 10. Rapor Bütünlüğü: Raw Lines Sayımı Birebir Tutarlılık Testi ---');

const rawStreamWithBlanks = `Line 1
Line 2

Line 4
Line 5

Line 7`;

const totalExpectedLines = rawStreamWithBlanks.split(/\r?\n/).length;
const diagReport = segmentRawTextIntoEventsWithDiagnostics(rawStreamWithBlanks);
const pipelineRes = await runAiSemanticLogPipeline({ rawInput: rawStreamWithBlanks });

assert.strictEqual(
  pipelineRes.rawLinesCount,
  diagReport.rawLinesCount,
  `Test 10.1: Pipeline rawLinesCount (${pipelineRes.rawLinesCount}) ile Parser Diagnostic rawLinesCount (${diagReport.rawLinesCount}) birebir eşit olmalıdır!`
);
assert.strictEqual(
  pipelineRes.rawLinesCount,
  totalExpectedLines,
  `Test 10.2: Toplam ham satır sayısı (${totalExpectedLines}) ile raporlanan (${pipelineRes.rawLinesCount}) tam eşleşmelidir!`
);
console.log(`  ✅ [PASS] Ham satır sayıları tam tutarlı: Pipeline = ${pipelineRes.rawLinesCount}, Parser Diagnostic = ${diagReport.rawLinesCount}.`);

// -----------------------------------------------------------------------------
// TEST 11: ZORUNLU PROVENANCE ZİNCİRİ
// FINAL DECISION → EVIDENCE → SEMANTIC INTERPRETATION → RAW SPAN
// -----------------------------------------------------------------------------
console.log('\n--- 11. Zorunlu Provenance Zinciri Doğrulaması ---');

for (const dec of sshFailedRes.deterministicDecisions) {
  const hasProvenance = dec.deepForensics.some((f) => f.includes('PROVENANCE: FINAL DECISION'));
  assert(hasProvenance, 'Test 11.1: SSH kararı PROVENANCE zinciri içermelidir');
}

for (const dec of postfixRes.deterministicDecisions) {
  const hasProvenance = dec.deepForensics.some((f) => f.includes('PROVENANCE: FINAL DECISION'));
  assert(hasProvenance, 'Test 11.2: Postfix kararı PROVENANCE zinciri içermelidir');
}
console.log('  ✅ [PASS] Her kararın zorunlu PROVENANCE zinciri başarıyla doğrulandı.');

console.log('\n================================================================');
console.log('🎉 TÜM PHASE 4.6 AI SEMANTIC AUTHORITY AUDIT TESTLERİ BAŞARIYLA GEÇTİ! 🎉');
console.log('================================================================');
