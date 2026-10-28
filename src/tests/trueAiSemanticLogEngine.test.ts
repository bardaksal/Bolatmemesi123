import assert from 'assert';
import {
  analyzeSemanticLogLocally,
  runAiSemanticLogPipeline,
} from '../services/aiSemanticLogEngine';
import { validateAiLogStructure } from '../services/rawSpanValidator';
import { convertSemanticToStructureResponse } from '../services/aiSemanticLogEngine';

console.log('================================================================');
console.log('⚡ PHASE 4.5 — TRUE AI LOG ANALYSIS ENGINE TEST SUITE ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: FORMAT GENERALIZATION — 16 FARKLI LOG FORMATI (SIFIR YENİ REGEX/PARSER)
// -----------------------------------------------------------------------------
console.log('\n--- 1. Format Generalization Test: 16 Farklı Format Tek Bir Motorda ---');

const sixteenFormats: Array<{
  name: string;
  rawLog: string;
  minRecords: number;
  expectedVendor: string;
  expectedFieldTypes: string[];
}> = [
  // 1. Windows Security
  {
    name: 'Windows Security',
    rawLog:
      'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: administrator, Computer: SRV-DC01, Logon Type: 10, Source Network Address: 10.0.0.5',
    minRecords: 1,
    expectedVendor: 'Microsoft-Windows-Security-Auditing',
    expectedFieldTypes: ['EVENT_ID', 'ACTOR_USER', 'HOST', 'SOURCE_ENDPOINT'],
  },
  // 2. Sysmon
  {
    name: 'Sysmon',
    rawLog:
      'Microsoft-Windows-Sysmon: [1] Process Create. User: system, Image: C:\\Windows\\System32\\cmd.exe, CommandLine: cmd.exe /c whoami, ParentImage: C:\\Windows\\explorer.exe',
    minRecords: 1,
    expectedVendor: 'Microsoft-Windows-Sysmon',
    expectedFieldTypes: ['EVENT_ID', 'PROCESS', 'COMMAND_LINE', 'PARENT_PROCESS'],
  },
  // 3. Linux sshd
  {
    name: 'Linux sshd',
    rawLog:
      'Oct 18 10:14:22 srv-prod sshd[18422]: Failed password for invalid user oracle from 198.51.100.44 port 44122 ssh2',
    minRecords: 1,
    expectedVendor: 'OpenSSH Server',
    expectedFieldTypes: ['ACTOR_USER', 'SOURCE_ENDPOINT', 'SOURCE_PORT'],
  },
  // 4. sudo
  {
    name: 'sudo',
    rawLog:
      'Oct 18 10:15:00 srv-prod sudo: tekin : TTY=pts/0 ; PWD=/home/tekin ; USER=root ; COMMAND=/bin/cat /etc/shadow',
    minRecords: 1,
    expectedVendor: 'Linux System',
    expectedFieldTypes: ['ACTOR_USER', 'COMMAND_LINE'],
  },
  // 5. Apache
  {
    name: 'Apache',
    rawLog:
      '192.168.1.100 - user_a [18/Oct/2026:10:00:00 +0300] "GET /index.html HTTP/1.1" 200 4523',
    minRecords: 1,
    expectedVendor: 'Apache HTTP Server',
    expectedFieldTypes: ['SOURCE_ENDPOINT', 'HTTP_METHOD', 'HTTP_REQUEST_URI', 'HTTP_STATUS'],
  },
  // 6. Nginx
  {
    name: 'Nginx',
    rawLog:
      'nginx: 10.20.30.40 - - [18/Oct/2026:10:01:00 +0000] "POST /api/v1/auth HTTP/1.1" 200 120 "-" "curl/7.88.1"',
    minRecords: 1,
    expectedVendor: 'Nginx Web Server',
    expectedFieldTypes: ['SOURCE_ENDPOINT', 'HTTP_METHOD', 'HTTP_REQUEST_URI', 'HTTP_STATUS'],
  },
  // 7. IIS
  {
    name: 'IIS',
    rawLog:
      '2026-10-18 10:00:00 192.168.1.50 GET /app/default.aspx - 80 - 10.20.40.10 Mozilla/5.0 200 0 0 15',
    minRecords: 1,
    expectedVendor: 'Microsoft IIS Web Server',
    expectedFieldTypes: ['HTTP_METHOD', 'HTTP_REQUEST_URI', 'HTTP_STATUS'],
  },
  // 8. CEF
  {
    name: 'CEF',
    rawLog:
      'CEF:0|SecurityVendor|Firewall|1.0|100|Drop packet|5|src=185.123.105.51 dst=10.0.0.1 spt=44122 dpt=443 act=drop msg=SynFlood',
    minRecords: 1,
    expectedVendor: 'CEF Telemetry Device',
    expectedFieldTypes: ['SOURCE_ENDPOINT', 'DESTINATION_ENDPOINT'],
  },
  // 9. LEEF
  {
    name: 'LEEF',
    rawLog:
      'LEEF:1.0|Vendor|IPS|2.0|Alert|src=10.0.0.5 dst=10.0.0.100 sev=6 msg=SuspiciousPayload',
    minRecords: 1,
    expectedVendor: 'LEEF Telemetry Device',
    expectedFieldTypes: ['SOURCE_ENDPOINT', 'DESTINATION_ENDPOINT'],
  },
  // 10. JSON
  {
    name: 'JSON',
    rawLog:
      '{"timestamp":"2026-10-18T10:00:00Z","user":"alice","action":"login","ip":"192.168.1.50","outcome":"SUCCESS"}',
    minRecords: 1,
    expectedVendor: 'JSON Structured Log',
    expectedFieldTypes: ['TIMESTAMP', 'ACTOR_USER', 'SOURCE_ENDPOINT'],
  },
  // 11. key=value
  {
    name: 'key=value',
    rawLog:
      'timestamp=2026-10-18T10:00:00Z src=10.0.0.1 user=sec_admin action=modify_policy status=success',
    minRecords: 1,
    expectedVendor: 'Key-Value Telemetry',
    expectedFieldTypes: ['TIMESTAMP', 'SOURCE_ENDPOINT', 'ACTOR_USER'],
  },
  // 12. Fortinet
  {
    name: 'Fortinet',
    rawLog:
      'date=2026-10-18 time=10:00:00 devname="FG-CORP" type=traffic subtype=forward action=deny srcip=198.51.100.50 dstip=10.0.0.1 service=HTTPS msg="Policy violation"',
    minRecords: 1,
    expectedVendor: 'Fortinet',
    expectedFieldTypes: ['SECURITY_DEVICE_ACTION', 'SOURCE_ENDPOINT'],
  },
  // 13. WAF
  {
    name: 'WAF',
    rawLog:
      'CEF:0|F5|BIG-IP ASM|15.1.0|WAF_BLOCK|Attack Blocked|10|src=185.123.105.51 dst=10.20.1.5 act=blocked msg="Path Traversal detected"',
    minRecords: 1,
    expectedVendor: 'F5 WAF / Security Gateway',
    expectedFieldTypes: ['SECURITY_DEVICE_ACTION', 'SOURCE_ENDPOINT'],
  },
  // 14. Custom application log
  {
    name: 'custom application log',
    rawLog:
      '[2026-10-18 10:20:00] [AuthService] [WARN] user=mehmet.y ip=172.16.5.20 message="Invalid MFA code entered"',
    minRecords: 1,
    expectedVendor: 'Generic/Unknown',
    expectedFieldTypes: ['ACTOR_USER', 'SOURCE_ENDPOINT'],
  },
  // 15. Multiline application log
  {
    name: 'multiline application log',
    rawLog: `2026-10-18 10:05:00 ERROR [com.corp.BillingService] Transaction failed for user=ayse
java.lang.NullPointerException: Object reference not set
\tat com.corp.BillingService.process(BillingService.java:88)
\tat com.corp.BillingController.checkout(BillingController.java:32)`,
    minRecords: 1,
    expectedVendor: 'Generic/Unknown',
    expectedFieldTypes: ['ACTOR_USER'],
  },
  // 16. Tamamen bilinmeyen log
  {
    name: 'tamamen bilinmeyen log',
    rawLog: '2026/10/18-10:30:00 ID=99988 XYZ_TOKEN="alpha-beta" SENDER="agent-007" STATUS="active"',
    minRecords: 1,
    expectedVendor: 'Generic/Unknown',
    expectedFieldTypes: ['UNKNOWN_FIELD'],
  },
];

for (const tf of sixteenFormats) {
  const parsed = analyzeSemanticLogLocally(tf.rawLog);
  assert(
    parsed.records.length >= tf.minRecords,
    `Format [${tf.name}]: En az ${tf.minRecords} logical event çıkarılmalıdır (Çıkan: ${parsed.records.length})`
  );

  const event = parsed.records[0];
  if (tf.expectedVendor === 'Generic/Unknown') {
    assert(
      event.logFormatAndVendor.vendorOrSource === 'Generic/Unknown' ||
        event.logFormatAndVendor.vendorOrSource === 'Key-Value Telemetry',
      `Format [${tf.name}]: Vendor Generic/Unknown veya Key-Value Telemetry olmalı (Bulunan: '${event.logFormatAndVendor.vendorOrSource}')`
    );
  } else {
    assert.strictEqual(
      event.logFormatAndVendor.vendorOrSource,
      tf.expectedVendor,
      `Format [${tf.name}]: Vendor '${tf.expectedVendor}' olmalı (Bulunan: '${event.logFormatAndVendor.vendorOrSource}')`
    );
  }

  // Verify that required semantic field types are extracted
  const extractedTypes = new Set(event.fields.map((f) => f.semanticType));
  for (const reqType of tf.expectedFieldTypes) {
    assert(
      extractedTypes.has(reqType as any),
      `Format [${tf.name}]: Gerekli semantik tip '${reqType}' çıkarılmalıdır.`
    );
  }

  // Verify raw-span precision
  for (const rec of parsed.records) {
    const slice = tf.rawLog.slice(rec.rawStart, rec.rawEnd);
    assert.strictEqual(
      slice,
      rec.rawText,
      `Format [${tf.name}]: rawStart/rawEnd span'ı rawText ile birebir örtüşmeli.`
    );
  }

  console.log(`  ✅ [${tf.name}] (${event.logFormatAndVendor.vendorOrSource}): ${parsed.records.length} olay, semantik tipler ve raw-span doğrulandı.`);
}

console.log('✅ 16 Farklı Log Formatı Sıfır Yeni Regex/Parser ile Başarıyla Ayrıştırıldı!');

// -----------------------------------------------------------------------------
// TEST 2: KRİTİK SEMANTİK BAĞLAM AYRIMLARI (CONTEXTUAL DISAMBIGUATION)
// -----------------------------------------------------------------------------
console.log('\n--- 2. Kritik Semantik Bağlam Ayrımları (Contextual Disambiguation) ---');

// 2.1: SSH "Connection closed by invalid user" -> NOT a Security Device Deny!
console.log('\n  • 2.1: SSH "Connection closed by invalid user" Testi');
const sshRaw = 'Oct 18 10:14:22 srv-prod sshd[18422]: Connection closed by invalid user admin 198.51.100.44 port 44122 [preauth]';
const sshResult = analyzeSemanticLogLocally(sshRaw);
const sshEvent = sshResult.records[0];

assert.strictEqual(
  sshEvent.logFormatAndVendor.isSecurityDevice,
  false,
  'Test 2.1.1: OpenSSH sunucusu ASLA güvenlik cihazı (Firewall/WAF) sayılmamalıdır'
);

const sshSecDevAction = sshEvent.fields.find((f) => f.semanticType === 'SECURITY_DEVICE_ACTION');
assert(
  !sshSecDevAction || sshSecDevAction.status === 'NOT_PRESENT',
  'Test 2.1.2: SSH logunda SECURITY_DEVICE_ACTION alanı NOT_PRESENT olmalı, ASLA Firewall/WAF block olmamalıdır'
);

const sshAuthOutcome = sshEvent.fields.find((f) => f.semanticType === 'AUTHENTICATION_OUTCOME');
assert(
  sshAuthOutcome !== undefined && sshAuthOutcome.value === 'FAILURE',
  'Test 2.1.3: SSH logunda AUTHENTICATION_OUTCOME = FAILURE olmalıdır'
);
console.log('    ✅ SSH "Connection closed" -> SECURITY_DEVICE_ACTION = NOT_PRESENT, AUTHENTICATION_OUTCOME = FAILURE');

// 2.2: Fortinet / WAF "BLOCK / DENY / DROP" -> Security Device Action
console.log('\n  • 2.2: Fortinet / WAF "BLOCK / DENY / DROP" Testi');
const fortinetRaw = 'date=2026-10-18 time=10:00:00 devname="FG-CORP" type=traffic action=deny srcip=198.51.100.50 dstip=10.0.0.1';
const fortiResult = analyzeSemanticLogLocally(fortinetRaw);
const fortiEvent = fortiResult.records[0];

assert.strictEqual(
  fortiEvent.logFormatAndVendor.isSecurityDevice,
  true,
  'Test 2.2.1: Fortinet telemetrisi isSecurityDevice = true olmalıdır'
);

const fortiSecDevAction = fortiEvent.fields.find((f) => f.semanticType === 'SECURITY_DEVICE_ACTION');
assert(
  fortiSecDevAction !== undefined && fortiSecDevAction.value.toUpperCase() === 'DENY',
  'Test 2.2.2: Fortinet SECURITY_DEVICE_ACTION = DENY olmalıdır'
);
console.log('    ✅ Fortinet telemetrisi -> isSecurityDevice = true, SECURITY_DEVICE_ACTION = DENY');

// 2.3: HTTP 403 alone -> NOT a WAF Block!
console.log('\n  • 2.3: HTTP 403 Tek Başına WAF Block Değildir Testi');
const http403Raw = '192.168.1.100 - - [18/Oct/2026:10:00:00 +0300] "GET /private/secret.pdf HTTP/1.1" 403 245';
const http403Result = analyzeSemanticLogLocally(http403Raw);
const http403Event = http403Result.records[0];

const httpStatusField = http403Event.fields.find((f) => f.semanticType === 'HTTP_STATUS');
assert.strictEqual(
  httpStatusField?.value,
  '403',
  'Test 2.3.1: HTTP_STATUS = 403 olmalıdır'
);

const httpSecDevAction = http403Event.fields.find((f) => f.semanticType === 'SECURITY_DEVICE_ACTION');
assert(
  !httpSecDevAction || httpSecDevAction.status === 'NOT_PRESENT',
  'Test 2.3.2: HTTP 403 tek başına WAF BLOCK DEĞİLDİR (SECURITY_DEVICE_ACTION NOT_PRESENT olmalıdır)'
);
console.log('    ✅ HTTP 403 tek başına -> HTTP_STATUS = 403, SECURITY_DEVICE_ACTION = NOT_PRESENT (WAF Block Sayılmadı)');

// 2.4: "GET /cgi-bin/../../etc/passwd" -> HTTP REQUEST, NEVER CommandLine
console.log('\n  • 2.4: /etc/passwd Path Traversal HTTP İsteği vs CommandLine Testi');
const pathTraversalRaw = '185.123.105.51 - - [18/Oct/2026:10:00:00 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 403 145';
const traversalResult = analyzeSemanticLogLocally(pathTraversalRaw);
const traversalEvent = traversalResult.records[0];

const uriField = traversalEvent.fields.find((f) => f.semanticType === 'HTTP_REQUEST_URI');
assert.strictEqual(
  uriField?.value,
  '/cgi-bin/../../etc/passwd',
  'Test 2.4.1: HTTP_REQUEST_URI = /cgi-bin/../../etc/passwd olmalıdır'
);

const cmdField = traversalEvent.fields.find((f) => f.semanticType === 'COMMAND_LINE');
assert(
  cmdField !== undefined && cmdField.status === 'NOT_PRESENT' && cmdField.value === '',
  'Test 2.4.2: HTTP isteğinde CommandLine KESİNLİKLE NOT_PRESENT olmalı, ASLA komut çalıştırma sayılmamalıdır!'
);

assert(
  traversalEvent.hypothesis !== undefined && traversalEvent.hypothesis.hypothesis === 'PATH_TRAVERSAL_ATTEMPT',
  'Test 2.4.3: Hipotez PATH_TRAVERSAL_ATTEMPT olmalıdır'
);
assert.notStrictEqual(
  traversalEvent.hypothesis?.status,
  'CONFIRMED',
  'Test 2.4.4: 403 alan istek için saldırı başarılı / CONFIRMED iddia edilemez'
);
console.log('    ✅ "GET /cgi-bin/../../etc/passwd" -> HTTP_REQUEST_URI, CommandLine = NOT_PRESENT, Hypothesis = PATH_TRAVERSAL_ATTEMPT (UNCONFIRMED)');

// 2.5: "7045 Service Installation" -> EVENT_TYPE = SERVICE_INSTALLATION, Not automatically Benign
console.log('\n  • 2.5: Event ID 7045 Servis Yükleme & Otomatik Benign Saymama Testi');
const svcRaw = 'System: [7045] A service was installed in the system. Service Name: MaliciousBackdoor, Service File Name: C:\\ProgramData\\CorpTools\\backdoor.exe, Subject User: SYSTEM, Computer: SRV-APP01';
const svcResult = analyzeSemanticLogLocally(svcRaw);
const svcEvent = svcResult.records[0];

assert.strictEqual(
  svcEvent.eventType,
  'SERVICE_INSTALLATION',
  'Test 2.5.1: eventType = SERVICE_INSTALLATION olmalıdır'
);

assert.notStrictEqual(
  svcEvent.verdict,
  'BENIGN',
  'Test 2.5.2: Şüpheli dizindeki 7045 servis yüklemesi OTOMATİK OLARAK BENIGN KABUL EDİLEMEZ'
);
console.log(`    ✅ Event 7045 -> eventType: SERVICE_INSTALLATION, verdict: ${svcEvent.verdict} (Otomatik Benign Değil)`);

console.log('✅ Tüm Kritik Semantik Bağlam Ayrımları Başarıyla Doğrulandı!');

// -----------------------------------------------------------------------------
// TEST 3: PROVENANCE KONTRAKTI & DETERMINISTIK RAW-SPAN VALIDASYONU
// -----------------------------------------------------------------------------
console.log('\n--- 3. Provenance Kontraktı: { field, value, semanticType, status, rawSpan, confidence, evidence } ---');

const complexRaw = 'Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: administrator, SubStatus: 0xC0000064, Source Network Address: 10.20.44.17, Computer: SRV-APP01';
const complexResult = analyzeSemanticLogLocally(complexRaw);
const complexEvent = complexResult.records[0];

for (const f of complexEvent.fields) {
  // Provenance schema contract
  assert(typeof f.field === 'string' && f.field.length > 0, 'Field name must be string');
  assert(typeof f.semanticType === 'string' && f.semanticType.length > 0, 'SemanticType must be string');
  assert(typeof f.status === 'string', 'Status must be string');
  assert(['HIGH', 'MEDIUM', 'LOW'].includes(f.confidence), 'Confidence must be HIGH|MEDIUM|LOW');

  if (f.status === 'OBSERVED') {
    assert(f.rawSpan !== undefined, `OBSERVED field '${f.field}' must have rawSpan`);
    assert(f.value.length > 0, `OBSERVED field '${f.field}' must have value`);
    const spanText = complexEvent.rawText.slice(f.rawSpan.start, f.rawSpan.end);
    assert.strictEqual(
      spanText,
      f.value,
      `Field '${f.field}': rawSpan [${f.rawSpan.start}..${f.rawSpan.end}] must equal field value '${f.value}'`
    );
  }
}

// Check with raw-span validator
const structureResp = convertSemanticToStructureResponse(complexResult);
const valReport = validateAiLogStructure(complexRaw, structureResp);
assert.strictEqual(valReport.hallucinationsDetected, 0, 'Test 3.1: Halüsinasyon 0 olmalı');
assert.strictEqual(valReport.crossEventContaminationsDetected, 0, 'Test 3.2: Çapraz kontaminasyon 0 olmalı');
assert.strictEqual(valReport.acceptedRecordsCount, 1, 'Test 3.3: Kayıt kabul edilmeli');

console.log('✅ Provenance Kontraktı ve Deterministik Raw-Span Validasyonu Başarıyla Doğrulandı!');

// -----------------------------------------------------------------------------
// TEST 4: ADLI HİPOTEZ KONTRAKTI (OBSERVED FACTS -> HYPOTHESIS -> REQUIRED EVIDENCE)
// -----------------------------------------------------------------------------
console.log('\n--- 4. Adli Hipotez Kontraktı: Gözlemlenen Olgulardan Kanıt Durumuna ---');

const blockedWafRaw = 'CEF:0|F5|BIG-IP ASM|15.1.0|WAF_BLOCK|Attack Blocked|10|src=185.123.105.51 dst=10.20.1.5 act=blocked msg="Path Traversal detected" request="GET /cgi-bin/../../etc/passwd HTTP/1.1"';
const pipelineResp = await runAiSemanticLogPipeline({ rawInput: blockedWafRaw });

assert.strictEqual(pipelineResp.pipelineStatus, 'SUCCESS', 'Pipeline başarıyla tamamlanmalı');
assert(pipelineResp.hypotheses.length > 0, 'En az 1 adli hipotez üretilmeli');

const hyp = pipelineResp.hypotheses[0];
assert(hyp.observedFacts.length > 0, 'observedFacts listesi boş olamaz');
assert(hyp.requiredEvidence.length > 0, 'requiredEvidence listesi boş olamaz');
assert.strictEqual(
  hyp.status,
  'BLOCKED_ATTEMPT',
  'WAF tarafından engellenen istek için hipotez durumu BLOCKED_ATTEMPT olmalıdır'
);

console.log(`  • Hipotez: ${hyp.hypothesis}`);
console.log(`  • Durum: ${hyp.status}`);
console.log(`  • Gözlemlenen Olgular: ${hyp.observedFacts.join(', ')}`);
console.log(`  • Gereken Kanıtlar: ${hyp.requiredEvidence.join(', ')}`);
console.log('✅ Adli Hipotez Kontraktı Başarıyla Doğrulandı!');

// -----------------------------------------------------------------------------
// TEST 5: AI ANALİZ BAŞARISIZ OLDUĞUNDA ANALYSIS_INCOMPLETE (ASLA BENIGN UYDURMA)
// -----------------------------------------------------------------------------
console.log('\n--- 5. AI Hata Güvenliği: ANALYSIS_INCOMPLETE & PARSE_NOT_ASSESSED ---');

const emptyRaw = '   ';
const failedResult = await runAiSemanticLogPipeline({ rawInput: emptyRaw });

assert.strictEqual(
  failedResult.pipelineStatus,
  'ANALYSIS_INCOMPLETE',
  'Test 5.1: Boş veya başarısız analiz durumunda pipelineStatus = ANALYSIS_INCOMPLETE olmalıdır'
);

assert(
  failedResult.errorMessage?.includes('PARSE_NOT_ASSESSED'),
  'Test 5.2: Hata mesajında PARSE_NOT_ASSESSED açıkça belirtilmelidir'
);

assert.strictEqual(
  failedResult.universalEvidences.length,
  0,
  'Test 5.3: Başarısız durumda tek olay veya varsayılan BENIGN kaydı uydurulamaz!'
);

console.log('✅ AI Hata Durumunda ANALYSIS_INCOMPLETE Garantisi Doğrulandı!');

// -----------------------------------------------------------------------------
// TEST 6: ZORUNLU PIPELINE SIRALAMASI
// -----------------------------------------------------------------------------
console.log('\n--- 6. Zorunlu Pipeline Sıralaması Doğrulaması ---');
console.log('  1. RAW INPUT');
console.log('  2. AI LOG UNDERSTANDING');
console.log('  3. AI SEMANTIC EVENT ANALYSIS');
console.log('  4. UNIVERSAL EVIDENCE');
console.log('  5. RAW-SPAN VALIDATION');
console.log('  6. FORENSIC REASONING');
console.log('  7. CORRELATION');
console.log('  8. FINAL DECISION');

const multiEventAudit = `Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Task Category: Logon
Computer:      SRV-APP01
Account Name:  administrator
SubStatus:     0xC0000064
Source Network Address: 10.20.44.17

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4624
Task Category: Logon
Computer:      SRV-APP01
Account Name:  administrator
Logon Type:    10
Source Network Address: 10.20.44.17`;

const multiResult = await runAiSemanticLogPipeline({ rawInput: multiEventAudit });

// 1. Raw Input
assert(multiResult.rawInput.length > 0, 'Step 1: RAW INPUT mevcut');
// 2 & 3. AI Log Understanding & Semantic Event Analysis
assert.strictEqual(multiResult.aiResponse.records.length, 2, 'Step 2 & 3: 2 logical event çıkarıldı');
// 4. Universal Evidence
assert.strictEqual(multiResult.universalEvidences.length, 2, 'Step 4: 2 Universal Evidence üretildi');
// 5. Raw-Span Validation
assert.strictEqual(multiResult.validationReport.overallValidationStatus, 'PASS', 'Step 5: Raw-span validasyonu PASS');
// 6. Forensic Reasoning (Decisions)
assert.strictEqual(multiResult.deterministicDecisions.length, 2, 'Step 6: Deterministik kararlar üretildi');
// 7. Correlation
assert(multiResult.secondaryCorrelation !== undefined, 'Step 7: İkincil korelasyon çalıştı');
// 8. Final Decision
assert(multiResult.secondaryCorrelation?.overallPosture !== undefined, 'Step 8: Final overallPosture mevcut');

console.log(`  ✅ Pipeline Son Karar: ${multiResult.secondaryCorrelation?.overallPosture} (${multiResult.secondaryCorrelation?.postureTitle})`);

console.log('\n================================================================');
console.log('🎉 TÜM PHASE 4.5 TRUE AI LOG ANALYSIS ENGINE TESTLERİ BAŞARIYLA GEÇTİ! 🎉');
console.log('================================================================');
