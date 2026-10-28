import assert from 'assert';
import {
  analyzeLogStructureLocally,
  runAiLogUnderstandingPipeline,
} from '../services/aiLogUnderstandingEngine';
import { validateAiLogStructure } from '../services/rawSpanValidator';
import { convertAiRecordToUniversalEvidence } from '../services/aiRecordToEvidence';
import { AiLogStructureResponse } from '../types/aiLogUnderstanding';

console.log('================================================================');
console.log('⚡ PHASE 4 — AI FORENSIC LOG UNDERSTANDING ENGINE TEST SUITE ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// TEST 1: ADVERSARIAL 46-EVENT FIXTURE (Section 15)
// -----------------------------------------------------------------------------
console.log('\n--- 1. Adversarial 46-Event Dataset & Raw-Span Validation Test ---');

const regressionEvents = [
  // 1: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user1, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.10',
  // 2: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user2, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.11',
  // 3: 4624 Type 2 (murat.k + 10.20.44.17 conflict)
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: murat.k, Computer: SRV-APP01, Logon Type: 2, Source Network Address: 10.20.44.17',
  // 4: 4672 Special Privileges
  'Microsoft-Windows-Security-Auditing: [4672] Special privileges assigned to new logon. Account Name: murat.k, Computer: SRV-APP01',
  // 5: 4688 conhost.exe
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: murat.k, New Process Name: C:\\Windows\\System32\\conhost.exe, Process Command Line: conhost.exe 0xffffffff',
  // 6: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user3, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.12',
  // 7: Sysmon 1 cmd.exe
  'Microsoft-Windows-Sysmon: [1] Process Create. User: murat.k, Image: C:\\Windows\\System32\\cmd.exe, CommandLine: cmd.exe /c echo test',
  // 8: 4688 tasklist.exe
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: murat.k, New Process Name: C:\\Windows\\System32\\tasklist.exe, Process Command Line: tasklist.exe',
  // 9: whoami.exe
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: murat.k, New Process Name: C:\\Windows\\System32\\whoami.exe, Process Command Line: C:\\Windows\\System32\\whoami.exe',
  // 10: 4625 administrator 0xC0000064 (unknown user)
  'Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: administrator, SubStatus: 0xC0000064, Source Network Address: 10.20.44.17, Computer: SRV-APP01',
  // 11: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user4, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.13',
  // 12: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user5, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.14',
  // 13: Sysmon 11
  'Microsoft-Windows-Sysmon: [11] File created. TargetFilename: C:\\Windows\\Temp\\tempfile1.tmp, Computer: SRV-APP01',
  // 14: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user6, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.15',
  // 15: PowerShell 4104 (no script content)
  'Microsoft-Windows-PowerShell: [4104] Script block logging event. Computer: SRV-APP01',
  // 16: 4663 Object Access (no object name / access mask)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: murat.k, Computer: SRV-APP01',
  // 17: 4625 administrator 0xC000006A (bad password)
  'Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: administrator, SubStatus: 0xC000006A, Source Network Address: 10.20.44.17, Computer: SRV-APP01',
  // 18: 4624 administrator SUCCESS
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: administrator, Computer: SRV-APP01, Logon Type: 10, Source Network Address: 10.20.44.17',
  // 19: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user7, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.16',
  // 20: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user8, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.17',
  // 21: 4688 conhost.exe
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: administrator, New Process Name: C:\\Windows\\System32\\conhost.exe, Process Command Line: conhost.exe 0xffffffff',
  // 22: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user9, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.18',
  // 23: PowerShell 4104 (no script content)
  'Microsoft-Windows-PowerShell: [4104] Script block logging event. Computer: SRV-APP01',
  // 24: 4663 Object Access (no object name / access mask)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: administrator, Computer: SRV-APP01',
  // 25: 4663 Object Access (no object name / access mask)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: administrator, Computer: SRV-APP01',
  // 26: Sysmon 11
  'Microsoft-Windows-Sysmon: [11] File created. TargetFilename: C:\\Windows\\Temp\\tempfile2.tmp, Computer: SRV-APP01',
  // 27: 4663 Object Access (no object name / access mask)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: IIS, Computer: SRV-APP01',
  // 28: 4663 Object Access with ObjectName & AccessMask (Routine/Meşru)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: murat.k, ObjectName: C:\\Shares\\Reports\\doc.pdf, AccessMask: 0x1, Computer: SRV-APP01',
  // 29: 7045 CorpInventoryUpdater
  'System: [7045] A service was installed in the system. Service Name: CorpInventoryUpdater, Service File Name: C:\\ProgramData\\CorpTools\\InventoryUpdater.exe, Subject User: SYSTEM, Computer: SRV-APP01',
  // 30: 4688
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: SYSTEM, New Process Name: C:\\ProgramData\\CorpTools\\InventoryUpdater.exe, Process Command Line: InventoryUpdater.exe /silent',
  // 31: 5156 Windows Filtering Platform
  'Microsoft-Windows-Security-Auditing: [5156] The Windows Filtering Platform has permitted a connection. Computer: SRV-APP01',
  // 32: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user10, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.19',
  // 33: 4634 Logoff
  'Microsoft-Windows-Security-Auditing: [4634] An account was logged off. Account Name: user1, Computer: SRV-APP01',
  // 34: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user11, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.20',
  // 35: 4663 Object Access with ObjectName & AccessMask (Routine/Meşru)
  'Microsoft-Windows-Security-Auditing: [4663] An attempt was made to access an object. Account Name: administrator, ObjectName: C:\\Shares\\Public\\readme.txt, AccessMask: 0x1, Computer: SRV-APP01',
  // 36: 1102 Security Audit Log Cleared
  'Microsoft-Windows-Security-Auditing: [1102] The audit log was cleared. Subject: Security ID: S-1-5-18, Account Name: administrator, Computer: SRV-APP01',
  // 37: 1102 Security Audit Log Cleared
  'Microsoft-Windows-Security-Auditing: [1102] The audit log was cleared. Subject: Security ID: S-1-5-18, Account Name: administrator, Computer: SRV-APP01',
  // 38: 4688 wevtutil.exe
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: administrator, New Process Name: C:\\Windows\\System32\\wevtutil.exe, Process Command Line: wevtutil.exe cl Security',
  // 39: 4688
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: SYSTEM, New Process Name: C:\\Windows\\System32\\svchost.exe, Process Command Line: svchost.exe -k netsvcs',
  // 40: 5140 Network Share Access
  'Microsoft-Windows-Security-Auditing: [5140] A network share object was accessed. Account Name: user1, Computer: SRV-APP01',
  // 41: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user12, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.21',
  // 42: 4688 SYSTEM /admin/reports/panel.aspx
  'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: SYSTEM, New Process Name: /admin/reports/panel.aspx, Process Command Line: /admin/reports/panel.aspx',
  // 43: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user13, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.22',
  // 44: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user14, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.23',
  // 45: 4624 Type 3
  'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: user15, Computer: SRV-APP01, Logon Type: 3, Source Network Address: 192.168.1.24',
  // 46: 104 System/App Log Cleared
  'System: [104] The log file was cleared. User: administrator, Computer: SRV-APP01',
];

const headerComments = Array(444).fill('# SOC Forensic Telemetry Audit Stream Record Archive');
const raw490LogText = [...headerComments, ...regressionEvents].join('\n');

const pipelineResult = await runAiLogUnderstandingPipeline({ rawInput: raw490LogText });

// 1.1 AI logical records count
assert.strictEqual(
  pipelineResult.aiResponse.records.length,
  46,
  `Test 1.1: AI tam olarak 46 logical record çıkarmalıdır (Çıkan: ${pipelineResult.aiResponse.records.length})`
);

// 1.2 Raw-Span Validator verification
assert.strictEqual(
  pipelineResult.validationReport.acceptedRecordsCount,
  46,
  `Test 1.2: Raw-span validator 46 geçerli kaydı doğrulamalıdır`
);
assert.strictEqual(
  pipelineResult.validationReport.hallucinationsDetected,
  0,
  `Test 1.3: Halüsinasyon sayısı tam 0 olmalıdır`
);
assert.strictEqual(
  pipelineResult.validationReport.crossEventContaminationsDetected,
  0,
  `Test 1.4: Çapraz olay kontaminasyonu tam 0 olmalıdır`
);
assert.strictEqual(
  pipelineResult.validationReport.hasOverlappingRecords,
  false,
  `Test 1.5: Örtüşen olaylar olmamalıdır`
);

// 1.3 Verify every event's raw span matches the raw text
for (let i = 0; i < pipelineResult.aiResponse.records.length; i++) {
  const r = pipelineResult.aiResponse.records[i];
  const sliceFromInput = raw490LogText.slice(r.rawStart, r.rawEnd);
  assert.strictEqual(
    sliceFromInput,
    r.rawText,
    `Test 1.6 [Record #${r.recordIndex}]: rawInput.slice([${r.rawStart}, ${r.rawEnd}]) birebir rawText ile eşleşmeli`
  );
}

// 1.4 Universal Evidence records count
assert.strictEqual(
  pipelineResult.universalEvidences.length,
  46,
  `Test 1.7: 46 UniversalEvidence kaydı oluşturulmalıdır`
);

// 1.5 Security engine event-level decisions count
assert.strictEqual(
  pipelineResult.deterministicDecisions.length,
  46,
  `Test 1.8: Deterministik güvenlik motoru 46 karar üretmelidir`
);

// 1.6 Secondary correlation
assert(
  pipelineResult.secondaryCorrelation !== undefined,
  'Test 1.9: İkincil korelasyon başarıyla tamamlanmalıdır'
);
assert.strictEqual(
  pipelineResult.secondaryCorrelation!.incidentCandidates.length,
  1,
  'Test 1.10: 1 adet korelasyon zinciri (INCIDENT-01) tespit edilmelidir'
);

console.log('✅ Adversarial 46-Event Dataset & Raw-Span Validation Başarıyla Geçti!');

// -----------------------------------------------------------------------------
// TEST 2: FORMAT GENERALIZATION TEST — 11 FARKLI LOG FORMATI (Section 16)
// -----------------------------------------------------------------------------
console.log('\n--- 2. Format Generalization Test (11 Farklı Log Formatı) ---');

const testFormats: Array<{ name: string; log: string; expectedMinRecords: number }> = [
  // 1. Windows Security
  {
    name: 'Windows Security',
    log: 'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: admin, Computer: SRV-DC01, Logon Type: 10, Source Network Address: 10.0.0.5',
    expectedMinRecords: 1,
  },
  // 2. Sysmon
  {
    name: 'Sysmon',
    log: 'Microsoft-Windows-Sysmon: [1] Process Create. User: system, Image: C:\\Windows\\System32\\cmd.exe, CommandLine: cmd.exe /c whoami, ParentImage: C:\\Windows\\explorer.exe',
    expectedMinRecords: 1,
  },
  // 3. Linux auth (sshd)
  {
    name: 'Linux auth',
    log: 'Oct 18 10:14:22 srv-prod sshd[18422]: Failed password for invalid user oracle from 198.51.100.44 port 44122 ssh2\nOct 18 10:14:25 srv-prod sshd[18425]: Accepted password for deploy from 198.51.100.44 port 44125 ssh2',
    expectedMinRecords: 2,
  },
  // 4. Apache Combined
  {
    name: 'Apache Combined',
    log: '192.168.1.100 - user_a [18/Oct/2026:10:00:00 +0300] "GET /index.html HTTP/1.1" 200 4523\n192.168.1.101 - - [18/Oct/2026:10:00:01 +0300] "POST /login HTTP/1.1" 401 234',
    expectedMinRecords: 2,
  },
  // 5. Nginx
  {
    name: 'Nginx',
    log: '10.20.30.40 - - [18/Oct/2026:10:01:00 +0000] "GET /api/v1/status HTTP/1.1" 200 120 "-" "curl/7.88.1"',
    expectedMinRecords: 1,
  },
  // 6. IIS W3C
  {
    name: 'IIS W3C',
    log: '2026-10-18 10:00:00 192.168.1.50 GET /app/default.aspx - 80 - 10.20.40.10 Mozilla/5.0 200 0 0 15',
    expectedMinRecords: 1,
  },
  // 7. CEF
  {
    name: 'CEF',
    log: 'CEF:0|SecurityVendor|Firewall|1.0|100|Drop packet|5|src=185.123.105.51 dst=10.0.0.1 spt=44122 dpt=443 act=drop msg=SynFlood',
    expectedMinRecords: 1,
  },
  // 8. JSON logs
  {
    name: 'JSON logs',
    log: '{"timestamp":"2026-10-18T10:00:00Z","user":"alice","action":"login","ip":"192.168.1.50","outcome":"SUCCESS"}\n{"timestamp":"2026-10-18T10:01:00Z","user":"bob","action":"logout","ip":"192.168.1.51","outcome":"SUCCESS"}',
    expectedMinRecords: 2,
  },
  // 9. key=value custom logs
  {
    name: 'key=value custom logs',
    log: 'timestamp=2026-10-18T10:00:00Z src=10.0.0.1 user=sec_admin action=modify_policy status=success\ntimestamp=2026-10-18T10:02:00Z src=10.0.0.2 user=guest action=view_report status=denied',
    expectedMinRecords: 2,
  },
  // 10. Multiline application logs
  {
    name: 'multiline application logs',
    log: `2026-10-18 10:05:00,123 ERROR [com.corp.AuthService] Failed to authenticate user tekin: Invalid token
java.lang.SecurityException: Token expired
\tat com.corp.AuthService.verify(AuthService.java:142)
\tat com.corp.AuthController.login(AuthController.java:55)`,
    expectedMinRecords: 1,
  },
  // 11. Bilinmeyen / Custom format (Section 8)
  {
    name: 'unknown/custom format',
    log: '2026/10/17 10:01 user=admin action=login\n2026/10/17 10:02 user=root action=logout',
    expectedMinRecords: 2,
  },
];

for (const tf of testFormats) {
  const result = analyzeLogStructureLocally(tf.log);
  assert(
    result.records.length >= tf.expectedMinRecords,
    `Format Gen [${tf.name}]: En az ${tf.expectedMinRecords} logical event çıkarılmalı (Çıkan: ${result.records.length})`
  );
  // Verify span validity for every record
  for (const rec of result.records) {
    const slice = tf.log.slice(rec.rawStart, rec.rawEnd);
    assert.strictEqual(
      slice,
      rec.rawText,
      `Format Gen [${tf.name}]: rawText span ile birebir örtüşmeli`
    );
  }
  console.log(`  ✅ Format [${tf.name}]: ${result.records.length} olay başarıyla ve sıfır regex koduyla ayrıştırıldı.`);
}

console.log('✅ 11 Farklı Log Formatı Genelleme Testi Başarıyla Geçti!');

// -----------------------------------------------------------------------------
// TEST 3: DETERMINISTIC RAW-SPAN VALIDATOR INVARIANTS (Sections 4 & 5)
// -----------------------------------------------------------------------------
console.log('\n--- 3. Deterministik Raw-Span Validator & Halüsinasyon Reddetme Testleri ---');

const baseRawInput = '2026-10-18 10:00:00 user=administrator host=SRV-DC01 action=allow';

// 3.1: Injected Hallucinated Field (AI claims value not in raw text)
const aiHallucinatedResponse: AiLogStructureResponse = {
  analysisVersion: '1.0',
  formatAssessment: { format: 'key=value', confidence: 'HIGH' },
  records: [
    {
      recordIndex: 1,
      rawStart: 0,
      rawEnd: baseRawInput.length,
      rawText: baseRawInput,
      fields: [
        { name: 'user', value: 'administrator', status: 'OBSERVED', sourceSpan: { start: 25, end: 38 } },
        { name: 'sourceIp', value: '198.51.100.99', status: 'OBSERVED', sourceSpan: { start: 0, end: 13 } }, // HALLUCINATION!
      ],
    },
  ],
  unparsedSpans: [],
  warnings: [],
};

const rep1 = validateAiLogStructure(baseRawInput, aiHallucinatedResponse);
assert.strictEqual(rep1.hallucinationsDetected, 1, 'Test 3.1: 1 adet halüsinasyon alan tespit edilmeli');
assert.strictEqual(rep1.validatedRecords[0].fields[1].decision, 'REJECTED', 'Test 3.2: Halüsinasyon alan REJECTED olmalı');
assert.strictEqual(rep1.validatedRecords[0].fields[1].isHallucinated, true, 'Test 3.3: isHallucinated = true olmalı');

// 3.2: Injected Cross-Event Data Contamination (Section 6)
const twoEventRaw = 'Event 1: Source Network Address: 10.20.44.17\nEvent 2: New Process Name: notepad.exe';
const aiContaminatedResponse: AiLogStructureResponse = {
  analysisVersion: '1.0',
  formatAssessment: { format: 'Windows', confidence: 'HIGH' },
  records: [
    {
      recordIndex: 1,
      rawStart: 0,
      rawEnd: 44,
      rawText: 'Event 1: Source Network Address: 10.20.44.17',
      fields: [
        { name: 'sourceIp', value: '10.20.44.17', status: 'OBSERVED' },
      ],
    },
    {
      recordIndex: 2,
      rawStart: 45,
      rawEnd: twoEventRaw.length,
      rawText: 'Event 2: New Process Name: notepad.exe',
      fields: [
        { name: 'process', value: 'notepad.exe', status: 'OBSERVED' },
        { name: 'sourceIp', value: '10.20.44.17', status: 'OBSERVED' }, // CROSS-CONTAMINATION FROM EVENT 1!
      ],
    },
  ],
  unparsedSpans: [],
  warnings: [],
};

const rep2 = validateAiLogStructure(twoEventRaw, aiContaminatedResponse);
assert.strictEqual(rep2.crossEventContaminationsDetected, 1, 'Test 3.4: 1 adet çapraz kontaminasyon yakalanmalı');
const contaminatedField = rep2.validatedRecords[1].fields[1];
assert.strictEqual(contaminatedField.decision, 'REJECTED', 'Test 3.5: Çapraz kontaminasyon içeren alan REJECTED olmalı');
assert.strictEqual(contaminatedField.isCrossEventContaminated, true, 'Test 3.6: isCrossEventContaminated = true olmalı');

// 3.3: Injected Out-of-Bounds Span
const aiOutOfBoundsResponse: AiLogStructureResponse = {
  analysisVersion: '1.0',
  formatAssessment: { format: 'UNKNOWN', confidence: 'LOW' },
  records: [
    {
      recordIndex: 1,
      rawStart: -5, // Invalid negative start
      rawEnd: 500,  // Exceeds rawInput length
      rawText: 'Invalid boundary text',
      fields: [],
    },
  ],
  unparsedSpans: [],
  warnings: [],
};

const rep3 = validateAiLogStructure(baseRawInput, aiOutOfBoundsResponse);
assert.strictEqual(rep3.validatedRecords[0].spanIntegrity, 'OUT_OF_BOUNDS', 'Test 3.7: Span integrity OUT_OF_BOUNDS olmalı');
assert.strictEqual(rep3.validatedRecords[0].recordStatus, 'REJECTED', 'Test 3.8: Sınır dışı kayıt REJECTED olmalı');

// 3.4: Injected Overlapping Records
const aiOverlapResponse: AiLogStructureResponse = {
  analysisVersion: '1.0',
  formatAssessment: { format: 'UNKNOWN', confidence: 'LOW' },
  records: [
    {
      recordIndex: 1,
      rawStart: 0,
      rawEnd: 30,
      rawText: baseRawInput.slice(0, 30),
      fields: [],
    },
    {
      recordIndex: 2,
      rawStart: 20, // OVERLAPS WITH RECORD 1 (20 < 30)
      rawEnd: baseRawInput.length,
      rawText: baseRawInput.slice(20),
      fields: [],
    },
  ],
  unparsedSpans: [],
  warnings: [],
};

const rep4 = validateAiLogStructure(baseRawInput, aiOverlapResponse);
assert.strictEqual(rep4.hasOverlappingRecords, true, 'Test 3.9: Örtüşen olaylar tespit edilmeli (hasOverlappingRecords = true)');
assert.strictEqual(rep4.validatedRecords[1].spanIntegrity, 'OVERLAPPING', 'Test 3.10: Record 2 OVERLAPPING olarak etiketlenmeli');

console.log('✅ Deterministik Raw-Span Validator & Halüsinasyon Reddetme Testleri Başarıyla Geçti!');

// -----------------------------------------------------------------------------
// TEST 4: MISSING DATA & NOT_PRESENT INVARIANT (Section 9)
// -----------------------------------------------------------------------------
console.log('\n--- 4. Eksik Alanlar (Missing Data) & NOT_PRESENT İlkesi Testi ---');

const svchostSingleLog = 'Microsoft-Windows-Sysmon: [1] Process Create. Image: C:\\Windows\\System32\\svchost.exe User: SYSTEM';
const parsedSvchost = analyzeLogStructureLocally(svchostSingleLog);
const parentField = parsedSvchost.records[0].fields.find((f) => f.name === 'parentProcess');

assert(parentField !== undefined, 'Test 4.1: parentProcess alanı yapıda bulunmalı');
assert.strictEqual(parentField!.status, 'NOT_PRESENT', 'Test 4.2: Olmayan ParentProcess alanı NOT_PRESENT olarak işaretlenmeli, asla tahmin edilmemeli');
assert.strictEqual(parentField!.value, '', 'Test 4.3: NOT_PRESENT alanı için uydurma değer üretilmemelidir');

console.log('✅ Eksik Veri & NOT_PRESENT Testi Başarıyla Geçti!');

// -----------------------------------------------------------------------------
// TEST 5: AI FAILURE & PARSE_NOT_ASSESSED INVARIANT (Section 13)
// -----------------------------------------------------------------------------
console.log('\n--- 5. AI Çağrısı Başarısız Olduğunda Tek Olay Uydurmama Testi ---');

// 50 satırlık log
const fiftyLinesRaw = Array(50).fill('Some raw firewall telemetry line without parser rule').join('\n');

// Simulating empty/failed AI response
const emptyFailedAiResponse: AiLogStructureResponse = {
  analysisVersion: '1.0',
  formatAssessment: { format: 'UNKNOWN', confidence: 'UNKNOWN' },
  records: [], // EMPTY RECORDS (AI failure!)
  unparsedSpans: [{ start: 0, end: fiftyLinesRaw.length, text: fiftyLinesRaw, reason: 'AI_TIMEOUT' }],
  warnings: ['AI_CALL_FAILED'],
};

const valReportFailed = validateAiLogStructure(fiftyLinesRaw, emptyFailedAiResponse);
assert.strictEqual(valReportFailed.totalCandidateRecords, 0, 'Test 5.1: AI hatasında kayıt sayısı 0 olmalıdır');
assert.notStrictEqual(valReportFailed.acceptedRecordsCount, 1, 'Test 5.2: 50 satırlık AI hatasında Parsed Events ASLA 1 OLAMAZ!');

console.log('✅ AI Failure & PARSE_NOT_ASSESSED Testi Başarıyla Geçti!');

// -----------------------------------------------------------------------------
// TEST 6: AI ASLA GÜVENLİK VERDİCTİ VEREMEZ (Section 10 & 18)
// -----------------------------------------------------------------------------
console.log('\n--- 6. AI Güvenlik Hükmü Sınırı Testi ---');

const aiOutputKeys = Object.keys(pipelineResult.aiResponse);
assert(!aiOutputKeys.includes('verdict'), 'Test 6.1: AI çıktısında verdict alanı yer alamaz');
assert(!aiOutputKeys.includes('threatLevel'), 'Test 6.2: AI çıktısında threatLevel alanı yer alamaz');
assert(!aiOutputKeys.includes('isAttack'), 'Test 6.3: AI çıktısında isAttack alanı yer alamaz');

for (const rec of pipelineResult.aiResponse.records) {
  const recKeys = Object.keys(rec);
  assert(!recKeys.includes('verdict'), 'Test 6.4: Record nesnesinde doğrudan verdict bulunamaz');
  assert(!recKeys.includes('threatLevel'), 'Test 6.5: Record nesnesinde doğrudan threatLevel bulunamaz');
}

console.log('✅ AI Güvenlik Hükmü Sınırı Testi Başarıyla Geçti!');

console.log('================================================================');
console.log('🎉 TÜM PHASE 4 AI FORENSIC LOG UNDERSTANDING TESTLERİ BAŞARIYLA GEÇTİ! 🎉');
console.log('================================================================');
