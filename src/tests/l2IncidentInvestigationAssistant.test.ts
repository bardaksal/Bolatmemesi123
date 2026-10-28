import { generateL2InvestigationPlan } from '../services/l2InvestigationEngine';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${message}`);
  }
}

let passCount = 0;
function runTest(name: string, fn: () => void) {
  try {
    fn();
    passCount++;
    console.log(`✅ [PASS ${passCount}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL] ${name}: ${err.message}`);
    process.exit(1);
  }
}

console.log('================================================================');
console.log('🛡️ L2 INCIDENT INVESTIGATION ASSISTANT AUDIT & VALIDATION 🛡️');
console.log('================================================================\n');

// -----------------------------------------------------------------------------
// SCENARIO 1: Windows Event 4625 (Failed Logon with RDP & Bad Password)
// -----------------------------------------------------------------------------
runTest('Test 1.1: Windows 4625 doğru sınıflandırılmalı ve platform bağlamı kurulmalı', () => {
  const rawLog = `An account failed to log on.
Subject:
  Security ID: NULL SID
  Account Name: -
Account For Which Logon Failed:
  Security ID: NULL SID
  Account Name: ahmet.kaya
Failure Information:
  Failure Reason: Unknown user name or bad password.
  Status: 0xC000006D
  Sub Status: 0xC000006A
Network Information:
  Workstation Name: PC-FINANS-12
  Source Network Address: 192.168.10.88
  Source Port: 54321
Detailed Authentication Information:
  Logon Process: User32
  Authentication Package: Negotiate
  Logon Type: 10`;

  const plan = generateL2InvestigationPlan(rawLog);

  // 1. Classification
  assert(plan.classification.platform === 'Windows', 'Platform Windows olmalı');
  assert(plan.classification.confidence === 'KESİN', 'Güven KESİN olmalı');
  assert(plan.classification.keyFields['Event ID'] === '4625', 'Event ID 4625 olmalı');
  assert(plan.classification.keyFields['Kullanıcı'] === 'ahmet.kaya', 'Kullanıcı ahmet.kaya olmalı');
  assert(plan.classification.keyFields['Logon Type'] === '10', 'Logon Type 10 olmalı');
  assert(plan.classification.keyFields['SubStatus'] === '0XC000006A', 'SubStatus 0xC000006A olmalı');

  // 2. Platform Context & Attack Chain
  assert(plan.platformContext.criticalFieldsExplained.length >= 4, 'En az 4 kritik alan açıklanmalı');
  assert(plan.platformContext.attackChainContext.includes('4625'), 'Zincir 4625 içermeli');
  assert(plan.platformContext.attackChainContext.includes('4624'), 'Zincir 4624 içermeli');
  assert(plan.platformContext.attackChainContext.includes('4672'), 'Zincir 4672 içermeli');
  assert(plan.platformContext.attackChainContext.includes('4688'), 'Zincir 4688 içermeli');
  assert(plan.platformContext.attackChainContext.includes('7045'), 'Zincir 7045 içermeli');
  assert(plan.platformContext.attackChainContext.includes('1102'), 'Zincir 1102 içermeli');
  assert(plan.platformContext.conditionalCaveat.includes('tek başına saldırı kanıtı değildir'), 'Adli ilke vurgulanmalı');
});

runTest('Test 1.2: Windows 4625 için çoklu hipotezler ve doğrulama matrisi üretilmeli', () => {
  const rawLog = `EventID=4625 TargetUserName="tekin.yilmaz" WorkstationName="PC-01" SubStatus="0xC000006A" LogonType=10 IpAddress="10.10.1.5"`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.hypotheses.length >= 2, 'En az 2 hipotez bulunmalı (Saldırı vs. Benign)');
  const attackHypo = plan.hypotheses.find((h) => h.type === 'ATTACK');
  const benignHypo = plan.hypotheses.find((h) => h.type === 'BENIGN_ANOMALY');

  assert(!!attackHypo, 'Saldırı hipotezi (Brute Force / Password Spraying) bulunmalı');
  assert(!!benignHypo, 'Kullanıcı hatası / eski kimlik bilgisi (Benign) hipotezi bulunmalı');
  assert(attackHypo!.strengtheningFindings.length >= 2, 'Güçlendiren bulgular listelenmeli');
  assert(attackHypo!.weakeningFindings.length >= 2, 'Zayıflatan bulgular listelenmeli');
});

runTest('Test 1.3: 5 Aşamalı L2 Soruşturma Planı (Authentication, Privilege, Process, Persistence, Defense Evasion)', () => {
  const rawLog = `EventID=4625 TargetUserName="admin" WorkstationName="SRV-DC01" SubStatus="0xC0000234" LogonType=3 IpAddress="10.0.0.99"`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.investigationSteps.length === 5, 'Tam 5 aşamalı L2 soruşturma adımı olmalı');
  const categories = plan.investigationSteps.map((s) => s.category);
  assert(categories.includes('AUTHENTICATION'), 'ADIM 1 AUTHENTICATION olmalı');
  assert(categories.includes('PRIVILEGE'), 'ADIM 2 PRIVILEGE olmalı');
  assert(categories.includes('PROCESS_EXECUTION'), 'ADIM 3 PROCESS_EXECUTION olmalı');
  assert(categories.includes('PERSISTENCE'), 'ADIM 4 PERSISTENCE olmalı');
  assert(categories.includes('DEFENSE_EVASION'), 'ADIM 5 DEFENSE_EVASION olmalı');

  // Check concrete Event IDs
  const allEventIds = plan.investigationSteps.flatMap((s) => s.eventIdsAndLogsToInspect).join(' ');
  assert(allEventIds.includes('4624'), '4624 aranmalı');
  assert(allEventIds.includes('4672'), '4672 aranmalı');
  assert(allEventIds.includes('4688'), '4688 aranmalı');
  assert(allEventIds.includes('7045'), '7045 aranmalı');
  assert(allEventIds.includes('1102'), '1102 aranmalı');
});

runTest('Test 1.4: Doğrudan çalıştırılabilir SIEM sorguları üretilmeli (Splunk, KQL, Elastic, QRadar, Sigma)', () => {
  const rawLog = `EventID=4625 TargetUserName="kullanici1" WorkstationName="PC-FINANS" SubStatus="0xC000006A" LogonType=10 IpAddress="192.168.1.10"`;
  const plan = generateL2InvestigationPlan(rawLog);

  // Splunk
  assert(plan.queries.splunk.includes('EventCode=4624'), 'Splunk sorgusunda 4624 olmalı');
  assert(plan.queries.splunk.includes('kullanici1'), 'Splunk sorgusunda hedef kullanıcı olmalı');

  // KQL
  assert(plan.queries.kql.includes('SecurityEvent'), 'KQL sorgusunda SecurityEvent tablosu olmalı');
  assert(plan.queries.kql.includes('EventID in (4624, 4625, 4672, 4688, 7045, 1102)'), 'KQL olay kodları olmalı');

  // Elastic & QRadar & Sigma
  assert(plan.queries.elastic.includes('winlog.event_id'), 'Elastic sorgusu winlog.event_id içermeli');
  assert(plan.queries.qradarAql.includes('SELECT'), 'QRadar sorgusu geçerli AQL SELECT olmalı');
  assert(plan.queries.sigmaRule.includes('logsource:'), 'Sigma kuralı geçerli YAML şeması içermeli');
});

runTest('Test 1.5: Somut L2 Containment ve Response adımları üretilmeli', () => {
  const rawLog = `EventID=4625 TargetUserName="muhasebe" WorkstationName="PC-MUH" SubStatus="0xC0000234" LogonType=10 IpAddress="192.168.1.50"`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.containment.containmentActions.length >= 2, 'En az 2 containment aksiyonu bulunmalı');
  assert(plan.containment.forensicArtifactsToCollect.length >= 2, 'Toplanacak adli kanıtlar listelenmeli');
  assert(plan.containment.severity === 'YÜKSEK', 'Hesap kilitlenmesi YÜKSEK öncelikli müdahale olmalı');
});

// -----------------------------------------------------------------------------
// SCENARIO 2: Windows Event 4688 (Process Creation with LOLBAS)
// -----------------------------------------------------------------------------
runTest('Test 2.1: Windows 4688 Process Creation adli komut satırı incelemesi', () => {
  const rawLog = `A new process has been created.
Subject:
  Account Name: SYSTEM
Process Information:
  New Process Name: C:\\Windows\\System32\\whoami.exe
  Process Command Line: whoami /priv
  Parent Process Name: C:\\Windows\\System32\\cmd.exe
Computer Name: WEB-PROD-01`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Windows', 'Platform Windows olmalı');
  assert(plan.classification.keyFields['Süreç'].includes('whoami.exe'), 'Süreç whoami.exe olmalı');
  assert(plan.classification.keyFields['Komut Satırı'].includes('/priv'), 'Komut satırı /priv içermeli');
  assert(plan.hypotheses.some((h) => h.title.includes('LOLBAS') || h.title.includes('Keşif')), 'Keşif/LOLBAS hipotezi olmalı');
  assert(plan.investigationSteps[2].category === 'PROCESS_EXECUTION', 'Process execution adımı bulunmalı');
});

// -----------------------------------------------------------------------------
// SCENARIO 3: Windows Event 1102 (Audit Log Cleared)
// -----------------------------------------------------------------------------
runTest('Test 3.1: Event 1102 Log Cleared Savunma Atlatma tespiti', () => {
  const rawLog = `The audit log was cleared.
Subject:
  Account Name: Administrator
  Domain: CORP
Computer: DC01.corp.local
Event ID: 1102`;

  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.keyFields['Event ID'] === '1102', 'Event ID 1102 olmalı');
  assert(plan.hypotheses[0].title.includes('Savunma Atlatma') || plan.hypotheses[0].title.includes('T1070.001'), 'T1070.001 hipotezi olmalı');
  assert(plan.containment.severity === 'YÜKSEK', 'Öncelik YÜKSEK olmalı');
});

// -----------------------------------------------------------------------------
// SCENARIO 4: Linux SSH Daemon (Failed / Accepted Password)
// -----------------------------------------------------------------------------
runTest('Test 4.1: Linux SSHd Failed Password brute-force planı', () => {
  const rawLog = `Mar 15 10:20:30 ubuntu-srv sshd[28491]: Failed password for root from 198.51.100.44 port 48122 ssh2`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Linux', 'Platform Linux olmalı');
  assert(plan.classification.keyFields['Kullanıcı'] === 'root', 'Kullanıcı root olmalı');
  assert(plan.classification.keyFields['Kaynak IP'] === '198.51.100.44', 'Kaynak IP 198.51.100.44 olmalı');
  assert(plan.investigationSteps.some((s) => s.eventIdsAndLogsToInspect.some((l) => l.includes('auth.log'))), 'auth.log incelenmeli');
  assert(plan.queries.splunk.includes('index=linux'), 'Splunk sorgusu index=linux olmalı');
  assert(plan.containment.containmentActions.some((a) => a.includes('iptables') || a.includes('IP') || a.includes('passwd')), 'Containment aksiyonu içermeli');
});

// -----------------------------------------------------------------------------
// SCENARIO 5: Web & WAF Exploit Attack (SQLi / Log4j)
// -----------------------------------------------------------------------------
runTest('Test 5.1: WAF SQL Injection ve Log4j için L2 Soruşturma Planı', () => {
  const rawLog = `host=web.sirket.com srcip=203.0.113.195 action=alert attack="SQL Injection" http_url="/products.php?id=1 UNION SELECT 1,username,password FROM users--"`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.platform === 'Web / Network', 'Platform Web / Network olmalı');
  assert(plan.classification.observedBehavior.includes('SQL Injection'), 'SQL Injection davranışı belirtilmeli');
  assert(plan.investigationSteps[0].title.includes('Erişim Loglarında'), 'Web erişim logu kontrol adımı olmalı');
  assert(plan.investigationSteps[1].title.includes('Süreç Ağacında'), 'Alt süreç kontrol adımı olmalı');
  assert(plan.detection.wafOrFirewallRule.includes('BLOCK'), 'BLOCK aksiyonuna geçiş önerilmeli');
});

// -----------------------------------------------------------------------------
// SCENARIO 6: Tanımlanamayan / Bilinmeyen Log Kaynağı
// -----------------------------------------------------------------------------
runTest('Test 6.1: Bilinmeyen log formatında spekülasyon yapılmamalı ve kaynak tespit protokolü sunulmalı', () => {
  const rawLog = `SOME_UNKNOWN_SYSTEM_DUMP: [CODE_991823] value=arbitrary_token_xyz99 status=unrecognized`;
  const plan = generateL2InvestigationPlan(rawLog);

  assert(plan.classification.logSource === 'Log kaynağı kesin belirlenemedi.', 'Kaynak kesin belirlenemediği açıkça söylenmeli');
  assert(plan.classification.platform === 'Bilinmiyor', 'Platform Bilinmiyor olmalı');
  assert(plan.classification.confidence === 'BELİRSİZ', 'Güven BELİRSİZ olmalı');
  assert(plan.platformContext.conditionalCaveat.includes('Log kaynağı kesin belirlenemediği için'), 'Uydurma yapılmadığı belirtilmeli');
  assert(plan.investigationSteps[0].title.includes('Cihaz Kaynağının Doğrulanması'), 'İlk adım kaynak doğrulama olmalı');
});

// -----------------------------------------------------------------------------
// SCENARIO 7: User-Facing Meta-Language & Clean Output
// -----------------------------------------------------------------------------
runTest('Test 7.1: Üretilen L2 Raporunda sistem self-description ve meta-dil bulunmamalı', () => {
  const rawLog = `EventID=4625 TargetUserName="kullanici" WorkstationName="PC-01" SubStatus="0xC000006A" LogonType=10 IpAddress="10.0.0.1"`;
  const plan = generateL2InvestigationPlan(rawLog);

  const md = plan.summaryMarkdown;
  const forbidden = [
    'Deterministik Çok Katmanlı Adli Motor',
    'Deterministik Adli Motor',
    'Forensic Engine',
    'AI Engine',
    'AI Layer',
    'Analysis Pipeline',
    'Processing Pipeline',
    'Metodoloji ve Adli Sınırlamalar',
    'Forensic Limitations',
    'Forensic Caveat',
    'Adli Metodoloji Uyarısı',
    'Grok',
    'Gemini tarafından analiz edildi',
  ];

  for (const f of forbidden) {
    assert(!md.toLowerCase().includes(f.toLowerCase()), `L2 Plan markdown çıktısı yasaklı meta ifade içermemeli: "${f}"`);
  }
});

console.log('\n================================================================');
console.log(`🎉 TÜM L2 INVESTIGATION ASSISTANT TESTLERİ BAŞARIYLA GEÇTİ: ${passCount} / 11`);
console.log('================================================================\n');
