import assert from 'assert';
import { extractWindowsDetails, splitRawTextIntoEvents } from '../services/quickTriageHelper';
import { evaluateUnifiedDecision } from '../services/unifiedDecisionEngine';
import { runSecondaryCorrelation, generateComprehensive6StageReport } from '../services/socCorrelationEngine';
import { analyzeRawLogText } from '../services/quickLogAnalyzer';
import { initializeFormatState, feedSampleLine, parseLineToNormalizedLog } from '../services/streamingParser';

console.log('================================================================');
console.log('⚡ AŞAMA 3.3 — ADVERSARIAL FORENSIC EVENT CLASSIFICATION & CORRELATION TEST SUITE ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// BÖLÜM 1: EVENT ID & TYPE TEK BAŞINA SALDIRI KANITI DEĞİLDİR
// -----------------------------------------------------------------------------
console.log('\n--- 1. Event ID / Type Tek Başına Şüpheli Üretmeme Testleri ---');

// 1.1: 4624 Logon Type 10 (RDP) tek başına saldırı veya şüpheli anomali değildir
const rdp4624 = 'Microsoft-Windows-Security-Auditing: [4624] An account was successfully logged on. Account Name: sysadmin, Computer: SRV-DC01, Logon Type: 10, Source Network Address: 10.10.20.15';
const stateRdp = initializeFormatState('rdp.log');
feedSampleLine(stateRdp, rdp4624);
const parsedRdp = parseLineToNormalizedLog(rdp4624, stateRdp);
const resRdp = evaluateUnifiedDecision({
  rawLine: rdp4624,
  eventIndex: 0,
  formatState: stateRdp,
  parsedLog: parsedRdp,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resRdp.verdict, 'AUTHORIZED_ACTIVITY', 'Test 1.1: Başarılı RDP oturumu (4624 Type 10) tek başına şüpheli üretmez, AUTHORIZED_ACTIVITY olmalıdır');
assert.strictEqual(resRdp.winDetails.mitreTechnique, undefined, 'Test 1.2: Meşru RDP oturumuna otomatik MITRE saldırı tekniği atanmaz');

// 1.2: 4672 Özel Ayrıcalık Ataması tek başına Yetki Yükseltme değildir
const priv4672 = 'Microsoft-Windows-Security-Auditing: [4672] Special privileges assigned to new logon. Account Name: sec_operator, Computer: SRV-APP01';
const statePriv = initializeFormatState('priv.log');
feedSampleLine(statePriv, priv4672);
const parsedPriv = parseLineToNormalizedLog(priv4672, statePriv);
const resPriv = evaluateUnifiedDecision({
  rawLine: priv4672,
  eventIndex: 0,
  formatState: statePriv,
  parsedLog: parsedPriv,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resPriv.verdict, 'AUTHORIZED_ACTIVITY', 'Test 1.3: Event 4672 tek başına yetki yükseltme değildir, AUTHORIZED_ACTIVITY olmalıdır');
assert.strictEqual(resPriv.winDetails.mitreTechnique, undefined, 'Test 1.4: Event 4672 için otomatik MITRE saldırı tekniği atanmaz');

// 1.3: 4688 whoami.exe veya CorpInventoryUpdater.exe tek başına saldırı değildir
const cmdWhoami = 'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: backup_user, New Process Name: C:\\Windows\\System32\\whoami.exe, Process Command Line: whoami.exe';
const stateWhoami = initializeFormatState('whoami.log');
feedSampleLine(stateWhoami, cmdWhoami);
const parsedWhoami = parseLineToNormalizedLog(cmdWhoami, stateWhoami);
const resWhoami = evaluateUnifiedDecision({
  rawLine: cmdWhoami,
  eventIndex: 0,
  formatState: stateWhoami,
  parsedLog: parsedWhoami,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resWhoami.verdict, 'AUTHORIZED_ACTIVITY', 'Test 1.5: whoami.exe tek başına şüpheli üretmez, standart süreç yürütmedir');

const cmdInventory = 'Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: SYSTEM, New Process Name: C:\\Program Files\\Corp\\CorpInventoryUpdater.exe, Process Command Line: CorpInventoryUpdater.exe /scan';
const stateInv = initializeFormatState('inv.log');
feedSampleLine(stateInv, cmdInventory);
const parsedInv = parseLineToNormalizedLog(cmdInventory, stateInv);
const resInv = evaluateUnifiedDecision({
  rawLine: cmdInventory,
  eventIndex: 0,
  formatState: stateInv,
  parsedLog: parsedInv,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resInv.verdict, 'AUTHORIZED_ACTIVITY', 'Test 1.6: Kurumsal envanter süreci meşru süreçtir');

// 1.4: 7045 Sisteme Yeni Servis Kurulumu tek başına kötü amaçlı kalıcılık değildir
const svc7045 = 'System: [7045] A service was installed in the system. Service Name: CorpInventoryUpdater, Service File Name: C:\\Program Files\\Corp\\CorpInventoryUpdater.exe, Subject User: SYSTEM';
const stateSvc = initializeFormatState('svc.log');
feedSampleLine(stateSvc, svc7045);
const parsedSvc = parseLineToNormalizedLog(svc7045, stateSvc);
const resSvc = evaluateUnifiedDecision({
  rawLine: svc7045,
  eventIndex: 0,
  formatState: stateSvc,
  parsedLog: parsedSvc,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resSvc.verdict, 'AUTHORIZED_ACTIVITY', 'Test 1.7: Standart servis kurulumu (7045) tek başına zararlı kalıcılık değildir');
assert.strictEqual(resSvc.winDetails.mitreTechnique, undefined, 'Test 1.8: Meşru servise otomatik T1543.003 MITRE etiketi basılmaz');

// 1.5: 4625 0xC0000064 tek başına credential spraying değildir
const fail64 = 'Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: bilinmeyen_kullanici, SubStatus: 0xC0000064, Source Network Address: 10.20.44.17';
const stateFail64 = initializeFormatState('fail64.log');
feedSampleLine(stateFail64, fail64);
const parsedFail64 = parseLineToNormalizedLog(fail64, stateFail64);
const resFail64 = evaluateUnifiedDecision({
  rawLine: fail64,
  eventIndex: 0,
  formatState: stateFail64,
  parsedLog: parsedFail64,
  sourceType: 'TEXT_LOG',
});
assert.strictEqual(resFail64.verdict, 'LIKELY_FALSE_POSITIVE', 'Test 1.9: Tekil 0xC0000064 LIKELY_FALSE_POSITIVE olmalıdır');
assert(!resFail64.threatTitle.toLowerCase().includes('credential spraying'), 'Test 1.10: Tekil 0xC0000064 başlığında credential spraying iddiası yer almaz');
assert(resFail64.summaryReason.toLowerCase().includes('tek başına parola püskürtme') || resFail64.summaryReason.toLowerCase().includes('tek başına'), 'Test 1.11: Gerekçe tek başına parola püskürtme kanıtı olmadığını açıklar');

// -----------------------------------------------------------------------------
// BÖLÜM 2: CREDENTIAL SPRAYING KANIT EŞİĞİ
// -----------------------------------------------------------------------------
console.log('\n--- 2. Credential Spraying Kanıt Eşiği Testleri ---');

// Tek hesap veya 2 hesap: Credential Spraying DENEMEZ
const twoUserLogs = `
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user1, SubStatus: 0xC000006A, Source Network Address: 198.51.100.99
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user2, SubStatus: 0xC000006A, Source Network Address: 198.51.100.99
`;
const triageTwoUsers = analyzeRawLogText(twoUserLogs)!;
assert(triageTwoUsers !== null, 'Test 2.1: 2 kullanıcılı log ayrıştırıldı');
const incTwoUsers = triageTwoUsers.wholeLogSummary.incidentCandidates;
if (incTwoUsers.length > 0) {
  assert(!incTwoUsers[0].title.includes('Credential Spraying'), 'Test 2.2: 2 kullanıcı için Credential Spraying iddiasında bulunulmaz');
  assert(!incTwoUsers[0].mitreTechniques.includes('T1110.003 (Credential Spraying)'), 'Test 2.3: 2 kullanıcı için T1110.003 atanmaz');
}

// 3+ farklı hesap: Kanıtlanmış Credential Spraying
const multiUserLogs = `
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user1, SubStatus: 0xC000006A, Source Network Address: 198.51.100.99
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user2, SubStatus: 0xC000006A, Source Network Address: 198.51.100.99
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user3, SubStatus: 0xC000006A, Source Network Address: 198.51.100.99
`;
const triageMultiUsers = analyzeRawLogText(multiUserLogs)!;
assert(triageMultiUsers !== null, 'Test 2.4: 3 kullanıcılı log ayrıştırıldı');
const incMultiUsers = triageMultiUsers.wholeLogSummary.incidentCandidates;
assert(incMultiUsers.length > 0, 'Test 2.5: 3 kullanıcı için korelasyon zinciri oluşturulmalıdır');
assert(incMultiUsers[0].title.includes('Credential Spraying'), 'Test 2.6: 3 farklı hesap hedef alındığında Credential Spraying tespit edilir');
assert(incMultiUsers[0].mitreTechniques.includes('T1110.003 (Credential Spraying)'), 'Test 2.7: T1110.003 tekniği kanıtla atanır');

// -----------------------------------------------------------------------------
// BÖLÜM 3: SAYAÇLARIN KESİN AYRIŞTIRILMASI (SATIR ≠ OLAY)
// -----------------------------------------------------------------------------
console.log('\n--- 3. Sayaçların Kesin Ayrıştırılması Testleri ---');

// Çok satırlı Windows Event Log (1 olay = 15 satır)
const multiLineSingleEvent = `
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          14.10.2026 10:00:00
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure
User:          N/A
Computer:      SRV-DC01.corp.local
Description:
An account failed to log on.
Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0
Logon Type:			10
Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		deneme_user
	Account Domain:		CORP
Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A
Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-
Network Information:
	Workstation Name:	CLIENT-PC01
	Source Network Address:	10.20.44.17
	Source Port:		52140
`;

const singleTriage = analyzeRawLogText(multiLineSingleEvent)!;
assert(singleTriage !== null, 'Test 3.1: Çok satırlı log analiz edildi');
assert(singleTriage.rawLinesCount > 20, `Test 3.2: Ham satır sayısı 20'den fazla (${singleTriage.rawLinesCount})`);
assert.strictEqual(singleTriage.parsedRecordsCount, 1, `Test 3.3: Ayrıştırılan olay kaydı tam olarak 1'dir (ham satırla karıştırılmadı)`);
assert.strictEqual(singleTriage.normalizedEventsCount, 1, 'Test 3.4: Normalize edilen olay sayısı 1');
assert.strictEqual(singleTriage.wholeLogSummary.rawLinesCount, singleTriage.rawLinesCount, 'Test 3.5: WholeLogSummary rawLinesCount tutarlı');
assert.strictEqual(singleTriage.wholeLogSummary.parsedRecordsCount, 1, 'Test 3.6: WholeLogSummary parsedRecordsCount 1');
assert.strictEqual(singleTriage.wholeLogSummary.uncorrelatedEventsCount, 1, 'Test 3.7: Bağımsız olay sayısı 1 (zincir yok)');

// Rapor metninde sayaçların ayrı başlıklarla sunulması
const reportText = singleTriage.comprehensive6StageReport;
assert(reportText.includes('Ham Satır Sayısı (Raw Log Lines):'), 'Test 3.8: Raporda Ham Satır Sayısı açıkça yer alıyor');
assert(reportText.includes('Ayrıştırılabilen Olay Kaydı Sayısı (Parsed Event Records): 1'), 'Test 3.9: Raporda Ayrıştırılan Olay Kaydı 1 olarak yazıyor');
assert(reportText.includes('Normalize Edilmiş Benzersiz Olay Sayısı (Normalized Events): 1'), 'Test 3.10: Raporda Normalize Edilmiş Olay Sayısı 1 olarak yazıyor');

// -----------------------------------------------------------------------------
// BÖLÜM 4: ADLİ VERİ İZOLASYONU (EVENT FIELDS BAŞKA OLAYDAN TAŞINMAZ)
// -----------------------------------------------------------------------------
console.log('\n--- 4. Adli Veri İzolasyonu (Alan Taşıma Engeli) ---');

// Olay 1: Kaynak IP'si var (4625 remote)
// Olay 2: Süreç oluşturma (4688 local, IP yok)
const mixedLogs = `
Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: user_a, Source Network Address: 192.168.1.100, Computer: SRV-APP01
Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: user_a, New Process Name: C:\\Windows\\notepad.exe, Computer: SRV-APP01
`;
const triageMixed = analyzeRawLogText(mixedLogs)!;
assert(triageMixed !== null, 'Test 4.1: İki olay analiz edildi');
assert.strictEqual(triageMixed.correlatedEvents.length, 2, 'Test 4.2: 2 olay ayrıştırıldı');

// Event 1 IP = 192.168.1.100
assert.strictEqual(triageMixed.correlatedEvents[0].sourceIp, '192.168.1.100', 'Test 4.3: Olay 1 kaynak IP doğru okundu');
// Event 2 IP = '-' (Olay 1'deki IP Olay 2'ye ASLA taşınmamalıdır!)
assert.strictEqual(triageMixed.correlatedEvents[1].sourceIp, '-', 'Test 4.4: Olay 2 yerel süreçtir, Olay 1 kaynak IP adresi taşınmamıştır (- olarak izoledir)');

// -----------------------------------------------------------------------------
// BÖLÜM 5: ADLİ KORELASYON VE KRİTİK SEVİYE ŞİŞİRMEME
// -----------------------------------------------------------------------------
console.log('\n--- 5. Rutin Olayların Zincir Seviyesini CRITICAL Yapmaması ---');

// Bir host üzerinde rutin süreç + servis kurulumu: Kesinlikle CRITICAL OLAMAZ
const benignChainLogs = `
Microsoft-Windows-Security-Auditing: [4688] A new process has been created. Creator Subject: Account Name: admin, New Process Name: C:\\Program Files\\Corp\\CorpInventoryUpdater.exe, Computer: SRV-FILE01
System: [7045] A service was installed in the system. Service Name: CorpInventoryUpdater, Service File Name: C:\\Program Files\\Corp\\CorpInventoryUpdater.exe, Subject User: admin, Computer: SRV-FILE01
`;
const triageBenignChain = analyzeRawLogText(benignChainLogs)!;
assert(triageBenignChain !== null, 'Test 5.1: Rutin zincir analiz edildi');
const incidents = triageBenignChain.wholeLogSummary.incidentCandidates;
if (incidents.length > 0) {
  assert.notStrictEqual(incidents[0].severity, 'CRITICAL', 'Test 5.2: Meşru servis kurulum zinciri CRITICAL olamaz');
  assert(!incidents[0].mitreTechniques.includes('T1543.003 (Windows Service)'), 'Test 5.3: Meşru servise otomatik kalıcılık MITRE etiketi basılmaz');
}
assert.notStrictEqual(triageBenignChain.wholeLogSummary.overallPosture, 'CRITICAL_THREAT', 'Test 5.4: Genel güvenlik duruşu CRITICAL_THREAT olamaz');

// -----------------------------------------------------------------------------
// BÖLÜM 6: AŞAMA 3.4 — 46-EVENT ADVERSARIAL REGRESSION DATASET & KESİN MATEMATİKSEL KONTRAT
// -----------------------------------------------------------------------------
console.log('\n--- 6. 46-Event Adversarial Regression Dataset & Matematiksel Kontrat ---');

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
  'System: [104] The log file was cleared. User: administrator, Computer: SRV-APP01'
];

// Exact 490 raw lines: 46 event lines + 444 header/comment lines = 490 lines
const headerComments = Array(444).fill('# SOC Forensic Telemetry Audit Stream Record Archive');
const raw490LogText = [...headerComments, ...regressionEvents].join('\n');

const triage46 = analyzeRawLogText(raw490LogText)!;
assert(triage46 !== null, 'Test 6.1: 46-event dataset ayrıştırıldı');

// 1. Matematiksel Sayaç Kontratı
assert.strictEqual(triage46.rawLinesCount, 490, 'Test 6.2: Raw lines tam 490');
assert.strictEqual(triage46.parsedRecordsCount, 46, 'Test 6.3: Parsed event records tam 46');
assert.strictEqual(triage46.normalizedEventsCount, 46, 'Test 6.4: Normalized events tam 46');
assert.strictEqual(triage46.correlatedEvents.length, 46, 'Test 6.5: Correlated events array uzunluğu 46');

// 2. Verdict Muhasebesi (0 Kritik, 0 Şüpheli, 3 Anomali, 2 FP, 34 Meşru, 7 Belirsiz)
const bk = triage46.wholeLogSummary.breakdown;
assert.strictEqual(bk.critical, 0, 'Test 6.6: 0 Kritik');
assert.strictEqual(bk.suspicious, 0, 'Test 6.7: 0 Şüpheli');
assert.strictEqual(bk.anomaly, 3, 'Test 6.8: 3 Anomali (#36 1102, #37 1102, #38 wevtutil)');
assert.strictEqual(bk.falsePositive, 2, 'Test 6.9: 2 FP Adayı (#10 0xC0000064, #17 0xC000006A)');
assert.strictEqual(bk.benign, 34, 'Test 6.10: 34 Meşru');
assert.strictEqual(bk.unknown, 7, 'Test 6.11: 7 Belirsiz (#15, #16, #23, #24, #25, #27, #42)');
assert.strictEqual(
  bk.critical + bk.suspicious + bk.anomaly + bk.falsePositive + bk.benign + bk.unknown,
  46,
  'Test 6.12: Verdict bucket toplamı tam 46'
);

// 3. Incident Muhasebesi (Olay Sayısına Eklenmez)
assert.strictEqual(triage46.wholeLogSummary.incidentCandidates.length, 1, 'Test 6.13: 1 Incident Candidate (INCIDENT-01)');
assert.strictEqual(triage46.wholeLogSummary.incidentEventsCount, 4, 'Test 6.14: Incident içinde 4 olay (#3, #10, #17, #18)');
assert.strictEqual(triage46.wholeLogSummary.uncorrelatedEventsCount, 42, 'Test 6.15: 42 Bağımsız olay');
assert.strictEqual(
  triage46.wholeLogSummary.incidentEventsCount + triage46.wholeLogSummary.uncorrelatedEventsCount,
  46,
  'Test 6.16: Invariant: 4 + 42 = 46'
);

// 4. INCIDENT-01 Adli Sınıflandırma
const inc01 = triage46.wholeLogSummary.incidentCandidates[0];
assert.strictEqual(inc01.confirmedAttack, false, 'Test 6.17: INCIDENT-01 kesin saldırı değildir (confirmedAttack = false)');
assert.strictEqual(inc01.credentialSprayingConfirmed, false, 'Test 6.18: INCIDENT-01 Credential Spraying değildir (credentialSprayingConfirmed = false)');
assert.strictEqual(inc01.bruteForceConfirmed, false, 'Test 6.19: INCIDENT-01 Brute Force değildir (bruteForceConfirmed = false)');
assert.strictEqual(inc01.compromiseConfirmed, false, 'Test 6.20: INCIDENT-01 sistem ele geçirme değildir (compromiseConfirmed = false)');
assert.strictEqual(inc01.verdict, 'INVESTIGATION_CANDIDATE', 'Test 6.21: Sınıf INVESTIGATION_CANDIDATE olmalıdır');
assert.strictEqual(inc01.mitreTechniques.length, 0, 'Test 6.22: Desteklenmeyen MITRE etiketi basılmaz');

// 5. Event #3 Type 2 + IP Çelişkisi
assert(
  inc01.observedLinks.some((l) => l.includes('Type 2') && l.includes('UNCERTAIN')),
  'Test 6.23: Type 2 + harici IP çelişkisi observedLinks içinde UNCERTAIN olarak raporlanır'
);
assert(
  inc01.missingEvidence.some((m) => m.includes('Type 2') && m.includes('UNCERTAIN')),
  'Test 6.24: Type 2 harici kaynak doğrulama eksik kanıt olarak listelenir'
);

// 6. Event #4 (4672): İdari ayrıcalık gözlemi, Privilege Escalation DEĞİL
const ev4 = triage46.correlatedEvents[3];
assert.strictEqual(ev4.eventId, 4672, 'Test 6.25: Olay 4 Event ID 4672');
assert.strictEqual(ev4.mitreTechnique, undefined, 'Test 6.26: 4672 tek başına yetki yükseltme değildir');
assert(ev4.threatTitle.includes('Özel Ayrıcalık Atandı'), 'Test 6.27: 4672 başlığı doğru');

// 7. Event #9 (whoami.exe): T1059 DEĞİL
const ev9 = triage46.correlatedEvents[8];
assert.strictEqual(ev9.mitreTechnique, undefined, 'Test 6.28: whoami.exe için T1059 atanmaz (NOT_ASSESSED)');

// 8. Event #13 & #26 (Sysmon 11): T1105 DEĞİL
const ev13 = triage46.correlatedEvents[12];
const ev26 = triage46.correlatedEvents[25];
assert.strictEqual(ev13.mitreTechnique, undefined, 'Test 6.29: Sysmon 11 T1105 atanmaz');
assert.strictEqual(ev26.mitreTechnique, undefined, 'Test 6.30: Sysmon 11 T1105 atanmaz');

// 9. Event #15 & #23 (PowerShell 4104): SCRIPT_CONTENT_NOT_ASSESSED / UNKNOWN
const ev15 = triage46.correlatedEvents[14];
const ev23 = triage46.correlatedEvents[22];
assert.strictEqual(ev15.verdict, 'UNKNOWN', 'Test 6.31: Event 15 içeriksiz 4104 UNKNOWN');
assert.strictEqual(ev23.verdict, 'UNKNOWN', 'Test 6.32: Event 23 içeriksiz 4104 UNKNOWN');

// 10. Event #29 (7045): NEW SERVICE INSTALLATION OBSERVED
const ev29 = triage46.correlatedEvents[28];
assert.strictEqual(ev29.eventId, 7045, 'Test 6.33: Event 29 Event ID 7045');
assert(ev29.summaryReason.includes('New Service Installation Observed'), 'Test 6.34: 7045 yeni servis kurulumu gözlemi olarak açıklanır');

// 11. Event #31 (5156): NETWORK CONNECTION PERMITTED
const ev31 = triage46.correlatedEvents[30];
assert.strictEqual(ev31.eventId, 5156, 'Test 6.35: Event 31 Event ID 5156');
assert(ev31.summaryReason.includes('Network Connection Permitted'), 'Test 6.36: 5156 izin verilmiş ağ bağlantısı olarak açıklanır');

// 12. Event #36 & #37 (1102): SUSPICIOUS_ANOMALY, T1070.001
const ev36 = triage46.correlatedEvents[35];
const ev37 = triage46.correlatedEvents[36];
assert.strictEqual(ev36.verdict, 'SUSPICIOUS_ANOMALY', 'Test 6.37: 1102 Anomali');
assert.strictEqual(ev37.verdict, 'SUSPICIOUS_ANOMALY', 'Test 6.38: 1102 Anomali');

// 13. Event #38 (wevtutil.exe): SUSPICIOUS_ANOMALY
const ev38 = triage46.correlatedEvents[37];
assert.strictEqual(ev38.verdict, 'SUSPICIOUS_ANOMALY', 'Test 6.39: wevtutil.exe Anomali');

// 14. Event #42 (/admin/reports/panel.aspx): UNKNOWN, Confidence = 50
const ev42 = triage46.correlatedEvents[41];
assert.strictEqual(ev42.verdict, 'UNKNOWN', 'Test 6.40: /admin/reports/panel.aspx UNKNOWN');
assert.strictEqual(ev42.confidence, 50, 'Test 6.41: Güven skoru 50');

// 15. Event #46 (104): AUTHORIZED_ACTIVITY, T1070.001 atanmaz
const ev46 = triage46.correlatedEvents[45];
assert.strictEqual(ev46.eventId, 104, 'Test 6.42: Event 46 Event ID 104');
assert.strictEqual(ev46.verdict, 'AUTHORIZED_ACTIVITY', 'Test 6.43: Event 104 AUTHORIZED_ACTIVITY');
assert.strictEqual(ev46.mitreTechnique, undefined, 'Test 6.44: Event 104 T1070.001 atanmaz');

// -----------------------------------------------------------------------------
// BÖLÜM 7: SYSMON EVENT 1 ALAN İZOLASYONU, SVCHOST ANOMALİSİ VE BÜTÜNSEL TUTARLILIK
// -----------------------------------------------------------------------------
console.log('\n--- 7. Sysmon Event 1 Alan İzolasyonu ve Anomali Testleri ---');

const twoEventTest = `
# Geçersiz veya başlığı eksik girdi (UNKNOWN)
Invalid raw text without security telemetry host=WIN-SRV-01

# Sysmon Event 1 with multi-field leak test
Microsoft-Windows-Sysmon: [1] Process Create. Image: C:\\Windows\\System32\\svchost.exe CommandLine: "Get-ChildItem C:\\Users\\murat.k\\Documents" ParentImage: C:\\Windows\\System32\\cmd.exe User: svc_backup Logon Type: 3 Source Network Address: 10.20.30.8 Computer: Windows Endpoint
`;

const triageTwo = analyzeRawLogText(twoEventTest)!;
assert(triageTwo !== null, 'Test 7.1: 2 olaylık test logu başarıyla ayrıştırıldı');
assert.strictEqual(triageTwo.parsedRecordsCount, 2, 'Test 7.2: Tam olarak 2 olay ayrıştırıldı');

// Event 1: UNKNOWN
const evTest1 = triageTwo.correlatedEvents[0];
assert.strictEqual(evTest1.verdict, 'UNKNOWN', 'Test 7.3: Event 1 UNKNOWN olmalı');

// Event 2: Sysmon Event 1 Anomaly
const evTest2 = triageTwo.correlatedEvents[1];
assert.strictEqual(evTest2.eventId, 1, 'Test 7.4: Event 2 Sysmon Event 1');
assert.strictEqual(evTest2.user, 'svc_backup', 'Test 7.5: Kullanıcı adı alan sızıntısından temizlenmeli (yalnızca svc_backup)');
assert(!evTest2.user.includes('Logon Type'), 'Test 7.6: Kullanıcı adına Logon Type sızmamalıdır');
assert(!evTest2.user.includes('Source Network Address'), 'Test 7.7: Kullanıcı adına IP adresi sızmamalıdır');
assert.strictEqual(evTest2.verdict, 'SUSPICIOUS_ANOMALY', 'Test 7.8: svchost parent=cmd ve Get-ChildItem veri keşfi SUSPICIOUS_ANOMALY olmalıdır (Körlemesine MEŞRU denemez)');

// Rapor Çıktısı Doğrulaması
const reportTwo = triageTwo.comprehensive6StageReport;
assert(reportTwo.includes('Yürütülen Süreç:'), 'Test 7.9: Sysmon 1 için Yürütülen Süreç başlığı yer alır');
assert(reportTwo.includes('Oturum Türü: Uygulanamaz (Süreç oluşturma)'), 'Test 7.10: Sysmon 1 için Oturum Türü Uygulanamaz olarak sunulur');
assert(!reportTwo.includes('Oturum Türü: Belirtilmemiş / Bilinmiyor'), 'Test 7.11: Sysmon 1 için yanıltıcı Oturum Türü: Bilinmiyor yazılmaz');
assert(!reportTwo.includes('Hata Kodu / Neden: Normal Akış'), 'Test 7.12: Sysmon 1 için oturum hata kodu yazılmaz');

// Bütünsel Gerekçe Doğrulaması: Belirsiz olay varken "Tüm olaylar meşrudur" iddiasında bulunulamaz
const summaryTwo = triageTwo.wholeLogSummary;
assert(!summaryTwo.postureJustification.includes('İncelenen tüm olaylarda yetkili idari işlemler veya olağan sistem günlükleri teyit edilmiştir'), 'Test 7.13: Belirsiz olay varken tüm olaylar teyitli meşru ilan edilmez');

console.log('================================================================');
console.log('✅ TÜM AŞAMA 3.4 ADVERSARIAL FORENSIC & ALAN İZOLASYON TESTLERİ BAŞARIYLA GEÇTİ!');
console.log('================================================================');

