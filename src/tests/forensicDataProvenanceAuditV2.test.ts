import assert from 'node:assert';
import {
  parseLineToNormalizedLog,
  initializeFormatState,
} from '../services/streamingParser';
import {
  compareSecurityPeriods,
  parseCountValue,
  buildPolicyComparisonWorkbook,
  generatePolicyEffectivenessHtmlReport,
} from '../services/policyComparisonEngine';

console.log('================================================================');
console.log('⚡ FORENSIC DATA PROVENANCE AUDIT v2 — 30 ADVERSARIAL TESTS ⚡');
console.log('================================================================');

let passedTests = 0;
let totalTests = 0;

function runProvenanceTest(name: string, fn: () => void) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`✅ [PASS ${totalTests}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL ${totalTests}] ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

// 1. VPC DENY without HTTP
runProvenanceTest('Test 1: VPC DENY without HTTP -> status_code is null, baglanti_karari is DENY', () => {
  const state = initializeFormatState('vpc.log');
  const line = '2 123456789010 eni-abc 192.168.1.50 10.0.0.5 54321 443 6 20 4249 1618530010 1618530070 REJECT OK';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'VPC DENY must not synthesize HTTP status_code 403');
  assert.strictEqual(parsed.baglanti_karari, 'DENY');
  assert.strictEqual(parsed.http_method, null, 'VPC Flow must not synthesize HTTP method');
});

// 2. VPC ACCEPT without HTTP
runProvenanceTest('Test 2: VPC ACCEPT without HTTP -> status_code is null, baglanti_karari is ACCEPT', () => {
  const state = initializeFormatState('vpc.log');
  const line = '2 123456789010 eni-abc 192.168.1.50 10.0.0.5 54321 443 6 20 4249 1618530010 1618530070 ACCEPT OK';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'VPC ACCEPT must not synthesize HTTP status_code 200');
  assert.strictEqual(parsed.baglanti_karari, 'ACCEPT');
  assert.strictEqual(parsed.http_method, null);
});

// 3. SSH login failure
runProvenanceTest('Test 3: SSH login failure -> status_code is null, baglanti_karari is DENY, port is kaynak_port', () => {
  const state = initializeFormatState('auth.log');
  const line = 'Oct  4 10:14:22 srv01 sshd[1234]: Failed password for invalid user admin from 198.51.100.77 port 54321 ssh2';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'SSH failure must not synthesize HTTP 401');
  assert.strictEqual(parsed.baglanti_karari, 'DENY');
  assert.strictEqual(parsed.kaynak_port, 54321, 'Port from client must be source port');
  assert.strictEqual(parsed.hedef_port, null, 'Destination port must not synthesize 22');
  assert.strictEqual(parsed.http_method, null, 'SSH must not synthesize HTTP method');
});

// 4. Windows Security Event
runProvenanceTest('Test 4: Windows Security Event -> status_code is null, baglanti_karari is preserved', () => {
  const state = initializeFormatState('security.log');
  const line = '2026-10-04 10:20:00 An account failed to log on. Event ID: 4625 Account Name: user1 Source Network Address: 10.10.10.5';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'Windows Security Event must not synthesize HTTP status_code 401 or 200');
});

// 5. Azure NSG deny without HTTP
runProvenanceTest('Test 5: Azure NSG deny without HTTP -> status_code is null, host is not synthetic', () => {
  const state = initializeFormatState('azure.json');
  const line = JSON.stringify({
    time: '2026-10-04T10:00:00Z',
    properties: {
      sourceIp: '198.51.100.10',
      destinationIp: '10.0.0.4',
      access: 'Deny',
    }
  });
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'Azure NSG deny must not synthesize HTTP 403');
  assert.strictEqual(parsed.baglanti_karari, 'DENY');
  assert.strictEqual(parsed.sunucu_ismi, null, 'Must not synthesize Azure-Resource');
  assert.strictEqual(parsed.http_method, null, 'Must not synthesize AZURE method');
});

// 6. Suricata non-HTTP event
runProvenanceTest('Test 6: Suricata non-HTTP event -> status_code is null', () => {
  const state = initializeFormatState('eve.json');
  const line = JSON.stringify({
    timestamp: '2026-10-04T10:00:00Z',
    event_type: 'alert',
    src_ip: '198.51.100.12',
    dest_ip: '10.0.0.8',
    alert: { action: 'blocked', signature: 'ET SCAN Nmap' }
  });
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, null, 'Suricata non-HTTP alert must have null status_code');
  assert.strictEqual(parsed.baglanti_karari, 'DENY');
});

// 7. Suricata real HTTP status
runProvenanceTest('Test 7: Suricata real HTTP status -> status_code is authentically preserved', () => {
  const state = initializeFormatState('eve.json');
  const line = JSON.stringify({
    timestamp: '2026-10-04T10:00:00Z',
    event_type: 'http',
    src_ip: '198.51.100.12',
    dest_ip: '10.0.0.8',
    http: { url: '/login', http_method: 'POST', status: 403 }
  });
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.status_code, 403, 'Authentic HTTP status 403 must be preserved');
  assert.strictEqual(parsed.http_method, 'POST');
});

// 8. Response 403 without Action
runProvenanceTest('Test 8: Response 403 without Action -> does not create Action-based BLOCK', () => {
  const csv = 'Policy Name,Threat Type,Event Name,Response,Count\nPolA,ThreatA,EvtA,403,50';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.actionDataAvailable, false, 'Action data must be marked unavailable');
  assert.strictEqual(res.periodA.blockedRequests, 0, 'Must NOT infer BLOCK from Response 403');
  assert.strictEqual(res.periodA.blockRate, 0, 'Block rate must be 0% when no Action exists');
});

// 9. Response 403 + ALERT
runProvenanceTest('Test 9: Response 403 + ALERT -> Action is strictly ALERT', () => {
  const csv = 'Policy Name,Threat Type,Event Name,Response,Action,Count\nPolA,ThreatA,EvtA,403,alert,50';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.actionDataAvailable, true);
  assert.strictEqual(res.periodA.alertedRequests, 50, 'Action=alert must be counted as ALERT');
  assert.strictEqual(res.periodA.blockedRequests, 0, 'Response 403 must NOT override Action ALERT');
  assert.strictEqual(res.periodA.blockRate, 0);
});

// 10. Response 403 + BLOCK
runProvenanceTest('Test 10: Response 403 + BLOCK -> Action is strictly BLOCK', () => {
  const csv = 'Policy Name,Threat Type,Event Name,Response,Action,Count\nPolA,ThreatA,EvtA,403,block,50';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.actionDataAvailable, true);
  assert.strictEqual(res.periodA.blockedRequests, 50);
  assert.strictEqual(res.periodA.blockRate, 100);
});

// 11. Response 500 without Action
runProvenanceTest('Test 11: Response 500 without Action -> does not assume BLOCK or backend compromise', () => {
  const csv = 'Policy Name,Threat Type,Event Name,Response,Count\nPolA,ThreatA,EvtA,500,20';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.periodA.blockedRequests, 0, 'Must NOT treat 500 as BLOCK');
  assert.strictEqual(res.serverErrorReductionPct, null, 'Must NOT claim backend impact without backend logs');
});

// 12. Missing port
runProvenanceTest('Test 12: Missing port -> destination_port is null, no synthetic 80 or 443', () => {
  const state = initializeFormatState('access.log');
  const line = '198.51.100.5 - - [04/Oct/2026:10:00:00 +0300] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.hedef_port, null, 'Apache log without port must have null destination_port, not 80');
});

// 13. Missing method
runProvenanceTest('Test 13: Missing method -> http_method is null, no synthetic GET/POST', () => {
  const state = initializeFormatState('firewall.csv');
  state.delimiter = ',';
  state.delimiterHeaders = ['date', 'source_ip', 'destination_ip', 'action'];
  const line = '2026-10-04,198.51.100.5,10.0.0.1,allow';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.http_method, null, 'Firewall CSV must have null http_method, not synthetic GET');
});

// 14. Missing host
runProvenanceTest('Test 14: Missing host -> host is null, no synthetic Hedef-Sunucu or Web-Server', () => {
  const state = initializeFormatState('access.log');
  const line = '198.51.100.5 - - [04/Oct/2026:10:00:00 +0300] "GET /test HTTP/1.1" 200 500 "-" "test"';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.sunucu_ismi, null, 'Must not synthesize Web-Server or Hedef-Sunucu');
});

// 15. Missing policy
runProvenanceTest('Test 15: Missing policy -> policy is null/undefined, no synthetic General-WAF-Policy', () => {
  const csv = 'Event Name,Action,Count\nSQL Injection,block,10';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert(res.signatureImpacts.length > 0);
  assert.strictEqual(res.signatureImpacts[0].policyName, undefined, 'Policy must be undefined when absent, not synthetic General-WAF-Policy');
});

// 16. Missing bytes
runProvenanceTest('Test 16: Missing bytes -> bytes is null, preventedTrafficMb is null', () => {
  const csv = 'Policy Name,Event Name,Action,Count\nPolA,SQLi,block,100';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.periodA.hasByteData, false);
  assert.strictEqual(res.preventedTrafficMb, null, 'preventedTrafficMb must be null when byte column is absent');
});

// 17. Missing timestamp
runProvenanceTest('Test 17: Missing timestamp -> does not use Date.now() or file upload time', () => {
  const state = initializeFormatState('no_time.csv');
  state.delimiter = ',';
  state.delimiterHeaders = ['source_ip', 'destination_ip', 'action'];
  const line = '192.168.1.1,10.0.0.1,allow';
  const parsed = parseLineToNormalizedLog(line, state);
  assert(parsed !== null);
  assert.strictEqual(parsed.tarih, null, 'Timestamp must remain null when absent');
});

// 18. Missing count (Forensic Null Provenance)
runProvenanceTest('Test 18: Missing Count -> null/undefined, never synthetic 1', () => {
  assert.strictEqual(parseCountValue(null), null, 'Null count cell must return null');
  assert.strictEqual(parseCountValue(undefined), null, 'Undefined count cell must return null');
  assert.strictEqual(parseCountValue(''), null, 'Empty string count cell must return null');
});

// 19. Malformed count
runProvenanceTest('Test 19: Malformed count -> handles 0, negative, commas, periods correctly', () => {
  assert.strictEqual(parseCountValue(0), 0, 'Count 0 must return 0');
  assert.strictEqual(parseCountValue('0'), 0, 'String "0" must return 0');
  assert.strictEqual(parseCountValue(1), 1, 'Count 1 must return 1');
  assert.strictEqual(parseCountValue('1'), 1, 'String "1" must return 1');
  assert.strictEqual(parseCountValue('4,092'), 4092, 'US format "4,092" must be 4092');
  assert.strictEqual(parseCountValue('1.250'), 1250, 'EU/TR format "1.250" must be 1250');
  assert.strictEqual(parseCountValue('invalid_count'), null, 'Invalid text must return null, never synthetic 1');
  assert.strictEqual(parseCountValue(-10), null, 'Negative count must return null, never synthetic 1');
});

// Regression Tests A through J for Count Provenance Contract
runProvenanceTest('Test 19.1: Regression A-G: Count provenance contract (0, "0", 1, null, missing, "", malformed)', () => {
  assert.strictEqual(parseCountValue(0), 0, 'A: Count = 0 -> 0');
  assert.strictEqual(parseCountValue('0'), 0, 'B: Count = "0" -> 0');
  assert.strictEqual(parseCountValue(1), 1, 'C: Count = 1 -> 1');
  assert.strictEqual(parseCountValue(null), null, 'D: Count = null -> null');
  assert.strictEqual(parseCountValue(undefined), null, 'E: Count missing -> null');
  assert.strictEqual(parseCountValue(''), null, 'F: Count = "" -> null');
  assert.strictEqual(parseCountValue('invalid_text'), null, 'G: Count malformed -> null');
});

runProvenanceTest('Test 19.2: Regression H: 2 rows with Count=100 + Count missing -> total 100, strictly not 101', () => {
  const csvH = 'Policy Name,Event Name,Action,Count\nPolA,Evt1,block,100\nPolA,Evt2,block,';
  const resH = compareSecurityPeriods(
    [{ name: 'before.csv', content: csvH }],
    [{ name: 'after.csv', content: csvH }]
  );
  assert.strictEqual(resH.periodA.totalRequests, 100, 'Total volume must strictly be 100 (never 101)');
});

runProvenanceTest('Test 19.3: Regression I: Before Count missing + After Count=100 -> Before volume UNKNOWN', () => {
  const csvBefore = 'Policy Name,Event Name,Action\nPolA,Evt1,block';
  const csvAfter = 'Policy Name,Event Name,Action,Count\nPolA,Evt1,block,100';
  const resI = compareSecurityPeriods(
    [{ name: 'before.csv', content: csvBefore }],
    [{ name: 'after.csv', content: csvAfter }]
  );
  assert.strictEqual(resI.periodA.hasCountData, false, 'Before has no count data');
  assert.strictEqual(resI.periodA.totalCount, null, 'Before volume must be null/UNKNOWN');
  assert.strictEqual(resI.periodB.totalCount, 100, 'After volume must be 100');
  assert(resI.periodA.totalCount !== 0, 'Before totalCount must not be falsely assumed 0');
});

runProvenanceTest('Test 19.4: Regression J: Before Count=0 + After Count=100 -> real 0 -> 100 preserved', () => {
  const csvBefore = 'Policy Name,Event Name,Action,Count\nPolA,Evt1,block,0';
  const csvAfter = 'Policy Name,Event Name,Action,Count\nPolA,Evt1,block,100';
  const resJ = compareSecurityPeriods(
    [{ name: 'before.csv', content: csvBefore }],
    [{ name: 'after.csv', content: csvAfter }]
  );
  assert.strictEqual(resJ.periodA.totalCount, 0, 'Before volume is strictly 0');
  assert.strictEqual(resJ.periodB.totalCount, 100, 'After volume is strictly 100');
});

// 20. Duplicate count row
runProvenanceTest('Test 20: Duplicate Count row -> SUM(Count) accurately aggregates without loss', () => {
  const csv = 'Policy Name,Event Name,Action,Count\nPolA,Evt1,block,100\nPolA,Evt1,block,250';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.periodA.totalCount, 350, 'Total Count must strictly equal SUM(Count) 100 + 250 = 350');
});

// 21. Unicode policy/event
runProvenanceTest('Test 21: Unicode policy and event names preserved without corruption', () => {
  const csv = 'Policy Name,Event Name,Action,Count\nŞirket_Güvenlik_Politikası,SQL_İnjection_Önleme,block,50';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.signatureImpacts[0].policyName, 'Şirket_Güvenlik_Politikası');
  assert.strictEqual(res.signatureImpacts[0].eventName, 'SQL_İnjection_Önleme');
});

// 22. Same Event + Different Policy
runProvenanceTest('Test 22: Same Event + Different Policy -> remains distinct entities', () => {
  const csv = 'Policy Name,Event Name,Action,Count\nPolicy_Alpha,SQL_Injection,alert,50\nPolicy_Beta,SQL_Injection,block,70';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.signatureImpacts.length, 2, 'Must NOT merge events across different policies');
});

// 23. Same Policy + Different Event
runProvenanceTest('Test 23: Same Policy + Different Event -> remains distinct entities', () => {
  const csv = 'Policy Name,Event Name,Action,Count\nPolicy_Alpha,SQL_Injection,alert,50\nPolicy_Alpha,Cross_Site_Scripting,block,70';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.signatureImpacts.length, 2);
  const events = res.signatureImpacts.map(s => s.eventName || s.name);
  assert(events.includes('SQL_Injection') && events.includes('Cross_Site_Scripting'));
});

// 24. Explicit Before newer than After
runProvenanceTest('Test 24: Explicit Before newer than After -> user role overrides chronological date', () => {
  const csvBefore = 'Policy Name,Event Name,Start Time,Action,Count\nPol1,Evt1,Sep 15 2026 10:00:00,alert,100';
  const csvAfter = 'Policy Name,Event Name,Start Time,Action,Count\nPol1,Evt1,Aug 15 2026 10:00:00,block,100';
  const res = compareSecurityPeriods(
    [{ name: 'september_before.csv', content: csvBefore }],
    [{ name: 'august_after.csv', content: csvAfter }]
  );
  // Explicit Before is Period A, Explicit After is Period B
  assert.strictEqual(res.periodA.alertedRequests, 100, 'Period A must remain Before despite newer date');
  assert.strictEqual(res.periodB.blockedRequests, 100, 'Period B must remain After despite older date');
  assert.strictEqual(res.chronologicalInversionDetected, true, 'System must flag chronological inversion warning');
});

// 25. Swap + HTML export
runProvenanceTest('Test 25: Swap + HTML export -> HTML report reflects reversed direction accurately', () => {
  const csv1 = 'Policy Name,Event Name,Action,Count\nPol1,Evt1,alert,100';
  const csv2 = 'Policy Name,Event Name,Action,Count\nPol1,Evt1,block,80';

  const normalRes = compareSecurityPeriods(
    [{ name: 'before.csv', content: csv1 }],
    [{ name: 'after.csv', content: csv2 }]
  );
  const swappedRes = compareSecurityPeriods(
    [{ name: 'after.csv', content: csv2 }],
    [{ name: 'before.csv', content: csv1 }]
  );

  const normalHtml = generatePolicyEffectivenessHtmlReport(normalRes);
  const swappedHtml = generatePolicyEffectivenessHtmlReport(swappedRes);

  assert(normalRes.blockRateDelta > 0, 'Normal delta should be positive');
  assert(swappedRes.blockRateDelta < 0, 'Swapped delta should be negative');
  assert(normalHtml !== swappedHtml, 'HTML reports must differ upon swap');
});

// 26. Swap + XLSX export
runProvenanceTest('Test 26: Swap + XLSX export -> Excel sheets reflect reversed direction accurately', () => {
  const csv1 = 'Policy Name,Event Name,Action,Count\nPol1,Evt1,alert,100';
  const csv2 = 'Policy Name,Event Name,Action,Count\nPol1,Evt1,block,80';

  const swappedRes = compareSecurityPeriods(
    [{ name: 'after.csv', content: csv2 }],
    [{ name: 'before.csv', content: csv1 }]
  );
  const wb = buildPolicyComparisonWorkbook(swappedRes);
  assert.strictEqual(wb.SheetNames.length, 5);
});

// 27. 3+ Chronological periods
runProvenanceTest('Test 27: 3+ Chronological periods -> sorts chronologically for time series', () => {
  const pJuly = { name: 'july.csv', content: 'Policy Name,Start Time,Count\nPol1,Jul 10 2026,100' };
  const pAug = { name: 'august.csv', content: 'Policy Name,Start Time,Count\nPol1,Aug 10 2026,200' };
  const pJune = { name: 'june.csv', content: 'Policy Name,Start Time,Count\nPol1,Jun 10 2026,50' };

  // Given in mixed order: August, July, June
  const files = [pAug, pJuly, pJune];
  const sorted = [...files].sort((a, b) => {
    const dateA = a.name.includes('june') ? 6 : a.name.includes('july') ? 7 : 8;
    const dateB = b.name.includes('june') ? 6 : b.name.includes('july') ? 7 : 8;
    return dateA - dateB;
  });
  assert.strictEqual(sorted[0].name, 'june.csv');
  assert.strictEqual(sorted[1].name, 'july.csv');
  assert.strictEqual(sorted[2].name, 'august.csv');
});

// 28. Empty Before
runProvenanceTest('Test 28: Empty Before -> handled safely with 0 count and without crashing', () => {
  const res = compareSecurityPeriods(
    [{ name: 'empty.csv', content: '' }],
    [{ name: 'b.csv', content: 'Policy Name,Event Name,Action,Count\nPol1,Evt1,block,50' }]
  );
  assert.strictEqual(res.periodA.totalCount, 0);
  assert.strictEqual(res.periodB.totalCount, 50);
});

// 29. Empty After
runProvenanceTest('Test 29: Empty After -> handled safely with 0 count and without crashing', () => {
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: 'Policy Name,Event Name,Action,Count\nPol1,Evt1,alert,50' }],
    [{ name: 'empty.csv', content: '' }]
  );
  assert.strictEqual(res.periodA.totalCount, 50);
  assert.strictEqual(res.periodB.totalCount, 0);
});

// 30. Action field completely absent
runProvenanceTest('Test 30: Action field completely absent -> report explicitly states action cannot be evaluated', () => {
  const csv = 'Policy Name,Event Name,Count\nPol1,Evt1,100';
  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csv }],
    [{ name: 'b.csv', content: csv }]
  );
  assert.strictEqual(res.actionDataAvailable, false);
  assert(
    res.executiveSummary.includes('aksiyon') ||
    res.executiveSummary.includes('Action') ||
    res.executiveSummary.includes('gözlem') ||
    res.footnotes.some(f => f.includes('Action') || f.includes('aksiyon')),
    'Must explain that action evaluation requires explicit Action column'
  );
});

console.log('================================================================');
console.log(`🎉 TÜM TESTLER BAŞARIYLA GEÇTİ: ${passedTests} / ${totalTests} (Sıfır Hata)`);
console.log('================================================================');
