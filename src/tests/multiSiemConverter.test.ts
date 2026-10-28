/**
 * Test Suite: Multi-SIEM Query & Sigma Rule Converter Validation
 */

import {
  generateSplunkQueries,
  generateSentinelKqlQueries,
  generateElasticQueries,
  generateSigmaRule,
  generateAllSiemQueries,
} from '../services/multiSiemConverter';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`[FAIL] ${message}`);
    throw new Error(`Test assertion failed: ${message}`);
  } else {
    console.log(`  [PASS] ${message}`);
  }
}

console.log('================================================================');
console.log('⚡ MULTI-SIEM (SPLUNK, SENTINEL, ELASTIC, SIGMA) TEST SUITE ⚡');
console.log('================================================================');

// -----------------------------------------------------------------------------
// BÖLÜM 1: Windows Event 4625 (Parola Püskürtme & Başarısız Giriş)
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 1: Windows Event 4625 Çoklu SIEM Doğrulaması ---');

const win4625Ctx = {
  eventId: 4625,
  ip: '192.168.10.45',
  user: 'ahmet.kaya',
  rawLog: 'An account failed to log on. Subject: Security ID: S-1-5-18 ... Event ID: 4625 SubStatus: 0xC000006A',
};

// 1.1 Splunk SPL
const splunkWin = generateSplunkQueries(win4625Ctx);
assert(splunkWin.length >= 2, 'Test 1.1: Splunk için en az 2 sorgu üretildi (Stats + Timechart)');
const splunk4625 = splunkWin.find(q => q.id === 'splunk_win_4625_spray');
assert(splunk4625 !== undefined, 'Test 1.2: Splunk EventCode=4625 parola püskürtme sorgusu mevcut');
assert(splunk4625!.query.includes('EventCode=4625'), 'Test 1.3: SPL içinde EventCode=4625 mevcut');
assert(splunk4625!.query.includes('TargetUserName="ahmet.kaya"'), 'Test 1.4: Kullanıcı adı SPL filtresine eklendi');
assert(splunk4625!.query.includes('192.168.10.45'), 'Test 1.5: Kaynak IP adresi SPL filtresine eklendi');

// 1.2 Microsoft Sentinel KQL
const sentinelWin = generateSentinelKqlQueries(win4625Ctx);
const kql4625 = sentinelWin.find(q => q.id === 'kql_win_4625_spray');
assert(kql4625 !== undefined, 'Test 1.6: Sentinel KQL EventID 4625 sorgusu mevcut');
assert(kql4625!.query.includes('EventID == 4625'), 'Test 1.7: KQL içinde EventID == 4625 mevcut');
assert(kql4625!.query.includes('TargetAccount has "ahmet.kaya"'), 'Test 1.8: Hedef hesap KQL filtresine eklendi');
assert(kql4625!.query.includes('192.168.10.45'), 'Test 1.9: Kaynak IP KQL filtresine eklendi');

// 1.3 Elasticsearch (ECS Standardı KQL & EQL)
const elasticWin = generateElasticQueries(win4625Ctx);
const elastic4625Kql = elasticWin.find(q => q.id === 'elastic_win_4625_kql');
assert(elastic4625Kql !== undefined, 'Test 1.10: Elastic KQL sorgusu mevcut');
assert(elastic4625Kql!.query.includes('winlog.event_id: 4625'), 'Test 1.11: Elastic KQL ECS uyumlu winlog.event_id içeriyor');
assert(elastic4625Kql!.query.includes('user.name: "ahmet.kaya"'), 'Test 1.12: Elastic KQL user.name filtresi içeriyor');
const elastic4625Eql = elasticWin.find(q => q.id === 'elastic_win_4625_eql');
assert(elastic4625Eql !== undefined, 'Test 1.13: Elastic EQL korelasyon kuralı mevcut');

// 1.4 Sigma Kuralı (YAML)
const sigmaWin = generateSigmaRule(win4625Ctx);
const sigma4625 = sigmaWin.find(q => q.id === 'sigma_win_4625');
assert(sigma4625 !== undefined, 'Test 1.14: Sigma Event 4625 YAML kuralı mevcut');
assert(sigma4625!.query.includes('EventID: 4625'), 'Test 1.15: Sigma detection içinde EventID: 4625 mevcut');
assert(sigma4625!.query.includes('SourceNetworkAddress: \'192.168.10.45\''), 'Test 1.16: Sigma detection içinde kaynak IP mevcut');
assert(sigma4625!.query.includes('attack.t1110.003'), 'Test 1.17: Sigma MITRE ATT&CK T1110.003 etiketi mevcut');

// -----------------------------------------------------------------------------
// BÖLÜM 2: Şüpheli Komut Satırı ve LOLBAS (PowerShell -enc / vssadmin)
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 2: Şüpheli Komut & LOLBAS Çoklu SIEM Doğrulaması ---');

const lolbasCtx = {
  eventId: 4688,
  processName: 'powershell.exe',
  commandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
  rawLog: 'A new process has been created. Event ID: 4688 New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Process Command Line: powershell.exe -enc ...',
};

// 2.1 Splunk LOLBAS
const splunkLolbas = generateSplunkQueries(lolbasCtx).find(q => q.id === 'splunk_win_4688_process');
assert(splunkLolbas !== undefined, 'Test 2.1: Splunk 4688 / Sysmon 1 komut avı sorgusu mevcut');
assert(splunkLolbas!.query.includes('CommandLine="*powershell*"'), 'Test 2.2: Splunk sorgusu CommandLine inceliyor');

// 2.2 Sentinel KQL LOLBAS
const sentinelLolbas = generateSentinelKqlQueries(lolbasCtx).find(q => q.id === 'kql_win_4688_process');
assert(sentinelLolbas !== undefined, 'Test 2.3: Sentinel 4688 komut avı sorgusu mevcut');
assert(sentinelLolbas!.query.includes('CommandLine has_any'), 'Test 2.4: Sentinel sorgusu LOLBAS listesini has_any ile tarıyor');

// 2.3 Elastic ECS LOLBAS
const elasticLolbas = generateElasticQueries(lolbasCtx).find(q => q.id === 'elastic_win_4688_kql');
assert(elasticLolbas !== undefined, 'Test 2.5: Elastic ECS process.command_line sorgusu mevcut');
assert(elasticLolbas!.query.includes('process.command_line: (*powershell* and *-enc*)'), 'Test 2.6: Elastic ECS powershell -enc filtresi içeriyor');

// 2.4 Sigma LOLBAS
const sigmaLolbas = generateSigmaRule(lolbasCtx).find(q => q.id === 'sigma_win_process_lolbas');
assert(sigmaLolbas !== undefined, 'Test 2.7: Sigma LOLBAS kuralı mevcut');
assert(sigmaLolbas!.query.includes('CommandLine|contains:'), 'Test 2.8: Sigma YAML CommandLine filtresi içeriyor');
assert(sigmaLolbas!.query.includes('vssadmin delete shadows'), 'Test 2.9: Sigma YAML vssadmin engeli içeriyor');

// -----------------------------------------------------------------------------
// BÖLÜM 3: Web Saldırısı (SQL Injection / Log4j JNDI)
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 3: Web İstismar (SQLi / JNDI) Çoklu SIEM Doğrulaması ---');

const webExploitCtx = {
  method: 'GET',
  url: '/api/search?q=1 UNION SELECT null, username, password FROM users--',
  ip: '185.220.101.5',
  statusCode: 200,
  rawLog: '185.220.101.5 - - [23/Sep/2026:10:00:00] "GET /api/search?q=1%20UNION%20SELECT HTTP/1.1" 200 4500',
};

// 3.1 Splunk Web
const splunkWeb = generateSplunkQueries(webExploitCtx).find(q => q.id === 'splunk_web_sqli_rce');
assert(splunkWeb !== undefined, 'Test 3.1: Splunk web exploit sorgusu mevcut');
assert(splunkWeb!.query.includes('uri="*union*select*"'), 'Test 3.2: Splunk uri union select filtresi içeriyor');

// 3.2 Sentinel KQL WAF
const sentinelWeb = generateSentinelKqlQueries(webExploitCtx).find(q => q.id === 'kql_web_sqli_rce');
assert(sentinelWeb !== undefined, 'Test 3.3: Sentinel WAF / ApplicationGatewayFirewallLog sorgusu mevcut');
assert(sentinelWeb!.query.includes('ApplicationGatewayFirewallLog'), 'Test 3.4: Sentinel WAF log kaynağı hedeflendi');

// 3.3 Elastic Web
const elasticWeb = generateElasticQueries(webExploitCtx).find(q => q.id === 'elastic_web_kql');
assert(elasticWeb !== undefined, 'Test 3.5: Elastic ECS url.original sorgusu mevcut');
assert(elasticWeb!.query.includes('url.original: (*union*select*'), 'Test 3.6: Elastic url.original filtresi içeriyor');

// 3.4 Sigma Web
const sigmaWeb = generateSigmaRule(webExploitCtx).find(q => q.id === 'sigma_web_exploit');
assert(sigmaWeb !== undefined, 'Test 3.7: Sigma Web Exploit YAML kuralı mevcut');
assert(sigmaWeb!.query.includes('c-uri|contains:'), 'Test 3.8: Sigma c-uri filtresi içeriyor');

// -----------------------------------------------------------------------------
// BÖLÜM 4: Bütünleşik Agregasyon (generateAllSiemQueries)
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 4: Bütünleşik Agregasyon Fonksiyonu ---');

const allQueries = generateAllSiemQueries(win4625Ctx);
assert(allQueries.SPLUNK.length > 0, 'Test 4.1: Bütünleşik Splunk listesi dolu');
assert(allQueries.SENTINEL.length > 0, 'Test 4.2: Bütünleşik Sentinel listesi dolu');
assert(allQueries.ELASTIC.length > 0, 'Test 4.3: Bütünleşik Elastic listesi dolu');
assert(allQueries.SIGMA.length > 0, 'Test 4.4: Bütünleşik Sigma listesi dolu');

console.log('\n================================================================');
console.log('✅ TÜM ÇOKLU SIEM & SIGMA DÖNÜŞTÜRÜCÜ TESTLERİ BAŞARIYLA GEÇTİ!');
console.log('================================================================');
