/**
 * ADVERSARIAL & EXTREME EDGE-CASE TEST SUITE FOR MULTI-SIEM ENGINE
 * 
 * Tests against:
 * 1. Quote Injection & Slash Escape Attacks (Bypass attempt)
 * 2. Garbage Placeholders (Hyphens, N/A, Bilinmiyor, Null, Undefined)
 * 3. Extreme Syntax & Bracket Balancing (Splunk SPL, KQL, EQL, YAML)
 * 4. Empty / Corrupted / Mixed Log Traps
 */

import {
  generateSplunkQueries,
  generateSentinelKqlQueries,
  generateElasticQueries,
  generateSigmaRule,
  cleanVal,
  escapeSpl,
  escapeKql,
  escapeElastic,
  escapeYaml,
} from '../services/multiSiemConverter';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ [FAIL] ${message}`);
    throw new Error(`Test assertion failed: ${message}`);
  } else {
    console.log(`  ✅ [PASS] ${message}`);
  }
}

console.log('================================================================');
console.log('🔥 ADVERSARIAL & STRESS TEST SUITE: MULTI-SIEM CONVERTER 🔥');
console.log('================================================================');

// -----------------------------------------------------------------------------
// STRES TESTİ 1: Zehirli Girdi ve Tırnak Kırma (Escaping & Injection Defense)
// -----------------------------------------------------------------------------
console.log('\n--- Test 1: Zehirli Karakterler, Kaçış ve Tırnak Kırma Koruması ---');

const toxicUser = 'CORP\\admin" OR 1=1 --';
const toxicIp = '10.0.0.1" OR *';
const toxicProc = 'powershell.exe" -enc';

const toxicCtx = {
  eventId: 4625,
  ip: toxicIp,
  user: toxicUser,
  processName: toxicProc,
  rawLog: 'EventID=4625 user=CORP\\admin" OR 1=1 -- ip=10.0.0.1" OR *',
};

// 1.1 Splunk Kaçış Doğrulaması
const splunkQueries = generateSplunkQueries(toxicCtx);
const splunk4625 = splunkQueries.find(q => q.id === 'splunk_win_4625_spray')!;
assert(!splunk4625.query.includes('TargetUserName="CORP\\admin" OR 1=1 --"'), 'Test 1.1: Çift tırnak korunmasız bırakılmadı (SPL enjeksiyonu engellendi)');
assert(splunk4625.query.includes('\\"'), 'Test 1.2: Çift tırnak güvenli bir şekilde \\" ile kaçırıldı');
assert(splunk4625.query.includes('\\\\'), 'Test 1.3: Ters slash (\\) güvenli bir şekilde \\\\ ile kaçırıldı');

// 1.2 Sentinel KQL Kaçış Doğrulaması
const sentinelQueries = generateSentinelKqlQueries(toxicCtx);
const kql4625 = sentinelQueries.find(q => q.id === 'kql_win_4625_spray')!;
assert(!kql4625.query.includes('TargetAccount has "CORP\\admin" OR 1=1 --"'), 'Test 1.4: KQL içinde kontrolsüz çift tırnak bırakılmadı');
assert(kql4625.query.includes('\\"'), 'Test 1.5: KQL için çift tırnak \\" olarak kaçırıldı');

// 1.3 Elastic KQL Kaçış Doğrulaması
const elasticQueries = generateElasticQueries(toxicCtx);
const elastic4625 = elasticQueries.find(q => q.id === 'elastic_win_4625_kql')!;
assert(elastic4625.query.includes('\\"'), 'Test 1.6: Elastic KQL için tırnak kaçışı sağlandı');

// 1.4 Sigma YAML Kaçış Doğrulaması
const sigmaRules = generateSigmaRule(toxicCtx);
const sigma4625 = sigmaRules.find(q => q.id === 'sigma_win_4625')!;
assert(!sigma4625.query.includes("TargetUserName: 'CORP\\admin'"), 'Test 1.7: YAML tek tırnağı tek bırakılmadı');

// -----------------------------------------------------------------------------
// STRES TESTİ 2: Çöp ve Sahte Değerlerin Temizlenmesi (Garbage Sanitization)
// -----------------------------------------------------------------------------
console.log('\n--- Test 2: Çöp Değerlerin (-, bilinmiyor, null, N/A) Filtreye Sızmaması ---');

const garbagePlaceholders = ['-', 'bilinmiyor', 'BILINMIYOR', 'unknown', 'UNKNOWN', 'n/a', 'N/A', 'null', 'none', '   '];

for (const garbage of garbagePlaceholders) {
  const cleaned = cleanVal(garbage, '');
  assert(cleaned === '', `Test 2.1 [${garbage}]: Çöp değer boş fallback değerine temizlendi`);
}

const garbageCtx = {
  eventId: 4625,
  ip: '-',
  user: 'bilinmiyor',
  destIp: 'N/A',
  processName: 'unknown',
  rawLog: 'EventID 4625 failed logon',
};

const garbageSplunk = generateSplunkQueries(garbageCtx).find(q => q.id === 'splunk_win_4625_spray')!;
assert(!garbageSplunk.query.includes('TargetUserName="-"'), 'Test 2.2: Splunk sorgusuna TargetUserName="-" sızmadı');
assert(!garbageSplunk.query.includes('TargetUserName="bilinmiyor"'), 'Test 2.3: Splunk sorgusuna TargetUserName="bilinmiyor" sızmadı');
assert(!garbageSplunk.query.includes('Source_Network_Address="-"'), 'Test 2.4: Splunk sorgusuna Source_Network_Address="-" sızmadı');

const garbageSentinel = generateSentinelKqlQueries(garbageCtx).find(q => q.id === 'kql_win_4625_spray')!;
assert(!garbageSentinel.query.includes('| where TargetAccount has "bilinmiyor"'), 'Test 2.5: Sentinel KQL sorgusuna sahte hesap sızmadı');
assert(!garbageSentinel.query.includes('| where IpAddress == "-"'), 'Test 2.6: Sentinel KQL sorgusuna sahte IP sızmadı');

// -----------------------------------------------------------------------------
// STRES TESTİ 3: Sözdizimi, Boru (|) ve Parantez Dengesi (Syntax Balance)
// -----------------------------------------------------------------------------
console.log('\n--- Test 3: Sözdizimi, Boru (|), Tırnak ve Parantez Dengesi ---');

function countChar(str: string, char: string): number {
  let count = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === char) count++;
  }
  return count;
}

// 3.1 Splunk SPL Boru & Parantez Dengesi
for (const q of splunkQueries) {
  const openParen = countChar(q.query, '(');
  const closeParen = countChar(q.query, ')');
  assert(openParen === closeParen, `Test 3.1 [${q.id}]: Splunk SPL parantezleri dengeli (${openParen} açılış == ${closeParen} kapanış)`);

  const lines = q.query.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('|')) {
      const command = trimmed.substring(1).trim().split(' ')[0];
      const validSplunkCommands = ['stats', 'search', 'timechart', 'where', 'sort', 'table'];
      assert(validSplunkCommands.includes(command), `Test 3.2 [${q.id}]: Borudan sonraki SPL komutu geçerli (${command})`);
    }
  }
}

// 3.2 Sentinel KQL Boru & Parantez Dengesi
for (const q of sentinelQueries) {
  const openParen = countChar(q.query, '(');
  const closeParen = countChar(q.query, ')');
  assert(openParen === closeParen, `Test 3.3 [${q.id}]: Sentinel KQL parantezleri dengeli (${openParen} açılış == ${closeParen} kapanış)`);

  const lines = q.query.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('|')) {
      const command = trimmed.substring(1).trim().split(' ')[0];
      const validKqlCommands = ['where', 'summarize', 'project', 'sort', 'render'];
      assert(validKqlCommands.includes(command), `Test 3.4 [${q.id}]: Borudan sonraki KQL komutu geçerli (${command})`);
    }
  }
}

// 3.3 Sigma YAML Format ve Alan Bütünlüğü
for (const q of sigmaRules) {
  assert(q.query.includes('title:'), `Test 3.5 [${q.id}]: Sigma kuralında 'title:' mevcut`);
  assert(q.query.includes('logsource:'), `Test 3.6 [${q.id}]: Sigma kuralında 'logsource:' mevcut`);
  assert(q.query.includes('detection:'), `Test 3.7 [${q.id}]: Sigma kuralında 'detection:' mevcut`);
  assert(q.query.includes('condition:'), `Test 3.8 [${q.id}]: Sigma kuralında 'condition:' mevcut`);
  assert(q.query.includes('level:'), `Test 3.9 [${q.id}]: Sigma kuralında 'level:' mevcut`);
}

// -----------------------------------------------------------------------------
// STRES TESTİ 4: Boş, Tanımsız veya Eksik Girdi Dayanıklılığı
// -----------------------------------------------------------------------------
console.log('\n--- Test 4: Boş ve Sıfır Bilgili Girdi Dayanıklılığı ---');

const emptyCtx = {};
let emptySplunk: any[];
let emptySentinel: any[];
let emptyElastic: any[];
let emptySigma: any[];

try {
  emptySplunk = generateSplunkQueries(emptyCtx);
  emptySentinel = generateSentinelKqlQueries(emptyCtx);
  emptyElastic = generateElasticQueries(emptyCtx);
  emptySigma = generateSigmaRule(emptyCtx);
  assert(true, 'Test 4.1: Tamamen boş bağlam {} verildiğinde hiçbir istisna/hata fırlatılmadı');
} catch (e: any) {
  assert(false, `Test 4.1: Boş bağlam çökmeye neden oldu: ${e.message}`);
}

console.log('\n================================================================');
console.log('🎉 TÜM ZORLAYICI VE STRES TESTLERİ EKSİKSİZ VE BAŞARIYLA GEÇTİ!');
console.log('================================================================');
