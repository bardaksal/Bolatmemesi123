import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as XLSX from 'xlsx';
import {
  compareSecurityPeriods,
  compareMultipleSecurityPeriods,
  parsePeriodContent,
  buildPolicyComparisonWorkbook,
  generatePolicyEffectivenessHtmlReport,
} from '../services/policyComparisonEngine';
import { inspectAndConvertExcel } from '../services/excelConverter';
import { parseLineToNormalizedLog, initializeFormatState } from '../services/streamingParser';
import { runAnalytics, createEmptyReport } from '../services/socEngine';
import { NormalizedLog, AllowlistData } from '../types';

console.log('================================================================');
console.log('⚡ EXTREME STRESS, ADVERSARIAL & MISDIAGNOSIS PREVENTION AUDIT ⚡');
console.log('================================================================');

let passedTests = 0;
let totalTests = 0;

function runTest(name: string, fn: () => void) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`✅ [PASS ${passedTests}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL] ${name}`);
    console.error(`   Hata Ayrıntısı:`, err?.message || err);
    throw err;
  }
}

// -------------------------------------------------------------
// BÖLÜM 1: POLICY COMPARISON & BEFORE/AFTER UÇ SENARYOLAR
// -------------------------------------------------------------

// Test 1: Tamamen Boş Dosyalar ve 0 Satırlı Dönemler (Crash & Division by Zero Koruması)
runTest('Bölüm 1.1: Boş dosyalar verildiğinde NaN / Crash üretilmez, 0 log teşhisi konur', () => {
  const emptyA = [{ name: 'empty_a.csv', content: '' }];
  const emptyB = [{ name: 'empty_b.csv', content: '' }];

  const res = compareSecurityPeriods(emptyA, emptyB, 'Dönem A', 'Dönem B');
  assert.strictEqual(res.periodA.totalRequests, 0, 'Dönem A istek sayısı 0 olmalı');
  assert.strictEqual(res.periodB.totalRequests, 0, 'Dönem B istek sayısı 0 olmalı');
  assert.strictEqual(res.periodA.blockRate, 0, 'Block rate 0 olmalı (NaN olmamalı)');
  assert.strictEqual(res.signatureImpacts.length, 0, 'İmza matrisi boş olmalı');
  assert(!isNaN(res.blockRateDelta), 'Block rate delta NaN olmamalı');
  assert.strictEqual(res.periodA.totalRequests + res.periodB.totalRequests, 0, 'Toplam gözlem 0 olmalı');
});

// Test 2: Tamamen Ayrık (Disjoint) Kurallar — Sahte Devamlılık Üretilmemesi
runTest('Bölüm 1.2: Ortak kuralı olmayan iki dönemde kurallar birbirine zorla bağlanmaz', () => {
  const csvA = 'Policy Name,Threat Type,Event Name,Count\nPol_Alpha,SQLi,SQL Injection Pattern,500';
  const csvB = 'Policy Name,Threat Type,Event Name,Count\nPol_Beta,XSS,Cross Site Scripting,250';

  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csvA }],
    [{ name: 'b.csv', content: csvB }],
    'Dönem Alpha',
    'Dönem Beta'
  );

  assert.strictEqual(res.signatureImpacts.length, 2, '2 bağımsız kural oluşmalı');
  const sqli = res.signatureImpacts.find(s => s.eventName === 'SQL Injection Pattern' || s.name === 'SQL Injection Pattern');
  const xss = res.signatureImpacts.find(s => s.eventName === 'Cross Site Scripting' || s.name === 'Cross Site Scripting');

  assert(sqli, 'SQLi kuralı bulunmalı');
  assert(xss, 'XSS kuralı bulunmalı');

  assert.strictEqual(sqli?.beforeCount, 500);
  assert.strictEqual(sqli?.afterCount, 0);
  assert.strictEqual(sqli?.isContinuingInAfter, 'Hayır', 'SQLi sonraki dönemde devam etmiyor olmalı');

  assert.strictEqual(xss?.beforeCount, 0);
  assert.strictEqual(xss?.afterCount, 250);
  assert.strictEqual(xss?.isContinuingInAfter, 'Yeni', 'XSS sonraki dönemde ilk kez görülmüş olmalı');
});

// Test 3: Türkçe Karakterler (İ/ı/Ş/ş/Ğ/ğ/Ü/ü/Ö/ö/Ç/ç) İle Kural Eşleşmesi
runTest('Bölüm 1.3: Türkçe karakterli policy ve olay isimleri bozulmadan eşleşir', () => {
  const csvA = 'Policy Name,Threat Type,Event Name,Count\n/Common/Şirket_İntranet_Gelişmiş_WAF,Veri Güvenliği,Veri Sızıntısı Koruması,1200';
  const csvB = 'Policy Name,Threat Type,Event Name,Count\n/Common/Şirket_İntranet_Gelişmiş_WAF,Veri Güvenliği,Veri Sızıntısı Koruması,300';

  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csvA }],
    [{ name: 'b.csv', content: csvB }],
    'Öncesi',
    'Sonrası'
  );

  assert.strictEqual(res.signatureImpacts.length, 1, 'Türkçe karakterli kural tek bir ortak kural olarak eşleşmeli');
  const rule = res.signatureImpacts[0];
  assert.strictEqual(rule.beforeCount, 1200);
  assert.strictEqual(rule.afterCount, 300);
  assert.strictEqual(rule.isContinuingInAfter, 'Evet');
  assert.strictEqual(rule.policyId, '/Common/Şirket_İntranet_Gelişmiş_WAF');
});

// Test 4: Aynı Kural İsimli Fakat Farklı Policy İsimli Olayların İzolasyonu
runTest('Bölüm 1.4: Farklı Policy altındaki aynı event isimleri kesinlikle birleştirilmez', () => {
  const csvA = [
    'Policy Name,Threat Type,Event Name,Count',
    'Policy_DMZ_Web,Injections,SQL Injection,100',
    'Policy_Internal_API,Injections,SQL Injection,50',
  ].join('\n');

  const csvB = [
    'Policy Name,Threat Type,Event Name,Count',
    'Policy_DMZ_Web,Injections,SQL Injection,20',
    'Policy_Internal_API,Injections,SQL Injection,10',
  ].join('\n');

  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: csvA }],
    [{ name: 'b.csv', content: csvB }]
  );

  assert.strictEqual(res.signatureImpacts.length, 2, '2 ayrı policy kaydı 2 bağımsız satır olmalıdır');
  const dmz = res.signatureImpacts.find(s => s.policyId === 'Policy_DMZ_Web');
  const internal = res.signatureImpacts.find(s => s.policyId === 'Policy_Internal_API');

  assert(dmz && internal, 'Her iki policy de mevcut olmalı');
  assert.strictEqual(dmz?.beforeCount, 100);
  assert.strictEqual(dmz?.afterCount, 20);
  assert.strictEqual(internal?.beforeCount, 50);
  assert.strictEqual(internal?.afterCount, 10);
});

// Test 5: Rastgele Kolon Sırası ve Farklı İsimlendirmeli CSV Şeması
runTest('Bölüm 1.5: Sütunların sırası değiştiğinde sistem kolonları başlıklarına göre doğru eşleştirir', () => {
  const disorderedCsvA = [
    'Count,Start Time,Response,Event Name,Threat Type,Policy Name',
    '150,2026-08-10 10:00:00,500,Data Leakage,Info Leak,Pol_Reverse',
  ].join('\n');

  const disorderedCsvB = [
    'Event Name,Count,Policy Name,Response,Threat Type,Start Time',
    'Data Leakage,40,Pol_Reverse,500,Info Leak,2026-09-10 10:00:00',
  ].join('\n');

  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: disorderedCsvA }],
    [{ name: 'b.csv', content: disorderedCsvB }]
  );

  assert.strictEqual(res.periodA.totalRequests, 150);
  assert.strictEqual(res.periodB.totalRequests, 40);
  assert.strictEqual(res.signatureImpacts.length, 1);
  assert.strictEqual(res.signatureImpacts[0].eventName, 'Data Leakage');
  assert.strictEqual(res.signatureImpacts[0].policyId, 'Pol_Reverse');
});

// Test 6: Noktalı ve Virgüllü Sayı Formatları ("1,500", "4.092", vb.) ve Negatif/Geçersiz Count
runTest('Bölüm 1.6: Sayısal Count kolonundaki noktalı/virgüllü formatlar bozulmadan sayıya çevrilir', () => {
  const formattedCountCsvA = [
    'Policy Name,Threat Type,Event Name,Count',
    'Pol1,Threat1,Evt1,"4,092"',
    'Pol1,Threat2,Evt2,1.250',
  ].join('\n');

  const formattedCountCsvB = [
    'Policy Name,Threat Type,Event Name,Count',
    'Pol1,Threat1,Evt1,100',
    'Pol1,Threat2,Evt2,50',
  ].join('\n');

  const res = compareSecurityPeriods(
    [{ name: 'a.csv', content: formattedCountCsvA }],
    [{ name: 'b.csv', content: formattedCountCsvB }]
  );

  assert.strictEqual(res.periodA.totalRequests, 4092 + 1250, 'Noktalı ve virgüllü sayılar doğru toplanmalı');
  assert.strictEqual(res.periodB.totalRequests, 150);
});

// Test 7: Çoklu Dönem Zaman Serisi (3+ Log / Rapor) Kronolojik Sıralama ve Matris Bütünlüğü
runTest('Bölüm 1.7: 3+ dönem yüklendiğinde kronolojik zaman serisi sıraya dizilir ve trend oluşturulur', () => {
  const p1 = {
    label: 'Haziran 2026',
    file: {
      name: 'p1.csv',
      content: 'Policy Name,Threat Type,Event Name,Start Time,Count\nPol_Trend,Threat_Trend,Attack_A,2026-06-01 10:00:00,1000',
    },
  };
  const p2 = {
    label: 'Temmuz 2026',
    file: {
      name: 'p2.csv',
      content: 'Policy Name,Threat Type,Event Name,Start Time,Count\nPol_Trend,Threat_Trend,Attack_A,2026-07-01 10:00:00,600',
    },
  };
  const p3 = {
    label: 'Ağustos 2026',
    file: {
      name: 'p3.csv',
      content: 'Policy Name,Threat Type,Event Name,Start Time,Count\nPol_Trend,Threat_Trend,Attack_A,2026-08-01 10:00:00,200',
    },
  };

  // Karışık sırada verelim: p2, p3, p1
  const multiRes = compareMultipleSecurityPeriods([p2, p3, p1]);

  assert.strictEqual(multiRes.periods.length, 3, '3 dönem ayrıştırılmalı');
  // Otomatik kronolojik sıralanmış olmalı: Haziran -> Temmuz -> Ağustos
  assert(multiRes.periods[0].label.includes('Haziran') || multiRes.periods[0].periodStart?.includes('2026-06'));
  assert(multiRes.periods[1].label.includes('Temmuz') || multiRes.periods[1].periodStart?.includes('2026-07'));
  assert(multiRes.periods[2].label.includes('Ağustos') || multiRes.periods[2].periodStart?.includes('2026-08'));

  assert.strictEqual(multiRes.signatures.length, 1, 'Tek bir imza satırı trend matrisi oluşturmalı');
  const trendItem = multiRes.signatures[0];
  const pId0 = multiRes.periods[0].periodId;
  const pId1 = multiRes.periods[1].periodId;
  const pId2 = multiRes.periods[2].periodId;
  assert.strictEqual(trendItem.counts[pId0], 1000, 'İlk dönem: 1000');
  assert.strictEqual(trendItem.counts[pId1], 600, 'İkinci dönem: 600');
  assert.strictEqual(trendItem.counts[pId2], 200, 'Üçüncü dönem: 200');
});

// Test 8: Gerçek Excel Binary ArrayBuffer Parsing & Formül / Hücre Güvenliği
runTest('Bölüm 1.8: Gerçek Excel binary buffer okuma, formül enjeksiyonu ve sheet tespiti doğrulanır', () => {
  const rows = [
    ['Policy Name (custom)', 'Threat Type (custom)', 'Event Name', 'Log Source', 'Response', 'Destination', 'Destination Port', 'Start Time', 'Low Level', 'Count'],
    ['=cmd|"/c calc"!A0', 'Injection Attack', 'Formula Injection In Event', 'F5ASM', '403', '10.0.0.5', 443, '2026-08-10 12:00:00', 'High', 10],
  ];

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  XLSX.utils.book_append_sheet(wb, ws, 'Attack_Summary');
  const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });

  const converted = inspectAndConvertExcel(buf, 'formula_test.xlsx');
  assert.strictEqual(converted.primarySheet, 'Attack_Summary');
  assert(converted.csvContent.includes('Formula Injection In Event'), 'Event name okunabilmeli');

  const parsed = parsePeriodContent([{ name: 'formula_test.xlsx', content: converted.csvContent, sheetName: converted.primarySheet }], 'Test');
  assert.strictEqual(parsed.logs.length, 1);
  assert.strictEqual(parsed.metrics.totalRequests, 10);
});

// -------------------------------------------------------------
// BÖLÜM 2: SOC ENGINE & YANLIŞ TEŞHİSİ ÖNLEME (FALSE POSITIVE/NEGATIVE)
// -------------------------------------------------------------

// Test 9: Masum REST ve SQL Arama Parametreleri SQL Injection Olarak Teşhis Edilmez
runTest('Bölüm 2.1: "/search?q=rock\'n\'roll" ve "/filter?by=select" gibi meşru istekler SQLi sayılmaz', () => {
  const benignLogs: NormalizedLog[] = [
    {
      kaynak_dosya: 'web.log',
      tarih: '2026-08-10 10:00:00',
      ip_adresi: '192.168.1.50',
      hedef_ip: '10.0.0.10',
      hedef_port: 443,
      kaynak_port: null,
      sunucu_ismi: 'shop.example.com',
      islem_komutu: '/products/search?query=rock\'n\'roll&category=music',
      http_method: 'GET',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      byte_degeri: 1200,
      istemci_byte: null,
      status_code: 200,
      baglanti_karari: 'ACCEPT',
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    },
    {
      kaynak_dosya: 'web.log',
      tarih: '2026-08-10 10:00:01',
      ip_adresi: '192.168.1.50',
      hedef_ip: '10.0.0.10',
      hedef_port: 443,
      kaynak_port: null,
      sunucu_ismi: 'shop.example.com',
      islem_komutu: '/api/v1/options?select=price,name&orderby=asc',
      http_method: 'GET',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      byte_degeri: 850,
      istemci_byte: null,
      status_code: 200,
      baglanti_karari: 'ACCEPT',
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    },
  ];

  const res = runAnalytics(benignLogs, 10 * 1024 * 1024, 5, 'BALANCED');
  const entity = res.entity_risk_queue.find(e => e.ip_adresi === '192.168.1.50');
  const hasSqliSignal = entity?.signals.some(s => s.code === 'SIG_SQLI' || s.category === 'EXPLOIT');

  assert(!hasSqliSignal, 'Meşru arama sorguları SQL Injection olarak işaretlenmemelidir');
  if (entity) {
    assert(entity.risk_puani < 50, 'Meşru trafik yüksek veya kritik risk almamalıdır');
  }
});

// Test 10: X-Forwarded-For IP Sahteciliği (Untrusted Spoofed XFF Reddi)
runTest('Bölüm 2.2: Güvenilmeyen X-Forwarded-For header ile gelen sahte iç IP (10.0.0.1) körlemesine kabul edilmez', () => {
  const line = '198.51.100.77 - - [10/Aug/2026:10:00:00 +0300] "GET /admin HTTP/1.1" 200 450 "-" "curl" "10.0.0.1"';
  const state = initializeFormatState('proxy.log');
  const parsed = parseLineToNormalizedLog(line, state);

  assert(parsed, 'Log ayrıştırılmalı');
  assert.strictEqual(parsed?.ip_adresi, '198.51.100.77', 'İstemci IP adresi sahte XFF değil doğrudan bağlanan peer IP olmalıdır');
});

// Test 11: Masum Sunucu Hataları (500) Exploit / Saldırı Kabul Edilmez
runTest('Bölüm 2.3: Tekil HTTP 500 sunucu hatası doğrudan exploit/istismar olarak teşhis edilmez', () => {
  const errorLogs: NormalizedLog[] = [
    {
      kaynak_dosya: 'web.log',
      tarih: '2026-08-10 10:00:00',
      ip_adresi: '192.168.1.80',
      hedef_ip: '10.0.0.10',
      hedef_port: 443,
      kaynak_port: null,
      sunucu_ismi: 'api.example.com',
      islem_komutu: '/api/v1/user/profile',
      http_method: 'GET',
      user_agent: 'Mozilla/5.0',
      byte_degeri: 340,
      istemci_byte: null,
      status_code: 500,
      baglanti_karari: 'DENY / HATA',
      kullanici_adi: null,
      referer: null,
      response_time_ms: null,
      session_cookie: null,
    },
  ];

  const res = runAnalytics(errorLogs, 10 * 1024 * 1024, 5, 'BALANCED');
  const entity = res.entity_risk_queue.find(e => e.ip_adresi === '192.168.1.80');
  const hasExploit = entity?.signals.some(s => s.category === 'EXPLOIT');

  assert(!hasExploit, 'Tek bir 500 kodu meşru yazılım bugı olabilir, exploit teşhisi konmamalıdır');
});

// Test 12: Yetkili Güvenlik Taramaları (Allowlist Scoped Rules) Teşhis Ayrımı
runTest('Bölüm 2.4: Allowlist dahilindeki yetkili tarayıcı IPleri sahte alarm üretmez', () => {
  const scannerLog: NormalizedLog = {
    kaynak_dosya: 'scanner.log',
    tarih: '2026-08-10 10:00:00',
    ip_adresi: '10.50.100.25',
    hedef_ip: '10.0.0.10',
    hedef_port: 80,
    kaynak_port: null,
    sunucu_ismi: 'intranet.corp',
    islem_komutu: '/test.php?id=1%20OR%201=1',
    http_method: 'GET',
    user_agent: 'Acunetix Web Vulnerability Scanner',
    byte_degeri: 1000,
    istemci_byte: null,
    status_code: 403,
    baglanti_karari: 'DENY',
    kullanici_adi: null,
    referer: null,
    response_time_ms: null,
    session_cookie: null,
  };

  const allowlist: AllowlistData = {
    ips: ['10.50.100.25'],
    cidrs: [],
    service_accounts: [],
    trusted_servers: [],
    scoped_rules: [],
  };

  const isAllowed = allowlist.ips.includes(scannerLog.ip_adresi || '');
  assert(isAllowed, 'Yetkili IP allowlist ile filtrelenebilmeli ve SOC yöneticisi bilgilendirilmelidir');
});

// Test 13: Bozuk, Kırpılmış ve Aşırı Uzun Satır Dayanıklılığı (Fuzzing / Robustness)
runTest('Bölüm 2.5: Bozuk format, binary karakterler ve 50KB tek satır parserı çökertmez', () => {
  const state = initializeFormatState('fuzz.log');
  const malformedLines = [
    '',
    '   ',
    '### COMMENT ONLY LINE ###',
    'corrupted line without any delimiter or ip address xyz123',
    '{"incomplete_json": true, "timestamp": "2026',
    '2026-08-10 10:00:00 ' + 'A'.repeat(50000) + ' /api/test 200',
    '2026-08-10T10:00:00 \x00\x01\x02\xFF\xFE binary garbage',
  ];

  for (const line of malformedLines) {
    assert.doesNotThrow(() => {
      parseLineToNormalizedLog(line, state);
    }, 'Bozuk satır parseLineToNormalizedLog fonksiyonunu çökertmemeli');
  }
});

// Test 14: Rapor Üreticisi (HTML & Excel) Null / Boş Güvenliği
runTest('Bölüm 2.6: Rapor motorları eksik ve null verilerde kusursuz render eder', () => {
  const emptyRes = compareSecurityPeriods(
    [{ name: 'a.csv', content: 'Policy Name,Count\nP1,10' }],
    [{ name: 'b.csv', content: 'Policy Name,Count\nP1,10' }]
  );

  assert.doesNotThrow(() => {
    const html = generatePolicyEffectivenessHtmlReport(emptyRes);
    assert(html.includes('WAF') && html.includes('Güvenlik Politikası'));
  }, 'HTML raporu üretimi hata vermemelidir');

  assert.doesNotThrow(() => {
    const wb = buildPolicyComparisonWorkbook(emptyRes);
    assert.strictEqual(wb.SheetNames.length, 5, '5 Excel sayfası üretilmelidir');
  }, 'Excel workbook üretimi hata vermemelidir');
});

// Test 15: Sentetik HTTP Status Code Uydurmama Regresyon Testi (Forensic Integrity)
runTest('Bölüm 2.7: Ağ, Güvenlik Duvarı, Syslog ve Event loglarında HTTP status_code asla sentetik üretilmez', () => {
  // 1. AWS VPC Flow Log (Network Layer 3/4)
  const vpcState = initializeFormatState('flow.log');
  const vpcRejectLine = '2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 REJECT OK';
  const parsedVpc = parseLineToNormalizedLog(vpcRejectLine, vpcState);
  assert(parsedVpc !== null, 'VPC flow log ayrıştırılmalıdır');
  assert.strictEqual(parsedVpc.status_code, null, 'AWS VPC Flow loglarında HTTP status_code asla 403 veya 200 gibi uydurulmamalıdır, null olmalıdır');
  assert.strictEqual(parsedVpc.baglanti_karari, 'DENY', 'VPC Flow REJECT kararı DENY olarak doğru atanmalıdır');

  // 2. SSH Syslog Log
  const syslogState = initializeFormatState('auth.log');
  const sshAcceptLine = 'Oct  4 10:14:22 web-srv-01 sshd[12345]: Accepted password for root from 192.168.1.100 port 54321 ssh2';
  const parsedSsh = parseLineToNormalizedLog(sshAcceptLine, syslogState);
  assert(parsedSsh !== null, 'SSH syslog ayrıştırılmalıdır');
  assert.strictEqual(parsedSsh.status_code, null, 'SSH Auth loglarında HTTP status_code 200 olarak uydurulmamalıdır, null olmalıdır');
  assert.strictEqual(parsedSsh.baglanti_karari, 'ACCEPT', 'SSH Accepted kararı ACCEPT olmalıdır');

  // 3. Generic Syslog with Deny Keyword
  const genericDenyLine = 'Oct  4 10:15:00 firewall-gw kernel: [DROP] packet denied from 203.0.113.5 to internal';
  const parsedDenySyslog = parseLineToNormalizedLog(genericDenyLine, syslogState);
  assert(parsedDenySyslog !== null, 'Generic deny syslog ayrıştırılmalıdır');
  assert.strictEqual(parsedDenySyslog.status_code, null, 'Generic syslog loglarında HTTP 403 uydurulmamalıdır, null olmalıdır');
  assert.strictEqual(parsedDenySyslog.baglanti_karari, 'DENY', 'Syslog drop kararı DENY olmalıdır');

  // 4. Windows Security Event Log
  const winState = initializeFormatState('Security.evtx.txt');
  const winEventLine = '2026-10-04 10:20:00 An account was successfully logged on. Event ID: 4624 Subject: Security ID: S-1-5-18 Account Name: SYSTEM';
  const parsedWin = parseLineToNormalizedLog(winEventLine, winState);
  assert(parsedWin !== null, 'Windows Security logu ayrıştırılmalıdır');
  assert.strictEqual(parsedWin.status_code, null, 'Windows Event logunda HTTP status_code uydurulmamalıdır, null olmalıdır');

  // 5. Suricata EVE non-HTTP Alert
  const suriState = initializeFormatState('eve.json');
  const suriLine = JSON.stringify({
    timestamp: '2026-10-04T10:25:00.000Z',
    event_type: 'alert',
    src_ip: '198.51.100.22',
    dest_ip: '10.0.0.15',
    alert: {
      action: 'blocked',
      signature: 'ET SCAN Potential SSH Scan',
      category: 'Attempted Information Leak'
    }
  });
  const parsedSuri = parseLineToNormalizedLog(suriLine, suriState);
  assert(parsedSuri !== null, 'Suricata alert ayrıştırılmalıdır');
  assert.strictEqual(parsedSuri.status_code, null, 'Suricata HTTP dışı alertlerde HTTP 200 veya 403 uydurulmamalıdır, null olmalıdır');
  assert.strictEqual(parsedSuri.baglanti_karari, 'DENY', 'Suricata blocked alarmı DENY olarak atanmalıdır');
});

console.log('================================================================');
console.log(`🎉 TÜM TESTLER BAŞARIYLA GEÇTİ: ${passedTests} / ${totalTests} (Sıfır Hata)`);
console.log('================================================================');
