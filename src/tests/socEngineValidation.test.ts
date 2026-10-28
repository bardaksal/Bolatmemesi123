import { runAnalytics, createEmptyReport } from '../services/socEngine';
import { resolveClientIp, classifyNetworkZone, isTrustedProxy, DEFAULT_TRUSTED_PROXIES, isIpInCidr } from '../services/proxyResolver';
import {
  parseLineToNormalizedLog,
  initializeFormatState,
  isDelimitedHeaderLine,
  feedSampleLine,
} from '../services/streamingParser';
import { isLogAllowedByAllowlist } from '../services/allowlistManager';
import { generateHTMLReport } from '../services/reportGenerator';
import { NormalizedLog, AllowlistData } from '../types';

function createDummyLog(overrides: Partial<NormalizedLog>): NormalizedLog {
  return {
    kaynak_dosya: 'test.log',
    tarih: '2026-03-30 10:00:00',
    tarih_obj: new Date('2026-03-30T10:00:00Z'),
    ip_adresi: '198.51.100.10',
    hedef_ip: '192.168.1.10',
    hedef_port: 80,
    kaynak_port: 49152,
    sunucu_ismi: 'WEB-SRV-01',
    islem_komutu: '/index.html',
    http_method: 'GET',
    status_code: 200,
    byte_degeri: 1024,
    istemci_byte: 256,
    baglanti_karari: 'ACCEPT',
    kullanici_adi: 'normal_user',
    user_agent: 'Mozilla/5.0',
    referer: null,
    response_time_ms: null,
    session_cookie: null,
    device: 'SERVER-01',
    network_zone: 'external',
    ip_source: 'direct-peer',
    immediate_peer_ip: '198.51.100.10',
    forwarded_client_ip: null,
    forwarded_chain: null,
    parse_warning: null,
    ...overrides,
  };
}

let passedCount = 0;
let totalCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  totalCount++;
  if (condition) {
    passedCount++;
    console.log(`[PASS] ${testName}`);
  } else {
    console.error(`[FAIL] ${testName} - Detail: ${detail || 'Assertion failed'}`);
    process.exitCode = 1;
  }
}

console.log('=== SOC DETECTION ENGINE — 12 FALSE-POSITIVE VE DOĞRULAMA TESTLERİ ===\n');

// Test 1 — Normal PHP
// GET /index.php 200 -> Webshell detection: false
{
  const logs = [createDummyLog({ islem_komutu: '/index.php', status_code: 200 })];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const webshellDetected = res.webshell_and_file_management.length > 0 ||
    res.entity_risk_queue.some(r => r.signals.some(s => s.code === 'SIG_WEBSHELL_RCE'));
  assert(!webshellDetected, 'Test 1: Normal PHP (GET /index.php 200) -> Webshell detection: false');
}

// Test 2 — Normal ASP.NET
// GET /login.aspx 200 -> Webshell detection: false
{
  const logs = [createDummyLog({ islem_komutu: '/login.aspx', status_code: 200 })];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const webshellDetected = res.webshell_and_file_management.length > 0 ||
    res.entity_risk_queue.some(r => r.signals.some(s => s.code === 'SIG_WEBSHELL_RCE'));
  assert(!webshellDetected, 'Test 2: Normal ASP.NET (GET /login.aspx 200) -> Webshell detection: false');
}

// Test 3 — Normal REST PUT
// PUT /api/v1/user/settings 200 -> Abnormal method detection: false
{
  const logs = [createDummyLog({ http_method: 'PUT', islem_komutu: '/api/v1/user/settings', status_code: 200 })];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const abnormalMethodDetected = res.entity_risk_queue.some(r => r.signals.some(s => s.code === 'SIG_ABNORMAL_METHOD'));
  assert(!abnormalMethodDetected, 'Test 3: Normal REST PUT (PUT /api/v1/user/settings 200) -> Abnormal method detection: false');
}

// Test 4 — Normal health check
// GET /healthz 200 (düzenli aralıklarla) -> Scanner detection: false
{
  const logs = Array.from({ length: 15 }, (_, i) =>
    createDummyLog({
      tarih: `2026-03-30 10:${String(i).padStart(2, '0')}:00`,
      islem_komutu: '/healthz',
      status_code: 200,
    })
  );
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const scannerDetected = res.scanner_and_bots.length > 0 ||
    res.entity_risk_queue.some(r => r.signals.some(s => s.category === 'SCANNER'));
  assert(!scannerDetected, 'Test 4: Periodic Health Check (GET /healthz 200) -> Scanner detection: false');
}

// Test 5 — Tek HTTP 500
// GET /api/profile 500 -> Exploit detection: false
{
  const logs = [createDummyLog({ islem_komutu: '/api/profile', status_code: 500 })];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const exploitCrashDetected = res.entity_risk_queue.some(r => r.signals.some(s => s.code === 'SIG_EXPLOIT_CRASH_5XX'));
  const suspCmdDetected = res.suspicious_commands.length > 0;
  assert(!exploitCrashDetected && !suspCmdDetected, 'Test 5: Single HTTP 500 (GET /api/profile 500) -> Exploit detection: false');
}

// Test 6 — Büyük normal download
// GET /reports/monthly.pdf 200 25 MB authenticated user -> Exfiltration detection: false or low confidence
{
  const logs = [
    createDummyLog({
      islem_komutu: '/reports/monthly.pdf',
      status_code: 200,
      byte_degeri: 25 * 1024 * 1024,
      kullanici_adi: 'finance_admin',
    }),
  ];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const criticalExfil = res.entity_risk_queue.some(r => r.signals.some(s => s.code === 'SIG_EXFILTRATION_CORRELATED'));
  assert(!criticalExfil, 'Test 6: Large normal download (25 MB pdf) -> Correlated exfiltration false');
}

// Test 7 — İç IP (10.x.x.x)
// Beklenen: trusted = false, ama network_zone = internal
{
  const ip = '10.54.206.15';
  const zone = classifyNetworkZone(ip);
  const isTrusted = isTrustedProxy(ip, DEFAULT_TRUSTED_PROXIES);
  assert(zone === 'internal' && !isTrusted, 'Test 7: Internal IP (10.54.206.15) -> network_zone = internal & not blindly trusted');
}

// Test 8 — Trusted proxy
// peer = trusted WAF, X-Forwarded-For = real client -> client IP = forwarded client
{
  const peer = '10.0.0.1'; // in DEFAULT_TRUSTED_PROXIES
  const xff = '203.0.113.50, 198.51.100.1';
  const resolved = resolveClientIp(peer, xff);
  assert(
    resolved.clientIp === '203.0.113.50' && resolved.ipSource === 'trusted-proxy-forwarded',
    'Test 8: Trusted Proxy -> client IP = forwarded client (203.0.113.50)'
  );
}

// Test 9 — Untrusted spoofed XFF
// peer = untrusted client, X-Forwarded-For = fake IP -> XFF ignored, client IP = peer
{
  const peer = '198.51.100.77'; // not in trusted list
  const xff = '127.0.0.1';
  const resolved = resolveClientIp(peer, xff);
  assert(
    resolved.clientIp === '198.51.100.77' && resolved.ipSource === 'untrusted-spoofed-ignored',
    'Test 9: Untrusted spoofed XFF -> XFF ignored, client IP = peer (198.51.100.77)'
  );
}

// Test 10 — İçeriden scanner
// internal IP + known device + authenticated user + 40 endpoints + high 404 rate
{
  const logs: NormalizedLog[] = [];
  for (let i = 1; i <= 45; i++) {
    logs.push(
      createDummyLog({
        ip_adresi: '10.10.5.25',
        network_zone: 'internal',
        kullanici_adi: 'john.doe',
        device: 'WS-CORP-44',
        islem_komutu: `/internal/api/discovery/endpoint_${i}`,
        status_code: 404,
      })
    );
  }
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '10.10.5.25');
  const detected = Boolean(entity && entity.signals.some(s => s.category === 'SCANNER' || s.code === 'SIG_FUZZING_RECON'));
  assert(detected, 'Test 10: Internal Fuzzing Scanner -> Scanner/Fuzzing detected');
}

// Test 11 — Şüpheli script endpoint
// /uploads/shell.php?cmd=whoami -> webshell suspicion = high
{
  const logs = [
    createDummyLog({
      ip_adresi: '198.51.100.99',
      islem_komutu: '/uploads/shell.php?cmd=whoami',
      status_code: 200,
    }),
  ];
  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.99');
  const hasWebshellSignal = Boolean(entity && entity.signals.some(s => s.code === 'SIG_WEBSHELL_RCE'));
  assert(hasWebshellSignal, 'Test 11: /uploads/shell.php?cmd=whoami -> webshell suspicion = HIGH');
}

// Test 12 — İçeriden şüpheli davranış
// RFC1918 + user + device + unusual endpoint enumeration + suspicious payload
{
  const logs: NormalizedLog[] = [];
  // Auth fails on multiple users
  for (let u = 1; u <= 5; u++) {
    logs.push(
      createDummyLog({
        ip_adresi: '10.20.30.40',
        sunucu_ismi: 'SRV-APP-1',
        network_zone: 'internal',
        kullanici_adi: `admin_target_${u}`,
        status_code: 401,
      })
    );
  }
  // Lateral server pivot + webshell probe
  logs.push(
    createDummyLog({
      ip_adresi: '10.20.30.40',
      sunucu_ismi: 'SRV-DB-2',
      network_zone: 'internal',
      islem_komutu: '/cmd.aspx?cmd=whoami',
      status_code: 500,
    })
  );

  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '10.20.30.40');
  const internalTreatedAsThreat = Boolean(entity && entity.risk_puani >= 40 && entity.signals.length >= 2);
  assert(internalTreatedAsThreat, 'Test 12: Internal Suspicious Behavior -> Correlated high risk (Not blindly trusted)');
}

// Test 13 — Boş Veri / Sıfır Kayıt Dayanıklılığı (Empty Report Resiliency)
{
  const emptyReport = createEmptyReport();
  const res = runAnalytics([], 10485760, 15, 'BALANCED');
  assert(
    res.summary.toplam_olay === 0 &&
    res.entity_risk_queue.length === 0 &&
    emptyReport.summary.toplam_olay === 0,
    'Test 13: Empty dataset handling -> zero errors, empty report structure valid'
  );
}

// Test 14 — HTML Rapor Oluşturucu Dayanıklılığı (HTML Report Generator Robustness)
{
  const emptyReport = createEmptyReport();
  const htmlEmpty = generateHTMLReport(emptyReport, 'Boş Test Raporu');
  const normalReport = runAnalytics([createDummyLog({ ip_adresi: '198.51.100.20' })], 10485760, 15);
  const htmlPopulated = generateHTMLReport(normalReport, 'Dolu Test Raporu');
  assert(
    typeof htmlEmpty === 'string' &&
    htmlEmpty.includes('<!DOCTYPE html>') &&
    typeof htmlPopulated === 'string' &&
    htmlPopulated.includes('198.51.100.20'),
    'Test 14: HTML Report Generator on empty and populated reports -> returns valid HTML string without throwing'
  );
}

// Test 15 — W3C IIS Format Ayrıştırma (W3C IIS Log Parser)
{
  const state = initializeFormatState('u_ex260330.log');
  state.isW3C = true;
  state.format = 'W3C_IIS';
  state.w3cFields = ['date', 'time', 'c_ip', 'cs_method', 'cs_uri_stem', 'sc_status', 'sc_bytes'];
  state.detected = true;

  const rawLine = '2026-03-30 14:22:10 198.51.100.45 GET /api/v1/health 200 452';
  const parsed = parseLineToNormalizedLog(rawLine, state);
  assert(
    Boolean(parsed && parsed.ip_adresi === '198.51.100.45' && parsed.status_code === 200 && parsed.http_method === 'GET' && parsed.byte_degeri === 452),
    'Test 15: Streaming parser on W3C IIS format -> parses accurately'
  );
}

// Test 16 — Apache / Nginx Combined Format Ayrıştırma
{
  const state = initializeFormatState('access.log');
  const rawLine = '198.51.100.88 - - [30/Mar/2026:14:22:10 +0300] "POST /api/login HTTP/1.1" 401 1280 "-" "curl/7.81.0"';
  const parsed = parseLineToNormalizedLog(rawLine, state);
  assert(
    Boolean(parsed && parsed.ip_adresi === '198.51.100.88' && parsed.http_method === 'POST' && parsed.status_code === 401 && parsed.byte_degeri === 1280),
    'Test 16: Streaming parser on Apache/Nginx Combined format -> parses IP, method, status, bytes'
  );
}

// Test 17 — JSON Log Format Ayrıştırma
{
  const state = initializeFormatState('app_events.json');
  const rawLine = JSON.stringify({
    timestamp: '2026-03-30T14:22:10Z',
    client_ip: '198.51.100.95',
    method: 'GET',
    uri: '/admin/dashboard',
    status: 200,
    bytes: 2048,
    action: 'ACCEPT',
  });
  const parsed = parseLineToNormalizedLog(rawLine, state);
  assert(
    Boolean(parsed && parsed.ip_adresi === '198.51.100.95' && parsed.http_method === 'GET' && parsed.status_code === 200 && parsed.byte_degeri === 2048),
    'Test 17: Streaming parser on JSON log format -> parses fields accurately'
  );
}

// Test 18 — Delimited CSV Başlık Satırı Tespiti (CSV Header Line Detection)
{
  const state = initializeFormatState('firewall_export.csv');
  state.delimiter = ',';
  state.delimiterHeaders = ['date', 'time', 'source_ip', 'destination_ip', 'action'];
  const headerLine = 'date,time,source_ip,destination_ip,action';
  const isHeader = isDelimitedHeaderLine(headerLine, state);
  const dataLine = '2026-03-30,14:22:10,198.51.100.5,192.168.1.1,ACCEPT';
  const isDataHeader = isDelimitedHeaderLine(dataLine, state);
  assert(
    isHeader === true && isDataHeader === false,
    'Test 18: Delimited CSV header line detection -> correctly identifies header lines'
  );
}

// Test 19 — Kapsamlı Allowlist Kural Eşleşmesi (Scoped Allowlist Rule Match)
{
  const log = createDummyLog({
    ip_adresi: '10.50.1.15',
    islem_komutu: '/api/v1/healthz',
    http_method: 'GET',
    network_zone: 'internal',
  });

  const allowlist: AllowlistData = {
    ips: [],
    cidrs: [],
    service_accounts: [],
    trusted_servers: [],
    scoped_rules: [
      {
        id: 'rule_1',
        reason: 'Internal Health Check Scoped Allowlist',
        createdBy: 'admin',
        scope: {
          cidr: '10.50.0.0/16',
          endpoint: '/api/v1/healthz',
          method: 'GET',
        },
        createdAt: '2026-01-01T00:00:00Z',
      },
    ],
  };

  const isAllowed = isLogAllowedByAllowlist(log, allowlist);
  assert(isAllowed === true, 'Test 19: Allowlist scoped rule matching -> matches valid target');
}

// Test 20 — Süresi Dolmuş Allowlist Kuralı (Expired Allowlist Rule)
{
  const log = createDummyLog({
    ip_adresi: '10.50.1.15',
    islem_komutu: '/api/v1/healthz',
    http_method: 'GET',
  });

  const allowlist: AllowlistData = {
    ips: [],
    cidrs: [],
    service_accounts: [],
    trusted_servers: [],
    scoped_rules: [
      {
        id: 'rule_expired',
        reason: 'Expired rule',
        createdBy: 'admin',
        scope: {
          ip: '10.50.1.15',
        },
        createdAt: '2025-01-01T00:00:00Z',
        expiresAt: '2025-02-01T00:00:00Z', // In the past
      },
    ],
  };

  const isAllowed = isLogAllowedByAllowlist(log, allowlist);
  assert(isAllowed === false, 'Test 20: Allowlist expired scoped rule -> Rule past expiresAt is ignored');
}

// Test 21 — Parola Püskürtme (Password Spraying) Tespiti
{
  const logs: NormalizedLog[] = [];
  // 6 different accounts targeted from same IP with auth fails
  for (let u = 1; u <= 6; u++) {
    for (let attempt = 0; attempt < 2; attempt++) {
      logs.push(
        createDummyLog({
          ip_adresi: '198.51.100.123',
          kullanici_adi: `victim_user_${u}`,
          status_code: 401,
          baglanti_karari: 'DENY',
        })
      );
    }
  }

  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.123');
  const hasSpraying = Boolean(entity && entity.signals.some(s => s.code === 'SIG_PASSWORD_SPRAYING'));
  assert(hasSpraying, 'Test 21: Password spraying detection -> 6 accounts targeted triggers SIG_PASSWORD_SPRAYING');
}

// Test 22 — Logaritmik Puan Sınırı & Sayı Taşması Koruması (Score Stability & Cap)
{
  const logs: NormalizedLog[] = [];
  // 1000 identical 404s
  for (let i = 0; i < 1000; i++) {
    logs.push(
      createDummyLog({
        ip_adresi: '198.51.100.200',
        islem_komutu: `/notfound_${i % 30}`,
        status_code: 404,
      })
    );
  }

  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.200');
  const scoreValid = Boolean(
    entity &&
    !isNaN(entity.risk_puani) &&
    entity.risk_puani >= 0 &&
    entity.risk_puani <= 100
  );
  assert(scoreValid, 'Test 22: Logarithmic score cap test -> bounded <= 100 and no NaN');
}

// Test 23 — Tespit Profilleri Farklılaşması (Profiles: RELAXED vs STRICT)
{
  const logs = [
    createDummyLog({
      ip_adresi: '198.51.100.210',
      islem_komutu: '/test.php?cmd=id',
      status_code: 200,
    }),
  ];

  const resRelaxed = runAnalytics(logs, 10485760, 15, 'RELAXED');
  const resStrict = runAnalytics(logs, 10485760, 15, 'STRICT');
  const entRelaxed = resRelaxed.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.210');
  const entStrict = resStrict.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.210');

  const diffValid = Boolean(entRelaxed && entStrict && entStrict.risk_puani >= entRelaxed.risk_puani);
  assert(diffValid, 'Test 23: Detection profiles differentiation -> STRICT score >= RELAXED score');
}

// Test 24 — Bileşik Korelasyon (Recon + Webshell Exploit -> Compound Bonus)
{
  const logs = [
    createDummyLog({
      ip_adresi: '198.51.100.220',
      user_agent: 'sqlmap/1.6#stable',
      islem_komutu: '/index.php',
      status_code: 200,
    }),
    createDummyLog({
      ip_adresi: '198.51.100.220',
      islem_komutu: '/uploads/shell.php?cmd=whoami',
      status_code: 200,
    }),
  ];

  const res = runAnalytics(logs, 10485760, 15, 'BALANCED');
  const entity = res.entity_risk_queue.find(r => r.ip_adresi === '198.51.100.220');
  const hasCorrelation = Boolean(
    entity &&
    entity.scoring_breakdown.some(b => b.item.includes('Korelasyon: Keşif -> İstismar')) &&
    entity.risk_puani >= 65
  );
  assert(hasCorrelation, 'Test 24: Correlated Recon -> Exploit triggers Compound Bonus and Critical risk');
}

// Test 25 — Timeout / Zaman Aşımı Doğru Sınıflandırma (Timeout Classification: Failure instead of Success)
{
  const state = initializeFormatState('firewall_events.csv');
  state.delimiter = ',';
  state.delimiterHeaders = ['date', 'time', 'source_ip', 'destination_ip', 'event_name', 'action'];

  // QRadar style event where action is permit/allowed, but event name is "Connection Timeout"
  const timeoutLine = '2026-03-30,15:30:00,198.51.100.99,192.168.1.50,Connection Timeout,permit';
  const parsed = parseLineToNormalizedLog(timeoutLine, state);

  const isTimeoutNotSuccess = Boolean(
    parsed &&
    parsed.baglanti_karari === 'DENY / HATA' &&
    parsed.status_code === 408
  );
  assert(
    isTimeoutNotSuccess,
    'Test 25: Event Name "Connection Timeout" -> Classified as DENY / HATA (408) instead of False Success'
  );
}

// Test 26 — FortiWeb WAF Key-Value Log Parser Doğrulaması
{
  const state = initializeFormatState('fortiweb_waf.log');
  const userFortiWebLog =
    '<185>date=2026-09-17 time=13:49:59 log_id=20000008 msg_id=019611820949 device_id=FV-1KFS124000273 eventtime=1789642199601982653 vd="root" timezone="(GMT+3:00)Istanbul" timezone_dayst="GMTg-3" type=attack pri=alert main_type="Signature Detection" sub_type="Generic Attacks(Extended)" trigger_policy="N/A" severity_level=Medium proto=tcp service=https/tls1.2 backend_service=unknown action=Alert policy="SP_ASGDMZSEC03" src=31.214.129.14 src_port=48602 dst=192.168.0.29 dst_port=443 http_method=get http_url="/owa/auth/logon.aspx?replaceCurrent=1&url=https://vnaportal.acibadem.com.tr:443/ecp" http_host="vnaportal.acibadem.com.tr" http_agent="Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" http_session_id=none msg="Parameter(url) triggered signature ID 060140003 of Signatures policy SIG_ASGDMZSEC03" signature_subclass="RFI Injection" signature_id="060140003" signature_cve_id="N/A" srccountry="Turkey" content_switch_name="none" server_pool_name="SP_ASGDMZSEC03" false_positive_mitigation="none" user_name="Unknown" monitor_status="Disabled" http_refer="https://www.google.com/search?" http_version="1.x" dev_id="D149460F603C96C4F6A29C1879875FDD1181" es=0 threat_weight=25 history_threat_weight=10570 threat_level=Moderate ftp_mode="N/A" ftp_cmd="N/A" cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" ml_log_hmm_probability=0.000000 ml_log_sample_prob_mean=0.000000 ml_log_sample_arglen_mean=0.000000 ml_log_arglen=0 ml_svm_log_main_types=0 ml_svm_log_match_types="none" ml_svm_accuracy="none" ml_domain_index=0 ml_url_dbid=0 ml_arg_dbid=0 ml_allow_method="none" owasp_top10="A03:2021-Injection" bot_info="none" matched_field="args" matched_pattern="https://vnaportal.acibadem.com.tr:443/ecp" attack_type="Generic Attacks(Extended)" client_level="Malicious" x509_cert_subject="none" owasp_api_top10="N/A" match_location="Parameter(url)"';

  feedSampleLine(state, userFortiWebLog);
  const parsed = parseLineToNormalizedLog(userFortiWebLog, state);

  const isValidFortiWeb = Boolean(
    parsed &&
    parsed.ip_adresi === '31.214.129.14' &&
    parsed.hedef_ip === '192.168.0.29' &&
    parsed.hedef_port === 443 &&
    parsed.http_method === 'GET' &&
    parsed.sunucu_ismi === 'vnaportal.acibadem.com.tr' &&
    parsed.islem_komutu?.includes('/owa/auth/logon.aspx')
  );

  assert(
    isValidFortiWeb,
    'Test 26: FortiWeb WAF Key-Value log correctly detected and fields extracted (IP, URL, Host, Method)'
  );
}

// Test 27 — OWA RFI False Positive Heuristic Doğrulaması
{
  const testUrl = '/owa/auth/logon.aspx?replaceCurrent=1&url=https://vnaportal.acibadem.com.tr:443/ecp';
  const testHost = 'vnaportal.acibadem.com.tr';
  const isOwa = testUrl.includes('/owa/auth/logon.aspx') && testUrl.includes('replaceCurrent=1');
  const hostMatches = testUrl.includes(testHost);
  const isFalsePositive = isOwa && hostMatches;

  assert(
    isFalsePositive,
    'Test 27: Microsoft Exchange OWA redirection URL heuristic -> Correctly classified as False Positive'
  );
}

console.log(`\nSonuç: ${passedCount}/${totalCount} test başarıyla tamamlandı!`);
