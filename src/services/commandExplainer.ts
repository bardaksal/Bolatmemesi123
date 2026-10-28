/**
 * Command Explainer Engine (Deterministic, Offline & Forensically Grounded)
 * Explains shell, PowerShell, Windows CMD, Linux Bash, and web exploit commands/logs
 * answering what the command is, what it does, legitimate usage, malicious misuse,
 * potential impact on the system, and recommended SOC triage steps without speculation.
 */

export interface CommandTokenExplanation {
  token: string;
  role: 'binary' | 'subcommand' | 'flag' | 'argument' | 'pipeline' | 'encoded' | 'operator';
  meaning: string;
  riskNote?: string;
}

export interface CommandExplainerContext {
  username?: string | null;
  host?: string | null;
  parentProcess?: string | null;
  processName?: string | null;
  timestamp?: string | null;
  eventId?: string | number | null;
  sourceIp?: string | null;
  destinationIp?: string | null;
  logSource?: string | null;
}

export interface CommandExplainerResult {
  rawCommand: string;
  normalizedCommand: string;
  category: string;
  ecosystem: 'PowerShell' | 'Windows CMD' | 'Linux Bash / Shell' | 'Web Exploit / Injection' | 'Network / Recon' | 'General';
  purpose: string;
  summary: string;
  decodedPayload?: string;
  riskLevel: 'KRİTİK' | 'YÜKSEK' | 'ORTA' | 'DÜŞÜK' | 'BİLGİ';
  mitreTechnique?: string;
  tokens: CommandTokenExplanation[];
  securityImplications: string[];
  recommendedDefenses: string[];
  legitimateUseCases: string[];
  troubleAndDamageRisks: string[];
  willCauseTrouble: 'EVET_YUKSEK' | 'POTANSIYEL' | 'HAYIR_GUVENLI';
  willCauseTroubleText: string;
  fullNarrativeMarkdown: string;
  context?: CommandExplainerContext;
  forensicCaveat: string;
}

// Common parameter dictionaries
const POWERSHELL_FLAGS: Record<string, string> = {
  '-nop': '-NoProfile: Kullanıcı profil dosyası betiklerini (scripts) yüklemez, daha hızlı ve iz bırakmadan çalışır.',
  '-noprofile': '-NoProfile: Kullanıcı profil dosyası betiklerini yüklemez, iz bırakmadan çalışır.',
  '-w': '-WindowStyle: Pencere görünürlüğünü belirler.',
  '-windowstyle': '-WindowStyle: Pencere görünürlüğünü ayarlar (örnek: hidden/gizli).',
  'hidden': 'hidden: Komut satırı penceresini masaüstünde kullanıcıya göstermeden arka planda çalıştırır.',
  '-ep': '-ExecutionPolicy: PowerShell komut yürütme politikasını geçici olarak değiştirir.',
  '-executionpolicy': '-ExecutionPolicy: PowerShell komut yürütme politikasını geçici olarak değiştirir.',
  'bypass': 'bypass: Güvenlik mekanizması olan yürütme politikasını atlar; imzasız/engelli betiklerin çalışmasına izin verir.',
  'unrestricted': 'unrestricted: Tüm betiklerin herhangi bir kısıtlama olmadan çalıştırılmasına izin verir.',
  '-noni': '-NonInteractive: Kullanıcıdan herhangi bir girdi veya onay beklemez.',
  '-noninteractive': '-NonInteractive: Kullanıcıdan onay veya konsol girdisi istemez.',
  '-enc': '-EncodedCommand: Base64 ile şifrelenmiş Unicode/UTF-16LE komut dizesini kabul eder ve çalıştırır.',
  '-encodedcommand': '-EncodedCommand: Base64 ile şifrelenmiş Unicode/UTF-16LE komut dizesini çözer ve çalıştırır.',
  '-e': '-EncodedCommand kısaltması: Base64 şifreli komut bloğu.',
  '-c': '-Command: Ardından gelen dizeyi komut veya betik bloğu olarak yorumlar.',
  '-command': '-Command: Belirtilen komutu veya blok dizesini çalıştırır.',
  'iex': 'Invoke-Expression: Verilen dizeyi (string) doğrudan çalıştırılabilir kod olarak icra eder (eval benzeri).',
  'invoke-expression': 'Invoke-Expression: Metin dizesini anında PowerShell komutu olarak çalıştırır.',
  'downloadstring': 'DownloadString: Belirtilen URL adresindeki içeriği belleğe (RAM) indirir ve string olarak döner.',
  'downloadfile': 'DownloadFile: Belirtilen URL adresindeki dosyayı doğrudan yerel diske kaydeder.',
  'net.webclient': 'System.Net.WebClient: Ağ üzerinden dosya/veri indirmek veya göndermek için kullanılan .NET sınıfı.',
  'invoke-webrequest': 'Invoke-WebRequest (curl/wget benzeri): HTTP/HTTPS üzerinden web içeriği veya dosya çeker.',
  'iwr': 'Invoke-WebRequest kısaltması: HTTP üzerinden dosya/sayfa indirir.',
  'invoke-restmethod': 'Invoke-RestMethod (irm): REST servisine HTTP isteği gönderir ve yanıtı doğrudan döner.',
  'irm': 'Invoke-RestMethod kısaltması: Uzak kaynaktan veri/kod çeker.',
};

const BASH_FLAGS: Record<string, string> = {
  '-c': 'Komut modunda çalıştır: Verilen dizeyi kabuk tarafından işlenecek komut olarak icra eder.',
  '-i': 'İnteraktif mod veya girdi dosyası.',
  '-rf': 'Recursive ve Force: Alt klasörlerle birlikte onay istemeden zorla silme.',
  '-r': 'Recursive: Alt dizinleri yinelemeli olarak dahil eder.',
  '-f': 'Force: Hata durumunda durmaz ve kullanıcıdan onay istemez.',
  '-la': 'Uzun liste formatında gizli dosyalar dahil tüm dosyaları listeler.',
  '-l': 'Uzun liste formatı (izinler, boyut, sahip).',
  '-a': 'Gizli dosyaları (nokta ile başlayan) da gösterir.',
  '-p': 'Gerekiyorsa üst dizinleri oluştur (mkdir -p) veya yetkileri koru.',
};

const CERTUTIL_FLAGS: Record<string, string> = {
  '-urlcache': 'Sertifika URL önbelleğini görüntüler veya uzaktan dosya çekmek için kötüye kullanılır.',
  '-f': 'Force: Hedef dosya varsa üzerine zorla yazar.',
  '-split': 'İndirilen dosyayı bloklara bölerek diske kaydeder.',
  '-decode': 'Base64 kodlanmış bir dosyayı ikili (binary/exe) dosyaya dönüştürür.',
  '-encode': 'İkili bir dosyayı Base64 metin dosyasına dönüştürür.',
  '-hashfile': 'Belirtilen dosyanın kriptografik hash (MD5, SHA1, SHA256) özetini hesaplar.',
  '-dump': 'Sertifika veya yapılandırma dökümünü ekrana basar.',
};

/**
 * Attempts to decode Base64 encoded payload commonly found in PowerShell or bash
 */
export function tryDecodePayload(command: string): string | null {
  // PowerShell -EncodedCommand / -enc Base64 UTF-16LE
  const psEncMatch = command.match(/(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{16,})/i);
  if (psEncMatch && psEncMatch[1]) {
    try {
      const b64 = psEncMatch[1];
      const binaryString = atob(b64);
      // UTF-16LE decoding (PowerShell default)
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const decoder = new TextDecoder('utf-16le');
      const decodedUtf16 = decoder.decode(bytes).replace(/\0/g, '').trim();
      if (decodedUtf16.length > 3 && /[a-zA-Z0-9_\s]/.test(decodedUtf16)) {
        return decodedUtf16;
      }
      // Fallback utf-8
      const utf8Decoder = new TextDecoder('utf-8');
      return utf8Decoder.decode(bytes).trim();
    } catch {
      // Ignore decoding failure
    }
  }

  // Base64 pipe in bash: echo ... | base64 -d
  const bashB64Match = command.match(/echo\s+['"]?([A-Za-z0-9+/=]{16,})['"]?\s*\|\s*base64\s+-d/i);
  if (bashB64Match && bashB64Match[1]) {
    try {
      return atob(bashB64Match[1]);
    } catch {
      // Ignore
    }
  }

  // URL encoded payloads
  if (command.includes('%20') || command.includes('%27') || command.includes('%3B') || command.includes('%2F')) {
    try {
      const decoded = decodeURIComponent(command);
      if (decoded !== command) return decoded;
    } catch {
      // Ignore
    }
  }

  return null;
}

import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
} from './httpRequestAnalyzer';

/**
 * Main Deterministic Command Explainer function
 */
export function explainCommand(inputRaw: string, context?: CommandExplainerContext): CommandExplainerResult {
  const trimmed = inputRaw.trim();
  const decodedPayload = tryDecodePayload(trimmed);
  const effectiveCmd = decodedPayload ? `${trimmed}\n[Çözülen Kod]: ${decodedPayload}` : trimmed;
  const lower = trimmed.toLowerCase();

  const tokens: CommandTokenExplanation[] = [];
  const securityImplications: string[] = [];
  const recommendedDefenses: string[] = [];
  const legitimateUseCases: string[] = [];
  const troubleAndDamageRisks: string[] = [];

  let category = 'Genel Sistem / Kabuk Komutu';
  let ecosystem: CommandExplainerResult['ecosystem'] = 'General';
  let purpose = '';
  let summary = '';
  let riskLevel: CommandExplainerResult['riskLevel'] = 'DÜŞÜK';
  let mitreTechnique = '';
  let willCauseTrouble: CommandExplainerResult['willCauseTrouble'] = 'HAYIR_GUVENLI';
  let willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Rutin bilgi alma veya standart sistem işlemidir.';

  // 0. HTTP REQUEST SEMANTIC ROUTING PROTECTION (HTTP REQUEST != COMMAND)
  if (isHttpRequestPattern(trimmed)) {
    const httpInfo = parseHttpRequestSemantics(trimmed);
    category = 'HTTP Ağ İsteği';
    ecosystem = 'Web Exploit / Injection';
    purpose = `Web sunucusundaki '${httpInfo?.endpoint || 'endpoint'}' adresine HTTP ${httpInfo?.method || 'istek'} iletmek.`;
    summary = `Belirtilen girdi bir işletim sistemi komutu veya ikili (binary) değil, web servisine yönelen bir HTTP ${httpInfo?.method || ''} isteğidir.`;
    riskLevel = httpInfo?.isKnownVulnerabilityTarget ? 'ORTA' : 'BİLGİ';
    willCauseTrouble = 'HAYIR_GUVENLI';
    willCauseTroubleText = 'HAYIR, STANDART İŞLEM. Belirtilen istek web sunucusuna iletilmiştir; tek başına işletim sisteminde komut çalıştırıldığını kanıtlamaz.';

    if (httpInfo) {
      tokens.push({
        token: httpInfo.method,
        role: 'subcommand',
        meaning: `HTTP İletim Metodu (${httpInfo.method})`,
      });
      tokens.push({
        token: httpInfo.endpoint,
        role: 'argument',
        meaning: `Hedef Servis / Endpoint Yolu (${httpInfo.targetTechnology || 'Web'})`,
      });
      if (httpInfo.query) {
        tokens.push({
          token: httpInfo.query,
          role: 'flag',
          meaning: `URL Sorgu Parametreleri (${httpInfo.query})`,
        });
      }
    }

    securityImplications.push('Bu girdi bir işletim sistemi süreci veya çalıştırılan binary değildir.');
    securityImplications.push('Görüntüde veya kayıtta sunucu yanıtı (HTTP status) ve süreç logları olmadan başarılı saldırı varsayılamaz.');
    troubleAndDamageRisks.push('HTTP istek satırı tek başına hedef sistemde komut yürütüldüğünü veya kalıcı hasar oluştuğunu kanıtlamaz.');
    legitimateUseCases.push('Uygulama istemcileri, API entegrasyonları veya yönetim panelleri tarafından sunucuya iletilen rutin web istekleri.');
    recommendedDefenses.push('Web erişim loglarında dönülen HTTP yanıt kodunu (200, 403 vb.) ve sunucuda süreç oluşturma kayıtlarını inceleyin.');
  }

  // 1. POWERSHELL SELECT-OBJECT & ROUTINE MANAGEMENT (Explicit Check First to Prevent False Positives)
  else if (
    lower.includes('select-object') ||
    lower.includes('get-process') ||
    lower.includes('get-service') ||
    lower.includes('get-childitem') ||
    lower.includes('get-eventlog') ||
    lower.includes('get-wmiobject') ||
    lower.includes('get-ciminstance')
  ) {
    ecosystem = 'PowerShell';
    category = 'PowerShell Rutin Sistem Yönetimi / Bilgi Alma';
    riskLevel = 'BİLGİ';
    willCauseTrouble = 'HAYIR_GUVENLI';
    willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. PowerShell nesne akışını filtreleme veya sistem durumu listeleme komutudur.';
    purpose = 'PowerShell ortamında sistem süreçlerini, servislerini veya nesne özelliklerini sorgulamak ve filtrelemek.';
    summary = 'PowerShell üzerinden sistem durumu veya süreç bilgilerini listeleyen meşru yönetim komutudur. SQL Injection kalıbı içermez.';

    tokens.push({
      token: trimmed.split(/\s+/)[0],
      role: 'binary',
      meaning: 'PowerShell yerel komut ve cmdlet aracı.',
    });

    if (lower.includes('select-object')) {
      tokens.push({
        token: 'Select-Object',
        role: 'subcommand',
        meaning: 'PowerShell komut çıktısında yalnızca belirli özellikleri (property) seçmek için kullanılan standart cmdlet.',
      });
    }

    legitimateUseCases.push('Sistem yöneticileri ve DevOps ekipleri tarafından süreç analizi, servis durumu izleme ve log dökümü.');
    troubleAndDamageRisks.push('Salt okunur bilgi sorgusu yaptığı için sisteme herhangi bir zarar vermez veya dosya silmez.');
    recommendedDefenses.push('Standart yönetimsel işlem; olağan dışı zaman dilimi veya yetkisiz kullanıcılar hariç müdahale gerektirmez.');
  }

  // 2. POWERSHELL DISCOVERY / ATTACK VECTORS
  else if (lower.includes('powershell') || lower.startsWith('powershell') || lower.includes('pwsh') || lower.includes('downloadstring') || lower.includes('invoke-expression')) {
    ecosystem = 'PowerShell';
    tokens.push({
      token: 'powershell.exe',
      role: 'binary',
      meaning: 'Windows PowerShell komut satırı ve otomasyon motoru.',
      riskNote: 'Saldırganlar bellek içi (fileless) kod çalıştırmak ve Living-off-the-Land teknikleri için sıklıkla kullanır.',
    });

    if (lower.includes('-nop') || lower.includes('-noprofile')) {
      tokens.push({ token: '-NoProfile', role: 'flag', meaning: POWERSHELL_FLAGS['-nop'] });
    }
    if (lower.includes('-w hidden') || lower.includes('windowstyle hidden')) {
      tokens.push({
        token: '-WindowStyle hidden',
        role: 'flag',
        meaning: 'Pencereyi gizleyerek arka planda sessizce yürütür.',
        riskNote: 'Gizleme (Defense Evasion) göstergesi.',
      });
      securityImplications.push('Kullanıcı arayüzünde görünmeyen gizli arka plan süreci başlatır.');
    }
    if (lower.includes('bypass') || lower.includes('-ep') || lower.includes('-executionpolicy')) {
      tokens.push({
        token: '-ExecutionPolicy Bypass',
        role: 'flag',
        meaning: 'PowerShell betik koruma politikasını atlar.',
        riskNote: 'Güvenlik kısıtlamalarını devre dışı bırakır.',
      });
      securityImplications.push('İmzasız betik kısıtlamalarını devre dışı bırakarak harici kodun çalışmasına izin verir.');
    }
    if (lower.includes('-enc') || lower.includes('-encodedcommand')) {
      tokens.push({
        token: '-EncodedCommand',
        role: 'flag',
        meaning: 'Base64 kodlanmış gizli komut dizesini çalıştırır.',
        riskNote: 'Komut satırı denetimlerini atlatmak (obfuscation) için kullanılır.',
      });
      securityImplications.push('Komut içeriği Base64 ile gizlenerek EDR ve log denetimlerinden kaçırılmaya çalışılmıştır.');
    }
    if (lower.includes('downloadstring') || lower.includes('webclient')) {
      tokens.push({
        token: 'Net.WebClient.DownloadString',
        role: 'subcommand',
        meaning: 'Uzak bir URL sunucusundan kodu doğrudan belleğe (RAM) çeker.',
        riskNote: 'Dosyasız (fileless) malware enjeksiyonu ve dropper göstergesi.',
      });
      securityImplications.push('Diske dosya yazmadan doğrudan RAM üzerinden harici kod çalıştırılması (C2 Callback).');
    }

    if (lower.includes('downloadstring') || lower.includes('-enc') || lower.includes('iex')) {
      category = 'Dosyasız (Fileless) İndirici & Yürütücü (Dropper/C2)';
      riskLevel = 'KRİTİK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, ÇOK YÜKSEK HASAR RİSKİ. Bu komut çalıştırılırsa sistem doğrudan saldırgan kontrolüne geçebilir, zararlı yük belleğe yüklenebilir.';
      mitreTechnique = 'T1059.001 (PowerShell), T1027 (Obfuscated Files), T1105 (Ingress Tool Transfer)';
      purpose = 'Harici bir web sunucusundan zararlı betik/yük indirip diske yazmadan doğrudan RAM üzerinde çalıştırmak.';
      summary = 'Bu komut PowerShell’in güvenlik politikalarını baypas ederek, pencereyi gizleyip uzak bir adresten kod indirip bellekte yürütmek (in-memory execution) için tasarlanmış tipik bir saldırı tekniğidir.';
      legitimateUseCases.push('SCCM veya Kurumsal MDM (InTune) sistemlerinin imzalı dağıtım görevleri (ancak -w hidden ve harici IP indirmesi meşru ortamlarda neredeyse hiç kullanılmaz).');
      troubleAndDamageRisks.push('Saldırganın Komuta Kontrol (C2) sunucusundan belleğe doğrudan zararlı yük (Cobalt Strike, Sliver, Meterpreter vb.) indirir.');
      troubleAndDamageRisks.push('Diske dosya yazmadığı için geleneksel antivirüsleri atlatabilir ve sistemi gizli bir zombiye (bot) dönüştürür.');
      troubleAndDamageRisks.push('Bellekte çalışan diğer servislerin ve kullanıcıların kimlik bilgilerini (LSASS dump) çalmak için zemin hazırlar.');
      recommendedDefenses.push(
        'Script Block Logging (Event ID 4104) ve Module Logging etkinleştirilmelidir.',
        'Constrained Language Mode (CLM) uygulanmalı ve AppLocker / WDAC ile yetkisiz PowerShell kısıtlanmalıdır.',
        'Komutta geçen hedef IP veya alan adı derhal güvenlik duvarında (Firewall/Proxy) engellenmelidir.'
      );
    } else {
      category = 'PowerShell Betik / Görev Çalıştırma';
      riskLevel = 'ORTA';
      willCauseTrouble = 'POTANSIYEL';
      willCauseTroubleText = 'DİKKAT / POTANSİYEL RİSK. Standart bir betik görevi olabilir ancak çalıştırılan betiğin kaynağı doğrulanmalıdır.';
      purpose = 'PowerShell ortamında belirli bir komut veya betik görevi icra etmek.';
      summary = 'PowerShell üzerinden sistem komutu çalıştırılmaktadır.';
      legitimateUseCases.push('Sistem yöneticilerinin rutin bakım ve otomasyon betikleri.');
      troubleAndDamageRisks.push('Yetkisiz bir betik çalıştırılıyorsa sistem ayarları değiştirilebilir.');
      recommendedDefenses.push('Betiğin kaynak dosyası ve çalıştıran kullanıcı hesabı incelenmelidir.');
    }
  }

  // 3. VSSADMIN / RANSOMWARE SHADOW COPY DELETION vs READ-ONLY QUERY
  else if (lower.includes('vssadmin') || lower.includes('shadowcopy') || lower.includes('wbadmin')) {
    ecosystem = 'Windows CMD';

    if (lower.includes('delete')) {
      category = 'Gölge Kopya ve Yedek İmha (Ransomware Hazırlığı)';
      riskLevel = 'KRİTİK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, KRİTİK HASAR RİSKİ. Sistemdeki tüm geri dönüş ve yedek mekanizması imha edilir; genellikle fidye şifrelemesi öncesi son adımdır.';
      mitreTechnique = 'T1490 (Inhibit System Recovery)';
      purpose = 'Windows Birim Gölge Kopyalarını (Volume Shadow Copies) silerek fidye yazılımı (ransomware) öncesi sistem geri yükleme imkanını yok etmek.';
      summary = 'Sistemdeki tüm geri yükleme noktalarını ve gölge kopyaları zorla siler. Neredeyse istisnasız tüm modern Ransomware türevleri şifreleme öncesinde bu komutu yürütür.';

      tokens.push(
        { token: 'vssadmin.exe', role: 'binary', meaning: 'Birim Gölge Kopyası Yönetim Aracı.' },
        { token: 'delete shadows', role: 'subcommand', meaning: 'Mevcut tüm sistem gölge kopyalarını sil.' },
        { token: '/all', role: 'flag', meaning: 'İstisnasız tüm birimlerdeki kopyaları kapsa.' },
        { token: '/quiet', role: 'flag', meaning: 'Kullanıcıya hiçbir onay sormadan sessizce sil.' }
      );
      legitimateUseCases.push('Disk alanı kritik derecede tükendiğinde sistem yöneticisinin eski yedek noktalarını manuel olarak temizlemesi.');
      troubleAndDamageRisks.push('Windows Birim Gölge Kopyalarını (Volume Shadow Copies) tamamen imha eder.');
      troubleAndDamageRisks.push('Olası bir fidye (Ransomware) saldırısı durumunda dosyaları kopyalardan geri getirme şansını sıfırlar.');
      troubleAndDamageRisks.push('Sistem çökmesi halinde önceki kararlı sürüme geri dönülemez.');
      securityImplications.push('Geri yükleme noktaları yok edilir, sistem çöküşü veya fidye yazılımı durumunda veri kurtarma engellenir.');
      recommendedDefenses.push(
        'Uç nokta (Host) derhal ağdan izole edilmelidir (Ağ karantinası).',
        'vssadmin.exe sürecini başlatan üst süreç (Parent Process) ve kullanıcı hesabı incelenmelidir.',
        'Sistemde çalışan şüpheli şifreleme süreçleri kontrol edilmelidir.'
      );
    } else {
      // Read-only query: vssadmin list shadows / list writers / list providers
      category = 'Sistem Gölge Kopya Keşfi (Read-Only Sorgu)';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Mevcut yedek veya gölge kopya durumunu sorgulayan salt okunur komuttur.';
      mitreTechnique = 'T1082 (System Information Discovery)';
      purpose = 'Windows Birim Gölge Kopyası servis durumunu veya mevcut kopyaları sorgulamak.';
      summary = 'Sistemdeki gölge kopyaları listeler; herhangi bir silme veya dosya değişikliği gerçekleştirmez.';

      tokens.push(
        { token: 'vssadmin.exe', role: 'binary', meaning: 'Birim Gölge Kopyası Yönetim Aracı.' },
        { token: trimmed.split(/\s+/)[1] || 'list', role: 'subcommand', meaning: 'Gölge kopyaları veya sağlayıcıları listeleme komutu.' }
      );
      legitimateUseCases.push('Yedekleme yazılımlarının veya sistem yöneticilerinin yedek durumunu ve VSS yazıcılarını (writers) denetlemesi.');
      troubleAndDamageRisks.push('Salt okunur bilgi sorgusu; sisteme veya dosyalara zarar vermez.');
      recommendedDefenses.push('Rutin denetim işlemidir; müdahale gerektirmez.');
    }
  }

  // 4. CERTUTIL / LIVING-OFF-THE-LAND (LOLBAS)
  else if (lower.includes('certutil')) {
    ecosystem = 'Windows CMD';
    tokens.push({
      token: 'certutil.exe',
      role: 'binary',
      meaning: 'Windows Sertifika Hizmetleri yardımcı programı (LOLBAS aracı).',
      riskNote: 'Saldırganlar dosya indirmek veya Base64 dosyaları çözmek için kötüye kullanır.',
    });

    if (lower.includes('-urlcache') || lower.includes('-split')) {
      tokens.push({ token: '-urlcache', role: 'flag', meaning: CERTUTIL_FLAGS['-urlcache'] });
      category = 'LOLBAS İle Dosya İndirme (Ingress Tool Transfer)';
      riskLevel = 'YÜKSEK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, YÜKSEK RİSK. Güvenlik duvarını atlatarak dışarıdan bilmediğiniz bir çalıştırılabilir dosya indirir.';
      mitreTechnique = 'T1105 (Ingress Tool Transfer), T1218 (System Binary Proxy Execution)';
      purpose = 'Meşru bir Windows sistem aracı (certutil) üzerinden harici bir sunucudan dosya/zararlı yazılım indirmek.';
      summary = 'Güvenlik duvarlarını ve indirme filtrelerini atlatmak amacıyla yerel certutil aracını kullanarak belirtilen URL’den dosya çeker.';
      legitimateUseCases.push('Kurumsal sertifika yetkilisi (Active Directory Certificate Services) yönetimi ve sertifika doğrulama.');
      troubleAndDamageRisks.push('Güvenlik duvarını meşru Windows aracı arkasına sığınarak deler ve uzaktaki sunucudan çalıştırılabilir zararlı dosya indirir.');
      troubleAndDamageRisks.push('Base64 ile kodlanmış gizli dosyaları açarak güvenlik yazılımlarının tespitinden kaçırır.');
      securityImplications.push('Meşru Windows ikilisi kullanılarak EDR/Proxy filtreleri atlatılmaya çalışılmaktadır.');
      recommendedDefenses.push(
        'Certutil ile harici URL erişimleri EDR ve proxy üzerinde engellenmeli ve alarmlanmalıdır.',
        'İndirilmeye çalışılan URL ve dosya adı SIEM havuzunda araştırılmalıdır.'
      );
    } else if (lower.includes('-decode')) {
      tokens.push({ token: '-decode', role: 'flag', meaning: CERTUTIL_FLAGS['-decode'] });
      category = 'Base64 Yük Çözme (Payload Deobfuscation)';
      riskLevel = 'YÜKSEK';
      willCauseTrouble = 'POTANSIYEL';
      willCauseTroubleText = 'DİKKAT / POTANSİYEL RİSK. Kodlanmış bir dosyayı çalıştırılabilir hale getirebilir.';
      mitreTechnique = 'T1140 (Deobfuscate/Decode Files or Information)';
      purpose = 'Metin görünümündeki zararlı kod dosyasını ikili (EXE/DLL) dosyaya dönüştürmek.';
      summary = 'Daha önce diske metin/sertifika olarak kaydedilmiş Base64 verisini çözerek çalıştırılabilir bir dosyaya çevirir.';
      legitimateUseCases.push('Sertifika dosyalarını PEM/DER formatları arasında dönüştürmek.');
      troubleAndDamageRisks.push('Gizlenmiş zararlı ikili dosyaları antivirüsleri atlatacak şekilde diske yazar.');
      recommendedDefenses.push('Oluşturulan dosyanın hash değeri virustotal ve EDR üzerinde doğrulanmalıdır.');
    } else {
      category = 'Dosya Hash Hesaplama & Bütünlük Kontrolü';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Dosya bütünlüğü veya sertifika durumunu sorgulayan standart araçtır.';
      purpose = 'Dosyanın kriptografik hash değerini hesaplamak veya sertifikayı incelemek.';
      summary = 'Certutil aracı ile dosya hash kontrolü veya sertifika sorgusu yapılmaktadır.';
      legitimateUseCases.push('Yazılımcıların ve yöneticilerin indirilen dosyaların SHA256/MD5 bütünlüğünü doğrulaması.');
      troubleAndDamageRisks.push('Salt okunur bilgi sorgusu; sisteme zarar vermez.');
      recommendedDefenses.push('Standart yönetim işlemi; müdahale gerektirmez.');
    }
  }

  // 4.1 BITSADMIN / BITS FILE TRANSFER (LOLBAS)
  else if (lower.includes('bitsadmin')) {
    ecosystem = 'Windows CMD';
    if (lower.includes('/transfer') || lower.includes('/create') || lower.includes('/addfile')) {
      category = 'BITS Servisi İle Dosya İndirme (Ingress Tool Transfer)';
      riskLevel = 'YÜKSEK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, YÜKSEK RİSK. Arka plan akıllı aktarım servisi (BITS) üzerinden harici kaynaktan dosya/zararlı yazılım indirir.';
      mitreTechnique = 'T1197 (BITS Jobs), T1105 (Ingress Tool Transfer)';
      purpose = 'Windows BITS servisini kullanarak arka planda harici bir adresten dosya indirmek.';
      summary = 'Arka planda sessiz dosya aktarımı yaparak EDR ve indirme kontrollerini atlatmaya yönelik LOLBAS yöntemidir.';
      tokens.push(
        { token: 'bitsadmin.exe', role: 'binary', meaning: 'Windows Arka Plan Akıllı Aktarım Servisi yönetim aracı (LOLBAS).' },
        { token: '/transfer', role: 'flag', meaning: 'Belirtilen URL adresinden yerel diske dosya transfer işi başlatır.' }
      );
      legitimateUseCases.push('Eski Windows güncelleme görevleri ve sistem yöneticilerinin bant genişliği kontrollü dosya indirme senaryoları.');
      troubleAndDamageRisks.push('Güvenlik duvarlarını ve izleme sistemlerini atlatarak uzaktan zararlı ikili dosyaları diske indirir.');
      securityImplications.push('Arka planda kalıcı indirme işi bırakılarak ağ filtreleri aşılmaya çalışılmaktadır.');
      recommendedDefenses.push('BITS işleri PowerShell "Get-BitsTransfer" ile izlenmeli, bilinmeyen aktarımlar iptal edilmelidir.');
    } else {
      category = 'BITS Görevleri Listeleme (Read-Only Sorgu)';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Mevcut BITS iş kuyruğunu sorgulayan salt okunur komuttur.';
      mitreTechnique = 'T1082 (System Information Discovery)';
      purpose = 'Sistemdeki aktif BITS indirme/yükleme görevlerini listelemek.';
      summary = 'Mevcut BITS görevlerini listeler; herhangi bir dosya indirmez veya silmez.';
      tokens.push(
        { token: 'bitsadmin.exe', role: 'binary', meaning: 'Windows BITS yönetim aracı.' },
        { token: '/list', role: 'flag', meaning: 'Aktif aktarım görevlerini listeler.' }
      );
      legitimateUseCases.push('Yöneticilerin arka plandaki transfer işlerini denetlemesi.');
      troubleAndDamageRisks.push('Salt okunur sorgudur; sisteme zarar vermez.');
      recommendedDefenses.push('Rutin denetim işlemidir.');
    }
  }

  // 4.2 WINDOWS REGISTRY RUN / PERSISTENCE
  else if (lower.includes('reg add') && (lower.includes('currentversion\\run') || lower.includes('currentversion\\runonce') || lower.includes('run'))) {
    ecosystem = 'Windows CMD';
    category = 'Kayıt Defteri Kalıcılık Anahtarı (Registry Persistence)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. Sisteme kalıcılık ekleyerek her Windows açılışında otomatik olarak çalışacak bir program tanımlar.';
    mitreTechnique = 'T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)';
    purpose = 'Windows Kayıt Defteri (Registry) Run anahtarına kayıt ekleyerek sistem açılışında kalıcılık sağlamak.';
    summary = 'Windows her başladığında kullanıcının veya sistemin haberi olmadan belirtilen programın arka planda çalışmasını sağlar.';
    tokens.push(
      { token: 'reg.exe', role: 'binary', meaning: 'Windows Kayıt Defteri yönetim komutu.' },
      { token: 'add', role: 'subcommand', meaning: 'Yeni bir kayıt anahtarı veya değer girdisi ekler.' },
      { token: 'Run Key', role: 'argument', meaning: 'Windows başlangıcında otomatik çalışacak programların tutulduğu kayıt defteri yolu.' }
    );
    legitimateUseCases.push('Yazılım kurulumlarının (Teams, OneDrive, Updater vb.) başlangıçta çalışma yapılandırmasını ayarlaması.');
    troubleAndDamageRisks.push('Zararlı yazılımın yeniden başlatmalardan sonra da sistemde kalıcı olarak çalışmasını sağlar.');
    securityImplications.push('Saldırgan sistemde kalıcılık (persistence) elde etmektedir.');
    recommendedDefenses.push('Kayıt defterindeki Run anahtarları Autoruns aracıyla ve EDR ile denetlenmeli, yetkisiz girdiler silinmelidir.');
  }

  // 4.3 RUNDLL32 LOLBAS
  else if (lower.includes('rundll32') || lower.startsWith('rundll32')) {
    ecosystem = 'Windows CMD';
    category = 'Rundll32 DLL Proxy Yürütme (LOLBAS)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. Doğrudan DLL kütüphanesindeki bir fonksiyonu dışarıdan çalıştırarak uygulama denetimlerini atlatabilir.';
    mitreTechnique = 'T1218.011 (System Binary Proxy Execution: Rundll32)';
    purpose = 'Bir DLL dosyasının dışa aktarılan (exported) fonksiyonunu meşru bir Windows ikilisi (rundll32) aracılığıyla yürütmek.';
    summary = 'Meşru bir sistem ikilisinin arkasına gizlenerek imzasız veya kötü amaçlı DLL kodlarını belleğe yükler.';
    tokens.push(
      { token: 'rundll32.exe', role: 'binary', meaning: 'Windows DLL çalıştırma yardımcı programı (LOLBAS aracı).' },
      { token: 'DLL / EntryPoint', role: 'argument', meaning: 'Yürütülecek dinamik kütüphane dosyası ve çağrılan giriş noktası.' }
    );
    legitimateUseCases.push('Denetim Masası araçlarını (.cpl) veya Windows sistem bileşenlerini çağırmak.');
    troubleAndDamageRisks.push('Uygulama beyaz listelerini (AppLocker/WDAC) atlatarak zararlı DLL kodlarını belleğe yükleyebilir.');
    securityImplications.push('Meşru ikili kullanılarak imzasız DLL kodlarının çalıştırılması.');
    recommendedDefenses.push('Çağrılan DLL dosyasının yolu ve hash değeri EDR havuzunda doğrulanmalıdır.');
  }

  // 4.4 REGSVR32 (SQUIBLYDOO)
  else if (lower.includes('regsvr32') || lower.startsWith('regsvr32')) {
    ecosystem = 'Windows CMD';
    category = 'Regsvr32 DLL / Scriptlet Yürütme (Squiblydoo)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. Uzak bir sunucudan scriptlet (.sct) çekip çalıştırabilir veya imzasız DLL kaydedebilir.';
    mitreTechnique = 'T1218.010 (System Binary Proxy Execution: Regsvr32)';
    purpose = 'COM bileşenlerini kaydetmek veya uzaktan zararlı XML/scriptlet kodlarını (Squiblydoo tekniği) çalıştırmak.';
    summary = 'Regsvr32 aracının uzaktan dosya çekme yeteneği (scrobj.dll /i:) kötüye kullanılarak EDR filtreleri atlatılır.';
    tokens.push(
      { token: 'regsvr32.exe', role: 'binary', meaning: 'OLE kontrolü ve DLL kayıt aracı (LOLBAS).' },
      { token: '/s /u /i', role: 'flag', meaning: 'Sessizce, kaydı kaldırarak ve belirtilen URL veya scriptlet üzerinden yük çalıştırma bayrakları.' }
    );
    legitimateUseCases.push('Yazılım kurulumlarında COM sunucularının ve ActiveX kontrollerinin sisteme kaydedilmesi.');
    troubleAndDamageRisks.push('Belleğe doğrudan zararlı betikler (JScript/VBScript) yükleyerek C2 bağlantısı açabilir.');
    securityImplications.push('Uygulama engelleri regsvr32 arkasına gizlenerek aşılmaktadır.');
    recommendedDefenses.push('Regsvr32 komutunun harici ağ bağlantısı kurması güvenlik duvarında engellenmelidir.');
  }

  // 4.5 MSHTA LOLBAS
  else if (lower.includes('mshta') || lower.startsWith('mshta')) {
    ecosystem = 'Windows CMD';
    category = 'Mshta HTA Betik Yürütme (LOLBAS)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. HTML uygulamaları (HTA) ve VBScript/JScript kodlarını sistem yetkileriyle doğrudan yürütür.';
    mitreTechnique = 'T1218.005 (System Binary Proxy Execution: Mshta)';
    purpose = 'HTML Application (.hta) dosyalarını veya uzak URL üzerindeki betikleri Windows Script Host yetkileriyle yürütmek.';
    summary = 'Zararlı HTML/betik yüklerini tarayıcı güvenlik korumalarını atlatarak doğrudan işletim sistemi seviyesinde çalıştırır.';
    tokens.push(
      { token: 'mshta.exe', role: 'binary', meaning: 'Microsoft HTML Uygulama Sunucusu (LOLBAS).' },
      { token: 'URL / .hta', role: 'argument', meaning: 'Çalıştırılacak zararlı betik veya HTA dosya konumu.' }
    );
    legitimateUseCases.push('Eski kurumsal yardım dosyaları ve intranet sihirbazlarının gösterimi.');
    troubleAndDamageRisks.push('VBScript/JScript istismarları ile sistemde uzaktan kod çalıştırma (RCE) sağlar.');
    securityImplications.push('Tarayıcı kısıtlamaları atlatılarak sistemde betik yürütülmektedir.');
    recommendedDefenses.push('Mshta.exe internete çıkışı ve bilinmeyen alan adlarına erişimi engellenmelidir.');
  }

  // 5. WHOAMI / NET USER / SYSTEM DISCOVERY
  else if (lower.includes('whoami') || lower.includes('net user') || lower.includes('net group') || lower.includes('net localgroup') || lower.includes('nltest') || lower.includes('systeminfo')) {
    ecosystem = lower.includes('whoami /priv') || lower.includes('net user') ? 'Windows CMD' : 'General';

    if (lower.includes('/add') || lower.includes('/delete')) {
      category = 'Kullanıcı Hesabı Ekleme/Değiştirme (Persistence)';
      riskLevel = 'KRİTİK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, YÜKSEK RİSK. Sisteme yeni bir yerel hesap ekler veya var olan hesapları değiştirir (Kalıcılık göstergesi).';
      mitreTechnique = 'T1136.001 (Local Account)';
      purpose = 'Sistemde yeni bir yerel veya yönetici hesabı oluşturarak kalıcılık sağlamak.';
      summary = 'Yerel işletim sistemi üzerinde yeni bir kullanıcı veya yönetici hesabı tanımlar.';
      tokens.push({
        token: lower.includes('/add') ? '/add' : '/delete',
        role: 'flag',
        meaning: lower.includes('/add') ? 'Sisteme yeni bir kullanıcı veya grup üyesi ekleme parametresi.' : 'Kullanıcı hesabı silme parametresi.',
        riskNote: 'Yetkisiz kalıcılık veya yerel arka kapı hesabı oluşturma göstergesi.',
      });
      legitimateUseCases.push('Sistem yöneticisinin yeni bir kullanıcı hesabı tanımlaması.');
      troubleAndDamageRisks.push('Saldırganın sistemde yetkili bir arka kapı hesabı oluşturmasına imkan tanır.');
      recommendedDefenses.push('Eklenen hesabın yetkili bir değişiklik talebi (Change Request) kapsamında olup olmadığı derhal doğrulanmalıdır.');
    } else if (lower.includes('/priv')) {
      category = 'Kullanıcı Ayrıcalıkları Keşfi (Privilege Enumeration)';
      riskLevel = 'ORTA';
      willCauseTrouble = 'POTANSIYEL';
      willCauseTroubleText = 'DİKKAT / POTANSİYEL RİSK. Mevcut token ayrıcalıklarını sorgulayarak yetki yükseltme zemini arar.';
      mitreTechnique = 'T1033 (System Owner/User Discovery)';
      purpose = 'Oturumun sahip olduğu Windows özel ayrıcalıklarını (SeDebugPrivilege, SeImpersonate vb.) denetlemek.';
      summary = 'Mevcut kullanıcının sahip olduğu güvenlik token izinlerini listeler.';
      tokens.push({
        token: '/priv',
        role: 'flag',
        meaning: 'Oturumun sahip olduğu Windows token ayrıcalıklarını (privileges) listeler.',
        riskNote: 'SeImpersonatePrivilege, SeDebugPrivilege gibi yetki yükseltme vektörlerini açığa çıkarır.',
      });
      legitimateUseCases.push('Yazılımcıların ve yöneticilerin güvenlik izinlerini denetlemesi.');
      troubleAndDamageRisks.push('Yetki yükseltme (Privilege Escalation / Potato exploit) için uygun zemin olup olmadığını açığa çıkarır.');
      recommendedDefenses.push('IIS/MSSQL servis hesaplarının whoami /priv çağırması kısıtlanmalıdır.');
    } else {
      category = 'Sistem & Hesap Keşfi (Reconnaissance / Discovery)';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Kullanıcı adını veya grup listesini sorgulayan rutin salt okunur komuttur.';
      mitreTechnique = 'T1033 (System Owner/User Discovery)';
      purpose = 'Mevcut oturumun kullanıcı adını veya kullanıcı listesini öğrenmek.';
      summary = 'Oturum açan kullanıcının kimliğini veya yerel hesapları listeler.';
      legitimateUseCases.push('Kullanıcıların veya betiklerin hangi hesap altında çalıştıklarını doğrulaması.');
      troubleAndDamageRisks.push('Salt okunur bilgi sorgusu; sisteme zarar vermez.');
      recommendedDefenses.push('Olağan dışı bir servisten (web sunucusu vb.) tetiklenmediyse müdahale gerektirmez.');
    }

    tokens.push({
      token: trimmed.split(/\s+/)[0],
      role: 'binary',
      meaning: 'Kullanıcı ve kimlik bilgisi sorgulama aracı.',
    });
  }

  // 6. LINUX REVERSE SHELL / BASH TCP
  else if (lower.includes('/dev/tcp/') || lower.includes('nc -e') || lower.includes('mkfifo') || lower.includes('/bin/sh -i') || lower.includes('/bin/bash -i')) {
    ecosystem = 'Linux Bash / Shell';
    category = 'Etkileşimli Ters Kabuk (Interactive Reverse Shell)';
    riskLevel = 'KRİTİK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, DOĞRUDAN ELE GEÇİRME RİSKİ. Sunucu terminalini doğrudan uzaktaki saldırganın IP adresine teslim eder.';
    mitreTechnique = 'T1059.004 (Unix Shell), T1571 (Non-Standard Port), T1071 (Application Layer Protocol)';
    purpose = 'Hedef Linux sunucusundan saldırganın dinleme yapan makinesine ters TCP bağlantısı kurarak tam yetkili uzaktan komut satırı (shell) erişimi sağlamak.';
    summary = 'Linux sistem kabuğunu doğrudan bir ağ soketine (/dev/tcp veya netcat) bağlar. Sunucu dışarıya bağlantı kurduğu için dışarıdan gelen güvenlik duvarı kurallarını aşar.';

    tokens.push(
      { token: 'bash -i', role: 'binary', meaning: 'İnteraktif kabuk oturumu başlatır.' },
      { token: '>& /dev/tcp/IP/PORT', role: 'pipeline', meaning: 'Girdi ve çıktıyı saldırganın IP ve portuna yönlendirir.' },
      { token: '0>&1', role: 'operator', meaning: 'Standart girdi akışını (stdin) standart çıktıya bağlayarak çift yönlü iletişim kurar.' }
    );
    legitimateUseCases.push('Yalnızca yetkili sızma testi (penetrasyon testi) uzmanlarının izinli güvenlik denetimleri hariç hiçbir meşru üretim ortamında kullanılmaz.');
    troubleAndDamageRisks.push('Sunucunun tüm kontrolünü uzaktaki saldırganın terminaline teslim eder (Ters Kabuk / Reverse Shell).');
    troubleAndDamageRisks.push('Saldırgan sunucu içerisindeki tüm veritabanlarına, dosyalara ve iç ağ kaynaklarına tam erişim kazanır.');
    securityImplications.push('Saldırgan sunucuda interaktif uzaktan komut yürütme kontrolünü ele geçirmiştir.');
    recommendedDefenses.push(
      'Hedef sunucu derhal ağdan izole edilmeli ve ilgili IP adresi engellenmelidir.',
      'Sunucudan dışarıya (outbound) bilinmeyen portlara yapılan TCP trafiği firewall seviyesinde sınırlandırılmalıdır.'
    );
  }

  // 6.5 LINUX FILE PERMISSIONS MODIFICATION (chmod 777 etc.)
  else if (lower.includes('chmod ') && (lower.includes('777') || lower.includes('666') || lower.includes('+x') || lower.includes('/etc/'))) {
    ecosystem = 'Linux Bash / Shell';
    category = 'Linux Dosya İzinleri Genişletme (Permission Modification)';
    riskLevel = 'ORTA';
    willCauseTrouble = 'POTANSIYEL';
    willCauseTroubleText = 'DİKKAT / POTANSİYEL RİSK. Dosya veya dizin izinlerini aşırı genişleterek yetkisiz tüm kullanıcıların okuma/yazma/çalıştırma yapmasına olanak tanır.';
    mitreTechnique = 'T1222.002 (Linux and Mac File and Directory Permissions Modification)';
    purpose = 'Dosya ve klasör yetkilerini değiştirerek herkese (World-Writable) tam erişim vermek.';
    summary = 'Dosya izinlerini genişleterek sistem dosyalarını veya betikleri savunmasız hale getirir.';
    tokens.push(
      { token: 'chmod', role: 'binary', meaning: 'Linux dosya erişim yetkilerini değiştirme komutu.' },
      { token: '777 / +x', role: 'argument', meaning: 'Herkes için okuma, yazma ve çalıştırma izni.' }
    );
    legitimateUseCases.push('Geliştiricilerin geçici test ortamlarında dosya yetki sorunlarını gidermesi.');
    troubleAndDamageRisks.push('Kritik sistem dosyaları (örn: /etc/passwd) değiştirilebilir hale gelirse yetkisiz kullanıcılar root yetkisi kazanabilir.');
    securityImplications.push('Sistem güvenlik sınırları ve dosya koruma mekanizmaları zayıflatılmaktadır.');
    recommendedDefenses.push('İzinler en az yetki prensibiyle (chmod 644/755) düzeltilmeli ve dosya bütünlüğü denetlenmelidir.');
  }

  // 7. LINUX SENSITIVE FILE ACCESS (/etc/passwd, /etc/shadow)
  else if (lower.includes('/etc/passwd') || lower.includes('/etc/shadow') || lower.includes('cat /etc/master.passwd')) {
    ecosystem = 'Linux Bash / Shell';
    category = 'Linux Sistem ve Kimlik Bilgisi Keşfi (Credential Access / Discovery)';
    riskLevel = lower.includes('/etc/shadow') ? 'KRİTİK' : 'YÜKSEK';
    willCauseTrouble = lower.includes('/etc/shadow') ? 'EVET_YUKSEK' : 'POTANSIYEL';
    willCauseTroubleText = lower.includes('/etc/shadow')
      ? 'EVET, YÜKSEK RİSK. Sistem kullanıcılarının şifrelenmiş parola özetlerine (hash) erişim denemesidir.'
      : 'DİKKAT / POTANSİYEL RİSK. Sistem yerel kullanıcı hesapları listesini okur.';
    mitreTechnique = 'T1003.008 (/etc/passwd and /etc/shadow)';
    purpose = 'Linux işletim sistemindeki kullanıcı hesaplarını veya parola özetlerini (hash) ele geçirmek.';
    summary = 'Sistemdeki yerel kullanıcı hesaplarının listelendiği /etc/passwd veya şifreli parolaların tutulduğu /etc/shadow dosyasına erişim girişimidir.';

    tokens.push(
      { token: 'cat / file access', role: 'binary', meaning: 'Dosya içeriğini okuma veya konsola yazdırma işlemi.' },
      { token: lower.includes('/etc/shadow') ? '/etc/shadow' : '/etc/passwd', role: 'argument', meaning: 'Kullanıcı hesapları veya şifreli parola özetlerini içeren kritik sistem dosyası.' }
    );
    legitimateUseCases.push('Sistem yöneticilerinin kullanıcı hesaplarını veya izinlerini yerel terminalden denetlemesi.');
    troubleAndDamageRisks.push('Saldırgan sistemdeki geçerli hesapları öğrenerek kaba kuvvet (brute-force) saldırısı başlatabilir.');
    securityImplications.push('Saldırgan sistem kullanıcılarını ve servis hesaplarını tespit etmektedir.');
    recommendedDefenses.push('Web uygulaması dosya okuma (LFI / Path Traversal) açıklarına karşı denetlenmelidir.');
  }

  // 7.2 WEB PATH TRAVERSAL / LFI (including URL Encoded %2e%2e%2f)
  else if (
    lower.includes('..%2f') ||
    lower.includes('%2e%2e%2f') ||
    lower.includes('%2e%2e/') ||
    lower.includes('../..') ||
    lower.includes('..\\..') ||
    (lower.includes('win.ini') && (lower.includes('..') || lower.includes('%2e')))
  ) {
    ecosystem = 'Web Exploit / Injection';
    category = 'Dizin Gezinme / Yol İstismarı (Path Traversal / LFI)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. Web uygulaması dizin sınırlarını aşarak sunucudaki kritik yapılandırma veya sistem dosyalarını okumaya çalışır.';
    mitreTechnique = 'T1083 (File and Directory Discovery), T1059 (Command and Scripting Interpreter)';
    purpose = 'Web kök dizininin dışına çıkarak işletim sisteminin hassas dosyalarını (win.ini, /etc/passwd vb.) çekmek.';
    summary = 'URL parametreleri üzerinden "../" ve URL kodlu dizin geçişleri kullanarak yetkisiz dosya okuma girişimidir.';
    tokens.push(
      { token: 'Path Traversal Payload', role: 'subcommand', meaning: 'Dizin atlama kalıbı (Dot-Dot-Slash / %2e%2e%2f).' }
    );
    legitimateUseCases.push('Yalnızca güvenlik ekiplerinin zaafiyet taramaları.');
    troubleAndDamageRisks.push('Hassas sistem parolaları, veritabanı şifreleri ve sunucu konfigürasyonları ifşa olabilir.');
    securityImplications.push('Web uygulaması yetkileri dahilinde yerel dosya sızıntısı (LFI) riski.');
    recommendedDefenses.push('Web uygulamasında dosya yolları doğrulanmalı, path normalization ve WAF kuralları uygulanmalıdır.');
  }

  // 8. WEB EXPLOITATION & INJECTIONS (SQLi, XSS, Path Traversal) vs LEGITIMATE SQL QUERIES
  else if (
    (lower.includes('union select') ||
      lower.includes('information_schema') ||
      lower.includes('waitfor delay') ||
      lower.includes('sleep(') ||
      lower.includes('benchmark(') ||
      /\bor\s+['"]?1['"]?\s*=\s*['"]?1/i.test(lower) ||
      /\bselect\b[\s\S]+\bfrom\b/i.test(lower)) &&
    !lower.includes('select-object') &&
    !lower.includes('select -')
  ) {
    ecosystem = 'Web Exploit / Injection';
    const isExploitIndicator =
      lower.includes('union') ||
      lower.includes('information_schema') ||
      lower.includes('waitfor delay') ||
      lower.includes('sleep(') ||
      lower.includes('benchmark(') ||
      /\bor\s+['"]?1['"]?\s*=\s*['"]?1/i.test(lower);

    if (isExploitIndicator) {
      category = 'SQL Enjeksiyonu (SQL Injection - SQLi)';
      riskLevel = 'KRİTİK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, VERİTABANI İSTİSMARI VE VERİ SIZINTISI RİSKİ. Veritabanındaki tüm tablolar okunabilir, silinebilir veya değiştirilebilir.';
      mitreTechnique = 'T1190 (Exploit Public-Facing Application)';
      purpose = 'Veritabanına yetkisiz SQL kodları enjekte ederek hassas tabloları çekmek veya zaman gecikmeli (blind) sorgularla veri sızdırmak.';
      summary = 'Uygulamanın veritabanı sorgu katmanını atlatarak doğrudan veritabanı motoruna ek SQL komutları enjekte eden tipik siber saldırı payload’ıdır.';
      tokens.push({
        token: 'SQL Injection Payload',
        role: 'subcommand',
        meaning: 'Uygulama veri filtresini atlatarak veritabanında harici komut koşturan kalıp.',
        riskNote: 'Veritabanı dökümü (data breach) riski.',
      });
      legitimateUseCases.push('Yalnızca yetkili güvenlik tarayıcılarının (SAST/DAST) veya izinli sızma testi uzmanlarının zaafiyet denetimleri.');
      troubleAndDamageRisks.push('Veritabanındaki tüm kullanıcı adları, parolalar, kredi kartları ve kişisel veriler sızdırılabilir.');
      troubleAndDamageRisks.push('Veritabanı tabloları silinebilir veya yetkili hesaplar ele geçirilebilir.');
      securityImplications.push('Veritabanındaki kullanıcı tabloları, parolalar veya müşteri verileri okunabilir veya değiştirilebilir.');
      recommendedDefenses.push(
        'Tüm SQL sorgularında Parametrik Sorgular (Parameterized Queries / Prepared Statements) kullanılmalıdır.',
        'WAF (Web Application Firewall) SQLi kural setleri devreye alınmalıdır.'
      );
    } else {
      ecosystem = 'General';
      category = 'Veritabanı Sorgusu (SQL Query)';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ. Standart veri sorgulama (SELECT ... FROM) komutudur; istismar kalıbı içermez.';
      purpose = 'Veritabanından belirli kriterlere göre kayıtları listelemek veya filtrelemek.';
      summary = 'Standart veri sorgulama (SELECT ... FROM) komutudur; istismar veya enjeksiyon kalıbı içermemektedir.';
      tokens.push({
        token: 'SELECT ... FROM',
        role: 'subcommand',
        meaning: 'Veritabanı tablosundan kayıt okuma komutu.',
      });
      legitimateUseCases.push('Uygulama geliştiricileri, veritabanı yöneticileri (DBA) veya iş analistleri tarafından veri çekmek amacıyla.');
      troubleAndDamageRisks.push('Salt okunur bilgi sorgusu; sisteme zarar vermez.');
      securityImplications.push('Sorgunun yetkili bir kullanıcı veya meşru uygulama konsolundan çalıştırıldığı doğrulanmalıdır.');
      recommendedDefenses.push('En az yetki prensibi (Principle of Least Privilege) ile veritabanı okuma hakları sınırlandırılmalıdır.');
    }
  }

  // 9. CROSS SITE SCRIPTING (XSS)
  else if (lower.includes('<script>') || lower.includes('javascript:') || lower.includes('onerror=') || lower.includes('onload=')) {
    ecosystem = 'Web Exploit / Injection';
    category = 'Siteler Arası Betik Çalıştırma (Cross-Site Scripting - XSS)';
    riskLevel = 'YÜKSEK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, YÜKSEK RİSK. Kullanıcı veya yönetici oturum çerezlerini (cookie) çalarak hesap ele geçirmeye yol açar.';
    mitreTechnique = 'T1059.007 (JavaScript)';
    purpose = 'Kullanıcı veya yönetici tarayıcısında yetkisiz JavaScript kodu işleterek oturum çerezlerini veya verileri çalmak.';
    summary = 'Web uygulamasına istemci taraflı betik enjekte etme girişimidir.';
    tokens.push({
      token: '<script> / DOM Event',
      role: 'subcommand',
      meaning: 'Tarayıcıda JavaScript çalıştıran HTML/JS enjeksiyon kalıbı.',
    });
    legitimateUseCases.push('Güvenlik uzmanlarının XSS açıklarını denetlemesi.');
    troubleAndDamageRisks.push('Oturum çerezleri (Session Hijacking) çalınarak yönetici yetkileri ele geçirilebilir.');
    securityImplications.push('Oturum çerezleri (Session Hijacking) veya kimlik bilgileri istemci tarayıcısından çalınabilir.');
    recommendedDefenses.push('Girdi doğrulama ve bağlama duyarlı çıktı kodlama (HTML Entity Encoding) uygulanmalıdır.');
  }

  // 10. CURL / WGET DOWNLOAD & EXECUTE PIPELINE
  else if (lower.includes('curl ') || lower.includes('wget ') || lower.startsWith('curl') || lower.startsWith('wget')) {
    ecosystem = lower.includes('sh') || lower.includes('|') ? 'Linux Bash / Shell' : 'General';
    tokens.push({
      token: lower.includes('curl') ? 'curl' : 'wget',
      role: 'binary',
      meaning: 'Ağ protokolleri üzerinden veri veya dosya aktarımı yapan komut satırı aracı.',
    });

    if (lower.includes('| bash') || lower.includes('| sh') || lower.includes('| python') || lower.includes('| perl')) {
      category = 'Tek Satırda İndir ve Çalıştır (Download & Pipe to Shell)';
      riskLevel = 'KRİTİK';
      willCauseTrouble = 'EVET_YUKSEK';
      willCauseTroubleText = 'EVET, ÇOK YÜKSEK RİSK. Dış kaynaktan çekilen doğrulanmamış kod doğrudan root/kullanıcı yetkisiyle çalıştırılır.';
      mitreTechnique = 'T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer)';
      purpose = 'Uzak sunucudaki betiği diske kaydetmeden doğrudan kabuk (bash/sh) sürecine yönlendirip çalıştırmak.';
      summary = 'Web üzerinden çekilen içeriği anında kabuk yorumlayıcısına (pipe) aktararak çalıştırır. Kötü amaçlı yazılımların yaygın kurulum yöntemidir.';
      legitimateUseCases.push('Bazı meşru araçların (Docker, Homebrew, Rust vb.) resmi tek satırlık kurulum betikleri.');
      troubleAndDamageRisks.push('Uzak sunucuda kod değiştirilirse sistem doğrudan saldırgan kontrolüne geçer.');
      securityImplications.push('İndirilen içeriğin doğruluğu denetlenmeden doğrudan sistemde kod çalıştırılmasına yol açar.');
      recommendedDefenses.push(
        'Sunuculardan doğrudan kabuğa aktarılan (pipe-to-shell) indirmeler engellenmelidir.',
        'Hedef URL ve IP güvenlik duvarında araştırılmalıdır.'
      );
    } else {
      category = 'Ağ Dosya İndirme Talebi';
      riskLevel = 'BİLGİ';
      willCauseTrouble = 'HAYIR_GUVENLI';
      willCauseTroubleText = 'HAYIR, GÜVENLİ. Belirtilen URL adresine standart bir HTTP isteği gönderir.';
      purpose = 'Belirtilen URL adresindeki kaynağı indirmek veya web yanıtını kontrol etmek.';
      summary = 'Ağ üzerinden belirtilen dosyayı veya web yanıtını çeker.';
      legitimateUseCases.push('Geliştiricilerin ve sistemcilerin API testleri, dosya indirme veya web servisi durum kontrolleri.');
      troubleAndDamageRisks.push('Salt indirme işlemi sisteme doğrudan zarar vermez.');
      recommendedDefenses.push('İndirilen dosya kaynağı güvenilir olmalıdır.');
    }
  }

  // 10.9 LINUX FORK BOMB (DoS)
  else if (lower.includes(':(){ :|:& };:') || lower.includes(':(){:|:&};:')) {
    ecosystem = 'Linux Bash / Shell';
    category = 'Fork Bomb / Kaynak Tüketimi (Denial of Service - DoS)';
    riskLevel = 'KRİTİK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, SİSTEM KİLİTLENMESİ VE ÇÖKME RİSKİ. Sonsuz özyinelemeli süreçler açarak bellek ve işlemci tablosunu tüketir, sistemi dondurur.';
    mitreTechnique = 'T1499 (Endpoint Denial of Service)';
    purpose = 'Sonsuz sayıda alt süreç üreterek işlem tablosunu (PID table) tüketmek ve sistemi yanıt veremez hale getirmek.';
    summary = 'Bash kabuğunda kendisini arka planda sonsuz kez çağıran klasik Fork Bomb saldırısıdır.';
    tokens.push(
      { token: ':()', role: 'subcommand', meaning: '":" adında özyinelemeli bir fonksiyon tanımlar.' },
      { token: '{ :|:& }', role: 'pipeline', meaning: 'Fonksiyonu çağırıp boru hattıyla tekrar arka planda & ile çoğaltır.' },
      { token: ';:', role: 'operator', meaning: 'Fonksiyonu ilk kez tetikleyerek sonsuz zinciri başlatır.' }
    );
    legitimateUseCases.push('Hiçbir üretim sisteminde meşru kullanımı yoktur; yalnızca kısıt (ulimit) testlerinde kullanılır.');
    troubleAndDamageRisks.push('Tüm işlemciyi ve PID havuzunu tüketerek sunucunun donmasına veya kilitlenmesine yol açar.');
    securityImplications.push('Hizmet engelleme (Denial of Service) ve sistem istikrarsızlaştırma göstergesi.');
    recommendedDefenses.push('/etc/security/limits.conf altında nproc (maksimum süreç sayısı) kısıtlaması uygulanmalıdır.');
  }

  // 11. RM / DESTRUCTIVE COMMANDS
  else if (lower.includes('rm -rf /') || lower.includes('rm -rf /*') || lower.includes('rm -f /')) {
    ecosystem = 'Linux Bash / Shell';
    category = 'Kök Dizin ve Sistem Dosyalarını Zorla Silme (Yıkıcı Komut)';
    riskLevel = 'KRİTİK';
    willCauseTrouble = 'EVET_YUKSEK';
    willCauseTroubleText = 'EVET, GERİ DÖNÜLEMEZ FELAKET HASARI. İşletim sisteminin tüm dosyalarını, yapılandırmalarını ve veritabanlarını kalıcı olarak siler ve sistemi çökerterek açılmaz hale getirir.';
    mitreTechnique = 'T1485 (Data Destruction)';
    purpose = 'İşletim sistemindeki tüm dosyaları onay istemeksizin kalıcı olarak imha etmek.';
    summary = 'Kök dizinden başlayarak tüm dosya sistemini zorla silen yıkıcı bir komuttur.';

    tokens.push(
      { token: 'rm', role: 'binary', meaning: 'Linux dosya ve dizin silme komutu.' },
      { token: '-rf', role: 'flag', meaning: 'Recursive ve Force: Tüm alt dizinleri onay sormaksızın zorla sil.' },
      { token: '/', role: 'argument', meaning: 'Kök dosya sistemi dizini.' }
    );
    legitimateUseCases.push('Hiçbir meşru üretim sisteminde root/kök dizin için kullanılmaz.');
    troubleAndDamageRisks.push('İşletim sistemini ve tüm kullanıcı verilerini tamamen imha eder, makine tekrar açılmaz.');
    securityImplications.push('Fidye yazılımı veya veri sabotajı göstergesi.');
    recommendedDefenses.push('Yetkili root hesaplarının erişim logları incelenmeli ve sistem snapshot yedeğinden kurtarılmalıdır.');
  }

  // 12. LEGITIMATE LINUX / WINDOWS DIAGNOSTIC & ADMIN COMMANDS
  else if (
    /^(?:systemctl|service|journalctl|docker|kubectl|ip\s+(?:route|addr)|ifconfig|netstat|ss\s+|df\s+|free\s+|uptime|ps\s+aux|top|htop|ping\s+|traceroute|tracert|nslookup|dig\s+|ipconfig|tasklist|git\s+|npm\s+|yarn\s+|bun\s+|hostname|uname|whoami|echo\s+|cat\s+|ls\s+|dir\b)/i.test(
      trimmed
    )
  ) {
    ecosystem = /^(?:ipconfig|tracert|tasklist|dir\b)/i.test(trimmed) ? 'Windows CMD' : 'Linux Bash / Shell';
    category = 'Sistem & Ağ Tanılama / Yönetim Komutu';
    riskLevel = 'BİLGİ';
    willCauseTrouble = 'HAYIR_GUVENLI';
    willCauseTroubleText = 'HAYIR, GÜVENLİ VE ZARARSIZ. Yetkili sistem yöneticileri veya kullanıcılar tarafından çalıştırılan rutin tanılama komutudur.';
    purpose = 'Sistem durumunu, ağ yapılandırmasını, servisleri veya kaynak kullanımını denetlemek.';
    summary = 'Yetkili sistem yöneticileri veya otomasyon betikleri tarafından çalıştırılan standart yönetim ve durum sorgulama komutudur.';

    tokens.push({
      token: trimmed.split(/\s+/)[0],
      role: 'binary',
      meaning: 'Sistem yönetimi, süreç listeleme ve durum tanılama aracı.',
    });

    legitimateUseCases.push('Sistem yöneticilerinin, DevOps mühendislerinin ve yazılımcıların günlük rutin servis durumu kontrolü, ağ teşhisi ve sürüm kontrolü.');
    troubleAndDamageRisks.push('Salt okunur bilgi sorgusu yaptığı için sisteme herhangi bir zarar vermez, çökertmez veya veri kaybına yol açmaz.');
    securityImplications.push('Rutin yönetim işlemidir; olağan dışı bir kullanıcı veya zaman diliminde çalışıp çalışmadığı kontrol edilebilir.');
    recommendedDefenses.push('Yönetimsel komutların yetkili personel ve atlama sunucuları (bastion host) üzerinden yürütüldüğü doğrulanmalıdır.');
  }

  // 13. GENERIC / FALLBACK PARSER
  else {
    category = 'Sistem Yürütme Komutu';
    riskLevel = 'BİLGİ';
    willCauseTrouble = 'HAYIR_GUVENLI';
    willCauseTroubleText = 'HAYIR, STANDART İŞLEM. Belirtilen komut standart sistem kabuğunda yürütülmektedir.';
    purpose = 'Sistem üzerinde bir işlem veya program çalıştırmak.';
    summary = `Belirtilen komut (${trimmed.slice(0, 60)}) sistem kabuğunda bir işlem yürütmektedir.`;
    legitimateUseCases.push('Sistem kullanıcıları tarafından belirli bir yazılım veya betiği başlatmak amacıyla.');
    troubleAndDamageRisks.push('Yüksek yetkilerle çalıştırılmıyorsa rutin bir süreçtir.');
  }

  // Token breakdown for remaining arguments if tokens empty
  if (tokens.length === 0) {
    const parts = trimmed.split(/\s+/).slice(0, 10);
    parts.forEach((p, idx) => {
      if (idx === 0) {
        tokens.push({ token: p, role: 'binary', meaning: 'Yürütülen ana ikili dosya veya komut adı.' });
      } else if (p.startsWith('-') || p.startsWith('/')) {
        tokens.push({ token: p, role: 'flag', meaning: 'Komut davranışını değiştiren parametre bayrağı.' });
      } else {
        tokens.push({ token: p, role: 'argument', meaning: 'Komut argümanı veya hedef dosya/yol parametresi.' });
      }
    });
  }

  if (securityImplications.length === 0) {
    securityImplications.push('Komutun yürütüldüğü yetki alanı (kullanıcı/servis hesabı) ve zaman damgası incelenmelidir.');
  }

  if (recommendedDefenses.length === 0) {
    recommendedDefenses.push('Komutu yürüten sürecin üst süreci (Parent Process) ve parametre bütünlüğü doğrulanmalıdır.');
  }

  // CONTEXT-AWARE RISK CALIBRATION (Central Context Integration)
  if (context) {
    const parentLower = (context.parentProcess || '').toLowerCase();
    const userLower = (context.username || '').toLowerCase();
    const isSuspiciousParent = parentLower.includes('w3wp') || parentLower.includes('httpd') || parentLower.includes('nginx') || parentLower.includes('sqlservr');
    const isExpectedAdmin = userLower.includes('admin') || userLower.includes('root') || userLower.includes('system');

    // Context B: Web server spawned command (High priority / Webshell suspicion)
    if (isSuspiciousParent) {
      if (riskLevel !== 'KRİTİK' && riskLevel !== 'YÜKSEK') {
        riskLevel = 'YÜKSEK';
        willCauseTrouble = 'POTANSIYEL';
        willCauseTroubleText = `DİKKAT / YÜKSEK ÖNCELİK. Normalde salt okunur olan bu komut, web sunucusu (${context.parentProcess}) altından başlatılmıştır; olası bir Webshell veya RCE keşif faaliyetine işaret edebilir.`;
      }
      securityImplications.unshift(`Web sunucusu (${context.parentProcess}) altından olağandışı komut yürütme (Olası RCE/Webshell keşfi).`);
    } else if (isExpectedAdmin && (context.logSource?.includes('maintenance') || context.logSource?.includes('admin'))) {
      // Context A: Verified administrative maintenance window
      if (riskLevel === 'YÜKSEK' && !lower.includes('rm -rf') && !lower.includes(':(){ :|:& };:')) {
        riskLevel = 'ORTA';
        willCauseTroubleText = `${willCauseTroubleText} (Not: Yetkili yönetici (${context.username}) bakım bağlamında yürütülmüştür).`;
      }
    }
  }

  // Forensic Note & Non-speculative boundary
  const forensicCaveat =
    'Adli Değerlendirme Notu: Bu analiz, komut satırı metninin statik teknik yeteneklerini açıklamaktadır. Bir komutun bir logda yer alması, sistemin kesin olarak ele geçirildiğini (compromised) veya saldırının başarılı olduğunu tek başına kanıtlamaz. Kesin hüküm için komutu başlatan üst süreç (Parent Process), kullanıcı kimliği, disk aktivitesi ve ağ bağlantıları birlikte korele edilmelidir.';

  // Generate full narrative markdown (Educational, forensically sound explanation)
  const fullNarrativeMarkdown = buildFullNarrativeMarkdown({
    rawCommand: trimmed,
    category,
    ecosystem,
    purpose,
    summary,
    decodedPayload: decodedPayload || undefined,
    riskLevel,
    mitreTechnique: mitreTechnique || undefined,
    tokens,
    securityImplications,
    recommendedDefenses,
    legitimateUseCases,
    troubleAndDamageRisks,
    willCauseTroubleText,
    context,
    forensicCaveat,
  });

  return {
    rawCommand: trimmed,
    normalizedCommand: trimmed,
    category,
    ecosystem,
    purpose,
    summary,
    decodedPayload: decodedPayload || undefined,
    riskLevel,
    mitreTechnique: mitreTechnique || undefined,
    tokens,
    securityImplications,
    recommendedDefenses,
    legitimateUseCases,
    troubleAndDamageRisks,
    willCauseTrouble,
    willCauseTroubleText,
    fullNarrativeMarkdown,
    context,
    forensicCaveat,
  };
}

function buildFullNarrativeMarkdown(params: {
  rawCommand: string;
  category: string;
  ecosystem: string;
  purpose: string;
  summary: string;
  decodedPayload?: string;
  riskLevel: string;
  mitreTechnique?: string;
  tokens: CommandTokenExplanation[];
  securityImplications: string[];
  recommendedDefenses: string[];
  legitimateUseCases: string[];
  troubleAndDamageRisks: string[];
  willCauseTroubleText: string;
  context?: CommandExplainerContext;
  forensicCaveat: string;
}): string {
  const {
    rawCommand,
    category,
    ecosystem,
    purpose,
    summary,
    decodedPayload,
    riskLevel,
    mitreTechnique,
    tokens,
    securityImplications,
    recommendedDefenses,
    legitimateUseCases,
    troubleAndDamageRisks,
    willCauseTroubleText,
    context,
    forensicCaveat,
  } = params;

  let md = `## 📌 1. Bu Komut Nedir ve Temel Amacı Ne İşe Yarar?\n\n`;
  md += `**İncelenen Komut:** \`${rawCommand}\`\n\n`;
  md += `* **Kategori:** ${category}\n`;
  md += `* **İşletim Sistemi / Ekosistem:** ${ecosystem}\n`;
  md += `* **Tehdit & Risk Düzeyi:** **${riskLevel}**\n`;
  if (mitreTechnique) {
    md += `* **İlişkili MITRE ATT&CK Tekniği:** \`${mitreTechnique}\`\n`;
  }
  md += `\n**Temel İşlevi ve Amacı:**\n${summary} ${purpose}\n\n`;

  if (decodedPayload) {
    md += `> 💡 **Otomatik Çözülen Gizli Yük (Base64 Decoded Payload):**\n> \`\`\`powershell\n> ${decodedPayload}\n> \`\`\`\n\n`;
  }

  md += `## 🛠️ 2. Normal Şartlarda Nerelerde ve Kimler Tarafından Kullanılır?\n\n`;
  legitimateUseCases.forEach((u) => {
    md += `* ${u}\n`;
  });
  md += `\n`;

  md += `## ⚠️ 3. Güvenlik Değerlendirmesi: Saldırganlar Bunu Nasıl ve Neden Kötüye Kullanır?\n\n`;
  securityImplications.forEach((s) => {
    md += `* **Teknik Tehdit Göstergesi:** ${s}\n`;
  });
  md += `\n`;

  md += `## 💥 4. Bu Komut Çalışırsa Sistemde Ne Sorun Çıkartır? (Risk & Hasar Analizi)\n\n`;
  md += `**Değerlendirme:** **${willCauseTroubleText}**\n\n`;
  troubleAndDamageRisks.forEach((r) => {
    md += `* ${r}\n`;
  });
  md += `\n`;

  md += `## 🔍 5. Adım Adım Parametre ve Bayrak (Flag) İncelemesi\n\n`;
  md += `| Parametre / Parça | Rol | Adli Anlamı ve İşlevi | Risk Notu |\n`;
  md += `| :--- | :--- | :--- | :--- |\n`;
  tokens.forEach((t) => {
    md += `| \`${t.token}\` | ${t.role} | ${t.meaning.replace(/\|/g, '/')} | ${t.riskNote ? t.riskNote.replace(/\|/g, '/') : '-'} |\n`;
  });
  md += `\n`;

  md += `## 🛡️ 6. Bir Sistemci veya SOC Analisti Bu Komutu Gördüğünde Ne Yapmalıdır?\n\n`;
  recommendedDefenses.forEach((d, idx) => {
    md += `${idx + 1}. **${d}**\n`;
  });
  md += `\n`;

  if (context) {
    md += `## 📋 7. İlişkili Log Bağlamı ve Olay Bilgisi\n\n`;
    md += `* **Kullanıcı Hesabı:** ${context.username || 'Bilinmiyor / Logda yer almamaktadır'}\n`;
    md += `* **Hedef / Bilgisayar Adı:** ${context.host || 'Bilinmiyor / Belirtilmemiş'}\n`;
    md += `* **Üst Süreç (Parent Process):** ${context.parentProcess || 'Bilinmiyor / Logda yer almamaktadır'}\n`;
    md += `* **Süreç Adı:** ${context.processName || 'Bilinmiyor / Belirtilmemiş'}\n`;
    md += `* **Olay ID (Event ID):** ${context.eventId ? String(context.eventId) : 'Bilinmiyor'}\n`;
    md += `* **Kaynak / Hedef IP:** ${context.sourceIp || 'Yerel'} → ${context.destinationIp || 'Yerel'}\n`;
    md += `* **Zaman Damgası:** ${context.timestamp || 'Bilinmiyor'}\n\n`;
  }

  return md;
}
