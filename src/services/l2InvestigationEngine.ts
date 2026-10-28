import { NormalizedLog } from '../types';
import {
  WindowsEventDetails,
  WINDOWS_SUBSTATUS_MAP,
  WINDOWS_LOGON_TYPE_MAP,
  WINDOWS_EVENT_NAMES,
  extractWindowsDetails,
} from './quickTriageHelper';
import { explainCommand, CommandExplainerResult } from './commandExplainer';
import { extractUniversalEvidence } from './universalEvidenceExtractor';
import { synthesizeDynamicHypotheses, buildTailoredInvestigationSteps } from './dynamicHypothesisEngine';
import {
  UniversalEvidence,
  DynamicHypothesis,
  TailoredInvestigationStep,
} from '../types/investigationEvidence';

// ============================================================================
// L2 INCIDENT INVESTIGATION ASSISTANT INTERFACES
// ============================================================================

export interface L2LogClassification {
  logSource: string; // e.g. "Windows Security Event Log", "Sysmon", "Linux Syslog / Auth", "Log kaynağı kesin belirlenemedi."
  platform: 'Windows' | 'Linux' | 'Web / Network' | 'Cloud' | 'Firewall / Ağ' | 'Bilinmiyor';
  confidence: 'KESİN' | 'YÜKSEK_OLASILIK' | 'ORTA' | 'BELİRSİZ';
  observedBehavior: string; // Direct factual description of the observed event
  keyFields: Record<string, string>;
}

export interface L2PlatformFieldExplained {
  field: string;
  value: string;
  forensicImportance: string;
}

export interface L2PlatformContext {
  platformName: string;
  significance: string;
  criticalFieldsExplained: L2PlatformFieldExplained[];
  attackChainContext: string;
  conditionalCaveat: string;
}

export interface L2Hypothesis {
  id: string; // "H1", "H2", "H3"
  title: string;
  type: 'ATTACK' | 'BENIGN_ANOMALY' | 'POLICY_VIOLATION';
  likelihood: 'YÜKSEK' | 'ORTA' | 'DÜŞÜK';
  statement: string; // Conditioned statement (non-speculative)
  strengtheningFindings: string[]; // Evidence that strengthens this hypothesis
  weakeningFindings: string[]; // Evidence that weakens or refutes this hypothesis (benign explanation)
}

export interface L2InvestigationStep {
  stepNumber: number;
  category: 'AUTHENTICATION' | 'PRIVILEGE' | 'PROCESS_EXECUTION' | 'PERSISTENCE' | 'DEFENSE_EVASION' | 'NETWORK_LATERAL';
  title: string;
  objective: string;
  targetEntities: { host: string; user: string; timeWindow: string };
  eventIdsAndLogsToInspect: string[];
  fieldsToCheck: string[];
  pivotingGuidance: string;
}

export interface L2GeneratedQueries {
  splunk: string;
  kql: string;
  elastic: string;
  qradarAql: string;
  sigmaRule: string;
}

export interface L2DetectionAndRuleRecommendation {
  siemLogic: string;
  wafOrFirewallRule: string;
  sigmaYamlPreview: string;
  tuningAdvice: string;
}

export interface L2ContainmentAndResponse {
  severity: 'KRİTİK' | 'YÜKSEK' | 'ORTA' | 'DÜŞÜK';
  containmentActions: string[];
  forensicArtifactsToCollect: string[];
}

export interface SafeContainmentStep {
  action: string;
  why: string;
  when: string;
  risk: string;
  evidenceRequired: string;
  isDestructiveOrImpacting: boolean;
}

export interface L2IocItem {
  type: string;
  value: string;
  field: string;
}

export interface L2IocBreakdown {
  observedIocs: L2IocItem[];
  potentialIocs: Array<{ type: string; value: string; condition: string }>;
}

export interface L2QueryFieldProvenance {
  field: string;
  value: string;
  classification: 'OBSERVED' | 'DERIVED' | 'PLACEHOLDER' | 'STATIC_QUERY_SYNTAX';
  source: string;
}

export interface L2InvestigationPlan {
  classification: L2LogClassification;
  platformContext: L2PlatformContext;
  whatIsThis?: string;
  whatIsImportant?: string[];
  securitySignificance?: string;
  legitimateExplanations?: string[];
  suspiciousExplanations?: string[];
  provenFacts?: string[];
  unprovenHypotheses?: string[];
  missingInformation?: string[];
  tailoredSteps?: TailoredInvestigationStep[];
  dynamicHypotheses?: DynamicHypothesis[];
  universalEvidence?: UniversalEvidence;
  commandAnalysis?: CommandExplainerResult | null;
  hypotheses: L2Hypothesis[];
  investigationSteps: L2InvestigationStep[];
  queries: L2GeneratedQueries;
  queryFieldProvenance?: L2QueryFieldProvenance[];
  detection: L2DetectionAndRuleRecommendation;
  containment: L2ContainmentAndResponse;
  safeContainmentSteps?: SafeContainmentStep[];
  iocBreakdown?: L2IocBreakdown;
  summaryMarkdown: string;
}

// ============================================================================
// HELPER: EXTRACT ENTITIES & LOG ATTRIBUTES
// ============================================================================

interface ExtractedLogMetadata {
  raw: string;
  isWindows: boolean;
  winDetails: WindowsEventDetails;
  host: string;
  user: string;
  sourceIp: string;
  destinationIp: string;
  port: string;
  process: string;
  parentProcess: string;
  commandLine: string;
  timestamp: string;
  action: string;
  attackPattern: string;
  detectedFormat: string;
}

function extractLogMetadata(rawLog: string, parsedLog?: NormalizedLog | null): ExtractedLogMetadata {
  const kvDict: Record<string, string> = {};
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=([^\s\t\r\n",]+|"[^"]*")/g;
  let kvMatch;
  while ((kvMatch = kvRegex.exec(rawLog)) !== null) {
    const k = kvMatch[1].toLowerCase();
    const v = kvMatch[2].replace(/^"|"$/g, '');
    kvDict[k] = v;
  }

  const win = extractWindowsDetails(rawLog, kvDict, parsedLog || null);
  const raw = rawLog.trim();
  const lower = raw.toLowerCase();

  let host = (win.isWindowsEvent ? (win.computer || win.workstation) : '') || parsedLog?.sunucu_ismi || '';
  let user = (win.isWindowsEvent ? (win.targetUser || win.subjectUser) : '') || parsedLog?.kullanici_adi || '';
  let sourceIp = (win.isWindowsEvent && win.sourceIp && win.sourceIp !== 'Bilinmiyor' && win.sourceIp !== '-')
    ? win.sourceIp
    : parsedLog?.ip_adresi || '';
  let destinationIp = parsedLog?.hedef_ip || '';
  let port = win.sourcePort || (parsedLog?.hedef_port ? String(parsedLog.hedef_port) : '');
  let process = win.processName || '';
  let parentProcess = win.parentProcess || '';
  let commandLine = win.commandLine || parsedLog?.islem_komutu || '';
  let timestamp = parsedLog?.tarih || '';
  let action = '';
  const actionMatch = raw.match(/\b(?:action|act|device_?action|waf_?action|policy_?action|disposition|aksiyon|karar)\s*[:=]\s*["']?([a-zA-Z_]+)/i);
  if (actionMatch && actionMatch[1]) {
    action = actionMatch[1];
  } else if (parsedLog?.baglanti_karari === 'DENY' || parsedLog?.baglanti_karari === 'ACCEPT') {
    action = parsedLog.baglanti_karari;
  }
  let attackPattern = '';
  let detectedFormat = '';

  // Extract from key=value if not found
  if (!host) {
    const hostMatch = raw.match(/\b(?:host|computer|workstation|devname|hostname)\s*[:=]\s*["']?([^\s"';]+)/i) ||
                      raw.match(/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)\s+/);
    if (hostMatch) host = hostMatch[1];
  }
  if (!user) {
    const userMatch = raw.match(/\b(?:user|username|account|targetuser|subjectuser|usr)\s*[:=]\s*["']?([^\s"';]+)/i) ||
                      raw.match(/(?:for|user)\s+(?:invalid user\s+)?([a-zA-Z0-9_\-\.]+)\s+from/i) ||
                      raw.match(/\b(?:sudo:\s+([a-zA-Z0-9_\-\.]+)\s*:)/i);
    if (userMatch) user = userMatch[1];
  }
  if (!sourceIp) {
    const ipMatch = raw.match(/\b(?:src|srcip|sourceip|client_ip|c-ip)\s*[:=]\s*["']?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i) ||
                    raw.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);
    if (ipMatch) sourceIp = ipMatch[1];
  }
  if (!timestamp) {
    const timeMatch = raw.match(/\b(20[2-9][0-9][-/.][0-1][0-9][-/.][0-3][0-9][ T][0-2][0-9]:[0-5][0-9]:[0-5][0-9])/);
    if (timeMatch) timestamp = timeMatch[1];
  }

  // Attack pattern extraction
  if ((lower.includes('union') && lower.includes('select')) || lower.includes('sql injection') || lower.includes('sqli') || (lower.includes('or') && (lower.includes('1=1') || lower.includes("'1'='1'")))) {
    attackPattern = 'SQL Injection Attack';
  } else if (lower.includes('jndi:') || lower.includes('${jndi')) {
    attackPattern = 'Apache Log4j JNDI RCE (CVE-2021-44228)';
  } else if (lower.includes('<script') || lower.includes('javascript:')) {
    attackPattern = 'Cross-site Scripting (XSS)';
  } else if (lower.includes('../') || lower.includes('..\\') || lower.includes('/etc/passwd') || lower.includes('win.ini')) {
    attackPattern = 'Path Traversal / Local File Inclusion';
  } else if (lower.includes('/dev/tcp') || lower.includes('nc -e') || lower.includes('powershell -enc') || lower.includes('base64')) {
    attackPattern = 'Reverse Shell / Encoded Dropper';
  }

  return {
    raw,
    isWindows: win.isWindowsEvent,
    winDetails: win,
    host: host || 'BILINMEYEN-HOST',
    user: user || 'BILINMEYEN-USER',
    sourceIp: sourceIp || 'Bilinmiyor',
    destinationIp: destinationIp || 'Bilinmiyor',
    port: port || 'Bilinmiyor',
    process,
    parentProcess,
    commandLine,
    timestamp: timestamp || 'Log Zamanı',
    action,
    attackPattern,
    detectedFormat,
  };
}

// ============================================================================
// CORE L2 INVESTIGATION ENGINE IMPLEMENTATION
// ============================================================================

export function generateL2InvestigationPlan(
  rawLog: string,
  parsedLog?: NormalizedLog | null
): L2InvestigationPlan {
  const meta = extractLogMetadata(rawLog, parsedLog);
  const trimmed = rawLog.trim();
  const lower = trimmed.toLowerCase();

  // 1. CLASSIFY LOG SOURCE & OBSERVED BEHAVIOR
  let classification: L2LogClassification;
  let platformContext: L2PlatformContext;
  let hypotheses: L2Hypothesis[] = [];
  let investigationSteps: L2InvestigationStep[] = [];
  let queries: L2GeneratedQueries;
  let detection: L2DetectionAndRuleRecommendation;
  let containment: L2ContainmentAndResponse;

  // --------------------------------------------------------------------------
  // BRANCH A: WINDOWS SECURITY / SYSMON / POWERSHELL EVENT LOG
  // --------------------------------------------------------------------------
  if (meta.isWindows && meta.winDetails.eventId) {
    const evId = meta.winDetails.eventId;
    const evName = meta.winDetails.eventName;
    const targetUser = meta.winDetails.targetUser || meta.user;
    const workstation = meta.winDetails.workstation || meta.winDetails.computer || meta.host;
    const logonType = meta.winDetails.logonType;
    const logonTypeDesc = meta.winDetails.logonTypeDesc || (logonType ? WINDOWS_LOGON_TYPE_MAP[logonType] : 'Bilinmiyor');
    const subStatus = meta.winDetails.subStatus;
    const subStatusDesc = meta.winDetails.subStatusDesc || (subStatus ? WINDOWS_SUBSTATUS_MAP[subStatus] : '');

    classification = {
      logSource: 'Windows Security Event Log (Microsoft-Windows-Security-Auditing)',
      platform: 'Windows',
      confidence: 'KESİN',
      observedBehavior: `Event ID ${evId} (${evName}) kaydedildi. Hedef Kullanıcı: "${targetUser}", İş İstasyonu/Host: "${workstation}"${logonType ? `, Giriş Türü: ${logonTypeDesc}` : ''}${subStatus ? `, Hata Kodu: ${subStatus} (${subStatusDesc})` : ''}.`,
      keyFields: {
        'Event ID': String(evId),
        'Olay Tanımı': evName,
        'Kullanıcı': targetUser,
        'İş İstasyonu / Host': workstation,
        'Logon Type': logonType ? String(logonType) : '-',
        'SubStatus': subStatus || '-',
        'Kaynak IP': meta.sourceIp,
        'Süreç': meta.winDetails.processName || '-',
        'Üst Süreç': meta.winDetails.parentProcess || '-',
        'Komut Satırı': meta.winDetails.commandLine || '-',
      },
    };

    // Platform Context: Detailed analysis of the Event ID & Windows Architecture
    platformContext = {
      platformName: 'Windows Active Directory & Uç Nokta Denetimi',
      significance: getWindowsEventSignificance(evId, evName),
      criticalFieldsExplained: [
        {
          field: 'Logon Type (Giriş Türü)',
          value: logonType ? `${logonType} (${logonTypeDesc})` : 'Uygulanmıyor',
          forensicImportance: 'Oturumun fiziksel konsoldan mı (Type 2), ağ paylaşımından mı (Type 3) yoksa uzaktan RDP (Type 10) üzerinden mi başlatıldığını ortaya koyar. Saldırganın erişim vektörünü belirler.',
        },
        {
          field: 'SubStatus Hex Hata Kodu',
          value: subStatus ? `${subStatus} (${subStatusDesc})` : '0x0 (Başarılı)',
          forensicImportance: 'Parola hatası (0xC000006A), olmayan kullanıcı (0xC0000064) veya hesap kilitlenmesi (0xC0000234) ayrımını yaparak brute force ile kullanıcı unutkanlığı arasındaki adli farkı gösterir.',
        },
        {
          field: 'Source Network Address (Kaynak IP)',
          value: meta.sourceIp,
          forensicImportance: 'İsteğin iç ağ segmentinden mi (lateral movement), VPN havuzundan mı yoksa DMZ sunucusundan mı geldiğini kanıtlar.',
        },
        {
          field: 'Logon ID (Oturum Tanımlayıcı)',
          value: '0x3E7 / Dinamik Hex',
          forensicImportance: 'Oturum açıldıktan sonra çalıştırılan tüm süreçleri (4688) ve ayrıcalık atamalarını (4672) bu benzersiz oturum ID ile birebir zincirlemek için kullanılır.',
        },
      ],
      attackChainContext:
        'Saldırı Zinciri Bağlamı: Bir Windows ortamında tek bir oturum olayı izole değerlendirilmemelidir. Adli tehdit avında tipik saldırgan ilerleyişi: 4625 (Keşif/Deneme) → 4624 (Başarılı Oturum) → 4672 (Yönetici Yetkisi Atama) → 4688/Sysmon 1 (Komut & İkili Yürütme) → 7045 (Servis ile Kalıcılık) → 1102 (İz Silme / Log Temizleme) zinciri olarak takip edilmelidir.',
      conditionalCaveat:
        'Bu olay tek başına saldırı kanıtı değildir. Meşru bir kullanıcının parola unutması, eski şifreli SMB ağ sürücüsü veya otomatik servis senaryoları bulunabilir. Ancak ardışık denemeler, mesai dışı saatler veya olağandışı kaynak IP ile birleştiğinde olay niteliği değişir.',
    };

    // Hypotheses based on Windows Event ID
    if (evId === 4625) {
      hypotheses = [
        {
          id: 'H1',
          title: 'Hipotez 1: Hedefli Parola Püskürtme (Password Spraying) veya Kaba Kuvvet (Brute Force) Saldırısı',
          type: 'ATTACK',
          likelihood: subStatus === '0XC0000234' ? 'YÜKSEK' : 'ORTA',
          statement: 'Dış veya iç bir kaynaktan, kullanıcı hesaplarına yönelik otomatik kimlik doğrulama denemeleri yürütülüyor olabilir.',
          strengtheningFindings: [
            'Aynı kaynak IP veya iş istasyonundan kısa sürede onlarca farklı hesaba 4625 üretilmesi.',
            'Hesabın Active Directory üzerinde kilitlenmesi (SubStatus 0xC0000234).',
            'Başarısız oturum denemelerinin ardından tek bir başarılı 4624 ve 4672 olayının gelmesi.',
            'Oturum türünün Type 10 (RDP) veya Type 3 (Ağ) olması ve kaynak IP adresinin beklenmeyen bir cihaz olması.',
          ],
          weakeningFindings: [
            'Yalnızca 1-3 adet başarısız deneme olması ve kullanıcının ardından doğru şifre ile giriş yapabilmesi.',
            'İş istasyonunda (Workstation) kullanıcının daha önceden kalmış eski şifreli Outlook/Teams veya SMB eşlenmiş sürücüsü (Mapped Drive) bulunması.',
            'SubStatus kodunun 0xC000006A (Kullanıcı adı geçerli, şifre yanlış) olması ve mesai başlangıç saatinde gerçekleşmesi.',
          ],
        },
        {
          id: 'H2',
          title: 'Hipotez 2: Eski Kayıtlı Kimlik Bilgisi Anomalisine Bağlı Kullanıcı Hatası (Benign False Positive)',
          type: 'BENIGN_ANOMALY',
          likelihood: subStatus === '0XC000006A' ? 'YÜKSEK' : 'DÜŞÜK',
          statement: 'Kullanıcının yakın zamanda şifresini değiştirmesi ve arka planda açık kalan bir Windows Credential Manager kaydının sürekli eski şifreyi sunması muhtemeldir.',
          strengtheningFindings: [
            'Kullanıcının Active Directory üzerinde pwdLastSet (parola değişim tarihi) kaydının son 24 saat içinde olması.',
            'Tüm 4625 kayıtlarının kullanıcının kendi zimmetli bilgisayarından (Workstation) üretilmesi.',
            'Başka hiçbir kullanıcı hesabına yönelik deneme kaydedilmemesi.',
          ],
          weakeningFindings: [
            'Denemelerin var olmayan kullanıcı adlarıyla (0xC0000064) yapılması.',
            'Denemelerin harici veya anonim bir IP adresinden gelmesi.',
          ],
        },
      ];
    } else if (evId === 4688) {
      hypotheses = [
        {
          id: 'H1',
          title: 'Hipotez 1: İstismar Sonrası Yerel Keşif / LOLBAS Komut Yürütme (Execution / Discovery)',
          type: 'ATTACK',
          likelihood: meta.winDetails.commandLine ? 'YÜKSEK' : 'ORTA',
          statement: 'Saldırgan ele geçirdiği oturum altında sistem yerleşik araçlarını (cmd, powershell, whoami, certutil) kullanarak sistemde komut koşturuyor olabilir.',
          strengtheningFindings: [
            'Üst sürecin (Parent Process) w3wp.exe, sqlservr.exe, excel.exe veya winword.exe olması.',
            'Komut satırında gizleme bayrakları (-enc, -w hidden, /all /quiet) yer alması.',
            'Komutun çalıştırılmasından hemen önce 4624/4672 olayının kaydedilmiş olması.',
          ],
          weakeningFindings: [
            'Üst sürecin kurumsal BT yazılım dağıtım ajanı (SCCM, Tanium, Intune) olması.',
            'Komutun her gün aynı saatte çalışan onaylı bir zamanlanmış görev (Scheduled Task) tarafından tetiklenmesi.',
          ],
        },
      ];
    } else if (evId === 1102 || evId === 104) {
      hypotheses = [
        {
          id: 'H1',
          title: 'Hipotez 1: Savunma Atlatma / Adli Delilleri Karartma (Defense Evasion - T1070.001)',
          type: 'ATTACK',
          likelihood: 'YÜKSEK',
          statement: 'Yetkili erişim elde eden aktör, adli izlerini silmek amacıyla Windows Güvenlik Günlüğünü temizlemiştir.',
          strengtheningFindings: [
            'Log silme eylemini gerçekleştiren kullanıcının kurumda rutin bakım görevlisi olmaması.',
            'Log silinmeden hemen önce ayrıcalık yükseltme (4672) veya şüpheli komut yürütme (4688) izlerinin bulunması.',
            'İlgili uç noktada EDR ajanının devre dışı bırakılmaya çalışılması.',
          ],
          weakeningFindings: [
            'Olayın Değişiklik Yönetimi (Change Management) biletine bağlı onaylı bir disk bakım/yeniden yapılandırma operasyonu olması.',
          ],
        },
      ];
    } else {
      hypotheses = [
        {
          id: 'H1',
          title: `Hipotez 1: ${evName} Kapsamında Olağandışı Yönetici Faaliyeti`,
          type: 'ATTACK',
          likelihood: 'ORTA',
          statement: 'Gerçekleşen eylem yetkili hesapların kötüye kullanımı veya kurumsal politika dışı bir aktivite olabilir.',
          strengtheningFindings: ['Mesai saatleri dışında gerçekleşmesi.', 'İlgili hostun kritik sunucu olması.'],
          weakeningFindings: ['Onaylı BT bakım çalışması kapsamında yapılmış olması.'],
        },
      ];
    }

    // 5-STAGE L2 INVESTIGATION PLAN (As required by prompt)
    investigationSteps = [
      {
        stepNumber: 1,
        category: 'AUTHENTICATION',
        title: 'ADIM 1 — Kimlik Doğrulama & Oturum Zinciri (Authentication)',
        objective: 'Başarısız girişlerin (4625) ardından veya öncesinde başarılı bir kimlik doğrulama (4624) gerçekleşmiş mi?',
        targetEntities: { host: workstation, user: targetUser, timeWindow: '-30m / +30m' },
        eventIdsAndLogsToInspect: ['Event ID 4625', 'Event ID 4624', 'Event ID 4776 (NTLM DC)'],
        fieldsToCheck: ['Logon Type', 'Source IP', 'Workstation Name', 'Logon ID', 'SubStatus'],
        pivotingGuidance: 'Eğer aynı kullanıcı adı veya kaynak IP için 4625 serisinin ardından Logon Type 10/3 ile tek bir 4624 görülürse, parola kırılmış veya geçerli bir kimlik bilgisi ele geçirilmiştir; derhal ADIM 2\'ye geçin.',
      },
      {
        stepNumber: 2,
        category: 'PRIVILEGE',
        title: 'ADIM 2 — Ayrıcalık ve Yetki Ataması (Privilege Escalation)',
        objective: 'Authentication sonrasında hesaba yüksek ayrıcalıklı haklar (SeDebugPrivilege / Admin) atanmış mı?',
        targetEntities: { host: workstation, user: targetUser, timeWindow: '+15m (Oturum sonrası)' },
        eventIdsAndLogsToInspect: ['Event ID 4672 (Special Privileges)', 'Event ID 4728 / 4732 (Grup Üyeliği)'],
        fieldsToCheck: ['PrivilegeList', 'SubjectUserSid', 'TargetUserName', 'Logon ID'],
        pivotingGuidance: '4624 oturum açılışındaki Logon ID ile eşleşen bir 4672 kaydı varsa, aktör yerel yönetici veya etki alanı yöneticisi haklarına ulaşmıştır.',
      },
      {
        stepNumber: 3,
        category: 'PROCESS_EXECUTION',
        title: 'ADIM 3 — Süreç ve Komut Yürütme Ağacı (Process Creation)',
        objective: 'Oturum açıldıktan hemen sonra uç noktada hangi ikili dosyalar veya komutlar çalıştırılmış?',
        targetEntities: { host: workstation, user: targetUser, timeWindow: '+60m (Oturum süresince)' },
        eventIdsAndLogsToInspect: ['Event ID 4688', 'Sysmon Event ID 1 (Process Create)', 'PowerShell 4104'],
        fieldsToCheck: ['CommandLine', 'ParentProcessName', 'NewProcessName', 'SubjectLogonId', 'Hashes'],
        pivotingGuidance: 'CommandLine alanında whoami, net user, ipconfig, powershell, certutil, vssadmin veya cmd.exe çağrıları varsa saldırgan keşif ve Living-off-the-Land fazındadır.',
      },
      {
        stepNumber: 4,
        category: 'PERSISTENCE',
        title: 'ADIM 4 — Kalıcılık ve Sistem Değişiklikleri (Persistence)',
        objective: 'Sistemde yeniden başlatma sonrasında çalışacak servis, zamanlanmış görev veya registry kaydı bırakılmış mı?',
        targetEntities: { host: workstation, user: targetUser, timeWindow: '+120m' },
        eventIdsAndLogsToInspect: ['Event ID 7045 (Service Installed)', 'Event ID 4697', 'Sysmon Event ID 12/13 (Registry)', 'TaskScheduler Event ID 106'],
        fieldsToCheck: ['ServiceName', 'ImagePath / ServiceFileName', 'TargetObject (Registry Run Keys)'],
        pivotingGuidance: 'Temp veya AppData altından çalışan ikililer içeren 7045 olayları kalıcı arka kapı (Backdoor) kurulduğunu gösterir.',
      },
      {
        stepNumber: 5,
        category: 'DEFENSE_EVASION',
        title: 'ADIM 5 — Savunma Atlatma & İz Silme (Defense Evasion)',
        objective: 'Saldırgan log kayıtlarını temizleyerek, servisi durdurarak veya EDR ajanını bozarak izlerini silmeye çalışmış mı?',
        targetEntities: { host: workstation, user: targetUser, timeWindow: 'Tüm Zaman Aralığı' },
        eventIdsAndLogsToInspect: ['Event ID 1102 (Audit Log Cleared)', 'Event ID 104 (System Log Cleared)', 'Event ID 7036 (Hizmet Durumu)'],
        fieldsToCheck: ['SubjectUserName', 'ServiceName', 'Status'],
        pivotingGuidance: '1102 veya 104 olayı doğrudan adli kanıt silme eylemidir; derhal adli bellek imajı ve MFT kopyası alınmalıdır.',
      },
    ];

    // Queries Generation: Splunk, KQL, Elastic, QRadar, Sigma
    queries = {
      splunk: `index=windows (host="${workstation}" OR Computer="${workstation}")
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR EventCode=4688 OR EventCode=7045 OR EventCode=1102)
earliest=-30m latest=+60m
| eval TargetUser=coalesce(TargetUserName, user, Account_Name)
| search TargetUser="${targetUser !== 'BILINMEYEN-USER' ? targetUser : '*'}"
| table _time, host, EventCode, TargetUser, Logon_Type, SubStatus, Process_Command_Line, Message
| sort _time asc`,

      kql: `let targetHost = "${workstation}";
let targetUser = "${targetUser !== 'BILINMEYEN-USER' ? targetUser : '*'}";
SecurityEvent
| where TimeGenerated >= ago(2h)
| where (Computer has targetHost or targetHost == "BILINMEYEN-HOST")
| where EventID in (4624, 4625, 4672, 4688, 7045, 1102)
| where (targetUser == "*" or TargetAccount has targetUser or Account has targetUser)
| project TimeGenerated, Computer, EventID, Activity, TargetAccount, LogonType, SubStatus, CommandLine, ParentProcessName
| order by TimeGenerated asc`,

      elastic: `host.name: "${workstation}" and winlog.event_id: (4624 or 4625 or 4672 or 4688 or 7045 or 1102) and @timestamp: [now-2h TO now]
| sort @timestamp asc`,

      qradarAql: `SELECT QIDNAME(qid) as "EventName", "EventID", "sourceip", "destinationip", "username", "devicename", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') as "StartTime"
FROM events
WHERE ("devicename" ILIKE '%${workstation}%' OR "username" ILIKE '%${targetUser}%')
AND "EventID" IN (4624, 4625, 4672, 4688, 7045, 1102)
ORDER BY starttime ASC
LAST 120 MINUTES`,

      sigmaRule: `title: Suspicious Multi-Stage Authentication & Execution Chain on ${workstation}
id: l2-investigation-chain-${evId}
status: experimental
description: Detects correlated failed logons followed by execution and privileged operations for ${targetUser}
logsource:
  product: windows
  service: security
detection:
  selection_auth:
    EventID:
      - 4625
      - 4624
    TargetUserName: '${targetUser}'
  selection_exec:
    EventID: 4688
  condition: selection_auth or selection_exec
fields:
  - EventID
  - TargetUserName
  - ComputerName
  - CommandLine
  - LogonType
falsepositives:
  - Stale credential mapped drives
  - Legitimate IT admin tasks
level: high`,
    };

    detection = {
      siemLogic: `Kural Adı: Ardışık Başarısız Giriş Sonrası Başarılı Giriş ve Süreç Yürütme (Chain Detection)
Eşik Değer: Aynı kullanıcı (${targetUser}) veya IP için 10 dakika içinde en az 5 adet Event 4625, ardından 1 adet Event 4624 ve 5 dakika içinde Event 4688/4672.`,
      wafOrFirewallRule: meta.sourceIp !== 'Bilinmiyor'
        ? `Sınır Güvenlik Duvarı: ${meta.sourceIp} IP adresinin harici RDP (3389) ve SMB (445) erişimleri derhal DROP/BLOCK edilmelidir.`
        : 'RDP ve SMB portlarının şirket dışından doğrudan erişime kapatılması, yalnızca MFA korumalı VPN üzerinden izin verilmesi.',
      sigmaYamlPreview: queries.sigmaRule,
      tuningAdvice: 'Eski kayıtlı kimlik bilgisi (Cached Credential) false positive\'lerini elemek için SubStatus=0xC000006A olan ve yalnızca tek bir iç iş istasyonundan gelen tekrarları eşik değer altına alınız.',
    };

    containment = {
      severity: evId === 1102 || subStatus === '0XC0000234' ? 'YÜKSEK' : 'ORTA',
      containmentActions: [
        `Kullanıcı Hesabı Kontrolü: "${targetUser}" hesabının Active Directory üzerinde kilit durumu kontrol edilmeli, gerekirse geçici olarak parola sıfırlaması (Force Password Reset) ve tüm aktif Kerberos biletlerinin (Revoke-AzureADUserAllRefreshToken / TGT) iptali yapılmalıdır.`,
        `İş İstasyonu İncelemesi: "${workstation}" cihazında Windows Credential Manager ve 'net use' bağlantıları incelenerek eski şifreyle kalmış servisler temizlenmelidir.`,
        `Ağ İzolasyonu: Eğer 4688 üzerinde zararlı komut veya 4672 ayrıcalık ataması doğrulanırsa uç nokta EDR üzerinden ağ izolasyonuna alınmalıdır.`,
      ],
      forensicArtifactsToCollect: [
        'Uç noktadan son 24 saatin Security.evtx ve System.evtx log dökümleri.',
        'Kullanıcının %APPDATA% ve C:\\Windows\\Prefetch dizin dökümü.',
        'Aktif ağ bağlantıları (netstat -ano) ve çalışan süreç listesi (tasklist /v).',
      ],
    };
  }

  // --------------------------------------------------------------------------
  // BRANCH B: LINUX SYSLOG / SSHD / SUDO / AUDITD
  // --------------------------------------------------------------------------
  else if (
    lower.includes('sshd') ||
    lower.includes('sudo:') ||
    lower.includes('auditd') ||
    lower.includes('/bin/bash') ||
    lower.includes('/bin/sh') ||
    lower.includes('failed password') ||
    lower.includes('accepted password')
  ) {
    const isSshFailed = lower.includes('failed password');
    const isSshSuccess = lower.includes('accepted password') || lower.includes('accepted publickey');
    const isSudo = lower.includes('sudo:');

    classification = {
      logSource: isSudo ? 'Linux Sudo Command Audit' : 'Linux SSH Daemon (sshd) Authentication Log',
      platform: 'Linux',
      confidence: 'YÜKSEK_OLASILIK',
      observedBehavior: isSshFailed
        ? `SSH servisine yönelik başarısız parola denemesi tespit edildi. Hedef Kullanıcı: "${meta.user}", Kaynak IP: ${meta.sourceIp}.`
        : isSshSuccess
        ? `SSH üzerinden başarılı oturum açma kaydedildi. Kullanıcı: "${meta.user}", Kaynak IP: ${meta.sourceIp}.`
        : `Sudo yetki yükseltme çağrısı kaydedildi. Kullanıcı: "${meta.user}", Komut: "${meta.commandLine || 'Sudo Komutu'}".`,
      keyFields: {
        'Log Tipi': isSudo ? 'Sudo Execution' : 'SSH Auth',
        'Kullanıcı': meta.user,
        'Kaynak IP': meta.sourceIp,
        'Hedef Host': meta.host,
        'Zaman': meta.timestamp,
        'İşlem': isSudo ? 'sudo' : 'sshd',
      },
    };

    platformContext = {
      platformName: 'Linux Enterprise & Sunucu Kimlik Doğrulama',
      significance: isSshFailed
        ? 'Linux sunucularında SSH portuna (22) yapılan başarısız denemeler genellikle internet tarayıcı botları veya parola püskürtme saldırılarının ilk fazıdır.'
        : isSshSuccess
        ? 'Başarılı SSH oturumu, sunucu üzerinde doğrudan kabuk (shell) yetkisi sağlar. Kaynak IP ve saat anomalisi kritiktir.'
        : 'Sudo kullanımı, kullanıcının root seviyesinde yetki elde ettiğini gösterir; komutun meşruiyet onayı aranmalıdır.',
      criticalFieldsExplained: [
        { field: 'Accepted/Failed Auth', value: isSshFailed ? 'Failed' : 'Success', forensicImportance: 'Erişimin başarısız bir denemede mi kaldığı yoksa sisteme sızılıp sızılmadığını kanıtlar.' },
        { field: 'Kaynak IP', value: meta.sourceIp, forensicImportance: 'İzinli yönetim IP aralığında mı yoksa dışarıdan bir IP mi olduğunu gösterir.' },
        { field: 'User', value: meta.user, forensicImportance: 'root doğrudan deneniyorsa PermitRootLogin politikasının ihlali sorgulanmalıdır.' },
      ],
      attackChainContext: 'Saldırı Zinciri: SSH Brute Force → Başarılı SSH Login → sudo -i / su root → bash history silme → Cronjob / SSH Authorized_Keys kalıcılık.',
      conditionalCaveat: 'Bu log tek başına sunucunun ele geçirildiğini kanıtlamaz; ancak başarısız denemelerin hemen ardından aynı IP\'den başarılı giriş gelirse acil alarm üretilmelidir.',
    };

    hypotheses = [
      {
        id: 'H1',
        title: isSshFailed ? 'Hipotez 1: Otomatik SSH Kaba Kuvvet Saldırısı' : 'Hipotez 1: Şüpheli Uzak SSH Erişimi ve Yetki Yükseltme',
        type: 'ATTACK',
        likelihood: 'YÜKSEK',
        statement: isSshFailed ? 'Saldırgan sunucuya yönelik kullanıcı adı/şifre kombinasyonlarını denemektedir.' : 'Ele geçirilen kimlik bilgisiyle sunucuya sızılmış olabilir.',
        strengtheningFindings: ['Aynı IP adresinden yüzlerce ardışık istek gelmesi.', 'Oturum sonrası cron veya /tmp altında script oluşturulması.'],
        weakeningFindings: ['Personelin parolasını unutup 2. denemede girmesi.', 'Sunucunun iç yönetim ağında bulunması.'],
      },
    ];

    investigationSteps = [
      {
        stepNumber: 1,
        category: 'AUTHENTICATION',
        title: 'ADIM 1 — SSH Oturum Geçmişi ve auth.log İncelemesi',
        objective: 'İlgili IP adresinden veya kullanıcıdan gelen son 24 saatteki tüm Accepted ve Failed kayıtları listelenmelidir.',
        targetEntities: { host: meta.host, user: meta.user, timeWindow: '-2h / +2h' },
        eventIdsAndLogsToInspect: ['/var/log/auth.log', '/var/log/secure', 'last -a', 'lastlog'],
        fieldsToCheck: ['Accepted password', 'Failed password', 'Invalid user', 'rhost'],
        pivotingGuidance: 'Eğer "Accepted" kaydı varsa hemen kullanıcının bash geçmişi ve çalışan süreçleri incelenmelidir.',
      },
      {
        stepNumber: 2,
        category: 'PROCESS_EXECUTION',
        title: 'ADIM 2 — Kabuk Süreçleri ve Komut Geçmişi (.bash_history)',
        objective: 'Oturum açıldıktan sonra hangi komutlar koşturulmuş?',
        targetEntities: { host: meta.host, user: meta.user, timeWindow: '+1h' },
        eventIdsAndLogsToInspect: ['~/.bash_history', 'auditd execve', 'ps auxf'],
        fieldsToCheck: ['COMMAND', 'PID', 'PPID', 'TTY'],
        pivotingGuidance: 'wget, curl, chmod +x veya nohup çağrıları doğrudan zararlı indirme göstergesidir.',
      },
      {
        stepNumber: 3,
        category: 'PERSISTENCE',
        title: 'ADIM 3 — Kalıcılık Mekanizmaları (Cron & SSH Keys)',
        objective: 'Saldırgan ~/.ssh/authorized_keys dosyasına yeni anahtar eklemiş mi veya crontab\'a görev yazmış mı?',
        targetEntities: { host: meta.host, user: meta.user, timeWindow: 'Son 24 saat' },
        eventIdsAndLogsToInspect: ['/etc/crontab', '/var/spool/cron/', '~/.ssh/authorized_keys'],
        fieldsToCheck: ['Dosya değiştirilme tarihi (mtime)', 'Yeni public key'],
        pivotingGuidance: 'authorized_keys dosyası oturum zamanından sonra değiştirilmişse kalıcı arka kapı bırakılmıştır.',
      },
    ];

    const hasSshSrcIp = meta.sourceIp && meta.sourceIp !== 'Bilinmiyor';
    queries = {
      splunk: `// Not: Alan adları SIEM veri modeline göre uyarlanmalıdır.
index=linux (host="${meta.host}" OR host="${meta.host}.*") (process="sshd" OR process="sudo")
(${meta.user !== 'BILINMEYEN-USER' ? `"${meta.user}"` : '*'}${hasSshSrcIp ? ` OR src_ip="${meta.sourceIp}"` : ''})
| table _time, host, process, user, src_ip, message
| sort _time asc`,
      kql: `// Not: Alan adları SIEM veri modeline göre uyarlanmalıdır.
Syslog
| where Computer has "${meta.host}"
| where ProcessName in ("sshd", "sudo")
${meta.user !== 'BILINMEYEN-USER' ? `| where SyslogMessage has "${meta.user}"\n` : ''}${hasSshSrcIp ? `| where SyslogMessage has "${meta.sourceIp}"\n` : ''}| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc`,
      elastic: `host.name: "${meta.host}" and process.name: ("sshd" or "sudo")${meta.user !== 'BILINMEYEN-USER' ? ` and message: "${meta.user}"` : ''}${hasSshSrcIp ? ` and (source.ip: "${meta.sourceIp}" or message: "${meta.sourceIp}")` : ''}`,
      qradarAql: `SELECT "username", "sourceip", "devicename", "payload" FROM events WHERE "devicename" ILIKE '%${meta.host}%' ${hasSshSrcIp ? `AND ("sourceip" = '${meta.sourceIp}' OR "payload" ILIKE '%${meta.sourceIp}%') ` : ''}AND ("payload" ILIKE '%sshd%' OR "payload" ILIKE '%sudo%') LAST 120 MINUTES`,
      sigmaRule: `title: Suspicious SSH Activity on Linux ${meta.host}
logsource:
  product: linux
  service: auth
detection:
  selection:
    message|contains:
      - 'Failed password for ${meta.user}'
      - 'Accepted password for ${meta.user}'
  condition: selection
level: medium`,
    };

    detection = {
      siemLogic: 'Fail2ban veya SIEM kuralı: Aynı kaynak IP\'den 5 dakika içinde 5 hatalı SSH girişi durumunda IP 1 saat süreyle iptables üzerinden düşürülmelidir.',
      wafOrFirewallRule: `iptables -A INPUT -s ${meta.sourceIp} -p tcp --dport 22 -j DROP`,
      sigmaYamlPreview: queries.sigmaRule,
      tuningAdvice: 'Otomatik yedekleme ve Ansible yönetim hesaplarının SSH Key tabanlı girişlerini parola kuralı istisnalarına ekleyin.',
    };

    containment = {
      severity: isSshSuccess ? 'YÜKSEK' : 'ORTA',
      containmentActions: [
        `Oturum Sonlandırma: Aktif şüpheli SSH oturumunu 'pkill -u ${meta.user}' ile sonlandırın.`,
        `Kullanıcı Kilitleme: 'passwd -l ${meta.user}' ile hesabı geçici olarak devre dışı bırakın.`,
        `IP Engeli: Güvenlik duvarı üzerinde ${meta.sourceIp} IP adresini engelleyin.`,
      ],
      forensicArtifactsToCollect: [
        '/var/log/auth.log ve /var/log/secure kopyası.',
        '~/.bash_history ve ~/.ssh/authorized_keys dosyaları.',
        'lsof -i -P -n ve netstat -tlpn çıktıları.',
      ],
    };
  }

  // --------------------------------------------------------------------------
  // BRANCH C: WAF / WEB APPLICATION ATTACK (SQLi, Log4j, XSS, Path Traversal)
  // --------------------------------------------------------------------------
  else if (
    meta.attackPattern ||
    lower.includes('cve-') ||
    lower.includes('select ') ||
    lower.includes('union') ||
    lower.includes('jndi:') ||
    lower.includes('waf') ||
    lower.includes('f5') ||
    lower.includes('fortiweb')
  ) {
    const attackName = meta.attackPattern || 'Web Uygulaması Güvenlik Olayı';
    const hasExplicitBlock =
      /^(?:block|deny|drop|reject|reset|close|prevent|blocked|engellendi)$/i.test(meta.action) ||
      /\b(?:block|deny|drop|reject|reset|close|prevent|engellendi)\b/i.test(meta.action);
    const isBlocked = hasExplicitBlock || (/\bblocked\b/i.test(lower) && !lower.includes('not blocked'));
    const wafDisplay = hasExplicitBlock
      ? 'BLOCKED (Engellendi)'
      : meta.action
      ? 'ALERT / İZİN VERİLDİ'
      : 'Belirtilmemiş (Aksiyon Alanı Yok)';

    classification = {
      logSource: 'WAF & Web Uygulaması Güvenlik Kaydı',
      platform: 'Web / Network',
      confidence: 'YÜKSEK_OLASILIK',
      observedBehavior: `Web sunucusuna yönelik ${attackName} atağı kaydedildi. Kaynak IP: ${meta.sourceIp}, Hedef: ${meta.host}, WAF Aksiyonu: ${wafDisplay}.`,
      keyFields: {
        'Saldırı Türü': attackName,
        'Kaynak IP': meta.sourceIp,
        'Hedef Host': meta.host,
        'WAF Aksiyonu': isBlocked ? 'BLOCK' : meta.action ? 'ALERT / ALLOW' : 'Belirtilmemiş',
        'Hedef URL / Parametre': meta.commandLine || 'Parametre İncelemesi',
      },
    };

    platformContext = {
      platformName: 'Web Uygulama Güvenliği (WAF / IIS / Nginx)',
      significance: 'Uygulama katmanı saldırıları, veritabanına erişim, sunucuda uzaktan kod yürütme (RCE) veya yetkisiz dosya okuma amacı taşır.',
      criticalFieldsExplained: [
        { field: 'WAF Aksiyonu', value: isBlocked ? 'Engellendi' : 'Engellenmedi', forensicImportance: 'Saldırının sunucuya ulaşıp ulaşmadığını belirleyen en kritik adli kriterdir.' },
        { field: 'Backend HTTP Status', value: isBlocked ? 'Engelleme Yanıtı (Teyit Gerekir)' : '200 / 500 teyidi gerekir', forensicImportance: 'Sunucu 500 veriyorsa veritabanı syntax hatası, 200 veriyorsa başarılı exploit şüphesi doğar.' },
        { field: 'Kaynak IP', value: meta.sourceIp, forensicImportance: 'Saldırganın altyapısını ve tehdit aktörü istihbaratını (Threat Intel) araştırmayı sağlar.' },
      ],
      attackChainContext: 'Saldırı Zinciri: Dizin Keşfi → Web Exploit Gönderimi → Webshell Yükleme → Komut Yürütme (whoami/cmd) → Ağ İçi Sızma.',
      conditionalCaveat: 'İstek WAF tarafından engellendiyse sömürü gerçekleşmemiştir; ancak Alert modunda kaldıysa veya 200 OK yanıtı döndüyse acil adli müdahale gerekir.',
    };

    hypotheses = [
      {
        id: 'H1',
        title: `Hipotez 1: ${attackName} Üzerinden Uzaktan İstismar Girişimi`,
        type: 'ATTACK',
        likelihood: isBlocked ? 'DÜŞÜK' : 'YÜKSEK',
        statement: isBlocked
          ? 'Saldırı girişimi WAF sınırında durdurulmuştur, sunucuya ulaşmamıştır.'
          : 'İstek uygulama katmanına ulaşmış ve zafiyetli bileşeni tetiklemiş olabilir.',
        strengtheningFindings: ['Web sunucusu access logunda aynı saniyede 200 OK veya 500 Internal Error dönmesi.', 'Sunucudan dışarıya olağandışı DNS/LDAP bağlantısı kurulması.'],
        weakeningFindings: ['WAF\'ın isteği kesin olarak BLOCK/DENY etmiş olması.', 'Uygulamanın bu parametreyi kullanmayan statik bir sayfada yer alması.'],
      },
    ];

    investigationSteps = [
      {
        stepNumber: 1,
        category: 'AUTHENTICATION',
        title: 'ADIM 1 — Web Erişim Loglarında (Access Log) Yanıt Kodu Kontrolü',
        objective: 'Hedef sunucunun erişim loglarında (IIS/Nginx/Apache) bu isteğe dönen gerçek HTTP durum kodu ve yanıt boyutu (bytes) nedir?',
        targetEntities: { host: meta.host, user: 'Web İstemcisi', timeWindow: '-15m / +15m' },
        eventIdsAndLogsToInspect: ['W3C IIS Logları', 'access.log', 'error.log'],
        fieldsToCheck: ['sc-status', 'sc-bytes', 'cs-method', 'cs-uri-stem', 'cs-uri-query'],
        pivotingGuidance: 'Eğer HTTP 200 dönmüş ve response boyutu normalse sömürü başarılı olmuş olabilir; derhal ADIM 2\'ye geçin.',
      },
      {
        stepNumber: 2,
        category: 'PROCESS_EXECUTION',
        title: 'ADIM 2 — Web Sunucu Süreç Ağacında Alt Süreç Kontrolü',
        objective: 'w3wp.exe, nginx veya apache süreçleri altından cmd.exe, powershell.exe, sh veya bash tetiklenmiş mi?',
        targetEntities: { host: meta.host, user: 'IIS_IUSRS / www-data', timeWindow: '+30m' },
        eventIdsAndLogsToInspect: ['Event ID 4688', 'Sysmon Event ID 1', 'auditd execve'],
        fieldsToCheck: ['ParentProcessName (w3wp.exe / httpd)', 'NewProcessName (cmd.exe / bash)'],
        pivotingGuidance: 'Web sunucusu altından komut kabuğu türemişse sistemde Webshell veya RCE gerçekleşmiştir.',
      },
      {
        stepNumber: 3,
        category: 'NETWORK_LATERAL',
        title: 'ADIM 3 — Dışarıya Yönelik Egress Ağ Bağlantıları (C2 / Reverse Shell)',
        objective: 'Sunucudan saldırganın IP\'sine doğru 4444, 1389, 389, 53 gibi portlardan dış bağlantı açılmış mı?',
        targetEntities: { host: meta.host, user: 'Sistem', timeWindow: '+60m' },
        eventIdsAndLogsToInspect: ['Sysmon Event ID 3 (Network)', 'Firewall Egress Logs', 'NetFlow'],
        fieldsToCheck: ['DestinationIp', 'DestinationPort', 'Initiated (true)'],
        pivotingGuidance: 'Sunucudan bilinmeyen bir dış IP\'ye TCP bağlantısı saptanırsa sunucu derhal ağdan izole edilmelidir.',
      },
    ];

    const hasWebSrcIp = meta.sourceIp && meta.sourceIp !== 'Bilinmiyor';
    queries = {
      splunk: `// Not: Alan adları SIEM veri modeline göre uyarlanmalıdır.
index=web host="${meta.host}" ${hasWebSrcIp ? `(c_ip="${meta.sourceIp}" OR client_ip="${meta.sourceIp}")` : ''}
| table _time, host, c_ip, cs_method, cs_uri_stem, cs_uri_query, sc_status, sc_bytes
| sort _time asc`,
      kql: `// Not: Alan adları SIEM veri modeline göre uyarlanmalıdır.
W3CIISLog
| where Computer has "${meta.host}"
${hasWebSrcIp ? `| where cIP == "${meta.sourceIp}"\n` : ''}| project TimeGenerated, Computer, cIP, csMethod, csUriStem, csUriQuery, scStatus, scBytes
| order by TimeGenerated asc`,
      elastic: `host.name: "${meta.host}" ${hasWebSrcIp ? `and source.ip: "${meta.sourceIp}" ` : ''}and url.path: *`,
      qradarAql: `SELECT "sourceip", "destinationip", "URL", "ResponseCode", "devicename" FROM events WHERE ${hasWebSrcIp ? `"sourceip" = '${meta.sourceIp}'` : `"devicename" ILIKE '%${meta.host}%'`} LAST 60 MINUTES`,
      sigmaRule: `title: Web Application Exploit Attempt against ${meta.host}
logsource:
  category: webserver
detection:
  selection:
    ${hasWebSrcIp ? `c-ip: '${meta.sourceIp}'` : `target_host: '${meta.host}'`}
  condition: selection
level: high`,
    };

    detection = {
      siemLogic: `WAF ve Access log korelasyonu: ${meta.sourceIp} IP adresinden gelen exploit istekleri için WAF alert verip access log 200 dönüyorsa CRITICAL alarm üretilmelidir.`,
      wafOrFirewallRule: `WAF Kuralı: İlgili URI ve imza kuralını ALERT modundan kademeli olarak BLOCK moduna geçirin. Kaynak IP (${meta.sourceIp}) 24 saat süreyle kara listeye (Blacklist) eklenmelidir.`,
      sigmaYamlPreview: queries.sigmaRule,
      tuningAdvice: 'İç zafiyet tarama araçlarının (Qualys/Nessus) IP adreslerini WAF korelasyon kurallarından hariç tutun.',
    };

    containment = {
      severity: isBlocked ? 'DÜŞÜK' : 'KRİTİK',
      containmentActions: [
        `WAF Kural Sıkılaştırma: İlgili saldırı deseni WAF üzerinde ALERT ise derhal BLOCK kuralına çekilmelidir.`,
        `IP Engelleme: Sınır güvenlik duvarında ${meta.sourceIp} IP adresi engellenmelidir.`,
        `Dosya Sistemi Taraması: Webroot dizininde son 24 saatte oluşturulan yeni script (.php, .aspx, .jsp) dosyaları taranmalıdır.`,
      ],
      forensicArtifactsToCollect: [
        'Web sunucusunun access.log / IIS W3C log dosyaları.',
        'Webroot dosya bütünlüğü hash kontrolü (FIM).',
      ],
    };
  }

  // --------------------------------------------------------------------------
  // BRANCH D: UNKNOWN / UNIDENTIFIED LOG SOURCE & UNIVERSAL SEMANTIC EXTRACTION
  // --------------------------------------------------------------------------
  else {
    const universalEv = extractUniversalEvidence(rawLog, parsedLog);
    const hasKnownActor = universalEv.actor.value || (meta.user && meta.user !== 'BILINMEYEN-USER');
    const hasKnownIp = universalEv.sourceEndpoint.ip.value || (meta.sourceIp && meta.sourceIp !== 'Bilinmiyor');
    const hasKnownError = universalEv.telemetry.errorCode.value || null;
    const actorName = universalEv.actor.value || meta.user;
    const ipName = universalEv.sourceEndpoint.ip.value || meta.sourceIp;

    const dynamicSemanticObs = (!universalEv.admissibility.isSecurityEvidence)
      ? 'Girdi incelendi; geçerli bir güvenlik telemetrisi veya olay kaydı içermemektedir (Non-Security Input).'
      : (hasKnownActor || hasKnownIp || hasKnownError)
      ? `Standart platform şeması dışında özel telemetri tespit edildi. Gözlenen Aktör: "${actorName || '-'}", Kaynak IP: ${ipName || '-'}, Durum: ${universalEv.outcome.value}${hasKnownError ? `, Neden: ${hasKnownError}` : ''}.`
      : `Belirtilen log satırının standart platform şeması (Windows Security, Sysmon, Linux Auth, WAF) kesin olarak eşleşmemiştir. Genel adli inceleme ve ayrıştırma protokolü devreye alınmıştır.`;

    classification = {
      logSource: 'Log kaynağı kesin belirlenemedi.',
      platform: 'Bilinmiyor',
      confidence: 'BELİRSİZ',
      observedBehavior: dynamicSemanticObs,
      keyFields: {
        'Ham Veri Uzunluğu': `${trimmed.length} karakter`,
        'Ayıklanan Host': (universalEv.destinationEndpoint.host.value || (meta.host !== 'BILINMEYEN-HOST' ? meta.host : null)) || 'Belirlenemedi',
        'Ayıklanan Kullanıcı': (universalEv.actor.value || (meta.user !== 'BILINMEYEN-USER' ? meta.user : null)) || 'Belirlenemedi',
        'Ayıklanan IP': (universalEv.sourceEndpoint.ip.value || (meta.sourceIp !== 'Bilinmiyor' ? meta.sourceIp : null)) || 'Belirlenemedi',
        ...(universalEv.telemetry.errorCode.value ? { 'Hata/Neden Kodu': universalEv.telemetry.errorCode.value } : {}),
      },
    };

    platformContext = {
      platformName: 'Tanımlanamayan Günlük Kaynağı (Generic Log Parser)',
      significance: 'Log kaynağı kesin belirlenemediğinde varsayımsal hüküm verilmemeli; öncelikle logun kaynak cihazı (Ağ cihazı, Özel Uygulama, Proxy) teyit edilmelidir.',
      criticalFieldsExplained: [
        { field: 'Ham Metin Yapısı', value: trimmed.slice(0, 40) + '...', forensicImportance: 'Formatın CEF, Syslog, JSON veya özel CSV olup olmadığını anlamak için ham metin incelenmelidir.' },
      ],
      attackChainContext: 'Log kaynağı netleşmeden saldırı zinciri tahmini yapılmamalıdır.',
      conditionalCaveat: 'Log kaynağı kesin belirlenemediği için bu log tek başına bir güvenlik ihlali olarak nitelendirilemez.',
    };

    hypotheses = [
      {
        id: 'H1',
        title: 'Hipotez 1: Özel Uygulama Hatası veya Tanımsız Güvenlik Telemetrisi',
        type: 'BENIGN_ANOMALY',
        likelihood: 'ORTA',
        statement: 'Log, kurum içi özel bir yazılımın veya güvenlik cihazının standart dışı bir bildirim kaydı olabilir.',
        strengtheningFindings: ['Log içinde hata, uyarı veya exception anahtar kelimelerinin yer alması.'],
        weakeningFindings: ['Log formatının standart RFC 5424 veya Windows XML şemasına uyması.'],
      },
    ];

    investigationSteps = [
      {
        stepNumber: 1,
        category: 'AUTHENTICATION',
        title: 'ADIM 1 — Logun Üretici ve Cihaz Kaynağının Doğrulanması',
        objective: 'Bu logu üreten cihazın (Firewall, Uygulama Sunucusu, Proxy vb.) tam adı ve IP adresi tespit edilmelidir.',
        targetEntities: { host: meta.host, user: meta.user, timeWindow: 'Belirsiz' },
        eventIdsAndLogsToInspect: ['Merkezi Syslog / SIEM Giriş Portları'],
        fieldsToCheck: ['Log Header', 'IP Header', 'Port'],
        pivotingGuidance: 'Cihaz türü belirlendikten sonra ilgili teknolojiye özel analiz başlatılmalıdır.',
      },
    ];

    queries = {
      splunk: `index=* "${trimmed.slice(0, 50).replace(/"/g, '')}" | head 10`,
      kql: `search "${trimmed.slice(0, 50).replace(/"/g, '')}" | take 10`,
      elastic: `"${trimmed.slice(0, 50).replace(/"/g, '')}"`,
      qradarAql: `SELECT * FROM events WHERE "payload" ILIKE '%${trimmed.slice(0, 40).replace(/'/g, '')}%' LAST 60 MINUTES`,
      sigmaRule: `# Log kaynağı kesin belirlenemediği için Sigma kuralı üretilemedi.`,
    };

    detection = {
      siemLogic: 'Log kaynağının SIEM üzerinde doğru Log Source Type ile eşleştirilmesi (DSM / Parser mapping) gereklidir.',
      wafOrFirewallRule: 'Belirlenemedi.',
      sigmaYamlPreview: '# N/A',
      tuningAdvice: 'Tanımlanamayan log kaynakları için özel parser (Custom Log Extension) geliştirilmelidir.',
    };

    containment = {
      severity: 'DÜŞÜK',
      containmentActions: ['Logun kaynağının ve meşruiyetinin ilgili sistem sahibinden teyit edilmesi.'],
      forensicArtifactsToCollect: ['Cihazın orijinal syslog yapılandırma dosyası.'],
    };
  }

  // Query Field Provenance
  const queryFieldProvenance: L2QueryFieldProvenance[] = [];
  if (classification.keyFields['Event ID'] || (meta.winDetails && meta.winDetails.eventId)) {
    queryFieldProvenance.push({
      field: 'EventID',
      value: String(classification.keyFields['Event ID'] || meta.winDetails.eventId),
      classification: 'OBSERVED',
      source: 'Doğrudan log telemetrisi',
    });
  }
  if (meta.host && meta.host !== 'BILINMEYEN-HOST') {
    queryFieldProvenance.push({
      field: 'host / Computer',
      value: meta.host,
      classification: 'OBSERVED',
      source: 'Doğrudan log telemetrisi',
    });
  } else {
    queryFieldProvenance.push({
      field: 'host / Computer',
      value: '<HOST_ADI>',
      classification: 'PLACEHOLDER',
      source: 'Logda hedef sunucu/iş istasyonu belirtilmemiş',
    });
  }
  if (meta.user && meta.user !== 'BILINMEYEN-USER') {
    queryFieldProvenance.push({
      field: 'user / TargetUserName',
      value: meta.user,
      classification: 'OBSERVED',
      source: 'Doğrudan log telemetrisi',
    });
  } else {
    queryFieldProvenance.push({
      field: 'user / TargetUserName',
      value: '<KULLANICI_HESABI>',
      classification: 'PLACEHOLDER',
      source: 'Logda kullanıcı hesabı belirtilmemiş',
    });
  }
  if (meta.sourceIp && meta.sourceIp !== 'Bilinmiyor') {
    queryFieldProvenance.push({
      field: 'src_ip / IpAddress',
      value: meta.sourceIp,
      classification: 'OBSERVED',
      source: 'Doğrudan log telemetrisi',
    });
  } else {
    queryFieldProvenance.push({
      field: 'src_ip / IpAddress',
      value: 'UYGULANMAZ (Logda Yok)',
      classification: 'PLACEHOLDER',
      source: 'Kaynak IP bulunmadığından sorgularda filtre uygulanmadı',
    });
  }
  queryFieldProvenance.push({
    field: 'TimeWindow',
    value: '-30m / +60m',
    classification: 'DERIVED',
    source: 'Olay etrafındaki adli inceleme penceresi',
  });
  queryFieldProvenance.push({
    field: 'DataModel',
    value: 'CIM / ASIM / ECS / QRadar DSM',
    classification: 'STATIC_QUERY_SYNTAX',
    source: 'Alan adı SIEM veri modeline göre uyarlanmalıdır.',
  });

  // Safe Containment Steps
  const safeContainmentSteps: SafeContainmentStep[] = [];
  const hostVal = meta.host !== 'BILINMEYEN-HOST' ? meta.host : 'Uç Nokta';
  const userVal = meta.user !== 'BILINMEYEN-USER' ? meta.user : 'İlgili Kullanıcı';

  safeContainmentSteps.push({
    action: `Host Ağ İzolasyonu Değerlendirmesi (${hostVal})`,
    why: 'Zararlı C2 trafiğini veya lateral movement yayılımını durdurmak.',
    when: 'Yalnızca uç noktada yetkisiz komut yürütme (RCE/Webshell) veya aktif ters kabuk bağlantısı kanıtlandığında uygulanmalıdır.',
    risk: 'Kritik sunucu ve üretim servislerinin durması, iş sürekliliği kesintisi riski.',
    evidenceRequired: 'Sysmon Event 3 dış ağ bağlantısı veya 4688 üzerinden doğrulanmış zararlı süreç.',
    isDestructiveOrImpacting: true,
  });

  safeContainmentSteps.push({
    action: `Hesap Parola Sıfırlama ve Oturum İptali (${userVal})`,
    why: 'Çalınmış olabilecek kimlik bilgisinin kötüye kullanımını engellemek.',
    when: 'Başarılı oturum açma (4624) sonrasında anormal yetki ataması (4672) veya olağandışı kaynak IP tespit edildiğinde.',
    risk: 'Meşru personelin iş akışının kesilmesi veya otomatik servis hesaplarının kilitlenmesi.',
    evidenceRequired: 'Yetkisiz coğrafi konumdan başarılı kimlik doğrulama veya olağandışı saatte oturum.',
    isDestructiveOrImpacting: false,
  });

  if (meta.sourceIp && meta.sourceIp !== 'Bilinmiyor') {
    safeContainmentSteps.push({
      action: `Kaynak IP Geçici Blokajı (${meta.sourceIp})`,
      why: 'Saldırgan IP adresinden gelen sonraki istekleri sınırda kesmek.',
      when: 'Aynı IP adresinden çoklu hedeflere kaba kuvvet veya istismar gönderimi doğrulandığında.',
      risk: 'Eğer kaynak IP bir kurumsal proxy, NAT geçidi veya CDN ise meşru kullanıcıların da engellenmesi riski.',
      evidenceRequired: 'Tehdit istihbaratı (Threat Intel) teyidi veya 10+ ardışık istismar isteği.',
      isDestructiveOrImpacting: true,
    });
  }

  // IOC Breakdown
  const observedIocs: L2IocItem[] = [];
  const potentialIocs: Array<{ type: string; value: string; condition: string }> = [];

  if (meta.sourceIp && meta.sourceIp !== 'Bilinmiyor' && /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(meta.sourceIp)) {
    observedIocs.push({ type: 'IPv4', value: meta.sourceIp, field: 'Source IP' });
  }
  if (meta.host && meta.host !== 'BILINMEYEN-HOST') {
    observedIocs.push({ type: 'Hostname', value: meta.host, field: 'Computer / Host' });
  }
  if (meta.user && meta.user !== 'BILINMEYEN-USER' && meta.user !== 'SYSTEM') {
    observedIocs.push({ type: 'Account', value: meta.user, field: 'Target User' });
  }
  if (meta.commandLine) {
    const urlMatch = meta.commandLine.match(/https?:\/\/([a-zA-Z0-9_\-\.]+)/i);
    if (urlMatch) {
      observedIocs.push({ type: 'URL / Domain', value: urlMatch[1], field: 'CommandLine' });
    }
  }
  potentialIocs.push({
    type: 'C2 IP / Domain',
    value: '<C2_SUNUCU_IP>',
    condition: 'Ağ seviyesinde dış bağlantı (Sysmon 3 / NetFlow) gözlenirse adli IOC olarak işlenir.',
  });

  const iocBreakdown: L2IocBreakdown = { observedIocs, potentialIocs };

  // BUILD SUMMARY MARKDOWN
  const summaryMarkdown = buildL2InvestigationMarkdown({
    classification,
    platformContext,
    hypotheses,
    investigationSteps,
    queries,
    detection,
    containment,
    queryFieldProvenance,
    safeContainmentSteps,
  });

  const universalEvidence = extractUniversalEvidence(rawLog, parsedLog);
  const dynamicSynth = synthesizeDynamicHypotheses(universalEvidence);
  const tailoredSteps = buildTailoredInvestigationSteps(universalEvidence);

  return {
    classification,
    platformContext,
    provenFacts: dynamicSynth.provenFacts,
    unprovenHypotheses: dynamicSynth.unprovenHypotheses,
    missingInformation: dynamicSynth.missingEvidence,
    tailoredSteps,
    dynamicHypotheses: dynamicSynth.hypotheses,
    universalEvidence,
    hypotheses,
    investigationSteps,
    queries,
    queryFieldProvenance,
    detection,
    containment,
    safeContainmentSteps,
    iocBreakdown,
    summaryMarkdown,
  };
}

// ============================================================================
// HELPER: WINDOWS EVENT SIGNIFICANCE DESCRIPTIONS
// ============================================================================

function getWindowsEventSignificance(eventId: number, eventName: string): string {
  switch (eventId) {
    case 4625:
      return 'Windows Event ID 4625, kimlik doğrulamanın başarısız olduğunu gösterir. Active Directory ve uç noktalarda en yaygın incelenen olaydır. Tek bir olay şifre yazım hatası olabilirken; farklı kullanıcılara ardışık denemeler parola püskürtme (Password Spraying), aynı kullanıcıya ardışık denemeler ise kaba kuvvet (Brute Force) saldırısına işaret eder.';
    case 4624:
      return 'Windows Event ID 4624, sistemde başarılı bir oturum açıldığını kanıtlar. Bu olay tek başına zararlı değildir; ancak mesai dışı saatte, bilinmeyen bir IP\'den veya RDP (Logon Type 10) protokolüyle gerçekleşmişse ve hemen ardından yetki yükseltme gelmişse kritik bir saldırı köprüsüdür.';
    case 4688:
      return 'Windows Event ID 4688 (veya Sysmon Event ID 1), yeni bir sürecin (Process) başlatıldığını bildirir. Komut satırı (CommandLine) ve Üst Süreç (ParentProcess) ilişkisi incelenerek saldırganın Living-off-the-Land araçlarını veya kötü amaçlı ikililerini nasıl yürüttüğü doğrudan adli olarak tespit edilir.';
    case 4672:
      return 'Windows Event ID 4672, yeni açılan bir oturuma özel ayrıcalıkların (SeDebugPrivilege, SeBackupPrivilege vb.) atandığını gösterir. Normal kullanıcı oturumlarında görülmemesi beklenir; yetki yükseltme (Privilege Escalation) tespiti için zorunlu korelasyon noktasıdır.';
    case 7045:
    case 4697:
      return 'Windows Event ID 7045/4697, sisteme yeni bir Windows servisinin kurulduğunu gösterir. Saldırganlar kalıcılık sağlamak (Persistence) ve sistem yeniden başladığında arka kapılarını çalıştırmak için servis oluşturma tekniğini (T1543.003) sıklıkla kullanır.';
    case 1102:
    case 104:
      return 'Windows Event ID 1102/104, Güvenlik veya Sistem olay günlüğünün kasıtlı olarak temizlendiğini (Cleared) gösterir. Neredeyse hiçbir meşru gerekçeyle rutin çalışma sırasında temizlenmez; saldırganın adli delilleri yok etme (Defense Evasion T1070.001) eylemidir.';
    default:
      return `${eventName} (Event ID ${eventId}), Windows denetim alt sisteminde kaydedilen önemli bir durum değişikliğidir.`;
  }
}

// ============================================================================
// HELPER: BUILD FULL L2 INVESTIGATION MARKDOWN
// ============================================================================

function buildL2InvestigationMarkdown(params: {
  classification: L2LogClassification;
  platformContext: L2PlatformContext;
  hypotheses: L2Hypothesis[];
  investigationSteps: L2InvestigationStep[];
  queries: L2GeneratedQueries;
  detection: L2DetectionAndRuleRecommendation;
  containment: L2ContainmentAndResponse;
  queryFieldProvenance?: L2QueryFieldProvenance[];
  safeContainmentSteps?: SafeContainmentStep[];
}): string {
  const { classification, platformContext, hypotheses, investigationSteps, queries, detection, containment, queryFieldProvenance, safeContainmentSteps } = params;

  let md = `# 🛡️ L2 INCIDENT INVESTIGATION PLAN & HYPOTHESIS MATRIX\n\n`;

  // 1. Log Classification & Observed Behavior
  md += `## 📋 1. Log Sınıflandırması ve Gözlenen Davranış\n\n`;
  md += `* **Belirlenen Log Kaynağı:** **${classification.logSource}**\n`;
  md += `* **Platform / Ekosistem:** ${classification.platform}\n`;
  md += `* **Sınıflandırma Güveni:** \`${classification.confidence}\`\n\n`;
  md += `**Gözlenen Davranış:**\n${classification.observedBehavior}\n\n`;

  md += `| Kritik Alan | Ayıklanan Değer |\n| :--- | :--- |\n`;
  for (const [k, v] of Object.entries(classification.keyFields)) {
    md += `| \`${k}\` | **${v}** |\n`;
  }
  md += `\n`;

  // 2. Platform Context & Critical Fields
  md += `## 🏛️ 2. Platform Bağlamı ve Adli Önemi\n\n`;
  md += `${platformContext.significance}\n\n`;
  md += `> ⚖️ **Adli İlke:** ${platformContext.conditionalCaveat}\n\n`;
  md += `**Zincirleme Olay Bağlamı:**\n${platformContext.attackChainContext}\n\n`;

  md += `### Kritik Parametrelerin Adli Anlamı:\n`;
  platformContext.criticalFieldsExplained.forEach((f) => {
    md += `* **${f.field}** (\`${f.value}\`): ${f.forensicImportance}\n`;
  });
  md += `\n`;

  // 3. Hypotheses
  md += `## 🔬 3. Olay Hipotezleri & Doğrulama Matrisi\n\n`;
  hypotheses.forEach((h, idx) => {
    md += `### ${h.title} [Olasılık: ${h.likelihood}]\n`;
    md += `*Değerlendirme:* ${h.statement}\n\n`;
    md += `**Hipotezi Güçlendiren Bulgular (İncelemede Aranacaklar):**\n`;
    h.strengtheningFindings.forEach((s) => {
      md += `* 🟢 ${s}\n`;
    });
    md += `\n**Hipotezi Zayıflatan / Çürüten Bulgular (Meşru Gerekçeler):**\n`;
    h.weakeningFindings.forEach((w) => {
      md += `* ⚪ ${w}\n`;
    });
    md += `\n`;
  });

  // 4. L2 Investigation Steps
  md += `## 🕵️‍♂️ 4. L2 Seviyesi Somut Soruşturma Planı (Adım Adım)\n\n`;
  investigationSteps.forEach((s) => {
    md += `### ${s.title}\n`;
    md += `**Amaç:** ${s.objective}\n\n`;
    md += `* **Hedef Host:** \`${s.targetEntities.host}\` | **Hedef Kullanıcı:** \`${s.targetEntities.user}\` | **Zaman Penceresi:** \`${s.targetEntities.timeWindow}\`\n`;
    md += `* **Aranacak Loglar / Olaylar:** ${s.eventIdsAndLogsToInspect.join(', ')}\n`;
    md += `* **İncelenecek Parametreler:** ${s.fieldsToCheck.join(', ')}\n`;
    md += `* **Yönlendirme / Pivot Kuralı:** ${s.pivotingGuidance}\n\n`;
  });

  // 5. Ready-to-Run Queries
  md += `## 💻 5. Doğrudan Çalıştırılabilir SIEM Sorguları\n\n`;
  md += `> ℹ️ *Not: Alan adları kurumunuzun SIEM veri modeline (CIM / ASIM / ECS / QRadar DSM) göre uyarlanmalıdır.*\n\n`;
  md += `### Splunk (SPL)\n\`\`\`splunk\n${queries.splunk}\n\`\`\`\n\n`;
  md += `### Microsoft Sentinel & Defender (KQL)\n\`\`\`kql\n${queries.kql}\n\`\`\`\n\n`;
  md += `### Elastic / Lucene (EQL)\n\`\`\`text\n${queries.elastic}\n\`\`\`\n\n`;
  md += `### IBM QRadar (AQL)\n\`\`\`sql\n${queries.qradarAql}\n\`\`\`\n\n`;

  if (queryFieldProvenance && queryFieldProvenance.length > 0) {
    md += `### 🔍 Sorgu Parametre Kökeni (Query Field Provenance):\n\n`;
    md += `| Parametre | Değer | Sınıflandırma | Kanıt Kaynağı |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    queryFieldProvenance.forEach((p) => {
      md += `| \`${p.field}\` | **${p.value}** | \`${p.classification}\` | ${p.source} |\n`;
    });
    md += `\n`;
  }

  // 6. Detection & Containment
  md += `## 🚨 6. Tespit Kuralı & Acil Müdahale (Containment)\n\n`;
  md += `**Önerilen SIEM / Algılama Mantığı:**\n${detection.siemLogic}\n\n`;
  md += `**Güvenlik Duvarı / WAF Önlemi:**\n${detection.wafOrFirewallRule}\n\n`;

  if (safeContainmentSteps && safeContainmentSteps.length > 0) {
    md += `### 🛡️ Koşullu ve Güvenli Müdahale Kılavuzu (Safe Containment Guidance):\n\n`;
    safeContainmentSteps.forEach((s, idx) => {
      md += `#### ${idx + 1}. ${s.action} ${s.isDestructiveOrImpacting ? '⚠️ [Servis Etkisi Var]' : '✅ [Düşük Risk]'}\n`;
      md += `* **Neden (Why):** ${s.why}\n`;
      md += `* **Ne Zaman (When):** ${s.when}\n`;
      md += `* **İş Sürekliliği Riski (Risk):** ${s.risk}\n`;
      md += `* **Zorunlu Adli Kanıt (Evidence Required):** ${s.evidenceRequired}\n\n`;
    });
  } else {
    md += `### Önerilen Müdahale Adımları (L2 Containment):\n`;
    containment.containmentActions.forEach((a, i) => {
      md += `${i + 1}. ${a}\n`;
    });
  }

  md += `\n### Toplanacak Adli Deliller (Artifacts):\n`;
  containment.forensicArtifactsToCollect.forEach((c) => {
    md += `* 📦 ${c}\n`;
  });
  md += `\n`;

  return md;
}
