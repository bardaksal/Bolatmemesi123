import {
  UniversalEvidence,
  DynamicHypothesis,
  TailoredInvestigationStep,
} from '../types/investigationEvidence';
import { WINDOWS_SUBSTATUS_MAP } from './quickTriageHelper';

/**
 * Dynamic Hypothesis Synthesizer:
 * Generates hypotheses based on verified observed facts and separates proven from unproven,
 * rather than hardcoding static essay blocks per Event ID or keyword.
 */
export function synthesizeDynamicHypotheses(evidence: UniversalEvidence): {
  hypotheses: DynamicHypothesis[];
  provenFacts: string[];
  unprovenHypotheses: string[];
  missingEvidence: string[];
} {
  const provenFacts: string[] = [];
  const unprovenHypotheses: string[] = [];
  const missingEvidence: string[] = [];
  const hypotheses: DynamicHypothesis[] = [];

  if (!evidence.admissibility.isSecurityEvidence) {
    return {
      hypotheses: [],
      provenFacts: ['Girdi güvenlik kanıtı veya olay telemetrisi içermemektedir.'],
      unprovenHypotheses: [],
      missingEvidence: ['Herhangi bir güvenlik olayı bulunmadığı için ek kanıt gerekmemektedir.'],
    };
  }

  const { actor, sourceEndpoint, destinationEndpoint, outcome, process, telemetry } = evidence;

  // 1. Compile Proven Facts (strictly what was OBSERVED/DERIVED from raw telemetry)
  if (telemetry.eventId.value) {
    provenFacts.push(`Event ID: ${telemetry.eventId.value}${telemetry.eventName.value ? ` (${telemetry.eventName.value})` : ''} kaydedildi.`);
  }
  if (actor.status === 'OBSERVED' && actor.value) {
    provenFacts.push(`İlgili hesap/kullanıcı: "${actor.value}".`);
  }
  if (sourceEndpoint.ip.status === 'OBSERVED' && sourceEndpoint.ip.value) {
    provenFacts.push(`Kaynak IP adresi: ${sourceEndpoint.ip.value}.`);
  }
  if (destinationEndpoint.host.status === 'OBSERVED' && destinationEndpoint.host.value) {
    provenFacts.push(`Hedef sistem/host: "${destinationEndpoint.host.value}".`);
  }
  if (telemetry.subStatus.value) {
    const desc = WINDOWS_SUBSTATUS_MAP[telemetry.subStatus.value.toUpperCase()] || '';
    provenFacts.push(`Alt durum (SubStatus) hata kodu: ${telemetry.subStatus.value}${desc ? ` — ${desc}` : ''}.`);
  }
  if (telemetry.errorCode.value) {
    provenFacts.push(`Olay hata/neden kodu: "${telemetry.errorCode.value}".`);
  }
  if (process.commandLine.status === 'OBSERVED' && process.commandLine.value) {
    provenFacts.push(`Yürütülen komut satırı: "${process.commandLine.value}".`);
  }
  if (telemetry.rawPayload.status === 'OBSERVED' && telemetry.rawPayload.value) {
    provenFacts.push(`HTTP isteğinde "${telemetry.rawPayload.value}" hedefi/deseni gözlemlendi.`);
  }
  if (outcome.status === 'OBSERVED' || outcome.status === 'DERIVED') {
    provenFacts.push(`İşlem neticesi: ${outcome.value === 'FAILURE' ? 'BAŞARISIZ' : outcome.value === 'SUCCESS' ? 'BAŞARILI' : outcome.value === 'BLOCKED' ? 'ENGELLENDİ' : 'BİLİNMİYOR'}.`);
  }

  // Check malicious request vs attack success distinction
  let rawOrDecoded = telemetry.rawPayload.value || '';
  try {
    rawOrDecoded = decodeURIComponent(rawOrDecoded);
  } catch {
    // Keep raw string if URI malformed
  }

  const hasMaliciousPattern = Boolean(
    telemetry.rawPayload.status === 'OBSERVED' &&
    rawOrDecoded &&
    /(?:\.\.\/|\.\.\\|\/etc\/passwd|union\s+select|or\s+1=1|\$\{jndi|cmd=|webshell)/i.test(rawOrDecoded)
  );

  if (hasMaliciousPattern && outcome.value !== 'BLOCKED') {
    unprovenHypotheses.push(
      'Saldırının başarılı olduğuna veya sistemin ele geçirildiğine dair kanıt saptanmamıştır (Attack success not established; yanıt içeriği ve sunucu logları teyit edilmelidir).'
    );
  }

  // 2. Synthesize Hypotheses based on context & missing facts
  const isAuthFailure = outcome.value === 'FAILURE' || telemetry.eventId.value === 4625 || telemetry.errorCode.value === 'otp_expired';
  const isProcessExec = Boolean(process.name.value || process.commandLine.value || telemetry.eventId.value === 4688 || telemetry.eventId.value === 1);
  const isLogCleared = telemetry.eventId.value === 1102 || telemetry.eventId.value === 104;

  if (isAuthFailure) {
    // Check if single failure or mass failure evidence exists
    const hasStaleCredCode = telemetry.subStatus.value?.toUpperCase() === '0XC000006A';
    const hasBadUserCode = telemetry.subStatus.value?.toUpperCase() === '0XC0000064';
    const hasLockout = telemetry.subStatus.value?.toUpperCase() === '0XC0000234';

    // Hypothesis A: Benign user mistake or stale credential
    hypotheses.push({
      id: 'H1',
      title: 'Hipotez 1: Kullanıcı Yazım Hatası veya Eski Kayıtlı Kimlik Bilgisi (Benign Anomali)',
      statement: `${actor.value || 'Kullanıcı'} tarafından girilen hatalı parola veya arka planda eski parola sunan otomatik bir uygulama/eşlenmiş sürücü (Cached Credential).`,
      type: 'BENIGN_EXPLANATION',
      supportStatus: hasStaleCredCode ? 'SUPPORTED_BY_EVIDENCE' : 'UNPROVEN_POSSIBILITY',
      observedSupportingFacts: [
        actor.value ? `Kullanıcı adının ("${actor.value}") geçerli formatta olması.` : 'Hedef kullanıcının belirtilmiş olması.',
        hasStaleCredCode ? 'SubStatus 0xC000006A (Kullanıcı geçerli, şifre yanlış) hata kodu.' : 'Tekil kimlik doğrulama başarısızlığı.',
      ],
      observedContradictingFacts: hasLockout ? ['Hesabın çok sayıda deneme neticesinde kilitlenmiş (0xC0000234) olması.'] : [],
      missingEvidenceRequired: [
        'Kullanıcının Active Directory parola değişim zamanı (pwdLastSet).',
        'Başarısız denemenin ardından başarılı oturum açma (4624) gelip gelmediği.',
      ],
      nextVerificationSteps: [
        'Kullanıcının iş istasyonundaki Windows Credential Manager ve ağ sürücülerini kontrol edin.',
      ],
    });

    // Hypothesis B: Credential Attack (Unproven until multi-attempt / IP correlation proven)
    hypotheses.push({
      id: 'H2',
      title: 'Hipotez 2: Otomatik Parola Denemesi veya Kimlik Saldırısı (Kaba Kuvvet / Püskürtme)',
      statement: 'Harici veya iç bir kaynaktan hesap parolasını tahmin etmeye veya ele geçirmeye yönelik yetkisiz deneme.',
      type: 'ATTACK_SCENARIO',
      supportStatus: hasLockout ? 'SUPPORTED_BY_EVIDENCE' : 'UNPROVEN_POSSIBILITY',
      observedSupportingFacts: [
        sourceEndpoint.ip.value ? `İsteğin ${sourceEndpoint.ip.value} IP adresinden gelmesi.` : 'Başarısız oturum kaydı bulunması.',
        hasBadUserCode ? 'Var olmayan kullanıcı adı (0xC0000064) denenmiş olması.' : 'Yetkilendirme hatası alınması.',
      ],
      observedContradictingFacts: hasStaleCredCode && !hasLockout ? ['Tekil başarısız oturumda kilitlenme veya kitlesel hesap taraması kanıtı olmaması.'] : [],
      missingEvidenceRequired: [
        'Aynı kaynaktan kısa sürede diğer kullanıcılara yönelik denemeler (Parola Püskürtme).',
        'Başarısız denemelerin hemen ardından gelen başarılı 4624 / 4672 yetki ataması.',
        'Kaynak IP adresinin kurum dışı veya şüpheli ağda olup olmadığı.',
      ],
      nextVerificationSteps: [
        `SIEM üzerinden ${sourceEndpoint.ip.value || 'kaynak IP'} ve ${actor.value || 'kullanıcı'} için +/- 30 dakikalık pencerede 4625/4624 taraması yapın.`,
      ],
    });

    unprovenHypotheses.push('Brute-force / Parola Püskürtme saldırısı (Tekil log ile kanıtlanamaz, çoklu deneme korelasyonu eksik).');
    missingEvidence.push('Başarısız oturumun ardından başarılı giriş (4624) gerçekleşip gerçekleşmediği.');
    missingEvidence.push('Aynı IP üzerinden farklı hesaplara yönelik eşzamanlı denemeler.');
  } else if (isProcessExec) {
    const cmd = process.commandLine.value || '';
    const isEncoded = /-(?:enc|encodedcommand|e)\b/i.test(cmd);
    const isBypass = /bypass|unrestricted/i.test(cmd);
    const isHashCalc = /certutil.*-hashfile/i.test(cmd);

    if (isHashCalc) {
      hypotheses.push({
        id: 'H1',
        title: 'Hipotez 1: Meşru Dosya Bütünlüğü ve Kriptografik Özet (Hash) Hesaplama',
        statement: 'Kullanıcı veya betik, dosyanın SHA256/MD5 özetini doğrulamak amacıyla standart certutil parametresini çalıştırmıştır.',
        type: 'AUTHORIZED_ADMIN',
        supportStatus: 'SUPPORTED_BY_EVIDENCE',
        observedSupportingFacts: [
          'Komut satırında indirme (-urlcache) değil, -hashfile parametresinin yer alması.',
        ],
        observedContradictingFacts: [],
        missingEvidenceRequired: ['Komutu çalıştıran kullanıcının yetki düzeyi.'],
        nextVerificationSteps: ['Dosyanın meşru bir kurulum veya doğrulama paketine ait olduğunu teyit edin.'],
      });
    } else {
      hypotheses.push({
        id: 'H1',
        title: 'Hipotez 1: Komut Satırı Yürütme ve Yerel Araç İstismarı (LOLBAS / Keşif)',
        statement: 'İkili dosya veya kabuk üzerinden sistemde komut icra edilmektedir.',
        type: isEncoded || isBypass ? 'ATTACK_SCENARIO' : 'BENIGN_EXPLANATION',
        supportStatus: isEncoded ? 'SUPPORTED_BY_EVIDENCE' : 'UNPROVEN_POSSIBILITY',
        observedSupportingFacts: [
          process.name.value ? `Süreç: "${process.name.value}".` : 'Süreç oluşturma olayı.',
          isEncoded ? 'Base64 ile gizlenmiş komut parametresi.' : 'Komut yürütme parametreleri.',
        ],
        observedContradictingFacts: [],
        missingEvidenceRequired: [
          'Üst sürecin (Parent Process) meşru bir yönetim ajanı (SCCM) mı yoksa web sunucusu (w3wp) mu olduğu.',
          'Komutun ardından açılan dış ağ bağlantıları (Sysmon Event 3).',
        ],
        nextVerificationSteps: ['Süreç ağacını (Parent-Child) ve çağıran kullanıcıyı doğrulayın.'],
      });
      unprovenHypotheses.push('Zararlı amaçlı komut yürütme (Üst süreç ve yetki bağlamı doğrulanana kadar kanıtlanmamıştır).');
      missingEvidence.push('Üst süreç (Parent Process Name ve PID).');
      missingEvidence.push('Komutun açtığı ağ bağlantıları veya oluşturduğu alt dosyalar.');
    }
  } else if (isLogCleared) {
    hypotheses.push({
      id: 'H1',
      title: 'Hipotez 1: Adli İz Karartma / Güvenlik Günlüğü Temizleme (Defense Evasion)',
      statement: 'Yetkili oturum altında denetim izlerini gizlemek amacıyla olay günlüğü sıfırlanmıştır.',
      type: 'ATTACK_SCENARIO',
      supportStatus: 'SUPPORTED_BY_EVIDENCE',
      observedSupportingFacts: [`Event ID ${telemetry.eventId.value} (Log Cleared) kaydedildi.`],
      observedContradictingFacts: [],
      missingEvidenceRequired: ['Onaylı Değişiklik Yönetimi (Change Management) bakım bileti.'],
      nextVerificationSteps: ['Log silinmeden önceki son 1 saatin olaylarını yedeklerden inceleyin.'],
    });
    missingEvidence.push('Log silinmesinden hemen önce yürütülen komutlar ve oturum açma kayıtları.');
  } else {
    // Generic / Unspecified Telemetry
    hypotheses.push({
      id: 'H1',
      title: 'Hipotez 1: Sistem/Uygulama Güvenlik Telemetri Olayı',
      statement: 'Sistem veya güvenlik bileşeni tarafından bir işlem kaydı oluşturulmuştur.',
      type: 'BENIGN_EXPLANATION',
      supportStatus: 'UNPROVEN_POSSIBILITY',
      observedSupportingFacts: provenFacts.length > 0 ? provenFacts.slice(0, 3) : ['Telemetri kaydı mevcut.'],
      observedContradictingFacts: [],
      missingEvidenceRequired: ['Olayın kaynak cihaz türü ve operasyonel bağlamı.'],
      nextVerificationSteps: ['Cihaz log kaynağını ve log format şemasını doğrulayın.'],
    });
    unprovenHypotheses.push('Olayın bir güvenlik ihlali veya saldırı olup olmadığı (Kanıt yetersiz).');
    missingEvidence.push('Olayın üretici kaynağı ve çevreleyen olay kayıtları.');
  }

  return {
    hypotheses,
    provenFacts,
    unprovenHypotheses,
    missingEvidence,
  };
}

/**
 * Builds tailored, evidence-driven investigation steps without applying a rigid 5-step template to all logs.
 */
export function buildTailoredInvestigationSteps(evidence: UniversalEvidence): TailoredInvestigationStep[] {
  const steps: TailoredInvestigationStep[] = [];
  let stepIdx = 1;

  if (!evidence.admissibility.isSecurityEvidence) {
    return [];
  }

  const { actor, sourceEndpoint, destinationEndpoint, outcome, process, telemetry } = evidence;
  const isAuth = outcome.value === 'FAILURE' || outcome.value === 'SUCCESS' || telemetry.eventId.value === 4625 || telemetry.eventId.value === 4624;
  const isProcess = Boolean(process.name.value || process.commandLine.value || telemetry.eventId.value === 4688 || telemetry.eventId.value === 1);
  const isNetworkOrWeb = Boolean(telemetry.httpStatus.value || telemetry.wafAction.value || sourceEndpoint.ip.value);

  // Step 1: Device / Log Source Verification (Only if log source was generic or unconfirmed)
  if (telemetry.eventId.status === 'NOT_PRESENT' && !telemetry.httpStatus.value) {
    steps.push({
      stepNumber: stepIdx++,
      category: 'DEVICE_IDENTIFICATION',
      title: `ADIM ${stepIdx - 1} — Log Üretici ve Cihaz Kaynağı Doğrulaması`,
      objective: 'Bu telemetriyi üreten sistem bileşeninin (Proxy, Özel Uygulama, Güvenlik Duvarı) ve IP adresinin teyidi.',
      targetEntities: { host: destinationEndpoint.host.value, user: actor.value, ip: sourceEndpoint.ip.value },
      logsToCheck: ['Merkezi Syslog / SIEM Log Source Tablosu'],
      fieldsToCheck: ['Log Header', 'Facility', 'App-Name'],
      groundedQuestions: [
        'Bu log formatı kurumun hangi kritik servisine aittir?',
        'Olayın meydana geldiği saatte sistemde planlı bir dağıtım veya bakım var mıydı?',
      ],
      pivotingGuidance: 'Cihazın kimliği netleştiğinde ilgili teknolojiye özel adli inceleme kuralını devreye alın.',
    });
  }

  // Step: Authentication Correlation (Only if auth event is present)
  if (isAuth) {
    steps.push({
      stepNumber: stepIdx++,
      category: 'AUTHENTICATION',
      title: `ADIM ${stepIdx - 1} — Kimlik Doğrulama Zinciri (Authentication History)`,
      objective: `${actor.value ? `"${actor.value}" kullanıcısı` : 'İlgili hesap'} için başarısız denemenin ardından başarılı oturum açma (4624) veya hesap kilitlenmesi gerçekleşmiş mi?`,
      targetEntities: {
        host: destinationEndpoint.host.value,
        user: actor.value,
        ip: sourceEndpoint.ip.value,
        timeWindow: '-30m / +30m',
      },
      logsToCheck: ['Windows Security (Event 4625, 4624, 4672)', 'Linux sshd / auth.log'],
      fieldsToCheck: ['TargetUserName', 'LogonType', 'SubStatus', 'IpAddress'],
      groundedQuestions: [
        `Kullanıcı "${actor.value || 'hedef'}" olağan çalışma saatinde ve zimmetli cihazından mı işlem yapıyor?`,
        'Başarısız oturum açma tekil mi, yoksa onlarca farklı hesap deneniyor mu?',
      ],
      pivotingGuidance: 'Eğer başarısız oturumun ardından aynı IP\'den başarılı 4624 gelmişse derhal yetki yükseltme ve süreç incelemesine geçin.',
    });
  }

  // Step: Process & Execution (Only if process is observed OR auth succeeded with admin privileges)
  if (isProcess) {
    steps.push({
      stepNumber: stepIdx++,
      category: 'PROCESS_EXECUTION',
      title: `ADIM ${stepIdx - 1} — Süreç Ağacı ve Komut Yürütme İncelemesi`,
      objective: `${process.name.value || 'İlgili süreç'} altından hangi çocuk süreçler türedi ve üst süreç (Parent) kim?`,
      targetEntities: {
        host: destinationEndpoint.host.value,
        user: actor.value,
        timeWindow: '+15m',
      },
      logsToCheck: ['Sysmon Event 1 (Process Create)', 'Windows Security Event 4688'],
      fieldsToCheck: ['ParentProcessName', 'CommandLine', 'ProcessId', 'User'],
      groundedQuestions: [
        `Üst süreç meşru bir yönetim aracı mı (SCCM, Tanium), yoksa web sunucusu (w3wp) mu?`,
        'Komut satırında gizleme veya doğrudan indirme parametresi var mı?',
      ],
      pivotingGuidance: 'Web sunucusu altından cmd veya powershell türemişse sistemde Webshell/RCE teyidi yapılmıştır.',
    });
  }

  // Step: Network Egress (If network IP or web event is involved)
  if (isNetworkOrWeb && sourceEndpoint.ip.value) {
    steps.push({
      stepNumber: stepIdx++,
      category: 'NETWORK_LATERAL',
      title: `ADIM ${stepIdx - 1} — Ağ İletişimi ve Dış Bağlantı (Egress) Kontrolü`,
      objective: `${destinationEndpoint.host.value || 'Hedef sistemden'} dışarıya doğru veya ${sourceEndpoint.ip.value} IP'sine doğru oturum açılmış mı?`,
      targetEntities: {
        host: destinationEndpoint.host.value,
        ip: sourceEndpoint.ip.value,
        timeWindow: '+60m',
      },
      logsToCheck: ['Sysmon Event 3 (Network Connection)', 'Firewall Egress Logs', 'NetFlow'],
      fieldsToCheck: ['DestinationIp', 'DestinationPort', 'Initiated', 'BytesSent'],
      groundedQuestions: [
        `Kaynak IP (${sourceEndpoint.ip.value}) Threat Intelligence veri tabanlarında bilinen bir saldırgan IP'si mi?`,
        'Sunucudan dışarıya doğru olağandışı portlara (4444, 1389, 8080) TCP bağlantısı var mı?',
      ],
      pivotingGuidance: 'Bilinmeyen bir dış IP\'ye aktif TCP oturumu tespit edilirse sunucu derhal ağdan izole edilmelidir.',
    });
  }

  // Fallback: If no specialized steps matched, provide tailored fact verification
  if (steps.length === 0) {
    steps.push({
      stepNumber: stepIdx++,
      category: 'AUTHENTICATION',
      title: 'ADIM 1 — Olayın Çevresel Korelasyonu ve Teyidi',
      objective: 'Olay zamanında aynı host ve kullanıcı için üretilen diğer sistem loglarının incelenmesi.',
      targetEntities: { host: destinationEndpoint.host.value, user: actor.value, timeWindow: '-15m / +15m' },
      logsToCheck: ['System.evtx', 'Security.evtx', 'access.log'],
      fieldsToCheck: ['TimeGenerated', 'Host', 'Message'],
      groundedQuestions: ['Bu olay rutin bir sistem faaliyeti midir?'],
      pivotingGuidance: 'Olayın tekil bir anomali mi yoksa bir sekansın parçası mı olduğunu doğrulayın.',
    });
  }

  return steps;
}
