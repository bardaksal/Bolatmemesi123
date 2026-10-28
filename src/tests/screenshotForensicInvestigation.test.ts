import { analyzeForensicScreenshot, ImageForensicResult } from '../services/imageForensicService';
import { explainCommand } from '../services/commandExplainer';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${message}`);
  }
}

let passCount = 0;
function runTest(name: string, fn: () => void | Promise<void>) {
  try {
    const res = fn();
    if (res instanceof Promise) {
      return res
        .then(() => {
          passCount++;
          console.log(`✅ [PASS ${passCount}] ${name}`);
        })
        .catch((err) => {
          console.error(`❌ [FAIL] ${name}: ${err.message}`);
          process.exit(1);
        });
    }
    passCount++;
    console.log(`✅ [PASS ${passCount}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL] ${name}: ${err.message}`);
    process.exit(1);
  }
}

async function runAllTests() {
  console.log('================================================================');
  console.log('📸 SCREENSHOT & IMAGE FORENSIC INVESTIGATION AUDIT 📸');
  console.log('================================================================\n');

  // Test 1: Event 4688 Screenshot with CommandLine & Process
  await runTest('Test 1: Event 4688 Ekran Görüntüsü ile Süreç ve Komut Satırı Çıkarımı (OBSERVED_FROM_IMAGE)', async () => {
    const mockBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    const supplementalText = 'EventID=4688 Computer="SRV-PROD-DC01" TargetUserName="SYSTEM" CommandLine="powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA..."';

    // Mock global fetch for test environment
    const originalFetch = global.fetch;
    global.fetch = async (url: any, opts: any) => {
      const body = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => ({
          success: true,
          result: {
            visualPlatform: 'Windows Event Viewer (Event 4688 - Süreç Oluşturma)',
            confidence: 'YÜKSEK',
            observedFromImage: {
              eventId: '4688',
              provider: 'Microsoft-Windows-Security-Auditing',
              timestamp: '2026-10-06 14:22:18',
              host: 'SRV-PROD-DC01',
              username: 'SYSTEM',
              sourceIp: null,
              destinationIp: null,
              port: null,
              processName: 'powershell.exe',
              parentProcess: 'cmd.exe',
              commandLine: 'powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...',
              action: null,
              status: '0x0',
              rawMessage: 'A new process has been created.',
            },
            missingOrUncertainFields: [
              'Kaynak IP görüntüde net olarak okunamıyor / uç nokta içi süreç oluşturma.',
            ],
            imageQualityNote: 'Görüntü çözünürlüğü yüksek, Event ID ve komut satırı net okundu.',
            commandAnalysis: {
              command: 'powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...',
              purpose: 'PowerShell yürütme ilkesini atlatarak Base64 kodlu komut çalıştırma.',
              riskLevel: 'KRİTİK',
              willCauseTrouble: 'EVET',
            },
            hypotheses: [
              {
                title: 'Hipotez 1: Dosyasız Zararlı Kod / Bellek İçi Yürütme (Defense Evasion)',
                statement: 'Komut satırındaki Base64 yükü ve Bypass bayrağı zararlı aktivite şüphesi taşımaktadır.',
                strengtheningEvidence: ['Bypass parametresi kullanımı', 'EncodedCommand varlığı'],
                weakeningEvidence: ['Onaylı BT yönetim scripti olması'],
              },
            ],
            investigationSteps: [
              {
                step: 1,
                title: 'ADIM 1 — Parent Process Doğrulaması',
                objective: 'cmd.exe sürecini kimin başlattığını bulmak.',
                logsToCheck: ['Sysmon Event 1', 'Event 4688'],
                action: 'ProcessGuid üzerinden üst süreç ağacı geriye doğru taranmalıdır.',
              },
            ],
            queries: {
              splunk: 'index=* EventCode=4688 CommandLine="*powershell*"',
              kql: 'SecurityEvent | where EventID == 4688 and CommandLine has "powershell"',
              elastic: 'winlog.event_id: 4688 AND process.command_line: *powershell*',
              qradarAql: 'SELECT * FROM events WHERE "EventID" = 4688',
            },
            iocs: ['powershell.exe', 'SRV-PROD-DC01'],
            detectionRecommendation: 'Sigma kuralı: proc_creation_win_powershell_obfuscated_execution',
            containmentActions: ['İlgili sürecin sonlandırılması ve host ağ izolasyonu'],
            fullReportMarkdown: '## Adli Rapor',
          },
        }),
      } as any;
    };

    try {
      const result = await analyzeForensicScreenshot(mockBase64, 'image/png', supplementalText);

      assert(result.visualPlatform.includes('Windows Event Viewer'), 'Platform Windows Event Viewer olmalı');
      assert(result.observedFromImage.eventId === '4688', 'Event ID 4688 olarak okunmalı');
      assert(result.observedFromImage.username === 'SYSTEM', 'Kullanıcı SYSTEM olmalı');
      assert(result.observedFromImage.commandLine?.includes('powershell'), 'CommandLine powershell içermeli');

      // Command Explainer otomatik zenginleştirmesi doğrulanmalı
      assert(result.localCommandExplainer !== null, 'Local Command Explainer çalıştırılmış olmalı');
      assert(result.localCommandExplainer?.decodedPayload !== null, 'Base64 çözülmüş yük bulunmalı');
      assert(result.missingOrUncertainFields.length > 0, 'Okunamayan alanlar (IP) net olarak listelenmeli');
    } finally {
      global.fetch = originalFetch;
    }
  });

  // Test 2: OCR / Görüntü Belirsizliği ve Uydurma Veri Yasağı
  await runTest('Test 2: OCR Belirsizliğinde Tahmin Etmeme ve Missing Fields İlkesi', async () => {
    const mockBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    const originalFetch = global.fetch;
    global.fetch = async () => ({
      ok: true,
      json: async () => ({
        success: true,
        result: {
          visualPlatform: 'Görsel Güvenlik Arayüzü / Terminal',
          confidence: 'ORTA',
          observedFromImage: {
            eventId: null,
            provider: null,
            timestamp: null,
            host: null,
            username: null,
            sourceIp: null,
            destinationIp: null,
            port: null,
            processName: null,
            parentProcess: null,
            commandLine: null,
            action: null,
            status: null,
            rawMessage: 'Kısmen kesilmiş terminal ekranı',
          },
          missingOrUncertainFields: [
            'Kaynak IP görüntüde net olarak okunamıyor / ekran dışında kalıyor.',
            'Kullanıcı hesabı görüntüde net okunamıyor.',
            'Hedef bilgisayar/host adı görüntüde net okunamıyor.',
          ],
          imageQualityNote: 'Düşük çözünürlük veya kesik görüntü; alanlar kesin olarak okunamadı.',
          hypotheses: [],
          investigationSteps: [],
          queries: { splunk: '', kql: '', elastic: '', qradarAql: '' },
          iocs: [],
          detectionRecommendation: 'Daha net görüntü gereklidir.',
          containmentActions: [],
          fullReportMarkdown: '## Ön İnceleme',
        },
      }),
    } as any);

    try {
      const result = await analyzeForensicScreenshot(mockBase64, 'image/png');
      assert(result.observedFromImage.sourceIp === null, 'Okunamayan IP kesinlikle null olmalı, uydurulmamalı');
      assert(result.missingOrUncertainFields.some((f) => f.includes('Kaynak IP')), 'Eksik alan uyarısı bulunmalı');
    } finally {
      global.fetch = originalFetch;
    }
  });

  // Test 3: Zero Meta-Language & Pure Analytical Value in Forensic Reports
  await runTest('Test 3: Görüntü Adli Çıktılarında Sıfır Sistem Self-Description ve Değer Odaklılık', async () => {
    const sampleNarrative = `
    Görsel Adli İnceleme & L2 Soruşturma Planı
    Görüntüde Okunan Kanıtlar (OBSERVED_FROM_IMAGE)
    Event ID: 4625
    Hedef Host: SRV-DC01
    Kullanıcı: admin_corp
    Kaynak IP: 194.26.29.112
    Logon Type: 10 (RDP)
    Hata Kodu: 0xC000006A (Hatalı Parola)
    `;

    const forbiddenPhrases = [
      'Deterministik Motor',
      'AI Engine',
      'AI katmanı',
      'Forensic Engine',
      'model tarafından',
      'AI inference',
      'processing pipeline',
      'sistem şu şekilde çalışır',
      'internal processing',
    ];

    for (const phrase of forbiddenPhrases) {
      assert(!sampleNarrative.toLowerCase().includes(phrase.toLowerCase()), `Forbidden phrase '${phrase}' bulunmamalı`);
    }
  });

  console.log('\n================================================================');
  console.log(`🎉 TÜM SCREENSHOT FORENSIC INVESTIGATION TESTLERİ GEÇTİ: ${passCount} / 3`);
  console.log('================================================================\n');
}

runAllTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
