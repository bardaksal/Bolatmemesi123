import assert from 'assert';
import {
  generateAnalysisFirstReport,
  renderAnalysisFirstMarkdown,
} from '../services/analysisFirstForensicReporting';

console.log('================================================================');
console.log('PHASE 3.7 TEST: Analyst-First Forensic Interpretation Validation');
console.log('================================================================');

// Scenario 1: F5 / WAF with multiple blocked requests (Path traversal, SQLi, sensitive endpoints)
const multiRequestWafResult = {
  evidenceSource: 'IMAGE_PIXEL' as const,
  platformFamily: 'F5_WAF' as const,
  verdict: 'BLOCKED_ATTACK_ATTEMPT' as const,
  confidence: 94,
  observedTelemetry: {
    eventId: null,
    provider: 'F5 BIG-IP ASM / WAF',
    timestamp: '2025-01-15T14:22:01Z',
    host: 'edge-waf-01.corp.internal',
    username: null,
    sourceIp: '198.51.100.42',
    destinationIp: '10.0.4.15',
    destinationPort: 443,
    processName: null,
    commandLine: null,
    rawText: 'F5 ASM Event Log\nGET /etc/passwd HTTP/1.1 Blocked 198.51.100.42\nPOST /api/v1/auth/login?id=1%20UNION%20SELECT HTTP/1.1 Blocked 198.51.100.42\nPOST /druid/coordinator/v1/lookups/config HTTP/1.1 Blocked 198.51.100.42\nGET /..%2F..%2Fwinnt/system32/cmd.exe HTTP/1.1 Blocked 198.51.100.42\nPOST /actuator/gateway/routes HTTP/1.1 Blocked 198.51.100.42',
    action: 'BLOCKED',
    outcome: 'BLOCKED',
  },
  ocrEvidenceLines: [
    { line: 1, text: 'GET /etc/passwd HTTP/1.1 - Status: Blocked' },
    { line: 2, text: 'POST /api/v1/auth/login?id=1 UNION SELECT - Status: Blocked' },
    { line: 3, text: 'POST /druid/coordinator/v1/lookups/config - Status: Blocked' },
    { line: 4, text: 'GET /..%2F..%2Fwinnt/system32/cmd.exe - Status: Blocked' },
    { line: 5, text: 'POST /actuator/gateway/routes - Status: Blocked' },
  ],
  investigationQuestions: {
    whatIsSeen: 'F5 WAF ekranında aynı kaynak IP adresinden gelen çok sayıda HTTP isteği görülüyor. İsteklerin tamamı blocked olarak işaretlenmiş.',
    whatDoesItMean: 'Saldırgan hedef web sunucusundaki açıkları tespit etmek amacıyla otomatik tarama gerçekleştirmektedir.',
    whyDoesItMatter: 'Saldırı girişimi engellenmiş olmakla birlikte hedef sistemlerin haritalandırıldığını gösterir.',
    whatIsProven: ['Kaynak IP (198.51.100.42) tarafından hedef sisteme HTTP istekleri gönderildiği.', 'WAF tarafından isteklerin engellendiği.'],
    whatIsNotProven: ['Hedef sistemde kod/komut çalıştırıldığı', 'Sunucunun ele geçirildiği', 'Hassas dosyaların okunduğu', 'Veri sızdırıldığı'],
    whatToDoNext: ['Kaynak IP adresini sınır güvenlik duvarında engelleyin.', 'SIEM üzerinden kaynak IP aktivitesini korele edin.'],
  },
  provenance: {
    imageHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    pixelCount: 1920000,
    extractionMethod: 'IMAGE_PIXEL' as const,
  },
};

const report1 = generateAnalysisFirstReport(multiRequestWafResult);

// Check 1: Must identify ENGELLENMİŞ SALDIRI GİRİŞİMİ
console.log('Verdict 1:', report1.securityVerdict);
assert.strictEqual(report1.securityVerdict, 'ENGELLENMİŞ SALDIRI GİRİŞİMİ');

// Check 2: Executive summary must clearly describe the WAF findings
console.log('Summary 1 snippet:\n', report1.executiveSummary);
assert.ok(report1.executiveSummary.includes('F5 WAF ekranında aynı kaynak IP'), 'Must mention F5 WAF multiple requests from same IP');
assert.ok(report1.executiveSummary.includes('/etc/passwd') || report1.executiveSummary.includes('path traversal'), 'Must mention observed attack patterns');
assert.ok(report1.executiveSummary.includes('ENGELLENMİŞ SALDIRI GİRİŞİMİ'), 'Summary must declare ENGELLENMİŞ SALDIRI GİRİŞİMİ');

// Check 3: What is NOT proven must contain unproven aspects
assert.ok(report1.unprovenAspects.some(u => u.includes('komut çalıştırıldığını') || u.includes('ele geçirildiğini')));
assert.ok(report1.unprovenAspects.some(u => u.includes('dosyanın') || u.includes('okunduğunu')));
assert.ok(report1.unprovenAspects.some(u => u.includes('sızdırıldığını') || u.includes('veri')));

// Check 4: Anti-jargon verification in report text
const md1 = renderAnalysisFirstMarkdown(report1);
const forbiddenWords = [
  'piksel analizi yapıldı',
  'Tesseract çalıştı',
  'IMAGE_PIXEL',
  'yerel OCR motoru',
  'adli zincir mühürlendi',
  'kanıt hash\'i',
  'görsel baytları',
];
for (const word of forbiddenWords) {
  assert.ok(!md1.toLowerCase().includes(word.toLowerCase()), `Markdown report leaked system jargon: "${word}"`);
}

// Scenario 2: Single Apache Druid blocked attack
const singleDruidResult = {
  evidenceSource: 'IMAGE_PIXEL' as const,
  platformFamily: 'F5_WAF' as const,
  verdict: 'BLOCKED_ATTACK_ATTEMPT' as const,
  confidence: 90,
  observedTelemetry: {
    eventId: null,
    provider: 'F5 BIG-IP ASM',
    timestamp: '2025-01-15T10:00:00Z',
    host: 'waf-01',
    username: null,
    sourceIp: '203.0.113.19',
    destinationIp: '10.0.2.1',
    destinationPort: 443,
    processName: null,
    commandLine: 'POST /druid/coordinator/v1/lookups/config HTTP/1.1',
    rawText: 'F5 ASM Blocked Event POST /druid/coordinator/v1/lookups/config',
    action: 'BLOCKED',
    outcome: 'BLOCKED',
  },
  ocrEvidenceLines: [
    { line: 1, text: 'POST /druid/coordinator/v1/lookups/config HTTP/1.1 - Blocked' },
  ],
  investigationQuestions: {
    whatIsSeen: 'F5 WAF ekranında Apache Druid RCE endpointine yönelik tekil POST isteği görülüyor.',
    whatDoesItMean: 'Saldırgan Apache Druid zafiyetini tetiklemeye çalışmıştır.',
    whyDoesItMatter: 'WAF isteği engellediği için saldırı engellenmiştir.',
    whatIsProven: ['POST isteği gönderildiği', 'İsteğin engellendiği'],
    whatIsNotProven: ['Komut çalıştırıldığı', 'Sunucunun ele geçirildiği'],
    whatToDoNext: ['Kaynak IP incelenmeli'],
  },
  provenance: {
    imageHash: 'abc',
    pixelCount: 1000,
    extractionMethod: 'IMAGE_PIXEL' as const,
  },
};

const report2 = generateAnalysisFirstReport(singleDruidResult);
assert.strictEqual(report2.securityVerdict, 'ENGELLENMİŞ SALDIRI GİRİŞİMİ');
assert.ok(report2.executiveSummary.includes('ENGELLENMİŞ SALDIRI GİRİŞİMİ'));
assert.ok(report2.unprovenAspects.some(u => u.includes('komut çalıştırıldığını')));

console.log('✅ ALL PHASE 3.7 TESTS PASSED SUCCESSFULLY!');
