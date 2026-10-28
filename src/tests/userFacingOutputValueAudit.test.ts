import { explainCommand } from '../services/commandExplainer';
import {
  compareSecurityPeriods,
  generatePolicyEffectivenessHtmlReport,
} from '../services/policyComparisonEngine';
import { generatePolicyComparisonExcelWorkbook } from '../services/policyExcelReportGenerator';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${message}`);
  }
}

let passCount = 0;
function runAudit(name: string, fn: () => void) {
  try {
    fn();
    passCount++;
    console.log(`✅ [PASS ${passCount}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL] ${name}: ${err.message}`);
    process.exit(1);
  }
}

console.log('================================================================');
console.log('🎯 USER-FACING OUTPUT VALUE & ZERO SELF-DESCRIPTION AUDIT 🎯');
console.log('================================================================\n');

const FORBIDDEN_RENDERED_META_STRINGS = [
  'Grok',
  'Deterministik Çok Katmanlı Adli Motor',
  'Deterministik Adli Motor',
  'Forensic Engine',
  'AI Layer',
  'AI Engine',
  'Analysis Pipeline',
  'Processing Pipeline',
  'Metodoloji ve Adli Sınırlamalar',
  'Forensic Methodology',
  'Forensic Limitations',
  'Forensic Caveat',
  'Adli Metodoloji Uyarısı',
  'Sistem nasıl çalışıyor',
  'Analiz nasıl gerçekleştirildi',
  'Bu sonuç nasıl üretildi',
  'AI tarafından oluşturuldu',
  'Gemini tarafından analiz edildi',
];

function assertNoForbiddenStrings(renderedText: string, contextName: string) {
  for (const forbidden of FORBIDDEN_RENDERED_META_STRINGS) {
    const hasForbidden = renderedText.toLowerCase().includes(forbidden.toLowerCase());
    assert(
      !hasForbidden,
      `${contextName} çıktısı yasaklı meta/self-description ifadesini içermemelidir: "${forbidden}"`
    );
  }
}

// -----------------------------------------------------------------------------
// SENARYO 1: vssadmin delete shadows /all /quiet
// -----------------------------------------------------------------------------
runAudit('Senaryo 1: vssadmin delete shadows /all /quiet rendered markdown analizi', () => {
  const res = explainCommand('vssadmin.exe delete shadows /all /quiet');
  
  // Rendered output checks
  assertNoForbiddenStrings(res.fullNarrativeMarkdown, 'Senaryo 1 Markdown');
  assertNoForbiddenStrings(res.summary, 'Senaryo 1 Summary');
  assertNoForbiddenStrings(res.purpose, 'Senaryo 1 Purpose');
  assertNoForbiddenStrings(res.willCauseTroubleText, 'Senaryo 1 Trouble Text');

  // Value checks
  assert(res.category.includes('Volume Shadow Copy') || res.category.includes('Gölge Kopya'), 'Kategori doğru olmalı');
  assert(res.riskLevel === 'KRİTİK', 'Risk seviyesi KRİTİK olmalı');
  assert(res.willCauseTrouble === 'EVET_YUKSEK', 'Sorun çıkarma EVET_YUKSEK olmalı');
  assert(res.fullNarrativeMarkdown.includes('## 📌 1. Bu Komut Nedir ve Temel Amacı Ne İşe Yarar?'), 'Bölüm 1 bulunmalı');
  assert(res.fullNarrativeMarkdown.includes('## 💥 4. Bu Komut Çalışırsa Sistemde Ne Sorun Çıkartır?'), 'Bölüm 4 bulunmalı');
});

// -----------------------------------------------------------------------------
// SENARYO 2: systemctl status nginx
// -----------------------------------------------------------------------------
runAudit('Senaryo 2: systemctl status nginx rutin servis kontrolü (Gereksiz alarm yok)', () => {
  const res = explainCommand('systemctl status nginx');

  // Rendered output checks
  assertNoForbiddenStrings(res.fullNarrativeMarkdown, 'Senaryo 2 Markdown');

  // Value checks
  assert(res.riskLevel === 'BİLGİ', 'Rutin servis sorgusu BİLGİ risk olmalı');
  assert(res.willCauseTrouble === 'HAYIR_GUVENLI', 'Rutin sorgu güvenli olmalı');
  assert(!res.fullNarrativeMarkdown.includes('saldırgan'), 'Rutin komut abartılı saldırgan alarmı içermemeli');
  assert(res.fullNarrativeMarkdown.includes('nginx'), 'nginx servis kontrolünü anlatmalı');
});

// -----------------------------------------------------------------------------
// SENARYO 3: WAF Before/After Karşılaştırması & HTML / Text Raporu
// -----------------------------------------------------------------------------
runAudit('Senaryo 3: WAF Before/After çıktıları doğrudan Policy → Event → Action sunmalı', () => {
  const linesA = Array(50).fill('date=2026-08-01 host=srv01 action="alert" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"').join('\n');
  const linesB = Array(50).fill('date=2026-09-01 host=srv01 action="deny" attack="SQL Injection" signature_id="OWASP-942-SQLI" http_url="/login"').join('\n');

  const compRes = compareSecurityPeriods(
    [{ name: 'periodA.log', content: linesA }],
    [{ name: 'periodB.log', content: linesB }]
  );

  // Key findings, footnotes, executive summary checks
  const joinedNarrative = [
    ...compRes.keyFindings,
    ...compRes.footnotes,
    compRes.executiveSummary,
  ].join(' \n ');

  assertNoForbiddenStrings(joinedNarrative, 'WAF Rapor Metinleri');

  // HTML Export checks
  const html = generatePolicyEffectivenessHtmlReport(compRes, 'Test Kurum', 'L3 Analist');
  assertNoForbiddenStrings(html, 'WAF HTML Raporu');
  assert(!html.includes('Metodoloji ve Adli Sınırlamalar'), 'HTML raporunda metodoloji bölümü olmamalı');
  assert(html.includes('1. 📋 Yönetici Özeti'), 'Yönetici özeti bulunmalı');
  assert(html.includes('2. 🛡️ Policy Before / After'), 'Before/After bölümü bulunmalı');
});

// -----------------------------------------------------------------------------
// SENARYO 4: Action alanı olmayan F5 Excel yüklenir (Metodoloji değil veri durumu)
// -----------------------------------------------------------------------------
runAudit('Senaryo 4: Action alanı olmayan F5 verisinde doğrudan veri yokluğu belirtilmeli', () => {
  // Aggregate data with Response code but no Action column
  const linesA = 'Event,Count,Response,Policy\nSQL Injection,100,500,WebPolicy\n';
  const linesB = 'Event,Count,Response,Policy\nSQL Injection,120,403,WebPolicy\n';

  const compRes = compareSecurityPeriods(
    [{ name: 'f5_A.csv', content: linesA }],
    [{ name: 'f5_B.csv', content: linesB }]
  );

  const findingsText = compRes.keyFindings.join(' ');
  assertNoForbiddenStrings(findingsText, 'Action-less Findings');

  // Must NOT have wordy methodology excuse
  assert(!findingsText.includes('Adli metodoloji gereğince'), 'Metodoloji mazereti olmamalı');
  assert(findingsText.includes('Action kolonu bulunmuyor') || findingsText.includes('Action alanı bulunmuyor'), 'Faktüel bilgi verilmeli');
});

// -----------------------------------------------------------------------------
// SENARYO 5: Backend telemetrisi yokken doğrudan veri durumu söylenmeli
// -----------------------------------------------------------------------------
runAudit('Senaryo 5: Backend logu yokken uzun metodoloji değil direkt durum söylenmeli', () => {
  const linesA = 'date=2026-08-01 host=srv01 action="alert" attack="XSS" signature_id="OWASP-941-XSS" http_url="/search"';
  const linesB = 'date=2026-09-01 host=srv01 action="deny" attack="XSS" signature_id="OWASP-941-XSS" http_url="/search"';

  const compRes = compareSecurityPeriods(
    [{ name: 'pA.log', content: linesA }],
    [{ name: 'pB.log', content: linesB }]
  );

  const backendFinding = compRes.keyFindings.find((f) => f.includes('5xx') || f.includes('Backend'));
  assert(!!backendFinding, 'Backend finding mevcut olmalı');
  assertNoForbiddenStrings(backendFinding!, 'Backend Finding');
  assert(backendFinding!.includes('Backend telemetrisi bulunmadığı için 5xx etkisi hesaplanamadı'), 'Kısa ve net olmalı');
});

// -----------------------------------------------------------------------------
// SENARYO 6: Excel Workbook Export Metinleri
// -----------------------------------------------------------------------------
runAudit('Senaryo 6: Excel Export sayfaları ve başlıkları temiz olmalı', () => {
  const linesA = 'date=2026-08-01 host=srv01 action="alert" attack="SQLi" signature_id="SIG-1" http_url="/api"';
  const linesB = 'date=2026-09-01 host=srv01 action="deny" attack="SQLi" signature_id="SIG-1" http_url="/api"';

  const compRes = compareSecurityPeriods(
    [{ name: 'pA.log', content: linesA }],
    [{ name: 'pB.log', content: linesB }]
  );

  const wb = generatePolicyComparisonExcelWorkbook(compRes);
  const sheetNames = wb.SheetNames;
  
  sheetNames.forEach((sheet) => {
    assert(!sheet.includes('Metodoloji'), `Sheet adı metodoloji içermemeli: ${sheet}`);
    assert(!sheet.includes('Pipeline'), `Sheet adı pipeline içermemeli: ${sheet}`);
  });
});

console.log('\n================================================================');
console.log(`🎉 TÜM KULLANICI ÇIKTISI DEĞER ODAKLI DENETİMLERİ GEÇTİ: ${passCount} / 6`);
console.log('================================================================\n');
