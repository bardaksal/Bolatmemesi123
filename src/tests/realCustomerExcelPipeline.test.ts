import * as XLSX from 'xlsx';
import {
  compareSecurityPeriods,
  buildPolicyComparisonWorkbook,
} from '../services/policyComparisonEngine';
import { inspectAndConvertExcel } from '../services/excelConverter';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    throw new Error(`[FAIL] ${msg}`);
  }
}

console.log('=== REAL CUSTOMER F5 EXCEL END-TO-END PIPELINE TEST ===\n');

// 1. Build Period A (Before) Excel Buffer in exact customer format
const headersA = [
  'Policy Name (custom)',
  'Threat Type (custom)',
  'Event Name',
  'Log Source',
  'Response',
  'Destination',
  'Destination Port',
  'Start Time',
  'Low Level',
  'Count',
];

const dataA = [
  headersA,
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Information Leakage',
    'Data Guard: Information leakage',
    'F5ASM @10.54.207.1',
    '500',
    '10.54.207.12',
    443,
    'Aug 10, 2026 10:14:00',
    'Information',
    4092,
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Buffer Overflow',
    'Illegal POST Data Length',
    'F5ASM @10.54.207.1',
    '200',
    '10.54.207.12',
    443,
    'Aug 11, 2026 11:20:00',
    'Invalid Command',
    205,
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'HTTP Parser Attack',
    'Illegal Request Length',
    'F5ASM @10.54.207.1',
    '403',
    '10.54.207.12',
    443,
    'Aug 12, 2026 12:30:00',
    'Unknown',
    124,
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Detection Evasion',
    'Evasion Technique Detected',
    'F5ASM @10.54.207.1',
    '502',
    '10.54.207.12',
    443,
    'Aug 13, 2026 14:00:00',
    'Compliant',
    96,
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Non-browser Client',
    'Illegal Method',
    'F5ASM @10.54.207.1',
    '400',
    '10.54.207.12',
    443,
    'Aug 14, 2026 15:00:00',
    'Compliant',
    38,
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Information Leakage',
    'Illegal HTTP Response Status',
    'F5ASM @10.54.207.1',
    '416',
    '10.54.207.12',
    443,
    'Aug 15, 2026 16:00:00',
    'Information',
    18,
  ],
];

const wbA = XLSX.utils.book_new();
const wsA = XLSX.utils.aoa_to_sheet(dataA);
XLSX.utils.book_append_sheet(wbA, wsA, 'F5_Security_Report');
const bufferA = XLSX.write(wbA, { bookType: 'xlsx', type: 'array' });

// 2. Build Period B (After) Excel Buffer with 11th Action column (Action: Block / Alert)
const headersB = [
  'Policy Name (custom)',
  'Threat Type (custom)',
  'Event Name',
  'Log Source',
  'Response',
  'Destination',
  'Destination Port',
  'Start Time',
  'Low Level',
  'Count',
  'Action',
];

const dataB = [
  headersB,
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Information Leakage',
    'Data Guard: Information leakage',
    'F5ASM @10.54.207.1',
    '500',
    '10.54.207.12',
    443,
    'Sep 10, 2026 10:14:00',
    'Information',
    3,
    'Block',
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Buffer Overflow',
    'Illegal POST Data Length',
    'F5ASM @10.54.207.1',
    '403',
    '10.54.207.12',
    443,
    'Sep 11, 2026 11:20:00',
    'Invalid Command',
    2,
    'Block',
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'HTTP Parser Attack',
    'Illegal Request Length',
    'F5ASM @10.54.207.1',
    '403',
    '10.54.207.12',
    443,
    'Sep 12, 2026 12:30:00',
    'Unknown',
    2,
    'Block',
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Detection Evasion',
    'Evasion Technique Detected',
    'F5ASM @10.54.207.1',
    '403',
    '10.54.207.12',
    443,
    'Sep 13, 2026 14:00:00',
    'Compliant',
    2,
    'Block',
  ],
  [
    '/Common/waf_appronassets.havas.net_dmz_https',
    'Non-browser Client',
    'Illegal Method',
    'F5ASM @10.54.207.1',
    '400',
    '10.54.207.12',
    443,
    'Sep 14, 2026 15:00:00',
    'Compliant',
    3,
    'Alert',
  ],
  // Note: 'Illegal HTTP Response Status' is omitted in Period B -> Disappeared / Not Observed
];

const wbB = XLSX.utils.book_new();
const wsB = XLSX.utils.aoa_to_sheet(dataB);
XLSX.utils.book_append_sheet(wbB, wsB, 'F5_Security_Report');
const bufferB = XLSX.write(wbB, { bookType: 'xlsx', type: 'array' });

// ==========================================
// TEST STEP 1: Excel Conversion & Metadata Inspection
// ==========================================
console.log('--- ADIM 1: Excel Okuma ve Şema Denetimi ---');
const inspA = inspectAndConvertExcel(bufferA, 'f5_agustos_2026.xlsx');
const inspB = inspectAndConvertExcel(bufferB, 'f5_eylul_2026.xlsx');

assert(inspA.primarySheet === 'F5_Security_Report', `Sheet name should be F5_Security_Report, got ${inspA.primarySheet}`);
assert(inspA.csvContent.length > 50, 'CSV content should not be empty');
assert(inspA.csvContent.includes('Policy Name (custom)'), 'CSV should preserve headers');
console.log('✅ ADIM 1 Başarılı: Gerçek Excel dosyaları binary ArrayBuffer üzerinden ayrıştırıldı.');

// ==========================================
// TEST STEP 2: Comparison Engine Processing with Policy Assumption / Real Action
// ==========================================
console.log('--- ADIM 2: Karşılaştırma Motoru ve Teşhis Doğrulaması ---');
const res = compareSecurityPeriods(
  [{ name: 'f5_agustos_2026.xlsx', content: inspA.csvContent, sheetName: inspA.primarySheet }],
  [{ name: 'f5_eylul_2026.xlsx', content: inspB.csvContent, sheetName: inspB.primarySheet }],
  'Ağustos 2026 (Alert / Kural Öncesi)',
  'Eylül 2026 (Block / Kural Sonrası)',
  { policyAssumptionMode: true }
);

// Diagnostic Checks
assert(res.diagnostics.periodA.length === 1, 'Period A should have 1 file diagnostic');
const diagA = res.diagnostics.periodA[0];
assert(diagA.detectedFormat === 'F5_AGGREGATED_REPORT', `Format must be F5_AGGREGATED_REPORT, got ${diagA.detectedFormat}`);
assert(diagA.isF5SchemaDetected === true, 'F5 schema must be detected as true');
assert(diagA.parsedRowsCount === 6, `Period A parsed rows must be 6, got ${diagA.parsedRowsCount}`);
assert(diagA.aggregateObservationCount === 4573, `Period A SUM(Count) must be 4573, got ${diagA.aggregateObservationCount}`);
assert(diagA.columnStatusList && diagA.columnStatusList.filter((c) => c.present).length === 10, 'All 10 customer F5 columns must be detected');

const diagB = res.diagnostics.periodB[0];
assert(diagB.parsedRowsCount === 5, `Period B parsed rows must be 5, got ${diagB.parsedRowsCount}`);
assert(diagB.aggregateObservationCount === 12, `Period B SUM(Count) must be 12, got ${diagB.aggregateObservationCount}`);
console.log('✅ ADIM 2 Başarılı: File Diagnostic, 10-kolon tespiti ve SUM(Count) aggregate değerleri doğrulandı.');

// ==========================================
// TEST STEP 3: Action, Block Rate and Metric Calculations
// ==========================================
console.log('--- ADIM 3: WAF Block Oranı ve Aksiyon Analizi ---');
assert(res.actionDataAvailable === true, 'Action data must be available');
assert(res.periodB.blockedRequests === 9, `Period B blocked requests must be 9 (3+2+2+2), got ${res.periodB.blockedRequests}`);
assert(res.periodB.blockRate === 75.0, `Period B block rate must be 75.0% (9 / 12), got ${res.periodB.blockRate}`);
assert(res.blockRateDelta === 75.0, `Block rate delta must be +75.0 percentage points, got ${res.blockRateDelta}`);

// Signature Impact Metrics
assert(res.signatureImpacts.length === 6, `Total examined rules/signatures must be 6, got ${res.signatureImpacts.length}`);
assert(res.continuingSignatures.blockObserved.length === 4, `Block observed signatures must be 4, got ${res.continuingSignatures.blockObserved.length}`);
assert(res.continuingSignatures.alertContinuing.length === 1, `Alert continuing signatures must be 1, got ${res.continuingSignatures.alertContinuing.length}`);
assert(res.notObservedSignatures.length === 1, `Not observed signatures must be 1, got ${res.notObservedSignatures.length}`);
console.log('✅ ADIM 3 Başarılı: WAF Block Oranı: %0 -> %75.0 (+75.0 yüzde puan) ve 4 BLOCK, 1 ALERT, 1 Gözlenmedi kural dağılımı doğrulandı.');

// ==========================================
// TEST STEP 4: Executive Summary Text Pattern Verification
// ==========================================
console.log('--- ADIM 4: Dinamik Yönetici Özeti Doğrulaması ---');
console.log('Üretilen Yönetici Özeti:\n' + res.executiveSummary + '\n');
assert(res.executiveSummary.includes('%0'), 'Summary must contain %0');
assert(res.executiveSummary.includes('%75'), 'Summary must contain %75');
assert(res.executiveSummary.includes('9 isteğe BLOCK'), 'Summary must mention 9 isteğe BLOCK');
assert(res.executiveSummary.includes('4 adedinde BLOCK'), 'Summary must mention 4 adedinde BLOCK');
assert(
  res.executiveSummary.includes("After dönemindeki kaynak F5 Excel'inde gözlenmemiştir") ||
  res.executiveSummary.includes("sonraki dönemde loglarda gözlenmemiştir"),
  "Summary must mention not observed count accurately"
);
console.log('✅ ADIM 4 Başarılı: Dinamik metin kullanıcının talep ettiği adli formatla birebir uyumlu üretildi.');

// ==========================================
// TEST STEP 5: Excel Export Workbook (5 Sayfalı Excel Raporu)
// ==========================================
console.log('--- ADIM 5: 5 Sayfalı Excel Raporu (.xlsx) Üretimi ---');
const exportWb = buildPolicyComparisonWorkbook(res);
assert(exportWb.SheetNames.includes('Yonetici_Ozeti_ve_KPI'), 'Workbook must include Yonetici_Ozeti_ve_KPI');
assert(exportWb.SheetNames.includes('Before_After_Matrisi'), 'Workbook must include Before_After_Matrisi');
assert(exportWb.SheetNames.includes('Devam_Eden_ve_Bloklananlar'), 'Workbook must include Devam_Eden_ve_Bloklananlar');
assert(exportWb.SheetNames.includes('Gozlenmeyen_ve_Yeni_Olaylar'), 'Workbook must include Gozlenmeyen_ve_Yeni_Olaylar');
assert(exportWb.SheetNames.includes('Sema_ve_Dosya_Diagnostik'), 'Workbook must include Sema_ve_Dosya_Diagnostik');

// Verify Sheet 2 has 15 columns (14 standard + forensic note)
const matrixSheet = exportWb.Sheets['Before_After_Matrisi'];
const matrixData = XLSX.utils.sheet_to_json(matrixSheet, { header: 1 }) as string[][];
const headerRow = matrixData[0];
assert(headerRow.length === 15, `Matrix sheet must have 15 columns, got ${headerRow.length}`);
assert(headerRow[0] === 'Policy Name', 'Column 0 must be Policy Name');
assert(headerRow[1] === 'Rule / Signature / Event', 'Column 1 must be Rule / Signature / Event');
assert(headerRow[2] === 'Threat Type', 'Column 2 must be Threat Type');
assert(headerRow[3] === 'Log Source', 'Column 3 must be Log Source');
assert(headerRow[4] === 'Before Count', 'Column 4 must be Before Count');
assert(headerRow[5] === 'After Count', 'Column 5 must be After Count');
assert(headerRow[6] === 'Before ALERT', 'Column 6 must be Before ALERT');
assert(headerRow[7] === 'Before BLOCK', 'Column 7 must be Before BLOCK');
assert(headerRow[8] === 'After ALERT', 'Column 8 must be After ALERT');
assert(headerRow[9] === 'After BLOCK', 'Column 9 must be After BLOCK');
assert(headerRow[10] === 'Action Değişimi', 'Column 10 must be Action Değişimi');
assert(headerRow[11] === 'Durum (Status)', 'Column 11 must be Durum (Status)');
assert(headerRow[12] === 'Fark (Delta)', 'Column 12 must be Fark (Delta)');
assert(headerRow[13] === 'Değişim (%)', 'Column 13 must be Değişim (%)');
console.log('✅ ADIM 5 Başarılı: 5 Sayfalı Excel Raporu ve 14-Kolonlu Before/After Matrisi eksiksiz oluşturuldu.');

console.log('\n============================================================');
console.log('TÜM GERÇEK MÜŞTERİ EXCEL BORU HATTI TESTLERİ BAŞARIYLA GEÇTİ!');
console.log('============================================================\n');
