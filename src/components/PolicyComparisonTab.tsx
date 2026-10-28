import React, { useState } from 'react';
import {
  ShieldCheck,
  TrendingUp,
  HardDrive,
  Download,
  AlertTriangle,
  CheckCircle2,
  Zap,
  Activity,
  Layers,
  Sparkles,
  Server,
  FileSpreadsheet,
  ChevronDown,
  ChevronUp,
  Search,
  ArrowRightLeft,
  Filter,
  BarChart3,
  PieChart as PieChartIcon,
  Calendar,
  Plus,
  Trash2,
  Clock,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
} from 'recharts';
import {
  compareSecurityPeriods,
  compareMultipleSecurityPeriods,
  loadSampleWafComparisonScenario,
  generatePolicyEffectivenessHtmlReport,
  exportPolicyComparisonToExcel,
  exportMultiPeriodComparisonToExcel,
} from '../services/policyComparisonEngine';
import {
  isExcelFile,
  convertExcelBufferToCsv,
  inspectAndConvertExcel,
} from '../services/excelConverter';
import { FileInput } from '../services/socEngine';
import {
  PolicyComparisonResult,
  PeriodParsingDiagnostic,
  MultiPeriodComparisonResult,
} from '../types';

interface PolicyComparisonTabProps {
  availableUploadedFiles?: Array<{ name: string; content: string }>;
}

export const PolicyComparisonTab: React.FC<PolicyComparisonTabProps> = ({
  availableUploadedFiles = [],
}) => {
  const [inputMode, setInputMode] = useState<'paste' | 'files' | 'select'>('paste');
  // Comparison Architecture Mode: 'pairwise' (Before-After 2 Dönem) or 'multi' (Çoklu Geçmiş Dönem / Trend)
  const [activeComparisonMode, setActiveComparisonMode] = useState<'pairwise' | 'multi'>('pairwise');

  // Multi-Period State (3+ Geçmiş Dosya)
  const [multiPeriodFiles, setMultiPeriodFiles] = useState<Array<{ id: string; label: string; file?: FileInput }>>([
    { id: '1', label: 'Dönem 1 (Örn: Temmuz)' },
    { id: '2', label: 'Dönem 2 (Örn: Ağustos)' },
    { id: '3', label: 'Dönem 3 (Örn: Eylül)' },
  ]);
  const [multiResult, setMultiResult] = useState<MultiPeriodComparisonResult | null>(null);
  const [isComparingMulti, setIsComparingMulti] = useState<boolean>(false);

  // Period labels
  const [labelA, setLabelA] = useState<string>('Ağustos 2026 (Alert / Kural Öncesi)');
  const [labelB, setLabelB] = useState<string>('Eylül 2026 (Block / Kural Sonrası)');

  // Paste mode text
  const [pasteA, setPasteA] = useState<string>('');
  const [pasteB, setPasteB] = useState<string>('');

  // File mode inputs
  const [fileA, setFileA] = useState<FileInput | null>(null);
  const [fileB, setFileB] = useState<FileInput | null>(null);

  // Selected existing files
  const [selectedFileNameA, setSelectedFileNameA] = useState<string>('');
  const [selectedFileNameB, setSelectedFileNameB] = useState<string>('');

  // Optional Policy Assumption Toggle
  const [policyAssumptionMode, setPolicyAssumptionMode] = useState<boolean>(false);

  // Table Search and Status Filter
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Result state
  const [result, setResult] = useState<PolicyComparisonResult | null>(null);
  const [isComparing, setIsComparing] = useState<boolean>(false);
  const [showDiagnostics, setShowDiagnostics] = useState<boolean>(false);

  // Load sample demo scenario
  const handleLoadDemoScenario = () => {
    const demo = loadSampleWafComparisonScenario();
    setLabelA(demo.periodALabel);
    setLabelB(demo.periodBLabel);
    setPasteA(demo.periodAFiles[0].content);
    setPasteB(demo.periodBFiles[0].content);
    setInputMode('paste');

    const res = compareSecurityPeriods(
      demo.periodAFiles,
      demo.periodBFiles,
      demo.periodALabel,
      demo.periodBLabel,
      { policyAssumptionMode }
    );
    setResult(res);
    setShowDiagnostics(false);
  };

  const handleSwapPeriods = () => {
    const prevLabelA = labelA;
    const prevLabelB = labelB;
    const prevPasteA = pasteA;
    const prevPasteB = pasteB;
    const prevFileA = fileA;
    const prevFileB = fileB;
    const prevSelectedA = selectedFileNameA;
    const prevSelectedB = selectedFileNameB;

    setLabelA(prevLabelB);
    setLabelB(prevLabelA);
    setPasteA(prevPasteB);
    setPasteB(prevPasteA);
    setFileA(prevFileB);
    setFileB(prevFileA);
    setSelectedFileNameA(prevSelectedB);
    setSelectedFileNameB(prevSelectedA);

    // If result was already generated, re-run with swapped inputs
    if (result) {
      setTimeout(() => {
        handleRunComparisonWithFiles(
          inputMode === 'paste'
            ? [{ name: 'donem_a_raw.log', content: prevPasteB.trim() }]
            : inputMode === 'files' && prevFileB
            ? [prevFileB]
            : [],
          inputMode === 'paste'
            ? [{ name: 'donem_b_raw.log', content: prevPasteA.trim() }]
            : inputMode === 'files' && prevFileA
            ? [prevFileA]
            : [],
          prevLabelB,
          prevLabelA
        );
      }, 50);
    }
  };

  const handleRunComparisonWithFiles = (
    filesA: FileInput[],
    filesB: FileInput[],
    lblA?: string,
    lblB?: string
  ) => {
    if (filesA.length === 0 || filesB.length === 0) return;
    setIsComparing(true);
    try {
      const res = compareSecurityPeriods(
        filesA,
        filesB,
        (lblA || labelA).trim() || undefined,
        (lblB || labelB).trim() || undefined,
        { policyAssumptionMode }
      );
      setResult(res);
      const hasZeroOrWarning =
        res.periodA.totalRequests === 0 ||
        res.periodB.totalRequests === 0 ||
        res.signatureImpacts.length === 0 ||
        Boolean(res.diagnostics?.periodA?.some((d) => d.warningOrError || d.parsedRowsCount === 0)) ||
        Boolean(res.diagnostics?.periodB?.some((d) => d.warningOrError || d.parsedRowsCount === 0));
      setShowDiagnostics(hasZeroOrWarning);
    } catch (err) {
      console.error('Kıyaslama hatası:', err);
    } finally {
      setIsComparing(false);
    }
  };

  const handleRunComparison = () => {
    let filesA: FileInput[] = [];
    let filesB: FileInput[] = [];

    if (inputMode === 'paste') {
      if (!pasteA.trim() || !pasteB.trim()) return;
      filesA = [{ name: 'donem_a_raw.log', content: pasteA.trim() }];
      filesB = [{ name: 'donem_b_raw.log', content: pasteB.trim() }];
    } else if (inputMode === 'files') {
      if (!fileA || !fileB) return;
      filesA = [fileA];
      filesB = [fileB];
    } else if (inputMode === 'select') {
      const matchA = availableUploadedFiles.find((f) => f.name === selectedFileNameA);
      const matchB = availableUploadedFiles.find((f) => f.name === selectedFileNameB);
      if (!matchA?.content || !matchB?.content) return;
      filesA = [{ name: matchA.name, content: matchA.content }];
      filesB = [{ name: matchB.name, content: matchB.content }];
    }

    handleRunComparisonWithFiles(filesA, filesB);
  };

  const handleDownloadReport = () => {
    if (!result) return;
    const html = generatePolicyEffectivenessHtmlReport(result);
    const blob = new Blob([html], { type: 'text/html;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WAF_Kural_Etkinlik_Raporu_${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadExcel = () => {
    if (!result) return;
    exportPolicyComparisonToExcel(result);
  };

  const handleDownloadMultiExcel = () => {
    if (!multiResult) return;
    exportMultiPeriodComparisonToExcel(multiResult);
  };

  const handleAddMultiPeriod = () => {
    const nextIdx = multiPeriodFiles.length + 1;
    setMultiPeriodFiles([
      ...multiPeriodFiles,
      { id: String(Date.now()), label: `Dönem ${nextIdx}` },
    ]);
  };

  const handleRemoveMultiPeriod = (id: string) => {
    if (multiPeriodFiles.length <= 2) return;
    setMultiPeriodFiles(multiPeriodFiles.filter((p) => p.id !== id));
  };

  const handleMultiPeriodFileChange = (e: React.ChangeEvent<HTMLInputElement>, id: string) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (isExcelFile(f.name)) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const buf = event.target?.result as ArrayBuffer;
        const inspection = inspectAndConvertExcel(buf, f.name);
        const fileObj = {
          name: f.name,
          content: inspection.csvContent,
          sheetName: inspection.primarySheet,
        };
        const dateHint = extractDateHint(f.name, inspection.csvContent);
        setMultiPeriodFiles((prev) =>
          prev.map((item) =>
            item.id === id
              ? {
                  ...item,
                  file: fileObj,
                  label: dateHint ? `${dateHint}` : item.label,
                }
              : item
          )
        );
      };
      reader.readAsArrayBuffer(f);
    } else {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = (event.target?.result as string) || '';
        const fileObj = { name: f.name, content };
        const dateHint = extractDateHint(f.name, content);
        setMultiPeriodFiles((prev) =>
          prev.map((item) =>
            item.id === id
              ? {
                  ...item,
                  file: fileObj,
                  label: dateHint ? `${dateHint}` : item.label,
                }
              : item
          )
        );
      };
      reader.readAsText(f);
    }
  };

  const handleRunMultiComparison = () => {
    const validPeriods = multiPeriodFiles.filter((p) => p.file && p.file.content);
    if (validPeriods.length < 2) return;

    setIsComparingMulti(true);
    try {
      const res = compareMultipleSecurityPeriods(
        validPeriods.map((p) => ({ label: p.label, file: p.file! })),
        { policyAssumptionMode }
      );
      setMultiResult(res);
    } catch (err) {
      console.error('Çoklu dönem kıyaslama hatası:', err);
    } finally {
      setIsComparingMulti(false);
    }
  };

  const extractDateHint = (name: string, content: string): string | null => {
    const text = (name + ' ' + content.slice(0, 4000)).toLowerCase();
    if (
      text.includes('agu') ||
      text.includes('ağustos') ||
      text.includes('aug') ||
      text.includes('2026-08') ||
      text.includes('08/2026') ||
      text.includes('08-2026')
    ) {
      return 'Ağustos 2026';
    }
    if (
      text.includes('eyl') ||
      text.includes('eylül') ||
      text.includes('sep') ||
      text.includes('2026-09') ||
      text.includes('09/2026') ||
      text.includes('09-2026')
    ) {
      return 'Eylül 2026';
    }
    if (text.includes('tem') || text.includes('temmuz') || text.includes('jul') || text.includes('2026-07')) {
      return 'Temmuz 2026';
    }
    if (text.includes('eki') || text.includes('ekim') || text.includes('oct') || text.includes('2026-10')) {
      return 'Ekim 2026';
    }
    const match = text.match(/\b(202[4-9]-(?:0[1-9]|1[0-2]))\b/);
    if (match) return match[1];
    return null;
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, period: 'A' | 'B') => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (isExcelFile(f.name)) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const buf = event.target?.result as ArrayBuffer;
        const inspection = inspectAndConvertExcel(buf, f.name);
        const fileObj = {
          name: f.name,
          content: inspection.csvContent,
          sheetName: inspection.primarySheet,
        };
        const dateHint = extractDateHint(f.name, inspection.csvContent);
        if (period === 'A') {
          setFileA(fileObj);
          if (dateHint) setLabelA(`${dateHint} (Alert / Kural Öncesi)`);
        } else {
          setFileB(fileObj);
          if (dateHint) setLabelB(`${dateHint} (Block / Kural Sonrası)`);
        }
      };
      reader.readAsArrayBuffer(f);
    } else {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = (event.target?.result as string) || '';
        const fileObj = { name: f.name, content };
        const dateHint = extractDateHint(f.name, content);
        if (period === 'A') {
          setFileA(fileObj);
          if (dateHint) setLabelA(`${dateHint} (Alert / Kural Öncesi)`);
        } else {
          setFileB(fileObj);
          if (dateHint) setLabelB(`${dateHint} (Block / Kural Sonrası)`);
        }
      };
      reader.readAsText(f);
    }
  };

  const renderDiagnosticCard = (diag: PeriodParsingDiagnostic, defaultTitle: string) => {
    const normCount = diag.normalizedRecordsCount ?? diag.parsedRowsCount;
    const isZeroRecords = normCount === 0;

    return (
      <div className="bg-white border border-slate-200 rounded-xl p-4 text-xs space-y-3 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-100 gap-2">
          <div>
            <span className="font-extrabold text-slate-900 block text-xs">FILE DIAGNOSTIC: {diag.fileName}</span>
            <span className="text-[10px] text-slate-500 font-mono">
              Dosya tipi: {diag.fileType || 'XLSX'} • Sheet: {diag.sheetName || 'Sheet1'} • Toplam satır: {diag.totalLines}
            </span>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                diag.headerFound !== false ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
              }`}
            >
              Header bulundu: {diag.headerFound !== false ? 'YES' : 'NO'}
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                diag.detectedFormat === 'F5_AGGREGATED_REPORT'
                  ? 'bg-indigo-100 text-indigo-800'
                  : 'bg-slate-100 text-slate-700'
              }`}
            >
              Format: {diag.detectedFormat}
            </span>
          </div>
        </div>

        {/* 10 Expected Columns Detection Table */}
        <div className="border border-slate-200 rounded-lg overflow-hidden">
          <div className="bg-slate-50 px-3 py-1.5 text-[11px] font-bold text-slate-700 border-b border-slate-200 flex justify-between items-center">
            <span>Detected columns (F5 10-Kolon Tespiti)</span>
            <span className="text-[10px] font-semibold text-slate-500">
              {diag.columnStatusList
                ? `${diag.columnStatusList.filter((c) => c.present).length} / 10 Kolon Tespit Edildi`
                : ''}
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 divide-x divide-y divide-slate-100 text-[10px]">
            {diag.columnStatusList?.map((col, cIdx) => (
              <div key={cIdx} className="p-2 flex flex-col justify-between bg-white hover:bg-slate-50">
                <span className="font-semibold text-slate-700 truncate" title={col.name}>
                  {col.name}
                </span>
                <div className="mt-1 flex items-center justify-between">
                  <span
                    className={`px-1.5 py-0.5 rounded font-black text-[9px] ${
                      col.present ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    {col.present ? 'YES' : 'NO'}
                  </span>
                  {col.rawHeaderName && (
                    <span
                      className="text-[9px] font-mono text-slate-400 truncate max-w-[65px]"
                      title={col.rawHeaderName}
                    >
                      {col.rawHeaderName}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Numerical Metrics Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
          <div className="p-2 bg-slate-50 rounded border border-slate-200">
            <span className="text-slate-500 block text-[10px]">Parsed rows:</span>
            <span className="font-bold text-slate-800 font-mono">{diag.parsedRowsCount}</span>
          </div>
          <div className="p-2 bg-slate-50 rounded border border-slate-200">
            <span className="text-slate-500 block text-[10px]">Rejected rows:</span>
            <span
              className={`font-bold font-mono ${
                (diag.rejectedRowsCount || 0) > 0 ? 'text-amber-700' : 'text-slate-700'
              }`}
            >
              {diag.rejectedRowsCount || 0}
            </span>
          </div>
          <div className="p-2 bg-slate-50 rounded border border-slate-200">
            <span className="text-slate-500 block text-[10px]">Normalized records:</span>
            <span className="font-bold text-slate-800 font-mono">{normCount}</span>
          </div>
          <div className="p-2 bg-indigo-50/60 rounded border border-indigo-200">
            <span className="text-indigo-600 block text-[10px] font-bold">Aggregate observation count (SUM):</span>
            <span className="font-extrabold text-indigo-900 font-mono">
              {(diag.aggregateObservationCount ?? diag.parsedRowsCount).toLocaleString('tr-TR')}
            </span>
          </div>
        </div>

        {/* Rejected Reason */}
        {diag.rejectionReasons && diag.rejectionReasons.length > 0 && (
          <div className="text-[11px] p-2 bg-amber-50 rounded border border-amber-200 text-amber-900">
            <span className="font-bold block text-[10px]">Rejected reason:</span>
            <ul className="list-disc list-inside text-[10px] mt-0.5 space-y-0.5">
              {diag.rejectionReasons.map((r, rIdx) => (
                <li key={rIdx}>{r}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Warning or Error / 0 Records Notice */}
        {isZeroRecords && (
          <div className="p-3 bg-rose-50 border border-rose-300 rounded-xl text-rose-900 text-xs font-medium space-y-1">
            <div className="flex items-center gap-1.5 font-extrabold text-rose-800">
              <AlertTriangle className="w-4 h-4 text-rose-600 flex-shrink-0" />
              <span>Excel okundu ancak karşılaştırılabilir kayıt oluşturulamadı.</span>
            </div>
            <div className="text-[11px] text-rose-700 pl-5">
              <strong>NEDEN:</strong> {diag.warningOrError || 'Dosyada geçerli veri satırı bulunamadı veya F5 şablonu algılanamadı.'}
            </div>
          </div>
        )}

        {/* Sample Row Verification */}
        {diag.sampleParsedValues && !isZeroRecords && (
          <div className="bg-indigo-50/40 p-2.5 rounded-lg border border-indigo-100 text-[11px] space-y-1">
            <div className="font-bold text-indigo-950 flex items-center gap-1 text-[10px]">
              <CheckCircle2 className="w-3.5 h-3.5 text-indigo-600" />
              <span>Ayrıştırılan İlk Satır Doğrulaması:</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5 text-[10px]">
              <div>
                <span className="text-slate-500 block">Policy:</span>
                <span className="font-mono font-semibold truncate block" title={diag.sampleParsedValues.samplePolicy}>
                  {diag.sampleParsedValues.samplePolicy}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Tehdit:</span>
                <span className="font-mono font-semibold truncate block" title={diag.sampleParsedValues.sampleThreat}>
                  {diag.sampleParsedValues.sampleThreat}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Aksiyon:</span>
                <span className="font-mono font-semibold block">{diag.sampleParsedValues.sampleResponse}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Hedef:</span>
                <span className="font-mono font-semibold block">{diag.sampleParsedValues.sampleDestination}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Adet/Count:</span>
                <span className="font-mono font-bold text-indigo-700 block">
                  {diag.sampleParsedValues.sampleCount?.toLocaleString('tr-TR')}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white rounded-2xl p-6 sm:p-8 shadow-md border border-slate-800">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-blue-500/20 text-blue-300 border border-blue-400/30 text-xs font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              <span>WAF &amp; Güvenlik Politikası Etki Analizörü</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black tracking-tight">
              Dönemsel Kıyaslama &amp; Kural Sıkılaştırma Etkinliği
            </h2>
            <p className="text-slate-300 text-xs sm:text-sm leading-relaxed">
              Network ve güvenlik ekipleriyle birlikte <strong>&quot;Alert (Yalnızca Uyar)&quot;</strong> modundan{' '}
              <strong>&quot;Block (Engelle)&quot;</strong> moduna çekilen kuralların kurumu ne kadar koruduğunu,
              önceki aya kıyasla ne kadarlık bir saldırı trafiğinin sınırda düşürüldüğünü ve sunucu hata rahatlamasını
              somut metriklerle analiz edip raporlayın. Excel ve log dosyalarınızı doğrudan karşılaştırabilirsiniz.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
            {result && (
              <>
                <button
                  type="button"
                  onClick={handleDownloadExcel}
                  className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-700 hover:bg-emerald-600 text-white rounded-xl text-xs sm:text-sm font-bold shadow-xs transition-all cursor-pointer"
                  title="Detaylı 5 Sayfalı Excel Raporunu (.xlsx) İndir"
                >
                  <FileSpreadsheet className="w-4 h-4 text-emerald-200" />
                  <span>Excel Raporu İndir (.xlsx)</span>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadReport}
                  className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs sm:text-sm font-bold shadow-xs transition-all cursor-pointer"
                  title="HTML ve PDF Baskı Raporunu İndir"
                >
                  <Download className="w-4 h-4" />
                  <span>Rapor İndir (HTML/PDF)</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Architecture Mode Selector: Pairwise vs Multi-Period */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-1.5 bg-slate-100 rounded-2xl border border-slate-200">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveComparisonMode('pairwise')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all cursor-pointer ${
              activeComparisonMode === 'pairwise'
                ? 'bg-white text-indigo-700 shadow-xs border border-indigo-100'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <ArrowRightLeft className="w-4 h-4 text-indigo-600" />
            <span>2 Dönem Kıyaslama (Before ⇄ After)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveComparisonMode('multi')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all cursor-pointer ${
              activeComparisonMode === 'multi'
                ? 'bg-white text-indigo-700 shadow-xs border border-indigo-100'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Clock className="w-4 h-4 text-purple-600" />
            <span>Çok Dönemli Geçmiş &amp; Zaman Serisi Trendi (3+ Rapor)</span>
            <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-purple-100 text-purple-800 font-extrabold">
              Yeni
            </span>
          </button>
        </div>
        <div className="text-xs text-slate-500 hidden sm:block pr-3 font-medium">
          {activeComparisonMode === 'pairwise'
            ? 'Ters yükleme kalkanı ve Before-After detay matrisi aktif'
            : 'Geçmiş ayları kronolojik sıralar ve trend matrisini üretir'}
        </div>
      </div>

      {activeComparisonMode === 'multi' && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-6 animate-in fade-in duration-150">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <Clock className="w-5 h-5 text-purple-600" />
                <span>Çoklu Dönem Zaman Serisi Analizi (3 ila 10 Geçmiş Rapor)</span>
              </h3>
              <p className="text-xs text-slate-500">
                Farklı aylara/haftalara ait F5 Excel veya log dosyalarını ekleyin. Sistem başlangıç tarihlerini otomatik tespit edip kronolojik sıraya dizer.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleAddMultiPeriod}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-bold transition-all cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5 text-purple-600" />
                <span>+ Yeni Dönem Ekle</span>
              </button>
              {multiResult && (
                <button
                  type="button"
                  onClick={handleDownloadMultiExcel}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-bold transition-all shadow-xs cursor-pointer"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-200" />
                  <span>Trend Excel (.xlsx)</span>
                </button>
              )}
            </div>
          </div>

          {/* Period File Upload Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {multiPeriodFiles.map((period, pIdx) => (
              <div
                key={period.id}
                className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3 relative hover:border-purple-300 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-black text-slate-800 flex items-center gap-1.5">
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-purple-100 text-purple-700 text-[10px]">
                      {pIdx + 1}
                    </span>
                    <span>Dönem {pIdx + 1}</span>
                  </span>
                  {multiPeriodFiles.length > 2 && (
                    <button
                      type="button"
                      onClick={() => handleRemoveMultiPeriod(period.id)}
                      className="text-slate-400 hover:text-rose-600 transition-colors p-1 cursor-pointer"
                      title="Bu dönemi kaldır"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div>
                  <label className="block text-[11px] font-bold text-slate-600 mb-1">Dönem Etiketi</label>
                  <input
                    type="text"
                    value={period.label}
                    onChange={(e) => {
                      const val = e.target.value;
                      setMultiPeriodFiles((prev) =>
                        prev.map((item) => (item.id === period.id ? { ...item, label: val } : item))
                      );
                    }}
                    placeholder="Örn: Temmuz 2026"
                    className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-200 rounded-lg font-semibold text-slate-800"
                  />
                </div>

                <div className="border border-dashed border-slate-300 rounded-lg p-3 text-center bg-white">
                  <input
                    type="file"
                    id={`multi-file-${period.id}`}
                    className="hidden"
                    accept=".xlsx,.xls,.xlsm,.xlsb,.log,.txt,.csv"
                    onChange={(e) => handleMultiPeriodFileChange(e, period.id)}
                  />
                  <label htmlFor={`multi-file-${period.id}`} className="cursor-pointer block space-y-1">
                    <FileSpreadsheet className="w-6 h-6 text-purple-500 mx-auto" />
                    <div className="text-[11px] font-bold text-slate-700 truncate max-w-full">
                      {period.file ? `✅ ${period.file.name}` : 'Dosya Seçin'}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      {period.file ? `${(period.file.content.length / 1024).toFixed(1)} KB` : '.xlsx, .csv, .log'}
                    </div>
                  </label>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={handleRunMultiComparison}
              disabled={isComparingMulti || multiPeriodFiles.filter((p) => p.file).length < 2}
              className="inline-flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-xl text-xs sm:text-sm font-bold shadow-xs cursor-pointer transition-all disabled:opacity-50"
            >
              <TrendingUp className="w-4 h-4" />
              <span>{isComparingMulti ? 'Zaman Serisi Hesaplanıyor...' : '📈 Çoklu Dönem Trendini Başlat'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Multi-Period Results View */}
      {activeComparisonMode === 'multi' && multiResult && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Executive Overview */}
          <div className="bg-gradient-to-r from-slate-900 to-indigo-950 text-white rounded-2xl p-6 shadow-md border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <Clock className="w-6 h-6 text-purple-400" />
                <div>
                  <h3 className="text-base font-bold">Çoklu Dönem Zaman Serisi &amp; Trend Özeti</h3>
                  <p className="text-xs text-slate-300">
                    {multiResult.periods.length} dönem kronolojik sırayla eşleştirildi • {multiResult.analyzedAt}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleDownloadMultiExcel}
                className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all shadow-xs cursor-pointer"
              >
                <FileSpreadsheet className="w-4 h-4 text-emerald-200" />
                <span>Çoklu Trend Raporunu İndir (.xlsx)</span>
              </button>
            </div>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-sans">
              {multiResult.executiveSummary}
            </p>
          </div>

          {/* Chronological Timeline Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            {multiResult.periods.map((p, idx) => (
              <div key={p.periodId} className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded text-[10px] font-black bg-purple-100 text-purple-800 font-mono">
                    Adım {idx + 1}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">{p.periodDays} Gün</span>
                </div>
                <div className="font-bold text-slate-900 text-xs truncate" title={p.label}>
                  {p.label}
                </div>
                <div className="text-xl sm:text-2xl font-black text-slate-900">
                  {p.totalRequests.toLocaleString('tr-TR')}
                </div>
                <div className="text-[11px] text-slate-500 flex justify-between">
                  <span>Günlük Ort:</span>
                  <span className="font-bold text-slate-700">{p.dailyAverageCount.toLocaleString('tr-TR')} / gün</span>
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate" title={p.periodStart || ''}>
                  📅 {p.periodStart ? p.periodStart.slice(0, 16) : 'Tarih yok'}
                </div>
              </div>
            ))}
          </div>

          {/* Volume Chart */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-3">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-purple-600" />
              <span>Dönemler Boyunca Toplam Gözlem Hacmi Eğilimi</span>
            </h4>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={multiResult.totalObservationHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="periodLabel" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="totalRequests" name="Toplam İstek / Gözlem" stroke="#6366f1" strokeWidth={2} />
                  <Line type="monotone" dataKey="dailyAverage" name="Günlük Ortalama" stroke="#10b981" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Multi-Period Matrix Table */}
          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs space-y-3 p-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                🛡️ Çok Dönemli Kural ve Olay Trend Matrisi ({multiResult.signatures.length} Olay)
              </h4>
              <span className="text-xs text-slate-500 font-medium">Eskiden Yeniye Seyir</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-50 text-slate-700 font-bold border-b border-slate-200 text-[11px]">
                  <tr>
                    <th className="p-3">Policy Name</th>
                    <th className="p-3">Rule / Event</th>
                    <th className="p-3">Threat Type</th>
                    {multiResult.periods.map((p) => (
                      <th key={p.periodId} className="p-3 font-mono text-center">
                        {p.label}
                      </th>
                    ))}
                    <th className="p-3 text-center">Genel Trend</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {multiResult.signatures.map((sig, sIdx) => (
                    <tr key={`${sig.policyId}:::${sig.signatureId}:::${sIdx}`} className="hover:bg-slate-50">
                      <td className="p-3 font-mono text-[11px] text-slate-600 truncate max-w-[150px]">
                        {sig.policyId}
                      </td>
                      <td className="p-3 font-bold text-slate-900">
                        {sig.name}
                      </td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-50 text-indigo-800 border border-indigo-100">
                          {sig.threatType}
                        </span>
                      </td>
                      {multiResult.periods.map((p, pIdx) => {
                        const cnt = sig.counts[p.periodId] || 0;
                        const delta = sig.deltas[p.periodId];
                        return (
                          <td key={p.periodId} className="p-3 text-center font-mono">
                            <span className="font-bold text-slate-800">{cnt.toLocaleString('tr-TR')}</span>
                            {pIdx > 0 && delta !== undefined && delta !== 0 && (
                              <span className={`block text-[10px] ${delta > 0 ? 'text-rose-600 font-semibold' : 'text-emerald-600 font-semibold'}`}>
                                {delta > 0 ? `+${delta.toLocaleString('tr-TR')}` : delta.toLocaleString('tr-TR')}
                              </span>
                            )}
                          </td>
                        );
                      })}
                      <td className="p-3 text-center">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-black ${
                          sig.overallTrend === 'DECREASING'
                            ? 'bg-emerald-100 text-emerald-800'
                            : sig.overallTrend === 'DISAPPEARED'
                            ? 'bg-slate-100 text-slate-600'
                            : sig.overallTrend === 'INCREASING'
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-blue-100 text-blue-800'
                        }`}>
                          {sig.trendLabel}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Input Selection Card for Pairwise (Before-After) */}
      {activeComparisonMode === 'pairwise' && (
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-indigo-600" />
            <h3 className="text-base font-bold text-slate-900">
              Kıyaslanacak İki Dönemin Belirlenmesi
            </h3>
          </div>

          {/* Mode Switcher */}
          <div className="inline-flex p-1 bg-slate-100 rounded-xl">
            <button
              type="button"
              onClick={() => setInputMode('paste')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors cursor-pointer ${
                inputMode === 'paste'
                  ? 'bg-white text-blue-600 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              ⚡ Canlı Log Yapıştır
            </button>
            <button
              type="button"
              onClick={() => setInputMode('files')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors cursor-pointer ${
                inputMode === 'files'
                  ? 'bg-white text-blue-600 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              📁 Dosya Seç (.xlsx, .log, .csv)
            </button>
            {availableUploadedFiles.length >= 2 && (
              <button
                type="button"
                onClick={() => setInputMode('select')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors cursor-pointer ${
                  inputMode === 'select'
                    ? 'bg-white text-blue-600 shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                🔄 Yüklü Dosyalardan Seç
              </button>
            )}
          </div>
        </div>

        {/* Labels Configuration and Swap Button */}
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] items-end gap-3">
            <div>
              <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                Dönem A Etiketi (Referans / Alert Öncesi)
              </label>
              <input
                type="text"
                value={labelA}
                onChange={(e) => setLabelA(e.target.value)}
                placeholder="Örn: Ağustos 2026 (Alert Modu)"
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-200 focus:border-blue-500 focus:outline-none font-semibold text-slate-800"
              />
            </div>

            <div className="flex justify-center pb-0.5">
              <button
                type="button"
                onClick={handleSwapPeriods}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-bold transition-all shadow-2xs cursor-pointer"
                title="Dönem A ve Dönem B dosyalarını/etiketlerini yer değiştir (A ⇄ B)"
              >
                <ArrowRightLeft className="w-3.5 h-3.5 text-indigo-600" />
                <span>Dönemleri Değiştir (A ⇄ B)</span>
              </button>
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                Dönem B Etiketi (Güncel / Block Sonrası)
              </label>
              <input
                type="text"
                value={labelB}
                onChange={(e) => setLabelB(e.target.value)}
                placeholder="Örn: Eylül 2026 (Block Modu)"
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-200 focus:border-blue-500 focus:outline-none font-semibold text-slate-800"
              />
            </div>
          </div>

          {/* Optional Policy Assumption Toggle */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between">
            <label className="relative inline-flex items-center cursor-pointer select-none">
              <input
                type="checkbox"
                checked={policyAssumptionMode}
                onChange={(e) => setPolicyAssumptionMode(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-8 h-4 bg-slate-300 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-indigo-600"></div>
              <div className="ml-2.5 text-xs">
                <span className="font-bold text-slate-800">
                  ⚡ Politika Varsayımı: Dosyada Action kolonu yoksa Dönem A = Alert, Dönem B = Block kabul et
                </span>
                <span className="text-[11px] text-slate-500 block">
                  (Varsayılan Kapalı: Gerçek Excel&apos;de Action kolonu yoksa yapay BLOCK üretilmez, salt gözlem hacmi analiz edilir).
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* Dynamic Input Body */}
        {inputMode === 'paste' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                  <HardDrive className="w-3.5 h-3.5 text-blue-600" />
                  {labelA}
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  {pasteA ? `${pasteA.split('\n').filter((l) => l.trim()).length} satır` : 'Boş'}
                </span>
              </div>
              <textarea
                value={pasteA}
                onChange={(e) => setPasteA(e.target.value)}
                placeholder="Dönem A log satırlarını buraya yapıştırın..."
                rows={7}
                className="w-full p-3 font-mono text-[11px] bg-white border border-slate-200 rounded-lg focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                  <HardDrive className="w-3.5 h-3.5 text-emerald-600" />
                  {labelB}
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  {pasteB ? `${pasteB.split('\n').filter((l) => l.trim()).length} satır` : 'Boş'}
                </span>
              </div>
              <textarea
                value={pasteB}
                onChange={(e) => setPasteB(e.target.value)}
                placeholder="Dönem B log satırlarını buraya yapıştırın..."
                rows={7}
                className="w-full p-3 font-mono text-[11px] bg-white border border-slate-200 rounded-lg focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {inputMode === 'files' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border-2 border-dashed border-slate-200 rounded-xl p-6 text-center hover:border-blue-400 transition-colors bg-slate-50">
              <input
                type="file"
                id="fileA-input"
                className="hidden"
                accept=".xlsx,.xls,.xlsm,.xlsb,.log,.txt,.csv"
                onChange={(e) => handleFileChange(e, 'A')}
              />
              <label htmlFor="fileA-input" className="cursor-pointer space-y-2 block">
                <FileSpreadsheet className="w-8 h-8 text-blue-500 mx-auto" />
                <div className="text-xs font-bold text-slate-800">{labelA} Dosyasını Seçin</div>
                <div className="text-[11px] text-slate-500 font-mono">
                  {fileA ? `✅ Seçildi: ${fileA.name}` : 'Henüz dosya seçilmedi (.xlsx, .xls, .log, .txt, .csv)'}
                </div>
              </label>
            </div>

            <div className="border-2 border-dashed border-slate-200 rounded-xl p-6 text-center hover:border-emerald-400 transition-colors bg-slate-50">
              <input
                type="file"
                id="fileB-input"
                className="hidden"
                accept=".xlsx,.xls,.xlsm,.xlsb,.log,.txt,.csv"
                onChange={(e) => handleFileChange(e, 'B')}
              />
              <label htmlFor="fileB-input" className="cursor-pointer space-y-2 block">
                <FileSpreadsheet className="w-8 h-8 text-emerald-500 mx-auto" />
                <div className="text-xs font-bold text-slate-800">{labelB} Dosyasını Seçin</div>
                <div className="text-[11px] text-slate-500 font-mono">
                  {fileB ? `✅ Seçildi: ${fileB.name}` : 'Henüz dosya seçilmedi (.xlsx, .xls, .log, .txt, .csv)'}
                </div>
              </label>
            </div>
          </div>
        )}

        {inputMode === 'select' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Dönem 1 (Referans Dosyası)
              </label>
              <select
                value={selectedFileNameA}
                onChange={(e) => setSelectedFileNameA(e.target.value)}
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-xl font-semibold bg-white text-slate-800"
              >
                <option value="">-- Dosya Seçin --</option>
                {availableUploadedFiles.map((f, fIdx) => (
                  <option key={`${f.name}_${fIdx}`} value={f.name}>
                    {f.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Dönem 2 (Güncel Dosya)
              </label>
              <select
                value={selectedFileNameB}
                onChange={(e) => setSelectedFileNameB(e.target.value)}
                className="w-full px-3 py-2 text-xs border border-slate-300 rounded-xl font-semibold bg-white text-slate-800"
              >
                <option value="">-- Dosya Seçin --</option>
                {availableUploadedFiles.map((f, fIdx) => (
                  <option key={`${f.name}_${fIdx}`} value={f.name}>
                    {f.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}

        {/* Action Button */}
        <div className="flex justify-end pt-2">
          <button
            type="button"
            onClick={handleRunComparison}
            disabled={isComparing}
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-xl text-xs sm:text-sm font-bold shadow-xs cursor-pointer transition-all disabled:opacity-50"
          >
            <Activity className="w-4 h-4" />
            <span>{isComparing ? 'Hesaplanıyor...' : '🛡️ Etki Analizini & Kıyaslamayı Başlat'}</span>
          </button>
        </div>
      </div>
      )}

      {/* Results View */}
      {activeComparisonMode === 'pairwise' && result && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Chronological Inversion Alert (Ters Yükleme Kalkanı) */}
          {result.chronologicalInversionDetected && (
            <div className="bg-gradient-to-r from-amber-50 to-orange-50 border-2 border-amber-400 text-amber-950 rounded-2xl p-5 shadow-sm space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start sm:items-center gap-3">
                  <AlertTriangle className="w-6 h-6 text-amber-600 flex-shrink-0 mt-0.5 sm:mt-0" />
                  <div>
                    <span className="font-black text-sm block text-amber-900">
                      ⚠️ Kronolojik Terslik Uyarısı (Ters Dosya Yükleme Kalkanı)
                    </span>
                    <p className="text-xs text-amber-800 leading-relaxed mt-0.5">
                      {result.chronologicalInversionWarning ||
                        'Dönem A başlangıç tarihi, Dönem B başlangıç tarihinden daha yenidir. Before ve After dosyalarını ters kutulara eklemiş olabilirsiniz.'}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleSwapPeriods}
                  className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-xl text-xs font-bold transition-all shadow-xs shrink-0 cursor-pointer"
                  title="Dönemleri otomatik olarak ters çevirip analizi yeniden çalıştırır"
                >
                  <ArrowRightLeft className="w-4 h-4" />
                  <span>🔄 Dönemleri Yer Değiştir &amp; Düzelt (A ⇄ B)</span>
                </button>
              </div>
              <div className="text-[11px] text-amber-700 bg-amber-100/70 p-2.5 rounded-lg border border-amber-200 font-mono">
                📅 Tespit: Dönem A = <strong>{result.periodA.periodStart || result.periodA.startDate || 'Bilinmiyor'}</strong> | Dönem B = <strong>{result.periodB.periodStart || result.periodB.startDate || 'Bilinmiyor'}</strong>
              </div>
            </div>
          )}

          {/* Demo Banner */}
          {result.isDemo && (
            <div className="bg-amber-500/10 border border-amber-400 text-amber-950 rounded-2xl p-4 flex items-center justify-between shadow-2xs">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
                <div>
                  <span className="font-extrabold text-xs sm:text-sm block">⚠️ DEMO / SİMÜLASYON VERİSİ</span>
                  <span className="text-[11px] sm:text-xs text-amber-800">
                    Bu analiz sentetik örnek loglarla oluşturulmuştur; gerçek müşteri ortamı ölçümü değildir.
                  </span>
                </div>
              </div>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-1 bg-amber-200/60 rounded-md border border-amber-300 text-amber-900">
                Simüle Senaryo
              </span>
            </div>
          )}

          {/* Diagnostic Alert & Inspection Panel */}
          {result.diagnostics && (
            <div className="bg-slate-50 border border-slate-300 rounded-2xl p-4 sm:p-5 shadow-2xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-200">
                <div className="flex items-center gap-2.5">
                  <Search className="w-5 h-5 text-indigo-600 flex-shrink-0" />
                  <div>
                    <h4 className="text-xs sm:text-sm font-bold text-slate-900 flex items-center gap-2">
                      <span>🔍 Log Ayrıştırma & Şema Teşhis Raporu</span>
                      {result.periodA.totalRequests === 0 && result.periodB.totalRequests === 0 ? (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300">
                          0 Olay Ayrıştırıldı
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                          {result.periodA.totalRequests + result.periodB.totalRequests} Olay Başarıyla Eşleşti
                        </span>
                      )}
                    </h4>
                    <p className="text-[11px] text-slate-500 mt-0.5">
                      F5 BIG-IP (10-kolon) veya standart WAF log formatlarının algılanma ve ayrıştırma durumu
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setShowDiagnostics(!showDiagnostics)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto cursor-pointer"
                >
                  <span>{showDiagnostics ? 'Teşhis Detaylarını Gizle' : 'Teşhis Detaylarını Göster'}</span>
                  {showDiagnostics ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* Notice when 0 logs found */}
              {result.periodA.totalRequests === 0 && result.periodB.totalRequests === 0 && (
                <div className="p-3 bg-rose-50 border border-rose-300 rounded-xl text-rose-900 text-xs font-medium flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold block">Dikkat: Analiz edilen dosyalardan 0 olay ayrıştırıldı.</span>
                    Müşteri F5 Excel şablonunda beklenen kolonlar: <span className="font-mono text-[11px] font-semibold">Policy Name (custom), Threat Type (custom), Event Name, Log Source, Response, Destination, Destination Port, Start Time, Low Level, Count</span>. Lütfen aşağıdaki dosya ve kolon eşleşme tablosunu inceleyiniz.
                  </div>
                </div>
              )}

              {/* Expanded Diagnostic Detail View */}
              {showDiagnostics && (
                <div className="space-y-4 pt-1 animate-in fade-in duration-150">
                  {/* Period A Diagnostics */}
                  <div className="space-y-2">
                    <div className="font-bold text-slate-800 flex items-center justify-between border-b pb-1">
                      <span className="text-xs uppercase tracking-wider font-extrabold text-blue-700">
                        📁 Dönem A (Referans / Kural Öncesi) Teşhis Raporu: {result.periodALabel}
                      </span>
                      <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-slate-100 text-slate-700">
                        {result.periodA.totalRequests.toLocaleString('tr-TR')} toplam gözlem ({result.periodA.blockedRequests} block, {result.periodA.alertedRequests || 0} alert)
                      </span>
                    </div>
                    {result.diagnostics.periodA && result.diagnostics.periodA.length > 0 ? (
                      result.diagnostics.periodA.map((diag, idx) => (
                        <div key={idx}>
                          {renderDiagnosticCard(diag, result.periodALabel)}
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 text-xs italic p-2 bg-white rounded-lg border">Dönem A için teşhis verisi bulunamadı.</div>
                    )}
                  </div>

                  {/* Period B Diagnostics */}
                  <div className="space-y-2">
                    <div className="font-bold text-slate-800 flex items-center justify-between border-b pb-1">
                      <span className="text-xs uppercase tracking-wider font-extrabold text-emerald-700">
                        📁 Dönem B (Güncel / Kural Sonrası) Teşhis Raporu: {result.periodBLabel}
                      </span>
                      <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-slate-100 text-slate-700">
                        {result.periodB.totalRequests.toLocaleString('tr-TR')} toplam gözlem ({result.periodB.blockedRequests} block, {result.periodB.alertedRequests || 0} alert)
                      </span>
                    </div>
                    {result.diagnostics.periodB && result.diagnostics.periodB.length > 0 ? (
                      result.diagnostics.periodB.map((diag, idx) => (
                        <div key={idx}>
                          {renderDiagnosticCard(diag, result.periodBLabel)}
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 text-xs italic p-2 bg-white rounded-lg border">Dönem B için teşhis verisi bulunamadı.</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Warning Banner for Different Period Durations */}
          {result.periodDaysDifferent && (
            <div className="bg-amber-50 border-2 border-amber-400 text-amber-950 rounded-2xl p-4 flex items-center gap-3 font-bold shadow-xs text-xs sm:text-sm animate-in fade-in duration-150">
              <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
              <span>
                ⚠️ Dönem süreleri farklıdır; toplam hacim karşılaştırması günlük ortalama ile birlikte değerlendirilmelidir.
              </span>
            </div>
          )}

          {/* 1. Executive Overview Banner */}
          <div className="bg-blue-50/70 border border-blue-200 rounded-2xl p-5 sm:p-6 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-blue-900 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-blue-600" />
                1. 📋 Yönetici Özeti (Executive Briefing)
              </span>
              <span className="text-xs font-semibold text-blue-700">
                Analiz Tarihi: {result.analyzedAt}
              </span>
            </div>
            <p className="text-sm text-blue-950 font-medium leading-relaxed">
              {result.executiveSummary}
            </p>
          </div>

          {/* Period Duration & Daily Normalized Volume Comparison */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-indigo-600" />
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Dönem Süreleri &amp; Günlük Normalize Gözlem Analizi
                </h4>
              </div>
              {result.periodDaysDifferent ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-100 text-amber-900 text-[11px] font-extrabold border border-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                  Farklı Dönem Süreleri ({result.periodA.periodDays || result.periodA.totalDays} Gün vs {result.periodB.periodDays || result.periodB.totalDays} Gün)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-900 text-[11px] font-bold border border-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  Eşit Dönem Süreleri ({result.periodA.periodDays || result.periodA.totalDays} Gün)
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Period A */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2">
                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  Dönem A (Referans / Öncesi)
                </div>
                <div className="font-extrabold text-slate-900 text-sm truncate">{result.periodALabel}</div>
                <div className="text-xs text-slate-600 space-y-1.5 font-medium pt-1.5 border-t border-slate-200">
                  <div>
                    <span className="text-slate-400">Tarih Aralığı:</span>{' '}
                    <span className="font-semibold text-slate-800">
                      {result.periodA.periodStart || result.periodA.startDate || '—'} →{' '}
                      {result.periodA.periodEnd || result.periodA.endDate || '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Dönem Süresi:</span>{' '}
                    <span className="font-bold text-indigo-700">{result.periodA.periodDays || result.periodA.totalDays} gün</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Toplam Gözlem:</span>{' '}
                    <span className="font-bold text-slate-900">
                      {(result.periodA.totalCount ?? result.periodA.totalRequests).toLocaleString('tr-TR')}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Günlük Ortalama:</span>{' '}
                    <span className="font-extrabold text-blue-700">
                      {result.periodA.dailyAverageCount?.toLocaleString('tr-TR')} gözlem/gün
                    </span>
                  </div>
                </div>
              </div>

              {/* Period B */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2">
                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  Dönem B (Güncel / Sonrası)
                </div>
                <div className="font-extrabold text-slate-900 text-sm truncate">{result.periodBLabel}</div>
                <div className="text-xs text-slate-600 space-y-1.5 font-medium pt-1.5 border-t border-slate-200">
                  <div>
                    <span className="text-slate-400">Tarih Aralığı:</span>{' '}
                    <span className="font-semibold text-slate-800">
                      {result.periodB.periodStart || result.periodB.startDate || '—'} →{' '}
                      {result.periodB.periodEnd || result.periodB.endDate || '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Dönem Süresi:</span>{' '}
                    <span className="font-bold text-indigo-700">{result.periodB.periodDays || result.periodB.totalDays} gün</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Toplam Gözlem:</span>{' '}
                    <span className="font-bold text-slate-900">
                      {(result.periodB.totalCount ?? result.periodB.totalRequests).toLocaleString('tr-TR')}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Günlük Ortalama:</span>{' '}
                    <span className="font-extrabold text-emerald-700">
                      {result.periodB.dailyAverageCount?.toLocaleString('tr-TR')} gözlem/gün
                    </span>
                  </div>
                </div>
              </div>

              {/* Comparison & Change */}
              <div className="bg-gradient-to-br from-indigo-50/60 to-white border border-indigo-200 rounded-xl p-4 space-y-2">
                <div className="text-[11px] font-bold text-indigo-900 uppercase tracking-wider">
                  Normalize Karşılaştırma &amp; Değişim
                </div>
                <div className="space-y-2 pt-1">
                  <div>
                    <span className="text-[11px] text-slate-500 block font-medium">Toplam Gözlem Hacmi Değişimi:</span>
                    <span className="text-sm font-black text-slate-900">
                      {result.periodA.totalRequests.toLocaleString('tr-TR')} → {result.periodB.totalRequests.toLocaleString('tr-TR')}{' '}
                      <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                        result.periodB.totalRequests <= result.periodA.totalRequests ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {result.periodA.totalRequests > 0
                          ? `${((result.periodB.totalRequests - result.periodA.totalRequests) / result.periodA.totalRequests * 100).toFixed(1)}%`
                          : '0%'}
                      </span>
                    </span>
                  </div>
                  <div>
                    <span className="text-[11px] text-slate-500 block font-medium">Günlük Ortalama Gözlem Değişimi:</span>
                    <span className="text-sm font-black text-slate-900">
                      {result.periodA.dailyAverageCount?.toLocaleString('tr-TR')} → {result.periodB.dailyAverageCount?.toLocaleString('tr-TR')}{' '}
                      {result.dailyAverageChangePct !== null && (
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                          result.dailyAverageChangePct <= 0 ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                        }`}>
                          {result.dailyAverageChangePct >= 0 ? '+' : ''}{result.dailyAverageChangePct}%
                        </span>
                      )}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 leading-snug italic pt-1">
                    * Toplam hacim değişimi doğrudan WAF etkinliği olarak yorumlanmamalı; gün sayıları farklı olduğunda günlük normalize ortalama esas alınmalıdır.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* KPI Delta Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {result.actionDataAvailable ? (
              <>
                <div className="bg-gradient-to-br from-emerald-50 to-white border border-emerald-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-emerald-800 uppercase tracking-wider block">
                    Engelleme Oranı Değişimi
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-slate-900">
                      %{result.periodB.blockRate}
                    </span>
                    <span className="text-xs font-bold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-full border border-emerald-300">
                      {result.blockRateDelta >= 0 ? '+' : ''}{result.blockRateDelta} Yüzde Puan
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block">
                    Önceki Dönem: %{result.periodA.blockRate}
                    {result.blockRateRelativeChangePct !== null
                      ? ` • Relatif: ${result.blockRateRelativeChangePct >= 0 ? '+' : ''}%${result.blockRateRelativeChangePct}`
                      : ''}
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Sınırda BLOCK Uygulanan İstek
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-blue-600">
                      {result.periodB.blockedRequests.toLocaleString('tr-TR')}
                    </span>
                    <span className="text-xs font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded-full border border-blue-200">
                      +{result.attackBlockedDeltaCount.toLocaleString('tr-TR')} Fark
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block">
                    Dönem B&apos;de WAF tarafından engellendi
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Kurtarılan Ağ Trafiği
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-purple-600">
                      {result.preventedTrafficMb !== null ? `${result.preventedTrafficMb} MB` : '—'}
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block leading-snug">
                    {result.preventedTrafficMb !== null
                      ? 'Sonraki dönemde BLOCK uygulanan loglanan byte hacmi'
                      : 'Log kaynağında byte bilgisi bulunmadığından hesaplanamadı'}
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Sunucu Hata Rahatlaması
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-emerald-600">
                      {result.serverErrorReductionPct !== null ? `-%${result.serverErrorReductionPct}` : '—'}
                    </span>
                    {result.serverErrorReductionPct !== null && (
                      <span className="text-xs font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                        5xx Hataları
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block leading-snug">
                    {result.serverErrorReductionPct !== null
                      ? 'Backend HTTP 5xx hatalarındaki düşüş'
                      : 'Backend telemetrisi bulunmadığı için 5xx etkisi hesaplanamadı'}
                  </span>
                </div>
              </>
            ) : (
              <>
                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Toplam Gözlem Hacmi
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-slate-900">
                      {result.periodB.totalRequests.toLocaleString('tr-TR')}
                    </span>
                    <span className="text-xs font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-200">
                      {result.periodB.totalRequests - result.periodA.totalRequests >= 0 ? '+' : ''}
                      {(result.periodB.totalRequests - result.periodA.totalRequests).toLocaleString('tr-TR')} Fark
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block">
                    Önceki Dönem: {result.periodA.totalRequests.toLocaleString('tr-TR')}
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Günlük Ortalama Gözlem
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-emerald-600">
                      {result.periodB.dailyAverageCount?.toLocaleString('tr-TR')}
                    </span>
                    {result.dailyAverageChangePct !== null && (
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
                        result.dailyAverageChangePct <= 0 ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-red-50 text-red-700 border-red-200'
                      }`}>
                        {result.dailyAverageChangePct >= 0 ? '+' : ''}{result.dailyAverageChangePct}%
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block">
                    Önceki Dönem: {result.periodA.dailyAverageCount?.toLocaleString('tr-TR')} / gün
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Dönem Süreleri
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-2xl sm:text-3xl font-black text-indigo-600">
                      {result.periodA.periodDays || result.periodA.totalDays} → {result.periodB.periodDays || result.periodB.totalDays}
                    </span>
                    <span className="text-xs font-bold text-slate-600 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
                      Gün
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block">
                    {result.periodDaysDifferent ? '⚠️ Süreler eşit değil' : 'Süreler eşit'}
                  </span>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Action Kolonu Durumu
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="text-xl sm:text-2xl font-black text-amber-600">
                      Action Yok
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 mt-1 block leading-snug">
                    Response kodu (500, 200, 403 vb.) Action olarak kabul edilmemiştir
                  </span>
                </div>
              </>
            )}
          </div>

          {/* 2. Main Policy Comparison Matrix */}
          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs">
            <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-indigo-600" />
                <h3 className="text-sm font-bold text-slate-900">
                  2. 🛡️ Policy Before / After (Ana Karşılaştırma Matrisi)
                </h3>
              </div>
              <span className="text-xs font-bold text-slate-500">
                {result.signatureImpacts.length} Kural / İmza İncelendi
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-100 text-slate-700 font-bold border-b border-slate-200 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="p-3">Policy</th>
                    <th className="p-3">Rule / Signature / Event</th>
                    <th className="p-3">Threat Type</th>
                    <th className="p-3">Log Source</th>
                    <th className="p-3">Before Count</th>
                    <th className="p-3">After Count</th>
                    <th className="p-3 text-red-700">Before ALERT</th>
                    <th className="p-3">Before BLOCK</th>
                    <th className="p-3 text-red-700">After ALERT</th>
                    <th className="p-3 text-emerald-700">After BLOCK</th>
                    <th className="p-3">Action Değişimi</th>
                    <th className="p-3">Durum (Status)</th>
                    <th className="p-3">Fark (Delta)</th>
                    <th className="p-3">Değişim (%)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {result.signatureImpacts.map((sig, sIdx) => (
                    <tr key={`${sig.policyId}:::${sig.signatureId || sig.name || 'sig'}:::${sIdx}`} className="hover:bg-slate-50 transition-colors">
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-800 border border-slate-200">
                          {sig.policyId}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="font-bold text-slate-900">{sig.eventName || sig.name}</div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {sig.signatureId} {sig.cveOrRef ? `• ${sig.cveOrRef}` : ''}
                        </div>
                      </td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-indigo-50 text-indigo-800 border border-indigo-100">
                          {sig.threatType || sig.category}
                        </span>
                      </td>
                      <td className="p-3 text-slate-600 font-mono text-[11px]">
                        {sig.logSource || '-'}
                      </td>
                      <td className="p-3 font-mono font-bold text-slate-800">
                        {(sig.beforeCount ?? sig.periodA_total).toLocaleString('tr-TR')}
                      </td>
                      <td className="p-3 font-mono font-bold text-slate-800">
                        {(sig.afterCount ?? sig.periodB_total).toLocaleString('tr-TR')}
                      </td>
                      <td className="p-3 font-mono text-red-600 font-semibold">
                        {sig.actionDataAvailable ? sig.periodA_alerted.toLocaleString('tr-TR') : 'N/A'}
                      </td>
                      <td className="p-3 font-mono text-slate-700">
                        {sig.actionDataAvailable ? sig.periodA_blocked.toLocaleString('tr-TR') : 'N/A'}
                      </td>
                      <td className="p-3 font-mono text-red-600 font-semibold">
                        {sig.actionDataAvailable ? sig.periodB_alerted.toLocaleString('tr-TR') : 'N/A'}
                      </td>
                      <td className="p-3 font-mono text-emerald-700 font-bold">
                        {sig.actionDataAvailable ? sig.periodB_blocked.toLocaleString('tr-TR') : 'N/A'}
                      </td>
                      <td className="p-3">
                        {sig.actionDataAvailable ? (
                          sig.actionChangeLabel === 'ALERT → BLOCK' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-black bg-emerald-100 text-emerald-800 border border-emerald-300">
                              <Zap className="w-3 h-3 text-emerald-600" />
                              <span>ALERT ➔ BLOCK</span>
                            </span>
                          ) : sig.actionChangeLabel === 'Kısmi değişim' ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300">
                              ⚠️ Kısmi değişim
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-700">
                              {sig.actionChangeLabel}
                            </span>
                          )
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] text-slate-400 italic">
                            N/A (Action Kolonu Yok)
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        {sig.technicalStatus === 'BLOCK_GOZLENDI' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                            <span>BLOCK Gözlendi</span>
                          </span>
                        ) : sig.technicalStatus === 'KISMI_DEGISIM' ? (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300">
                            ⚠️ Kısmi Değişim
                          </span>
                        ) : sig.technicalStatus === 'ALERT_DEVAM_EDIYOR' ? (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300">
                            ALERT Devam Ediyor
                          </span>
                        ) : sig.technicalStatus === 'LOGLARDA_GOZLENMEDI' ? (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-200">
                            📴 Gözlenmedi
                          </span>
                        ) : sig.technicalStatus === 'YENI_GORULEN_EVENT' ? (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
                            ✨ Yeni Kayıt
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-700">
                            {sig.statusLabel}
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-mono font-bold text-xs">
                        {(() => {
                          const d =
                            sig.delta !== undefined
                              ? sig.delta
                              : (sig.afterCount ?? sig.periodB_total) -
                                (sig.beforeCount ?? sig.periodA_total);
                          return (
                            <span className={d > 0 ? 'text-blue-600' : d < 0 ? 'text-emerald-600' : 'text-slate-500'}>
                              {d > 0 ? `+${d.toLocaleString('tr-TR')}` : d.toLocaleString('tr-TR')}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="p-3 font-mono text-xs">
                        {sig.changePct !== null && sig.changePct !== undefined ? (
                          <span
                            className={
                              sig.changePct > 0
                                ? 'text-blue-600 font-bold'
                                : sig.changePct < 0
                                ? 'text-emerald-600 font-bold'
                                : 'text-slate-500'
                            }
                          >
                            {sig.changePct >= 0 ? `+${sig.changePct}%` : `${sig.changePct}%`}
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 3. Continuing Signatures Section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* 3.1 Block Observed */}
            <div className="bg-white rounded-2xl border border-emerald-200 p-4 shadow-2xs space-y-3">
              <div className="flex items-center justify-between border-b border-emerald-100 pb-2">
                <span className="text-xs font-bold text-emerald-900 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  3.1. BLOCK Gözlenen İmzalar
                </span>
                <span className="text-xs font-bold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-full">
                  {result.continuingSignatures.blockObserved.length}
                </span>
              </div>
              <div className="space-y-2">
                {result.continuingSignatures.blockObserved.length > 0 ? (
                  result.continuingSignatures.blockObserved.map((s, idx) => (
                    <div key={`${s.policyId}:::${s.signatureId || s.name}:::${idx}`} className="text-xs p-2 bg-emerald-50/50 rounded-lg border border-emerald-100">
                      <div className="font-bold text-slate-900">{s.name}</div>
                      <div className="text-[11px] text-emerald-700 font-semibold mt-0.5">
                        {s.periodB_blocked} BLOCK uygulandı
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 italic p-2">Kayıt bulunamadı.</div>
                )}
              </div>
            </div>

            {/* 3.2 Partial Change */}
            <div className="bg-white rounded-2xl border border-amber-200 p-4 shadow-2xs space-y-3">
              <div className="flex items-center justify-between border-b border-amber-100 pb-2">
                <span className="text-xs font-bold text-amber-900 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600" />
                  3.2. Kısmi Değişim (ALERT + BLOCK)
                </span>
                <span className="text-xs font-bold text-amber-700 bg-amber-100 px-2 py-0.5 rounded-full">
                  {result.continuingSignatures.partialChange.length}
                </span>
              </div>
              <div className="space-y-2">
                {result.continuingSignatures.partialChange.length > 0 ? (
                  result.continuingSignatures.partialChange.map((s, idx) => (
                    <div key={`${s.policyId}:::${s.signatureId || s.name}:::${idx}`} className="text-xs p-2 bg-amber-50/50 rounded-lg border border-amber-100">
                      <div className="font-bold text-slate-900">{s.name}</div>
                      <div className="text-[11px] text-amber-800 font-semibold mt-0.5">
                        {s.periodB_alerted} ALERT / {s.periodB_blocked} BLOCK
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 italic p-2">Kısmi değişim kaydedilmedi.</div>
                )}
              </div>
            </div>

            {/* 3.3 ALERT Continuing */}
            <div className="bg-white rounded-2xl border border-red-200 p-4 shadow-2xs space-y-3">
              <div className="flex items-center justify-between border-b border-red-100 pb-2">
                <span className="text-xs font-bold text-red-900 flex items-center gap-1.5">
                  <Zap className="w-4 h-4 text-red-600" />
                  3.3. ALERT Devam Eden İmzalar
                </span>
                <span className="text-xs font-bold text-red-700 bg-red-100 px-2 py-0.5 rounded-full">
                  {result.continuingSignatures.alertContinuing.length}
                </span>
              </div>
              <div className="space-y-2">
                {result.continuingSignatures.alertContinuing.length > 0 ? (
                  result.continuingSignatures.alertContinuing.map((s, idx) => (
                    <div key={`${s.policyId}:::${s.signatureId || s.name}:::${idx}`} className="text-xs p-2 bg-red-50/50 rounded-lg border border-red-100">
                      <div className="font-bold text-slate-900">{s.name}</div>
                      <div className="text-[11px] text-red-700 font-semibold mt-0.5">
                        {s.periodB_alerted} istek hâlâ ALERT modunda
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 italic p-2">Tümü engelleme aksiyonuna geçmiştir.</div>
                )}
              </div>
            </div>
          </div>

          {/* 4. Not Observed Signatures */}
          {result.notObservedSignatures.length > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  4. 📴 After Dönemindeki Kaynak F5 Excel'inde Gözlenmeyen Eventler
                </span>
                <span className="text-xs font-bold text-slate-500">
                  {result.notObservedSignatures.length} İmza / Event
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {result.notObservedSignatures.map((s, idx) => (
                  <div key={`${s.policyId}:::${s.signatureId || s.name}:::${idx}`} className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs">
                    <div className="font-bold text-slate-900">{s.name}</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">{s.signatureId}</div>
                    <div className="text-[11px] text-amber-700 font-medium mt-1">
                      Önceki Dönem: {s.periodA_alerted} Alert ➔ Sonraki Dönem: 0 İstek
                    </div>
                    <div className="text-[10px] text-slate-400 italic mt-1">
                      İlgili event After dönemindeki kaynak F5 Excel'inde gözlenmemiştir.
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 5. Traffic Impact */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-2">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
              5. 📶 Trafik Hacmi Analizi
            </h3>
            {result.preventedTrafficMb !== null ? (
              <p className="text-xs text-slate-700">
                Sonraki dönemde BLOCK aksiyonu uygulanan log kayıtlarına ait gözlenen trafik hacmi: <strong>{result.preventedTrafficMb} MB</strong>.
              </p>
            ) : (
              <p className="text-xs text-slate-500 italic">
                Log kaynağında byte bilgisi bulunmadığından trafik hacmi hesaplanamadı.
              </p>
            )}
          </div>

          {/* 6. Hierarchical Breakdown (Policy ➔ Rule/Signature ➔ Target Host) */}
          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs">
            <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-indigo-600" />
                <h3 className="text-sm font-bold text-slate-900">
                  6. 🗂️ Hiyerarşik Dağılım (Policy ➔ Kural/İmza ➔ Hedef Sunucu)
                </h3>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-100 text-slate-700 font-bold border-b border-slate-200 uppercase tracking-wider">
                  <tr>
                    <th className="p-3">Hiyerarşi Seviyesi</th>
                    <th className="p-3">Kimlik / Hedef</th>
                    <th className="p-3 text-red-700">Önceki Dönem (Alert)</th>
                    <th className="p-3 text-emerald-700">Sonraki Dönem (WAF BLOCK)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {result.signatureImpacts.map((sig, sigIdx) => (
                    <React.Fragment key={`${sig.policyId}:::${sig.signatureId || sig.name}:::${sigIdx}-hierarchy`}>
                      <tr className="bg-slate-50/80 font-bold">
                        <td className="p-3 text-slate-900" colSpan={2}>
                          🛡️ Policy: {sig.policyId} • {sig.name} ({sig.signatureId})
                        </td>
                        <td className="p-3 font-mono text-red-600">{sig.periodA_alerted} Alert</td>
                        <td className="p-3 font-mono text-emerald-700">{sig.periodB_blocked} Block</td>
                      </tr>
                      {sig.targetHosts && sig.targetHosts.length > 0 ? (
                        sig.targetHosts.map((t, tIdx) => (
                          <tr key={`${sig.policyId}:::${sig.signatureId || sig.name}:::${t.host}:::${tIdx}`} className="hover:bg-slate-50">
                            <td className="p-3 pl-8 text-slate-400 font-mono text-[11px]">└─ Hedef Host</td>
                            <td className="p-3 font-semibold text-slate-800">{t.host}</td>
                            <td className="p-3 font-mono text-slate-600">{t.beforeAlert} Alert</td>
                            <td className="p-3 font-mono text-emerald-700 font-bold">{t.afterBlock} Block</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td className="p-3 pl-8 text-slate-400" colSpan={4}>
                            Hedef host ayrımı tespit edilemedi
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 7. Actionable Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <div className="bg-emerald-500/10 border border-emerald-300 rounded-2xl p-5 space-y-3">
              <h3 className="text-xs font-bold text-emerald-950 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-700" />
                7. 🛡️ Önerilen Güvenlik Aksiyonları
              </h3>
              <ul className="space-y-1.5 text-xs text-emerald-900 font-medium">
                {result.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-emerald-700 font-bold">•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
