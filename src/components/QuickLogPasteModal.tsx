import React, { useState, useMemo, useCallback, useRef } from 'react';
import {
  FileText,
  X,
  Copy,
  Check,
  AlertTriangle,
  ShieldCheck,
  Info,
  Send,
  HelpCircle,
  Sparkles,
  Search,
  ChevronRight,
  Trash2,
  Server,
  ShieldAlert,
  Shield,
  Layers,
  Network,
  ListTree,
  FileCheck2,
  Clock,
  User,
  Activity,
  ArrowRight,
  Terminal,
  Image as ImageIcon,
  UploadCloud,
  RefreshCw,
  ZoomIn,
  Eye,
} from 'lucide-react';
import { RawLogTriageSummary } from '../types';
import { splitRawTextIntoEvents } from '../services/quickTriageHelper';
import {
  CorrelatedEventInput,
  IncidentCandidate,
  WholeLogSummary,
} from '../services/socCorrelationEngine';
import {
  analyzeRawLogText,
  QuickAnalysisResult,
  ForensicVerdict,
} from '../services/quickLogAnalyzer';
import { QradarAqlStudio } from './QradarAqlStudio';
import { generateL2InvestigationPlan, L2InvestigationPlan } from '../services/l2InvestigationEngine';
import { L2InvestigationPlanView } from './L2InvestigationPlanView';
import { ImageForensicView } from './ImageForensicView';
import {
  analyzeForensicScreenshot,
  fileToBase64,
  ImageForensicResult,
} from '../services/imageForensicService';

interface QuickLogPasteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportToHunting?: (file: File, triageSummary?: RawLogTriageSummary) => void;
  onOpenCommandExplainer?: (cmd: string, context?: any) => void;
  onOpenAiLogUnderstanding?: (initialText?: string) => void;
  initialViewTab?: 'comprehensiveReport' | 'l2InvestigationPlan' | 'incidents' | 'eventInspector' | 'qradarStudio' | 'imageForensic';
}

export type { ForensicVerdict, QuickAnalysisResult };

export const QuickLogPasteModal: React.FC<QuickLogPasteModalProps> = ({
  isOpen,
  onClose,
  onImportToHunting,
  onOpenCommandExplainer,
  onOpenAiLogUnderstanding,
  initialViewTab,
}) => {
  const [rawText, setRawText] = useState('');
  const [copiedResponse, setCopiedResponse] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [selectedLogIndex, setSelectedLogIndex] = useState(0);

  // Split lines / blocks intelligently (handles multiline Windows events as single blocks)
  const lines = useMemo(() => {
    return splitRawTextIntoEvents(rawText);
  }, [rawText]);

  // Centralized unified forensic triage & decision pipeline
  const triageResult = useMemo(() => {
    return analyzeRawLogText(rawText);
  }, [rawText]);

  const analysisResults = useMemo<QuickAnalysisResult[]>(() => {
    return triageResult?.analysisResults || [];
  }, [triageResult]);

  const [activeViewTab, setActiveViewTab] = useState<
    'comprehensiveReport' | 'l2InvestigationPlan' | 'incidents' | 'eventInspector' | 'qradarStudio' | 'imageForensic'
  >(initialViewTab || 'comprehensiveReport');
  const [copiedReport, setCopiedReport] = useState(false);

  // Image / Screenshot Forensic State
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null);
  const [isAnalyzingImage, setIsAnalyzingImage] = useState(false);
  const [imageForensicResult, setImageForensicResult] = useState<ImageForensicResult | null>(null);
  const [imageAnalysisError, setImageAnalysisError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Sync initialViewTab when opened with specific tab
  React.useEffect(() => {
    if (initialViewTab) {
      setActiveViewTab(initialViewTab);
    }
  }, [initialViewTab]);

  const handleImageSelect = useCallback(async (file: File) => {
    if (!file.type.startsWith('image/')) {
      setImageAnalysisError('Lütfen geçerli bir resim dosyası seçin (PNG, JPG, WebP).');
      return;
    }
    setImageFile(file);
    setImageAnalysisError(null);
    const url = URL.createObjectURL(file);
    setImagePreviewUrl(url);

    // Auto trigger forensic screenshot analysis
    setIsAnalyzingImage(true);
    try {
      const base64 = await fileToBase64(file);
      const forensicRes = await analyzeForensicScreenshot(base64, file.type, rawText);
      setImageForensicResult(forensicRes);
      setActiveViewTab('imageForensic');
    } catch (err: any) {
      console.error('Ekran görüntüsü analizi hatası:', err);
      setImageAnalysisError(err?.message || 'Görüntü analiz edilirken bir hata oluştu.');
    } finally {
      setIsAnalyzingImage(false);
    }
  }, [rawText]);

  const handleManualAnalyzeImage = async () => {
    if (!imageFile) return;
    setIsAnalyzingImage(true);
    setImageAnalysisError(null);
    try {
      const base64 = await fileToBase64(imageFile);
      const forensicRes = await analyzeForensicScreenshot(base64, imageFile.type, rawText);
      setImageForensicResult(forensicRes);
      setActiveViewTab('imageForensic');
    } catch (err: any) {
      setImageAnalysisError(err?.message || 'Görüntü analiz edilirken bir hata oluştu.');
    } finally {
      setIsAnalyzingImage(false);
    }
  };

  const handleClearImage = () => {
    if (imagePreviewUrl) {
      URL.revokeObjectURL(imagePreviewUrl);
    }
    setImageFile(null);
    setImagePreviewUrl(null);
    setImageForensicResult(null);
    setImageAnalysisError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    if (activeViewTab === 'imageForensic') {
      setActiveViewTab(lines.length > 0 ? 'l2InvestigationPlan' : 'comprehensiveReport');
    }
  };

  const handlePasteEvent = useCallback((e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.type.startsWith('image/')) {
        const file = item.getAsFile();
        if (file) {
          e.preventDefault();
          handleImageSelect(file);
          return;
        }
      }
    }
  }, [handleImageSelect]);

  const handleLoadSampleScreenshot = async (sampleType: 'powershell_4688' | 'rdp_4625') => {
    const canvas = document.createElement('canvas');
    canvas.width = 900;
    canvas.height = 500;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.fillStyle = '#1e293b';
    ctx.fillRect(0, 0, 900, 500);

    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, 900, 42);
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 14px sans-serif';
    ctx.fillText(
      sampleType === 'powershell_4688'
        ? 'Event Properties - Event 4688, Microsoft Windows security auditing'
        : 'Event Properties - Event 4625, Microsoft Windows security auditing',
      20,
      26
    );

    ctx.fillStyle = '#090d16';
    ctx.fillRect(15, 55, 870, 425);
    ctx.strokeStyle = '#334155';
    ctx.strokeRect(15, 55, 870, 425);

    ctx.font = '13px monospace';
    ctx.fillStyle = '#94a3b8';

    if (sampleType === 'powershell_4688') {
      ctx.fillStyle = '#38bdf8';
      ctx.fillText('A new process has been created.', 30, 85);
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText('Creator Subject: Security ID: S-1-5-18 | Account Name: SYSTEM | Domain: NT AUTHORITY', 30, 115);
      ctx.fillText('Process Information:', 30, 145);
      ctx.fillText('  New Process ID: 0x1f4c', 30, 170);
      ctx.fillText('  New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 30, 195);
      ctx.fillStyle = '#fde047';
      ctx.fillText('  Process Command Line: powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...', 30, 220);
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText('  Parent Process Name: C:\\Windows\\System32\\cmd.exe', 30, 245);
      ctx.fillText('Computer: SRV-FIN-DC01.corp.local', 30, 275);
      ctx.fillText('Logged: 2026-10-06 14:22:18 UTC', 30, 300);
      ctx.fillStyle = '#f87171';
      ctx.fillText('Task Category: Process Creation | Keywords: Audit Success', 30, 330);
    } else {
      ctx.fillStyle = '#f87171';
      ctx.fillText('An account failed to log on.', 30, 85);
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText('Account For Which Logon Failed: Account Name: admin_corp | Domain: CORP', 30, 115);
      ctx.fillText('Failure Information:', 30, 145);
      ctx.fillText('  Failure Reason: Unknown user name or bad password.', 30, 170);
      ctx.fillText('  Status: 0xC000006D | Sub Status: 0xC000006A', 30, 195);
      ctx.fillText('Network Information:', 30, 225);
      ctx.fillText('  Workstation Name: PC-REMOTE-09', 30, 250);
      ctx.fillText('  Source Network Address: 194.26.29.112 | Source Port: 49812', 30, 275);
      ctx.fillText('Logon Type: 10 (RemoteInteractive / RDP)', 30, 305);
      ctx.fillText('Computer: SRV-DC01.corp.local', 30, 335);
    }

    canvas.toBlob(async (blob) => {
      if (blob) {
        const file = new File(
          [blob],
          sampleType === 'powershell_4688' ? 'event_4688_powershell.png' : 'event_4625_failed_rdp.png',
          { type: 'image/png' }
        );
        await handleImageSelect(file);
      }
    }, 'image/png');
  };

  // Compute L2 Incident Investigation Plan for current event
  const currentRawLog = lines[selectedLogIndex] || rawText;
  const currentL2Plan: L2InvestigationPlan | null = useMemo(() => {
    if (!currentRawLog.trim()) return null;
    return generateL2InvestigationPlan(currentRawLog, analysisResults[selectedLogIndex]?.parsedLog);
  }, [currentRawLog, selectedLogIndex, analysisResults]);

  // Build unpolluted event objects for secondary correlation engine
  const correlatedEvents = useMemo<CorrelatedEventInput[]>(() => {
    return triageResult?.correlatedEvents || [];
  }, [triageResult]);

  // Execute secondary correlation layer: clusters true incidents and isolates co-occurring events
  const defaultWholeLogSummary: WholeLogSummary = {
    totalEvents: 0,
    rawLinesCount: 0,
    parsedRecordsCount: 0,
    normalizedEventsCount: 0,
    uncorrelatedEventsCount: 0,
    breakdown: { critical: 0, suspicious: 0, anomaly: 0, benign: 0, falsePositive: 0, unknown: 0 },
    incidentCandidates: [],
    incidentEventsCount: 0,
    uncorrelatedImportantEvents: [],
    falsePositiveCandidates: [],
    benignEventsCount: 0,
    unknownEventsCount: 0,
    overallPosture: 'BENIGN_NORMAL',
    postureTitle: 'Normal Güvenlik Durumu',
    postureJustification: 'İncelenecek olay bulunmamaktadır.',
    evidenceBasedSummary: '',
    overallFindings: [],
    analystActions: [],
  };

  const wholeLogSummary = useMemo<WholeLogSummary>(() => {
    return triageResult?.wholeLogSummary || defaultWholeLogSummary;
  }, [triageResult]);

  // Generate strictly structured 6-stage SOC report
  const comprehensive6StageReport = useMemo<string>(() => {
    return triageResult?.comprehensive6StageReport || '';
  }, [triageResult]);

  const currentResult = analysisResults[selectedLogIndex] || analysisResults[0];

  const handleCopyResponse = () => {
    if (!currentResult) return;
    navigator.clipboard.writeText(currentResult.customerResponseText);
    setCopiedResponse(true);
    setTimeout(() => setCopiedResponse(false), 2000);
  };

  const handleCopyComprehensiveReport = () => {
    navigator.clipboard.writeText(comprehensive6StageReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(rawText);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleImport = () => {
    if (!onImportToHunting || !rawText.trim()) return;
    const blob = new Blob([rawText], { type: 'text/plain;charset=utf-8' });
    const file = new File([blob], 'pasted_customer_logs.log', { type: 'text/plain' });

    const triageSummary: RawLogTriageSummary = {
      pastedAt: new Date().toISOString(),
      totalEvents: lines.length,
      overallPosture: wholeLogSummary.overallPosture,
      postureTitle: wholeLogSummary.postureTitle,
      evidenceBasedSummary: wholeLogSummary.evidenceBasedSummary,
      incidentCandidatesCount: wholeLogSummary.incidentCandidates.length,
      overallFindings: wholeLogSummary.overallFindings,
      analystActions: wholeLogSummary.analystActions,
      fullReportText: comprehensive6StageReport,
      rawText: rawText,
    };

    onImportToHunting(file, triageSummary);
    onClose();
  };

  const handleClearText = () => {
    setRawText('');
    setSelectedLogIndex(0);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 overflow-y-auto">
      <div
        id="quick-log-paste-modal"
        className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-indigo-600 text-white flex items-center justify-center shadow-xs">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <span>Hızlı Log &amp; Ekran Görüntüsü Adli Analizi</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 font-bold border border-indigo-200">
                  L2 Investigation
                </span>
              </h2>
              <p className="text-xs text-slate-500">
                Log metinlerini yapıştırın veya güvenlik ekran görüntülerini (Windows Event Viewer, Splunk, Sentinel, EDR, WAF, Terminal) yükleyip inceleyin.
              </p>
            </div>
          </div>
          <button
            id="quick-log-close-header-btn"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-md transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5" onPaste={handlePasteEvent}>
          {/* Hidden File Input for Image Upload */}
          <input
            type="file"
            ref={fileInputRef}
            accept="image/*"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleImageSelect(e.target.files[0]);
              }
            }}
          />

          {/* Top Actions: Screenshot Upload & Quick Simulation Buttons */}
          <div className="flex items-center justify-between gap-2 flex-wrap pb-1">
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Cihazınızdan ekran görüntüsü yükleyin"
              >
                <UploadCloud className="w-3.5 h-3.5 text-indigo-600" />
                <span>Ekran Görüntüsü Yükle</span>
              </button>

              <div className="hidden sm:flex items-center gap-1.5 text-[11px] text-slate-500 bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200">
                <ImageIcon className="w-3 h-3 text-slate-400" />
                <span>Pano Görseli (Ctrl+V / Cmd+V) Doğrudan Yapıştırılabilir</span>
              </div>
            </div>
          </div>

          {/* Image Uploaded Preview Card if present */}
          {imagePreviewUrl && (
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-in fade-in duration-150">
              <div className="flex items-center gap-3">
                <div className="relative group shrink-0">
                  <img
                    src={imagePreviewUrl}
                    alt="Yüklenen Ekran Görüntüsü"
                    className="w-16 h-12 object-cover rounded-md border border-amber-300 shadow-xs cursor-pointer hover:opacity-90"
                    onClick={() => setActiveViewTab('imageForensic')}
                  />
                  <div className="absolute inset-0 bg-black/30 rounded-md opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity pointer-events-none">
                    <ZoomIn className="w-4 h-4 text-white" />
                  </div>
                </div>
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-amber-950">
                      {imageFile?.name || 'Ekran Görüntüsü'}
                    </span>
                    <span className="text-[10px] font-mono bg-amber-100 text-amber-800 px-2 py-0.5 rounded font-bold border border-amber-200">
                      OBSERVED_FROM_IMAGE
                    </span>
                  </div>
                  <p className="text-[11px] text-amber-900">
                    Ekran görüntüsü adli incelemeye hazır. Aşağıdaki alana dilerseniz ek log metni de girebilirsiniz (Screenshot + Text birlikte analiz edilir).
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
                <button
                  type="button"
                  onClick={handleManualAnalyzeImage}
                  disabled={isAnalyzingImage}
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzingImage ? 'animate-spin' : ''}`} />
                  <span>{isAnalyzingImage ? 'İnceleniyor...' : 'Görseli Analiz Et'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleClearImage}
                  className="p-1.5 bg-white hover:bg-rose-50 text-slate-500 hover:text-rose-600 border border-amber-200 rounded-lg text-xs transition-colors cursor-pointer"
                  title="Görseli kaldır"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Image Analysis Progress Banner */}
          {isAnalyzingImage && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-slate-200 flex items-center gap-3 animate-pulse">
              <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin shrink-0" />
              <div className="space-y-0.5">
                <h4 className="text-xs font-bold text-white">Görsel Adli İnceleme Yürütülüyor...</h4>
                <p className="text-[11px] text-slate-400">
                  Ekran görüntüsündeki platform arayüzü, Event ID, süreçler, komut satırları ve eksik kanıt alanları ayıklanıyor.
                </p>
              </div>
            </div>
          )}

          {/* Image Analysis Error */}
          {imageAnalysisError && (
            <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-xl p-3 text-xs flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                <span>{imageAnalysisError}</span>
              </div>
              <button
                type="button"
                onClick={handleManualAnalyzeImage}
                className="px-2.5 py-1 bg-rose-600 text-white rounded text-[11px] font-bold hover:bg-rose-700 transition-colors"
              >
                Tekrar Dene
              </button>
            </div>
          )}

          {/* Textarea Area */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-indigo-600" />
                <span>{imageFile ? 'Ek Log Metni (Opsiyonel — Screenshot + Text Birlikte Değerlendirilir)' : 'Ham Log Metni'}</span>
              </label>
              {rawText && (
                <button
                  id="quick-log-clear-btn"
                  type="button"
                  onClick={handleClearText}
                  className="px-2.5 py-1 rounded bg-slate-100 text-slate-600 hover:text-rose-600 hover:bg-rose-50 text-xs font-medium border border-slate-200 flex items-center gap-1 transition-colors cursor-pointer"
                  title="Yapıştırılan metni temizle"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Temizle</span>
                </button>
              )}
            </div>

            <div className="relative">
              <textarea
                id="quick-log-input-textarea"
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                onPaste={handlePasteEvent}
                placeholder={
                  imageFile
                    ? "Ekran görüntüsü yüklendi. Varsa ek log satırını buraya yapıştırabilirsiniz..."
                    : "Log satırlarını buraya yapıştırın veya doğrudan ekran görüntüsü yapıştırın (Ctrl+V)..."
                }
                rows={imageFile ? 3 : 4}
                className="w-full font-mono text-xs p-3.5 bg-slate-950 text-slate-100 rounded-lg border border-slate-800 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all placeholder:text-slate-600 leading-relaxed"
              />
              {rawText && (
                <button
                  id="quick-log-copy-raw-btn"
                  type="button"
                  onClick={handleCopyRaw}
                  className="absolute top-2 right-2 px-2 py-1 bg-slate-800/80 hover:bg-slate-700 text-slate-300 rounded text-[10px] flex items-center gap-1 cursor-pointer"
                >
                  {copiedRaw ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedRaw ? 'Kopyalandı' : 'Kopyala'}</span>
                </button>
              )}
            </div>
          </div>

          {/* If logs are detected */}
          {lines.length > 0 && currentResult && (
            <div className="space-y-4 pt-2 border-t border-slate-200">
              {/* Holistic Control & Navigation Bar */}
              <div className="bg-slate-900 text-slate-100 rounded-xl p-3 border border-slate-800 flex flex-col md:flex-row md:items-center md:justify-between gap-3 shadow-sm">
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  <div className="flex items-center gap-1.5 font-bold text-indigo-300 mr-1">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    <span>Adli Sayaçlar:</span>
                  </div>
                  <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono text-[11px] border border-slate-700" title="Girdideki toplam ham satır sayısı">
                    Ham Satır: <strong className="text-white">{wholeLogSummary.rawLinesCount ?? triageResult?.rawLinesCount ?? lines.length}</strong>
                  </span>
                  <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono text-[11px] border border-slate-700" title="Ayrıştırılan yapılandırılmış olay kaydı sayısı">
                    Ayrıştırılan Kayıt: <strong className="text-white">{wholeLogSummary.parsedRecordsCount ?? lines.length}</strong>
                  </span>
                  <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono text-[11px] border border-slate-700" title="Normalize edilmiş bağımsız olay sayısı">
                    Normalize Olay: <strong className="text-white">{wholeLogSummary.normalizedEventsCount ?? lines.length}</strong>
                  </span>
                  <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${
                    wholeLogSummary.incidentCandidates.length > 0 ? 'bg-indigo-950 text-indigo-300 border-indigo-700' : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`} title="Kanıtlarla birbirine bağlanan korelasyon olay zinciri sayısı">
                    Zincir (Incident): <strong className={wholeLogSummary.incidentCandidates.length > 0 ? 'text-indigo-200' : 'text-slate-400'}>{wholeLogSummary.incidentCandidates.length}</strong>
                  </span>
                  <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono text-[11px] border border-slate-700" title="Herhangi bir korelasyon zincirine dahil olmayan bağımsız olay sayısı">
                    Bağımsız Olay: <strong className="text-white">{wholeLogSummary.uncorrelatedEventsCount ?? (wholeLogSummary.totalEvents - wholeLogSummary.incidentEventsCount)}</strong>
                  </span>
                </div>

                {/* View Switcher Tabs */}
                <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 shrink-0">
                  <button
                    id="quick-log-tab-comprehensive-report"
                    type="button"
                    onClick={() => setActiveViewTab('comprehensiveReport')}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      activeViewTab === 'comprehensiveReport'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <ListTree className="w-3.5 h-3.5" />
                    <span>6-Aşamalı Bütünsel Rapor</span>
                  </button>
                  <button
                    id="quick-log-tab-l2-plan"
                    type="button"
                    onClick={() => setActiveViewTab('l2InvestigationPlan')}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      activeViewTab === 'l2InvestigationPlan'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                    <span>L2 Investigation Planı</span>
                  </button>
                  <button
                    id="quick-log-tab-incidents"
                    type="button"
                    onClick={() => setActiveViewTab('incidents')}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      activeViewTab === 'incidents'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" />
                    <span>Olay Zincirleri ({wholeLogSummary.incidentCandidates.length})</span>
                  </button>
                  <button
                    id="quick-log-tab-event-inspector"
                    type="button"
                    onClick={() => setActiveViewTab('eventInspector')}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      activeViewTab === 'eventInspector'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <FileCheck2 className="w-3.5 h-3.5" />
                    <span>Olay Bazında Detay (#{selectedLogIndex + 1})</span>
                  </button>
                  <button
                    id="quick-log-tab-qradar-studio"
                    type="button"
                    onClick={() => setActiveViewTab('qradarStudio')}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      activeViewTab === 'qradarStudio'
                        ? 'bg-blue-600 text-white shadow-xs'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <Terminal className="w-3.5 h-3.5 text-blue-400" />
                    <span>Çoklu SIEM &amp; Kural Stüdyosu</span>
                  </button>
                  {onOpenAiLogUnderstanding && (
                    <button
                      id="quick-log-tab-ai-understanding"
                      type="button"
                      onClick={() => onOpenAiLogUnderstanding(rawText)}
                      className="px-3 py-1.5 rounded-md text-xs font-bold flex items-center gap-1.5 transition-colors bg-purple-950/70 text-purple-300 hover:text-white hover:bg-purple-900 border border-purple-700/60 shadow-xs cursor-pointer"
                      title="Format bağımsız AI Log Yapı Anlama ve Raw-Span Doğrulama Motorunu Aç (Phase 4)"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-purple-300" />
                      <span>AI Log Anlamlandırma (Phase 4)</span>
                    </button>
                  )}
                  {imageForensicResult && (
                    <button
                      id="quick-log-tab-image-forensic"
                      type="button"
                      onClick={() => setActiveViewTab('imageForensic')}
                      className={`px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                        activeViewTab === 'imageForensic'
                          ? 'bg-amber-600 text-white shadow-xs'
                          : 'text-amber-300 hover:text-white hover:bg-slate-800/60'
                      }`}
                    >
                      <ImageIcon className="w-3.5 h-3.5 text-amber-300" />
                      <span>Görsel Adli İnceleme (Screenshot)</span>
                    </button>
                  )}
                </div>
              </div>

              {/* ========================================================================= */}
              {/* TAB 1: 6-AŞAMALI BÜTÜNSEL SOC RAPORU */}
              {/* ========================================================================= */}
              {activeViewTab === 'comprehensiveReport' && (
                <div className="space-y-4">
                  {/* Action Bar */}
                  <div className="flex items-center justify-between bg-indigo-50 border border-indigo-200 rounded-xl p-3.5">
                    <div>
                      <h3 className="text-sm font-bold text-indigo-950 flex items-center gap-2">
                        <ListTree className="w-4 h-4 text-indigo-600" />
                        <span>Resmi SOC Log Analiz ve Olay Özeti</span>
                      </h3>
                      <p className="text-xs text-indigo-800 mt-0.5">
                        Tüm olaylar incelenmiş, ilişkili varlıklar üzerinden olay zincirleri ve güvenlik bulguları derlenmiştir.
                      </p>
                    </div>
                    <button
                      id="quick-log-copy-all-report-btn"
                      type="button"
                      onClick={handleCopyComprehensiveReport}
                      className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-xs transition-colors shrink-0"
                    >
                      {copiedReport ? <Check className="w-4 h-4 text-emerald-300" /> : <Copy className="w-4 h-4" />}
                      <span>{copiedReport ? 'Tüm Rapor Kopyalandı!' : '6-Aşamalı Raporu Kopyala'}</span>
                    </button>
                  </div>

                  {/* Visual 6 Stages Container */}
                  <div className="space-y-4">
                    {/* Stage 1: Dosya / Log Özeti */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-3 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 flex items-center justify-between pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">1. DOSYA / LOG ÖZETİ</span>
                        <div className="flex items-center gap-2">
                          <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full ${
                            wholeLogSummary.overallPosture === 'CRITICAL_THREAT'
                              ? 'bg-rose-100 text-rose-800'
                              : wholeLogSummary.overallPosture === 'SUSPICIOUS_ACTIVITY'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-emerald-100 text-emerald-800'
                          }`}>
                            {wholeLogSummary.overallPosture === 'CRITICAL_THREAT'
                              ? 'KRİTİK TEHDİT / AKTİF MÜDAHALE'
                              : wholeLogSummary.overallPosture === 'SUSPICIOUS_ACTIVITY'
                              ? 'ŞÜPHELİ AKTİVİTE / İNCELEME'
                              : 'MEŞRU / BEKLENEN ETKİNLİK'}
                          </span>
                          <span className="text-[10px] text-slate-500 font-medium bg-slate-100 px-2 py-0.5 rounded">
                            {wholeLogSummary.postureTitle}
                          </span>
                        </div>
                      </div>

                      {/* Evidence-Based Summary Banner */}
                      <div className="bg-indigo-50/70 border border-indigo-100 rounded-lg p-3 space-y-1.5 text-xs">
                        <div className="flex items-center gap-1.5 font-bold text-indigo-950">
                          <ShieldAlert className="w-4 h-4 text-indigo-600 shrink-0" />
                          <span>Kanıta Dayalı Bütünsel Değerlendirme</span>
                        </div>
                        <p className="text-indigo-900 font-medium leading-relaxed">
                          {wholeLogSummary.evidenceBasedSummary}
                        </p>
                        <p className="text-slate-600 text-[11px] leading-relaxed border-t border-indigo-100/70 pt-1">
                          <strong className="text-slate-700 font-semibold">Adli Gerekçe:</strong> {wholeLogSummary.postureJustification}
                        </p>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1 text-xs">
                        <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200/80">
                          <span className="text-slate-500 block text-[10px]">Toplam Olay:</span>
                          <span className="font-bold text-slate-800 font-mono text-sm">{wholeLogSummary.totalEvents} Adet</span>
                        </div>
                        <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200/80">
                          <span className="text-slate-500 block text-[10px]">Tespit Edilen Olay Zinciri:</span>
                          <span className="font-bold text-indigo-700 font-mono text-sm">{wholeLogSummary.incidentCandidates.length} Incident</span>
                        </div>
                        <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200/80">
                          <span className="text-slate-500 block text-[10px]">Kritik / Şüpheli Olay:</span>
                          <span className="font-bold text-rose-600 font-mono text-sm">
                            {wholeLogSummary.breakdown.critical + wholeLogSummary.breakdown.suspicious} Olay
                          </span>
                        </div>
                        <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200/80">
                          <span className="text-slate-500 block text-[10px]">Meşru / Düşük Öncelik:</span>
                          <span className="font-bold text-emerald-700 font-mono text-sm">{wholeLogSummary.benignEventsCount} Olay</span>
                        </div>
                      </div>
                    </div>

                    {/* Stage 2: Event-by-Event Analysis Summary Table */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-2 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 flex items-center justify-between pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">
                          2. EVENT-BY-EVENT ANALYSIS (OLAY BAZINDA ADLİ AYRIŞTIRMA)
                        </span>
                        <span className="text-[10px] text-slate-500 font-normal">
                          Her olay bağımsız değerlendirilmiş, veri sızıntısı engellenmiştir
                        </span>
                      </div>
                      <div className="max-h-64 overflow-y-auto divide-y divide-slate-100 text-xs">
                        {correlatedEvents.map((ev) => (
                          <div
                            key={ev.index}
                            className="py-2 px-1 flex items-center justify-between hover:bg-slate-50 transition-colors gap-3"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="font-mono font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded text-[11px] shrink-0">
                                #{ev.index}
                              </span>
                              <div className="min-w-0">
                                <div className="font-semibold text-slate-800 truncate flex items-center gap-1.5">
                                  <span>{ev.isWindows && ev.eventId ? `Event ${ev.eventId} (${ev.eventName})` : ev.threatTitle}</span>
                                  {ev.timestamp && <span className="text-[10px] text-slate-400 font-mono">[{ev.timestamp}]</span>}
                                </div>
                                <div className="text-[11px] text-slate-500 font-mono truncate">
                                  Host: <strong className="text-slate-700">{ev.host}</strong> | Hesap: <strong className="text-slate-700">{ev.user}</strong>
                                  {ev.commandLine && ` | Komut: ${ev.commandLine.slice(0, 40)}...`}
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${ev.verdictBadge.badgeClasses}`}>
                                {ev.verdictBadge.text}
                              </span>
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedLogIndex(ev.index - 1);
                                  setActiveViewTab('eventInspector');
                                }}
                                className="px-2 py-1 bg-slate-100 hover:bg-indigo-50 hover:text-indigo-600 text-slate-600 rounded text-[10px] font-medium transition-colors"
                              >
                                İncele &rarr;
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Stage 3: Correlation Analysis (Incident Candidates) */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-3 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 flex items-center justify-between pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">
                          3. CORRELATION ANALYSIS (İLİŞKİLİ OLAY ZİNCİRLERİ)
                        </span>
                        <span className="text-[10px] bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono">
                          {wholeLogSummary.incidentCandidates.length} Incident
                        </span>
                      </div>

                      {wholeLogSummary.incidentCandidates.length === 0 ? (
                        <div className="p-3 bg-slate-50 text-slate-600 rounded-lg text-xs leading-relaxed border border-slate-200">
                          Log dosyasında aynı host/kullanıcı ve ardışık saldırı sekansı içeren çoklu olay zinciri bulunmamaktadır.
                          Aynı dosyada yer alan olaylar farklı makine ve bağlamlara ait olduğu için tek bir saldırı zincirine bağlanmamış, adli izolasyon korunmuştur.
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {wholeLogSummary.incidentCandidates.map((inc) => (
                            <div
                              key={inc.id}
                              className={`p-3.5 rounded-xl border ${
                                inc.severity === 'CRITICAL'
                                  ? 'bg-rose-50/70 border-rose-200'
                                  : inc.severity === 'HIGH'
                                  ? 'bg-amber-50/70 border-amber-200'
                                  : 'bg-indigo-50/70 border-indigo-200'
                              } space-y-2.5`}
                            >
                              <div className="flex items-center justify-between flex-wrap gap-2">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-bold text-xs bg-slate-900 text-white px-2 py-0.5 rounded">
                                    {inc.id}
                                  </span>
                                  <h4 className="text-xs font-bold text-slate-900">{inc.title}</h4>
                                </div>
                                <div className="flex items-center gap-1.5 text-[10px]">
                                  <span className="bg-white/90 text-slate-700 font-semibold px-2 py-0.5 rounded border border-slate-200">
                                    Olaylar: #{inc.eventIndices.join(', #')}
                                  </span>
                                  <span className="bg-indigo-100 text-indigo-900 font-bold px-2 py-0.5 rounded border border-indigo-200">
                                    Korelasyon Gücü: {inc.correlationStrength}
                                  </span>
                                </div>
                              </div>

                              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono bg-white/80 p-2.5 rounded-lg border border-slate-200/60">
                                <div>
                                  <span className="text-slate-500 block">Ortak Host:</span>
                                  <strong className="text-slate-800">{inc.sharedHost}</strong>
                                </div>
                                <div>
                                  <span className="text-slate-500 block">Ortak Kullanıcı:</span>
                                  <strong className="text-slate-800">{inc.sharedUser}</strong>
                                </div>
                                <div>
                                  <span className="text-slate-500 block">Zaman Aralığı:</span>
                                  <strong className="text-slate-800">{inc.timeWindow}</strong>
                                </div>
                              </div>

                              <div className="space-y-1">
                                <span className="text-[11px] font-semibold text-slate-700 block">
                                  Korelasyon Kanıt Listesi (Evidence):
                                </span>
                                <ul className="space-y-1 text-xs text-slate-700 bg-white/90 p-2.5 rounded-lg border border-slate-200/70 font-mono">
                                  {inc.correlationEvidence.map((evItem, evIdx) => (
                                    <li key={evIdx} className="flex items-center gap-1.5 text-slate-800 font-medium text-[11px]">
                                      <Check className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                                      <span>{evItem.startsWith('- ') ? evItem.substring(2) : evItem}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>

                              {/* Sequence timeline */}
                              <div className="pt-2 border-t border-slate-200/60">
                                <span className="text-[11px] font-semibold text-slate-700 block mb-1">
                                  Olay Akış Sırası (Chronological Chain):
                                </span>
                                <div className="space-y-1 text-xs font-mono">
                                  {inc.sequence.map((seq, sIdx) => (
                                    <div key={sIdx} className="flex items-center gap-2 bg-white/90 p-1.5 rounded border border-slate-200/80 text-[11px]">
                                      <span className="text-indigo-600 font-bold shrink-0">#{seq.eventIndex}</span>
                                      <span className="text-slate-400 shrink-0">{seq.timestamp}</span>
                                      <span className="text-slate-700 truncate font-semibold">{seq.action}</span>
                                      <span className="text-[10px] text-slate-500 ml-auto shrink-0 font-sans">[{seq.verdict}]</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Stage 4: Uncorrelated Important Events */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-2 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 flex items-center justify-between pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">
                          4. UNCORRELATED IMPORTANT EVENTS (İLİŞKİSİZ ÖNEMLİ / ŞÜPHELİ OLAYLAR)
                        </span>
                        <span className="text-[10px] bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono">
                          {wholeLogSummary.uncorrelatedImportantEvents.length} Olay
                        </span>
                      </div>
                      {wholeLogSummary.uncorrelatedImportantEvents.length === 0 ? (
                        <div className="p-3 bg-slate-50 text-slate-600 rounded-lg text-xs border border-slate-200">
                          Olay zincirleri dışında kalan münferit kritik/şüpheli olay bulunmamaktadır.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          <p className="text-xs text-slate-600">
                            Aşağıdaki olaylar kendi başlarına şüpheli veya inceleme gerektiren nitelikte olup, ortak host/kullanıcı/zaman bağı tespit edilemediği için bağımsız tutulmuştur:
                          </p>
                          {wholeLogSummary.uncorrelatedImportantEvents.map((evIdx) => {
                            const ev = correlatedEvents.find((e) => e.index === evIdx);
                            if (!ev) return null;
                            return (
                              <div
                                key={evIdx}
                                className="bg-slate-50 p-3 rounded-lg border border-slate-200 flex items-center justify-between text-xs gap-3"
                              >
                                <div className="space-y-0.5">
                                  <div className="font-semibold text-slate-800 flex items-center gap-2">
                                    <span className="font-mono text-indigo-600 font-bold">#{ev.index}</span>
                                    <span>{ev.threatTitle}</span>
                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${ev.verdictBadge.badgeClasses}`}>
                                      {ev.verdictBadge.text}
                                    </span>
                                  </div>
                                  <div className="text-[11px] text-slate-500 font-mono">
                                    Host: {ev.host} | Kullanıcı: {ev.user} | IP: {ev.sourceIp}
                                  </div>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedLogIndex(ev.index - 1);
                                    setActiveViewTab('eventInspector');
                                  }}
                                  className="px-2.5 py-1 bg-white hover:bg-indigo-50 hover:text-indigo-600 text-slate-700 rounded border border-slate-200 text-xs font-medium transition-colors shrink-0"
                                >
                                  Detaya Git &rarr;
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {/* Stage 5: Whole-Log Summary */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-2 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">
                          5. WHOLE-LOG SUMMARY (BÜTÜNSEL LOG DEĞERLENDİRMESİ)
                        </span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-slate-800 leading-relaxed">
                        {wholeLogSummary.overallFindings.map((finding, idx) => (
                          <li key={idx} className="flex items-start gap-2 bg-slate-50 p-2 rounded border border-slate-200/70">
                            <span className="w-1.5 h-1.5 rounded-full bg-indigo-600 mt-1.5 shrink-0" />
                            <span>{finding}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Stage 6: Analyst Actions */}
                    <div className="bg-white rounded-xl p-4 border border-slate-200 space-y-2 shadow-xs">
                      <div className="text-xs font-bold text-slate-900 pb-2 border-b border-slate-100">
                        <span className="uppercase tracking-wider text-indigo-700 font-mono">
                          6. ANALYST ACTIONS (DOĞRULANMASI GEREKEN ADIMLAR VE TEYİTLER)
                        </span>
                      </div>
                      <ol className="space-y-1.5 text-xs text-slate-800">
                        {wholeLogSummary.analystActions.map((act, idx) => (
                          <li key={idx} className="flex items-start gap-2 bg-indigo-50/50 p-2.5 rounded-lg border border-indigo-100">
                            <span className="w-5 h-5 rounded-full bg-indigo-600 text-white text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="leading-snug">{act}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    {/* Formatted Full Output Text Box */}
                    <div className="space-y-2 bg-slate-900 text-slate-100 rounded-xl p-4 border border-slate-800">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Send className="w-4 h-4 text-indigo-400" />
                          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                            Ham Metin Rapor Çıktısı (Kopyalamaya Hazır)
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={handleCopyComprehensiveReport}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md text-xs font-medium flex items-center gap-1.5 shadow-xs transition-colors"
                        >
                          {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedReport ? 'Metin Kopyalandı!' : 'Metni Kopyala'}</span>
                        </button>
                      </div>
                      <textarea
                        readOnly
                        rows={12}
                        value={comprehensive6StageReport}
                        className="w-full font-mono text-xs p-3 bg-slate-950 text-slate-200 rounded-lg border border-slate-800 focus:outline-hidden leading-relaxed select-all"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* ========================================================================= */}
              {/* TAB 2: OLAY ZİNCİRLERİ (INCIDENTS) DETAYLI GÖRÜNÜMÜ */}
              {/* ========================================================================= */}
              {activeViewTab === 'incidents' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between bg-slate-50 border border-slate-200 rounded-xl p-4">
                    <div>
                      <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                        <Network className="w-4 h-4 text-indigo-600" />
                        <span>Korele Olay Zincirleri &amp; Incident Adayları</span>
                      </h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        Ortak hedef sistem, kullanıcı hesabı ve süreç sırasına sahip ilişkili olaylar gruplandırılmıştır.
                      </p>
                    </div>
                    <span className="text-xs bg-indigo-100 text-indigo-800 font-bold px-3 py-1 rounded-full font-mono">
                      {wholeLogSummary.incidentCandidates.length} Doğrulanmış Zincir
                    </span>
                  </div>

                  {wholeLogSummary.incidentCandidates.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 space-y-2 bg-slate-50 rounded-xl border border-slate-200">
                      <Network className="w-8 h-8 mx-auto text-slate-400" />
                      <h4 className="text-sm font-semibold text-slate-700">İlişkili Olay Zinciri Bulunamadı</h4>
                      <p className="text-xs text-slate-500 max-w-md mx-auto">
                        Log dosyasındaki olaylar farklı uç noktalara, hesaplara veya zamanlara aittir. Sırf aynı dosyada bulundukları için birbirine bağlanmamış, adli veri bütünlüğü korunmuştur.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {wholeLogSummary.incidentCandidates.map((inc) => (
                        <div
                          key={inc.id}
                          className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-4"
                        >
                          <div className="flex items-center justify-between flex-wrap gap-2 pb-3 border-b border-slate-100">
                            <div className="flex items-center gap-2.5">
                              <span className="font-mono font-bold text-xs bg-slate-900 text-white px-2.5 py-1 rounded-md">
                                {inc.id}
                              </span>
                              <h4 className="text-sm font-bold text-slate-900">{inc.title}</h4>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="bg-indigo-50 text-indigo-700 font-bold text-xs px-2.5 py-1 rounded-md border border-indigo-200">
                                Korelasyon Gücü: {inc.correlationStrength}
                              </span>
                              <span className={`text-xs font-bold px-2.5 py-1 rounded-md ${
                                inc.severity === 'CRITICAL'
                                  ? 'bg-rose-100 text-rose-800'
                                  : inc.severity === 'HIGH'
                                  ? 'bg-amber-100 text-amber-800'
                                  : 'bg-slate-100 text-slate-800'
                              }`}>
                                {inc.severity}
                              </span>
                            </div>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs bg-slate-50 p-3 rounded-lg border border-slate-200/80 font-mono">
                            <div>
                              <span className="text-slate-500 block text-[10px]">Hedef Host:</span>
                              <strong className="text-slate-900 font-semibold">{inc.sharedHost}</strong>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">Kullanıcı Hesabı:</span>
                              <strong className="text-slate-900 font-semibold">{inc.sharedUser}</strong>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">Zaman Penceresi:</span>
                              <strong className="text-slate-900 font-semibold">{inc.timeWindow}</strong>
                            </div>
                          </div>

                          <div className="space-y-1.5">
                            <span className="text-xs font-bold text-slate-800 block">
                              Korelasyon Kanıt Listesi (Evidence):
                            </span>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                              {inc.correlationEvidence.map((evItem, evIdx) => (
                                <div key={evIdx} className="flex items-center gap-2 bg-slate-50 p-2 rounded border border-slate-200 text-slate-800">
                                  <Check className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                                  <span className="font-medium">{evItem.startsWith('- ') ? evItem.substring(2) : evItem}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Sequence */}
                          <div className="space-y-2 pt-2 border-t border-slate-100">
                            <span className="text-xs font-bold text-slate-800 block">
                              Zincir İçindeki Olay Sekansı:
                            </span>
                            <div className="space-y-1.5 font-mono text-xs">
                              {inc.sequence.map((item, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between bg-slate-50 p-2.5 rounded-lg border border-slate-200 hover:bg-indigo-50/40 transition-colors"
                                >
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className="font-bold text-indigo-700 bg-indigo-100 px-2 py-0.5 rounded text-[11px] shrink-0">
                                      #{item.eventIndex}
                                    </span>
                                    <span className="text-slate-400 text-[10px] shrink-0">{item.timestamp}</span>
                                    <span className="text-slate-800 truncate font-semibold">{item.action}</span>
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0">
                                    <span className="text-[10px] text-slate-600 font-sans">[{item.verdict}]</span>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setSelectedLogIndex(item.eventIndex - 1);
                                        setActiveViewTab('eventInspector');
                                      }}
                                      className="px-2 py-0.5 bg-white hover:bg-indigo-600 hover:text-white text-slate-600 rounded border border-slate-200 text-[10px] font-medium transition-colors"
                                    >
                                      Olayı Aç &rarr;
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ========================================================================= */}
              {/* TAB 3: OLAY BAZINDA DETAY (EVENT INSPECTOR) */}
              {/* ========================================================================= */}
              {activeViewTab === 'eventInspector' && (
                <div className="space-y-4">
              {/* If multiple lines pasted, show pagination chips */}
              {lines.length > 1 && (
                <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
                  <span className="text-slate-500 shrink-0 font-medium">Tespit Edilen Olaylar ({lines.length}):</span>
                  {lines.map((_, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedLogIndex(idx)}
                      className={`px-2.5 py-1 rounded-md font-mono shrink-0 transition-colors ${
                        selectedLogIndex === idx
                          ? 'bg-indigo-600 text-white font-bold'
                          : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                      }`}
                    >
                      Olay #{idx + 1}
                    </button>
                  ))}
                </div>
              )}

              {/* Forensically Calibrated Verdict Card */}
              <div className={`p-4 rounded-xl border ${currentResult.verdictBadge.cardClasses}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${currentResult.verdictBadge.iconBgClasses}`}
                    >
                      {currentResult.verdictBadge.iconType === 'shieldCheck' ? (
                        <ShieldCheck className="w-6 h-6" />
                      ) : currentResult.verdictBadge.iconType === 'shieldAlert' ? (
                        <ShieldAlert className="w-6 h-6" />
                      ) : currentResult.verdictBadge.iconType === 'shield' ? (
                        <Shield className="w-6 h-6" />
                      ) : (
                        <AlertTriangle className="w-6 h-6" />
                      )}
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${currentResult.verdictBadge.badgeClasses}`}>
                          {currentResult.verdictBadge.text}
                        </span>
                        <span className="text-xs font-medium text-slate-500">
                          Format: <strong className="text-slate-800">{currentResult.detectedFormat}</strong>
                        </span>
                        <span className="text-xs font-medium text-slate-500" title={currentResult.confidenceLabel}>
                          Olasılık: <strong className="text-slate-800">%{currentResult.confidence}</strong> ({currentResult.confidenceLabel})
                        </span>
                        {currentResult.winDetails?.mitreTechnique && (
                          <span className="text-xs font-mono bg-purple-100 text-purple-800 px-2 py-0.5 rounded">
                            MITRE {currentResult.winDetails.mitreTechnique}
                          </span>
                        )}
                      </div>
                      <h3 className="text-base font-bold text-slate-900">
                        {currentResult.threatTitle}
                      </h3>
                      <p className="text-xs text-slate-700 leading-relaxed max-w-3xl">
                        {currentResult.summaryReason}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-start shrink-0">
                    <button
                      type="button"
                      onClick={() => setActiveViewTab('l2InvestigationPlan')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow-xs transition-all cursor-pointer"
                      title="Bu olay için uygulanabilir L2 Investigation Planı & Hipotez Matrisini aç"
                    >
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-300" />
                      <span>L2 Planı &rarr;</span>
                    </button>
                  </div>
                </div>

                {/* Deep Forensics Evidence List */}
                {currentResult.deepForensics.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-200/80 space-y-1.5">
                    <div className="text-xs font-semibold text-slate-800">
                      Adli İnceleme ve Bağlam Kanıtları (Forensic Evidence):
                    </div>
                    <ul className="text-xs text-slate-700 space-y-1">
                      {currentResult.deepForensics.map((f, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Grid: Extracted Normalized Fields & Required Extra Info */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Normalized Extracted Fields - Adaptive for Windows vs Web/Network */}
                {currentResult.winDetails?.isWindowsEvent ? (
                  <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 space-y-2">
                    <div className="text-xs font-semibold text-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-4 h-4 text-indigo-600" />
                        <span>Ayrıştırılan Windows Güvenlik Olayı</span>
                      </div>
                      <span className="text-[10px] bg-indigo-100 text-indigo-800 font-bold px-2 py-0.5 rounded font-mono">
                        Event {currentResult.winDetails.eventId || 'Windows'}
                      </span>
                    </div>

                    {currentResult.winDetails.eventId === 4688 ? (
                      /* Strict Schema for Event 4688 (Process Creation) - NO Field Leakage */
                      <div className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Olay Kimliği (Event ID):</span>
                          <span className="font-semibold text-slate-800">4688 (Yeni Süreç Oluşturuldu)</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Hedef Bilgisayar (Host):</span>
                          <span className="font-semibold text-indigo-700 font-bold">
                            {currentResult.winDetails.computer || 'Bilinmiyor'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Çalıştıran Hesap (SubjectUser):</span>
                          <span className="font-semibold text-slate-900 font-bold">
                            {currentResult.winDetails.subjectUser || currentResult.winDetails.targetUser || 'SYSTEM'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Üst Süreç (Parent Process):</span>
                          <span className="font-semibold text-slate-800 truncate max-w-[200px]" title={currentResult.winDetails.parentProcess}>
                            {currentResult.winDetails.parentProcess || 'Belirtilmemiş'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200 text-slate-400">
                          <span>Oturum Türü (Logon Type):</span>
                          <span>Uygulanamaz (Süreç oluşturma)</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200 text-slate-400">
                          <span>Ağ Kaynak IP:</span>
                          <span>Uygulanamaz (Uç nokta içi)</span>
                        </div>
                        <div className="py-1">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-slate-500">Yürütülen Komut / Süreç:</span>
                            {onOpenCommandExplainer && (currentResult.winDetails.commandLine || currentResult.winDetails.processName) && (
                              <button
                                type="button"
                                onClick={() =>
                                  onOpenCommandExplainer(
                                    currentResult.winDetails?.commandLine || currentResult.winDetails?.processName || '',
                                    {
                                      username: currentResult.winDetails?.targetUser || currentResult.winDetails?.subjectUser || currentResult.parsedLog?.kullanici_adi || null,
                                      host: currentResult.winDetails?.computer || currentResult.winDetails?.workstation || currentResult.parsedLog?.sunucu_ismi || null,
                                      parentProcess: currentResult.winDetails?.parentProcess || null,
                                      processName: currentResult.winDetails?.processName || null,
                                      eventId: currentResult.winDetails?.eventId || null,
                                      timestamp: currentResult.parsedLog?.tarih || null,
                                      sourceIp: currentResult.winDetails?.sourceIp || currentResult.parsedLog?.ip_adresi || null,
                                      logSource: 'Windows Event / Sysmon',
                                    }
                                  )
                                }
                                className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded transition-colors cursor-pointer"
                                title="Bu komutun tüm parametrelerini ve amacını anında açıkla"
                              >
                                <Terminal className="w-3 h-3 text-indigo-600" />
                                <span>Komutu Açıkla</span>
                              </button>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-800 bg-white p-2 rounded border border-slate-200 break-all font-mono">
                            {currentResult.winDetails.commandLine || currentResult.winDetails.processName || 'Belirtilmemiş'}
                          </div>
                        </div>
                      </div>
                    ) : currentResult.winDetails.eventId === 7045 || currentResult.winDetails.eventId === 4697 ? (
                      /* Strict Schema for Event 7045 (New Service Installed) */
                      <div className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Olay Kimliği (Event ID):</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.eventId} ({currentResult.winDetails.eventName})
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Servis Adı:</span>
                          <span className="font-semibold text-indigo-700 font-bold">
                            {currentResult.winDetails.serviceName || 'Bilinmiyor'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Kuran Hesap:</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.subjectUser || 'Bilinmiyor'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Hedef Bilgisayar:</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.computer || 'Windows Endpoint'}
                          </span>
                        </div>
                        <div className="py-1">
                          <span className="text-slate-500 block mb-0.5">Servis Dosya Yolu:</span>
                          <div className="text-[11px] text-slate-800 bg-white p-2 rounded border border-slate-200 break-all font-mono">
                            {currentResult.winDetails.serviceFile || 'Belirtilmemiş'}
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Strict Schema for Logon/Audit Events (4624, 4625, etc.) */
                      <div className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Olay Kimliği (Event ID):</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.eventId ? `${currentResult.winDetails.eventId} (${currentResult.winDetails.eventName})` : '-'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Hedef Hesap (Target User):</span>
                          <span className="font-semibold text-indigo-700 font-bold">
                            {currentResult.winDetails.targetUser || '-'}
                          </span>
                        </div>
                        {currentResult.winDetails.subjectUser && (
                          <div className="flex justify-between py-1 border-b border-slate-200">
                            <span className="text-slate-500">Tetikleyen Hesap (Subject):</span>
                            <span className="font-semibold text-slate-800">
                              {currentResult.winDetails.subjectUser}
                            </span>
                          </div>
                        )}
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Oturum Türü (Logon Type):</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.logonTypeDesc}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Hata Kodu / Neden:</span>
                          <span className="font-semibold text-rose-600">
                            {currentResult.winDetails.subStatus
                              ? `${currentResult.winDetails.subStatus} ${currentResult.winDetails.subStatusDesc ? `(${currentResult.winDetails.subStatusDesc})` : ''}`
                              : currentResult.winDetails.status || 'Normal Akış'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">İş İstasyonu / Bilgisayar:</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.workstation || currentResult.winDetails.computer || '-'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-200">
                          <span className="text-slate-500">Kaynak IP / Port:</span>
                          <span className="font-semibold text-slate-800">
                            {currentResult.winDetails.sourceIp || '-'}{currentResult.winDetails.sourcePort ? `:${currentResult.winDetails.sourcePort}` : ''}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 space-y-2">
                    <div className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                      <Search className="w-4 h-4 text-slate-600" />
                      <span>Ayrıştırılan Log Değerleri (Ağ &amp; Web Olayı)</span>
                    </div>
                    <div className="space-y-1 text-xs font-mono">
                      <div className="flex justify-between py-1 border-b border-slate-200">
                        <span className="text-slate-500">Kaynak IP / Port:</span>
                        <span className="font-semibold text-slate-800">
                          {currentResult.parsedLog?.ip_adresi || '-'}:
                          {currentResult.parsedLog?.kaynak_port || '-'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-200">
                        <span className="text-slate-500">Hedef IP / Port:</span>
                        <span className="font-semibold text-slate-800">
                          {currentResult.parsedLog?.hedef_ip || '-'}:
                          {currentResult.parsedLog?.hedef_port || '-'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-200">
                        <span className="text-slate-500">HTTP Metot / Durum:</span>
                        <span className="font-semibold text-slate-800">
                          {currentResult.parsedLog?.http_method || '-'}{' '}
                          {currentResult.parsedLog?.status_code ? `(${currentResult.parsedLog.status_code})` : ''}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-200">
                        <span className="text-slate-500">Bağlantı / Cihaz Kararı:</span>
                        <span
                          className={`font-semibold ${
                            currentResult.parsedLog?.baglanti_karari.startsWith('DENY') || currentResult.verdict === 'BLOCKED_ATTACK_ATTEMPT'
                              ? 'text-rose-600'
                              : 'text-emerald-700'
                          }`}
                        >
                          {currentResult.parsedLog?.baglanti_karari || '-'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-200">
                        <span className="text-slate-500">Hedef Host:</span>
                        <span className="font-semibold text-slate-800 truncate max-w-[200px]" title={currentResult.parsedLog?.sunucu_ismi || ''}>
                          {currentResult.parsedLog?.sunucu_ismi || '-'}
                        </span>
                      </div>
                      <div className="py-1">
                        <span className="text-slate-500 block mb-0.5">İstek Komutu / URL:</span>
                        <div className="text-[11px] text-slate-800 bg-white p-2 rounded border border-slate-200 break-all">
                          {currentResult.parsedLog?.islem_komutu || '-'}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Required Extra Info for Customer - Intelligently Tailored */}
                <div className="bg-blue-50/60 rounded-xl p-4 border border-blue-200 space-y-2">
                  <div className="text-xs font-semibold text-blue-900 flex items-center gap-1.5">
                    <HelpCircle className="w-4 h-4 text-blue-700" />
                    <span>Müşteriden Talep Edilmesi Gereken Teyitler</span>
                  </div>
                  <p className="text-[11px] text-blue-800 leading-relaxed">
                    Bu olayı kesinleştirmek ve müşterinin sistem yöneticisinden doğrulatmak üzere özel olarak türetilen sorular:
                  </p>
                  <ul className="space-y-1.5 text-xs text-blue-950">
                    {currentResult.requiredExtraInfo.map((info, idx) => (
                      <li key={idx} className="flex items-start gap-2 bg-white/80 p-2 rounded border border-blue-100">
                        <span className="w-4 h-4 rounded-full bg-blue-200 text-blue-900 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span className="leading-snug">{info}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Forensic Data Integrity & Cross-Event Traceability Card */}
              {currentResult.correlations && currentResult.correlations.length > 0 && (
                <div className="bg-emerald-50/80 rounded-xl p-4 border border-emerald-200 text-xs space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-bold text-emerald-900">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      <span>Adli Veri Bütünlüğü &amp; Olay İzolasyonu Doğrulandı</span>
                    </div>
                    <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2.5 py-0.5 rounded-full font-mono font-bold border border-emerald-200">
                      Sızıntısız Bağımsız Nesne Modeli
                    </span>
                  </div>
                  <p className="text-[11px] text-emerald-800 leading-relaxed">
                    Her log satırı bağımsız bir adli olay nesnesi olarak işlenmiştir. Farklı olaylara ait alanlar (LogonType, SubStatus, WorkstationName, SourceNetworkAddress, Servis Kurulumu vb.) mevcut olaya kopyalanmamış, yapay alan sızıntısı (field leakage) engellenmiştir.
                  </p>
                  <div className="pt-2 border-t border-emerald-200/80 space-y-1.5">
                    <span className="font-semibold text-emerald-950 block text-[11px]">
                      Ayrık Olarak İzlenen Diğer Olaylar ({currentResult.correlations.length}):
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {currentResult.correlations.map((corr, cIdx) => (
                        <div
                          key={cIdx}
                          className="bg-white/90 rounded-lg p-2.5 border border-emerald-200/70 font-mono text-[11px] text-slate-700 flex flex-col gap-1 shadow-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-indigo-700">
                              [Event {corr.sourceEventId}] {corr.sourceHost}
                            </span>
                            <span className="text-[10px] text-slate-500 font-sans">
                              {corr.eventType}
                            </span>
                          </div>
                          {corr.isolatedFields.length > 0 && (
                            <div className="text-[10px] text-slate-600">
                              İzole Edilen Alanlar: <span className="text-slate-800 font-semibold">{corr.isolatedFields.join(', ')}</span>
                            </div>
                          )}
                          <div className="text-[10px] text-emerald-700 font-sans italic">
                            Gerekçe: {corr.correlationReason}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Ready-to-Send Customer Response Text Template */}
              <div className="space-y-2 bg-slate-900 text-slate-100 rounded-xl p-4 border border-slate-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Send className="w-4 h-4 text-indigo-400" />
                    <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                      Müşteriye Gönderilmeye Hazır Profesyonel SOC Yanıtı
                    </span>
                  </div>
                  <button
                    id="quick-log-copy-response-btn"
                    type="button"
                    onClick={handleCopyResponse}
                    className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-md text-xs font-medium flex items-center gap-1.5 shadow-xs transition-colors"
                  >
                    {copiedResponse ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedResponse ? 'Metin Kopyalandı!' : 'Yanıtı Kopyala'}</span>
                  </button>
                </div>

                <div className="relative">
                  <textarea
                    id="quick-log-response-textarea"
                    readOnly
                    rows={9}
                    value={currentResult.customerResponseText}
                    className="w-full font-mono text-xs p-3 bg-slate-950 text-slate-200 rounded-lg border border-slate-800 focus:outline-hidden leading-relaxed select-all"
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                  <span className="flex items-center gap-1">
                    <Info className="w-3.5 h-3.5 text-slate-500" />
                    Bu şablon, ham logdan doğrudan türetilmiştir. Sıfır uydurma veri içerir.
                  </span>
                  {onImportToHunting && (
                    <button
                      id="quick-log-import-hunting-btn"
                      type="button"
                      onClick={handleImport}
                      className="text-indigo-400 hover:text-indigo-300 font-semibold underline decoration-indigo-400/50 hover:decoration-indigo-300 transition-colors"
                    >
                      Bu logu Derin Tehdit Avı (Threat Hunting) paneline aktar &rarr;
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 4: QRADAR AQL & REGEX STUDIO */}
          {/* ========================================================================= */}
          {activeViewTab === 'qradarStudio' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-blue-400" />
                    <span>Çoklu SIEM Avcılık &amp; Kural Stüdyosu (Splunk, Sentinel, Elastic, Sigma, QRadar)</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Yapıştırılan logdan türetilen Splunk SPL, Microsoft Sentinel KQL, Elastic KQL/EQL, evrensel Sigma kuralları ve QRadar AQL avcılık sorguları.
                  </p>
                </div>
                {onImportToHunting && (
                  <button
                    id="quick-log-qradar-import-hunting-btn"
                    type="button"
                    onClick={handleImport}
                    className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-xs transition-colors shrink-0"
                  >
                    <span>Derin Tehdit Avı Paneline Aktar &rarr;</span>
                  </button>
                )}
              </div>

              <QradarAqlStudio
                rawLogSample={lines[selectedLogIndex] || rawText}
                contextParams={{
                  ip: currentResult?.parsedLog?.ip_adresi !== '-' ? currentResult?.parsedLog?.ip_adresi : currentResult?.winDetails?.sourceIp,
                  destIp: currentResult?.parsedLog?.hedef_ip !== '-' ? currentResult?.parsedLog?.hedef_ip : undefined,
                  user: currentResult?.parsedLog?.kullanici_adi !== '-' ? currentResult?.parsedLog?.kullanici_adi : currentResult?.winDetails?.targetUser,
                  port: currentResult?.parsedLog?.hedef_port || currentResult?.winDetails?.sourcePort,
                  method: currentResult?.parsedLog?.http_method,
                  url: currentResult?.parsedLog?.islem_komutu,
                  statusCode: currentResult?.parsedLog?.status_code,
                  eventId: currentResult?.winDetails?.eventId ?? undefined,
                  processName: currentResult?.winDetails?.processName,
                  hostname: currentResult?.parsedLog?.sunucu_ismi !== '-' ? currentResult?.parsedLog?.sunucu_ismi : currentResult?.winDetails?.computer,
                }}
              />
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 5: L2 INCIDENT INVESTIGATION PLAN & HYPOTHESIS MATRIX */}
          {/* ========================================================================= */}
          {activeViewTab === 'l2InvestigationPlan' && (
            <div className="space-y-4">
              {currentL2Plan ? (
                <L2InvestigationPlanView plan={currentL2Plan} />
              ) : (
                <div className="p-8 text-center text-slate-500 bg-white rounded-xl border border-slate-200">
                  L2 Investigation planı oluşturmak için lütfen yukarıya bir log yapıştırın.
                </div>
              )}
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 6: GÖRSEL ADLİ İNCELEME & SCREENSHOT L2 INVESTIGATION */}
          {/* ========================================================================= */}
          {activeViewTab === 'imageForensic' && (
            <div className="space-y-4">
              {imageForensicResult ? (
                <ImageForensicView
                  result={imageForensicResult}
                  imagePreviewUrl={imagePreviewUrl}
                  onClearImage={handleClearImage}
                  onOpenCommandExplainer={onOpenCommandExplainer}
                />
              ) : (
                <div className="p-8 text-center text-slate-500 bg-white rounded-xl border border-slate-200">
                  Görsel adli inceleme için lütfen yukarıdan bir ekran görüntüsü yükleyin veya yapıştırın.
                </div>
              )}
            </div>
          )}
        </div>
      )}

          {/* Direct Image Forensic View when no text logs pasted, but image is analyzed */}
          {lines.length === 0 && imageForensicResult && (
            <div className="space-y-4 pt-2 border-t border-slate-200">
              <ImageForensicView
                result={imageForensicResult}
                imagePreviewUrl={imagePreviewUrl}
                onClearImage={handleClearImage}
                onOpenCommandExplainer={onOpenCommandExplainer}
              />
            </div>
          )}

          {/* Empty State when no text and no image */}
          {lines.length === 0 && !imageForensicResult && !isAnalyzingImage && (
            <div className="py-12 text-center text-slate-400 space-y-3 bg-slate-50 rounded-xl border border-dashed border-slate-200">
              <div className="w-12 h-12 mx-auto rounded-full bg-slate-100 flex items-center justify-center text-slate-400">
                <FileText className="w-6 h-6" />
              </div>
              <div className="max-w-md mx-auto space-y-2">
                <h4 className="text-sm font-semibold text-slate-700">Analiz Edilecek Log veya Ekran Görüntüsü Bekleniyor</h4>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Yukarıdaki alana Windows Olay Günlüğü (4625, 4624, 4688, 1102 vb.), FortiWeb WAF, Firewall veya Syslog kaydınızı yapıştırın ya da doğrudan güvenlik ekran görüntüsü yükleyin / yapıştırın (Ctrl+V).
                </p>
                <div className="flex items-center justify-center gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>Ekran Görüntüsü Yükle</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-end px-6 py-3 border-t border-slate-200 bg-slate-50 text-xs">
          <button
            id="quick-log-close-footer-btn"
            onClick={onClose}
            className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-800 rounded-lg font-medium transition-colors"
          >
            Kapat
          </button>
        </div>
      </div>
    </div>
  );
};
