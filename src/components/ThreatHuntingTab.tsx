import React, { useState, useMemo } from 'react';
import { TablePagination, usePagination } from './TablePagination';
import {
  HuntingReport,
  RiskQueueItem,
  RiskLevel,
  DetectionProfile,
} from '../types';
import {
  Upload,
  Download,
  FileCode,
  AlertTriangle,
  Server,
  Radio,
  FileSpreadsheet,
  CheckCircle2,
  XCircle,
  Clock,
  Terminal,
  ArrowRight,
  ShieldCheck,
  Search,
  Database,
  Plus,
  Trash2,
  X,
  FileText,
  ShieldAlert,
  Sparkles,
  Loader2,
  Layers,
  Files,
  Filter,
  Scale,
  Mail,
  Info,
  ExternalLink,
  Activity,
  Network,
  Clipboard,
  Play,
  Zap,
  RotateCcw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Legend,
} from 'recharts';
import { generateHTMLReport } from '../services/reportGenerator';
import { PortBadgesCell } from './PortBadgesCell';
import { PortDetailsModal } from './PortDetailsModal';
import { FileBreakdownModal } from './FileBreakdownModal';
import { ForensicQuarantineModal } from './ForensicQuarantineModal';
import { RiskExplainModal } from './RiskExplainModal';
import { AnalysisProgress } from '../services/logWorkerController';
import { DuckDbHuntingConsole } from './DuckDbHuntingConsole';
import { QradarAqlStudio } from './QradarAqlStudio';
import { analyzeRawLogText } from '../services/quickLogAnalyzer';
import {
  requestAiSocAnalysis,
  formatGemini38FlashForensicReport,
} from '../services/aiService';

interface ThreatHuntingTabProps {
  report: HuntingReport;
  onUploadFiles: (files: FileList | File[]) => void;
  onRemoveFile?: (fileName: string) => void;
  onClearAllFiles?: () => void;
  exfiltrationMb: number;
  setExfiltrationMb: (mb: number) => void;
  failedAttempts: number;
  setFailedAttempts: (count: number) => void;
  useAllowlist: boolean;
  setUseAllowlist: (val: boolean) => void;
  detectionProfile?: DetectionProfile;
  setDetectionProfile?: (profile: DetectionProfile) => void;
  onOpenAiModal?: (item?: RiskQueueItem, ip?: string) => void;
  onOpenQuickLogModal?: () => void;
  onPasteAndHunt?: (rawText: string) => void;
  onOpenCommandExplainer?: (initialCommand?: string, context?: any) => void;
  activeFiles: string[];
  isProcessing?: boolean;
  progress?: AnalysisProgress | null;
  onAbort?: () => void;
  onNavigateToPolicyComparison?: () => void;
}

type SubTab =
  | 'raw_log_triage'
  | 'risk_queue'
  | 'dest_ports'
  | 'cross_day'
  | 'data_transfer'
  | 'webshell'
  | 'bots'
  | 'ftp'
  | 'brute_force'
  | 'suspicious_cmds'
  | 'duckdb_sql';

export const ThreatHuntingTab: React.FC<ThreatHuntingTabProps> = ({
  report,
  onUploadFiles,
  onRemoveFile,
  onClearAllFiles,
  exfiltrationMb,
  setExfiltrationMb,
  failedAttempts,
  setFailedAttempts,
  useAllowlist,
  setUseAllowlist,
  detectionProfile = 'BALANCED',
  setDetectionProfile,
  onOpenAiModal,
  onOpenQuickLogModal,
  onPasteAndHunt,
  onOpenCommandExplainer,
  activeFiles,
  isProcessing = false,
  progress = null,
  onAbort,
  onNavigateToPolicyComparison,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>('risk_queue');
  const [copiedTriageReport, setCopiedTriageReport] = useState(false);
  const [triageReportOverride, setTriageReportOverride] = useState<string | null>(null);
  const [isRegeneratingAiReport, setIsRegeneratingAiReport] = useState(false);
  const [rawLogInput, setRawLogInput] = useState('');
  const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste');
  const [isHeaderPasteOpen, setIsHeaderPasteOpen] = useState(false);
  const [copiedRawNotification, setCopiedRawNotification] = useState(false);

  // Automatically focus the Raw Log Triage tab if imported from Quick Log Paste
  React.useEffect(() => {
    if (report.raw_log_triage) {
      setActiveSubTab('raw_log_triage');
    }
  }, [report.raw_log_triage?.pastedAt]);

  const handleRegenerateAiTriageReport = async () => {
    if (!report.raw_log_triage) return;
    setIsRegeneratingAiReport(true);
    try {
      const socAnalysis = await requestAiSocAnalysis({
        report,
        targetIp: report.top_ips?.[0]?.ip_adresi || report.entity_risk_queue?.[0]?.ip_adresi,
        customNotes: `Log Triage & Olay Analiz Raporu: ${report.raw_log_triage.evidenceBasedSummary || ''}`,
      });
      const generatedMarkdown = formatGemini38FlashForensicReport(socAnalysis, {
        totalEvents: report.raw_log_triage.totalEvents,
        postureTitle: report.raw_log_triage.postureTitle,
        rawLinesCount: report.raw_log_triage.totalEvents,
        rawTextSample: report.raw_log_triage.rawText,
      });
      setTriageReportOverride(generatedMarkdown);
    } catch (err) {
      console.warn('AI Triage Report generation failed:', err);
    } finally {
      setIsRegeneratingAiReport(false);
    }
  };

  const currentTriageReport = triageReportOverride || report.raw_log_triage?.fullReportText || '';

  const handleCopyTriageReport = () => {
    if (currentTriageReport) {
      navigator.clipboard.writeText(currentTriageReport);
      setCopiedTriageReport(true);
      setTimeout(() => setCopiedTriageReport(false), 2000);
    }
  };
  const [searchTerm, setSearchTerm] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [isFileBreakdownOpen, setIsFileBreakdownOpen] = useState(false);
  const [isQuarantineModalOpen, setIsQuarantineModalOpen] = useState(false);
  const [explainModalItem, setExplainModalItem] = useState<RiskQueueItem | null>(null);
  const [selectedFileFilter, setSelectedFileFilter] = useState<string | null>(null);
  const [portModalData, setPortModalData] = useState<{
    isOpen: boolean;
    hedefIp: string;
    portString: string;
  }>({
    isOpen: false,
    hedefIp: '',
    portString: '',
  });
  const [selectedPortFilter, setSelectedPortFilter] = useState<number | null>(null);

  // --- MEMOIZED & PAGINATED DATASETS TO PREVENT BROWSER FREEZING ---
  // 1. Risk Queue Pagination
  const filteredRiskQueue = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.entity_risk_queue.filter(r =>
      r.ip_adresi.includes(searchTerm) ||
      r.sunucu_ismi.toLowerCase().includes(term) ||
      r.risk_gerekcesi.toLowerCase().includes(term)
    );
  }, [report.entity_risk_queue, searchTerm]);
  const riskQueuePage = usePagination(filteredRiskQueue, 25);

  // 2. Dest IP & Port Pagination
  const filteredDestIp = useMemo(() => {
    return report.destination_ip_analysis.filter(d =>
      d.hedef_ip.includes(searchTerm) || d.portlar.includes(searchTerm)
    );
  }, [report.destination_ip_analysis, searchTerm]);
  const destIpPage = usePagination(filteredDestIp, 25);

  const filteredPortAnalysis = useMemo(() => {
    return report.port_analysis
      .filter(p => selectedPortFilter === null || p.port === selectedPortFilter)
      .filter(p => String(p.port).includes(searchTerm) || p.servis_tahmini.toLowerCase().includes(searchTerm.toLowerCase()));
  }, [report.port_analysis, selectedPortFilter, searchTerm]);
  const portPage = usePagination(filteredPortAnalysis, 25);

  // 3. Cross Day Correlation
  const filteredCrossDay = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.cross_day_correlation.filter(c =>
      c.ip_adresi.includes(searchTerm) ||
      c.kullanici_adi.toLowerCase().includes(term) ||
      c.asama_izleri.toLowerCase().includes(term)
    );
  }, [report.cross_day_correlation, searchTerm]);
  const crossDayPage = usePagination(filteredCrossDay, 25);

  // 4. Data Transfer
  const filteredDataTransfer = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.data_transfer_details
      .filter(t => !selectedFileFilter || !t.kaynak_dosya || t.kaynak_dosya.includes(selectedFileFilter))
      .filter(t =>
        t.ip_adresi.includes(searchTerm) || t.kullanici_adi.toLowerCase().includes(term)
      );
  }, [report.data_transfer_details, searchTerm, selectedFileFilter]);
  const dataTransferPage = usePagination(filteredDataTransfer, 25);

  const filteredLargestRequests = useMemo(() => {
    return report.largest_transfer_requests
      .filter(r => !selectedFileFilter || !r.kaynak_dosya || r.kaynak_dosya.includes(selectedFileFilter))
      .filter(r =>
        r.ip_adresi.includes(searchTerm) || r.islem_komutu.includes(searchTerm)
      );
  }, [report.largest_transfer_requests, searchTerm, selectedFileFilter]);
  const largestRequestsPage = usePagination(filteredLargestRequests, 25);

  // 5. Webshell
  const filteredWebshell = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.webshell_and_file_management.filter(w =>
      w.ip_adresi.includes(searchTerm) || w.eylem_ornekleri.toLowerCase().includes(term)
    );
  }, [report.webshell_and_file_management, searchTerm]);
  const webshellPage = usePagination(filteredWebshell, 25);

  const filteredWebshellTimeline = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.webshell_activity_timeline.filter(t =>
      t.ip_adresi.includes(searchTerm) || t.islem_komutu.toLowerCase().includes(term)
    );
  }, [report.webshell_activity_timeline, searchTerm]);
  const webshellTimelinePage = usePagination(filteredWebshellTimeline, 25);

  // 6. Bots / Scanners
  const filteredScanners = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.scanner_and_bots.filter(b =>
      b.ip_adresi.includes(searchTerm) || b.user_agent.toLowerCase().includes(term)
    );
  }, [report.scanner_and_bots, searchTerm]);
  const scannersPage = usePagination(filteredScanners, 25);

  // 7. Brute Force & Password Spraying
  const filteredBruteForce = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.brute_force_attempts.filter(bf =>
      bf.ip_adresi.includes(searchTerm) || bf.kullanici_adi.toLowerCase().includes(term)
    );
  }, [report.brute_force_attempts, searchTerm]);
  const bruteForcePage = usePagination(filteredBruteForce, 25);

  const filteredPasswordSpraying = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.password_spraying.filter(ps =>
      ps.ip_adresi.includes(searchTerm) || ps.hedeflenen_kullanicilar.toLowerCase().includes(term)
    );
  }, [report.password_spraying, searchTerm]);
  const passwordSprayingPage = usePagination(filteredPasswordSpraying, 25);

  // 8. FTP
  const filteredFtpFiles = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.ftp_file_operations.filter(f =>
      f.ip_adresi.includes(searchTerm) || f.kullanici_adi.toLowerCase().includes(term) || f.sunucu_ismi.toLowerCase().includes(term)
    );
  }, [report.ftp_file_operations, searchTerm]);
  const ftpFilesPage = usePagination(filteredFtpFiles, 25);

  const filteredFtpSuspicious = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.ftp_suspicious_activity.filter(s =>
      s.ip_adresi.includes(searchTerm) || s.islem_komutu.toLowerCase().includes(term) || s.kullanici_adi.toLowerCase().includes(term)
    );
  }, [report.ftp_suspicious_activity, searchTerm]);
  const ftpSuspiciousPage = usePagination(filteredFtpSuspicious, 25);

  // 9. Suspicious Commands & Sensitive Endpoints
  const filteredCommands = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.suspicious_commands.filter(c =>
      c.sunucu_ismi.toLowerCase().includes(term) || c.islem_komutu.toLowerCase().includes(term)
    );
  }, [report.suspicious_commands, searchTerm]);
  const commandsPage = usePagination(filteredCommands, 25);

  const filteredEndpoints = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return report.sensitive_endpoints.filter(e =>
      e.sunucu_ismi.toLowerCase().includes(term) || e.islem_komutu.toLowerCase().includes(term)
    );
  }, [report.sensitive_endpoints, searchTerm]);
  const endpointsPage = usePagination(filteredEndpoints, 25);

  const summary = report.summary;
  const totalGb = (summary.toplam_transfer_byte / (1024 * 1024 * 1024)).toFixed(2);

  const handleDownloadHtml = () => {
    const htmlContent = generateHTMLReport(report);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc_threat_hunting_report_${new Date().toISOString().substring(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc_threat_hunting_report_${new Date().toISOString().substring(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onUploadFiles(e.dataTransfer.files);
    }
  };

  const handleStartHuntingWithLogs = (textToUse?: string) => {
    const text = (textToUse !== undefined ? textToUse : rawLogInput).trim();
    if (!text) return;

    if (onPasteAndHunt) {
      onPasteAndHunt(text);
    } else {
      const res = analyzeRawLogText(text);
      if (res) {
        onUploadFiles([res.file]);
      }
    }
    setRawLogInput('');
    setIsHeaderPasteOpen(false);
  };

  const handlePasteFromClipboard = async () => {
    try {
      if (navigator?.clipboard?.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setRawLogInput(text);
        }
      }
    } catch (err) {
      console.warn('Pano okuma izni alınamadı:', err);
    }
  };

  const subTabButtons: { key: SubTab; label: string; count?: number; color?: string; badge?: string }[] = useMemo(() => {
    const buttons: { key: SubTab; label: string; count?: number; color?: string; badge?: string }[] = [];
    if (report.raw_log_triage) {
      buttons.push({
        key: 'raw_log_triage',
        label: '⚡ Raw Log SOC Triage & QRadar Studio',
        count: report.raw_log_triage.totalEvents,
        badge: report.raw_log_triage.postureTitle,
      });
    }
    buttons.push(
      { key: 'risk_queue', label: '🚨 Öncelikli Risk Kuyruğu', count: report.entity_risk_queue.length },
      { key: 'dest_ports', label: '🎯 Hedef IP & Portlar', count: report.destination_ip_analysis.length },
      { key: 'cross_day', label: '📅 Günler Arası Korelasyon', count: report.cross_day_correlation.length },
      { key: 'data_transfer', label: '💾 Veri Transfer Kanıtları', count: report.data_transfer_details.length },
      { key: 'webshell', label: '🪓 Webshell & Dosya Yönetimi', count: report.webshell_and_file_management.length },
      { key: 'bots', label: '🤖 Bot & Tarayıcı Tespiti', count: report.scanner_and_bots.length },
      { key: 'ftp', label: '📁 FTP Operasyonları', count: report.ftp_file_operations.length + report.ftp_authentication.length },
      { key: 'brute_force', label: '🔑 Brute Force & Password Spraying', count: report.brute_force_attempts.length },
      { key: 'suspicious_cmds', label: '⚡ Şüpheli Komutlar & Hassas Yollar', count: report.suspicious_commands.length },
      { key: 'duckdb_sql', label: '🦆 DuckDB SQL Hunting', count: summary.toplam_olay },
    );
    return buttons;
  }, [report, summary.toplam_olay]);

  const getSeverityBadge = (level: RiskLevel) => {
    switch (level) {
      case 'KRİTİK':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'YÜKSEK':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'ORTA':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  // If no files are uploaded, show the dedicated user upload and ingestion screen
  if (activeFiles.length === 0 || summary.toplam_olay === 0) {
    return (
      <div className="space-y-6">
        <div className="bg-white rounded-2xl border border-slate-200 p-8 sm:p-12 shadow-xs text-center">
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="w-16 h-16 bg-blue-50 text-blue-600 rounded-2xl flex items-center justify-center mx-auto shadow-inner">
              {isProcessing ? (
                <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
              ) : (
                <ShieldAlert className="w-8 h-8" />
              )}
            </div>

            <div>
              <h2 className="text-2xl font-bold text-slate-900 tracking-tight">
                {isProcessing
                  ? 'Log Dosyaları İşleniyor...'
                  : activeFiles.length > 0
                  ? 'Analiz Edilecek Olay Bulunamadı'
                  : 'Log Dosyalarını Yükleyin'}
              </h2>
              <p className="text-sm text-slate-500 mt-2 leading-relaxed">
                {isProcessing
                  ? 'Loglar ayrıştırılıyor ve analiz ediliyor...'
                  : activeFiles.length > 0
                  ? 'Geçerli log kaydı bulunamadı veya filtreler tarafından elendi.'
                  : 'İncelemek istediğiniz log dosyalarını bırakın veya seçin.'}
              </p>

              {activeFiles.length > 0 && !isProcessing && (
                <div className="mt-4 p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs text-left max-w-lg mx-auto space-y-2">
                  <div className="font-bold flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    <span>Yüklenen Dosyalar ({activeFiles.length}):</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {activeFiles.map((fn, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-white border border-amber-300 font-mono text-[11px]">
                        {fn}
                      </span>
                    ))}
                  </div>
                  {useAllowlist && (
                    <div className="pt-2 border-t border-amber-200 flex items-center justify-between gap-3">
                      <span>💡 Güvenli İzin Listesi açık olduğu için kayıtlar elenmiş olabilir.</span>
                      <button
                        onClick={() => setUseAllowlist(false)}
                        className="px-2.5 py-1 bg-amber-600 hover:bg-amber-700 text-white rounded font-bold whitespace-nowrap cursor-pointer"
                      >
                        İzin Listesini Kapat
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Active In-Progress Processing Banner */}
            {isProcessing && progress && (
              <div className="bg-slate-900 text-white rounded-2xl p-6 shadow-xl border border-slate-800 text-left">
                <div className="flex items-center justify-between gap-4 mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-blue-500/20 border border-blue-400/30 flex items-center justify-center">
                      <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white">
                        {progress.stage === 'CORRELATING' ? 'Tehdit Korelasyonu Yapılıyor' : 'Log Satırları Ayrıştırılıyor'}
                      </h4>
                      <p className="text-xs text-slate-400">
                        {progress.stageMessage || `${progress.fileName || 'Dosya'} okunuyor...`}
                      </p>
                    </div>
                  </div>
                  <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-300 font-mono font-bold text-xs">
                    %{Math.min(100, Math.max(1, progress.percent))}
                  </span>
                </div>

                <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-700 mb-3">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-blue-500 to-emerald-400 transition-all duration-150"
                    style={{ width: `${Math.min(100, Math.max(1, progress.percent))}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800">
                  <div className="flex items-center gap-2 font-mono">
                    <span className="text-slate-200 font-bold">{progress.linesRead.toLocaleString()}</span>
                    <span>satır okundu</span>
                  </div>
                  {onAbort && (
                    <button
                      onClick={onAbort}
                      className="text-red-400 hover:text-red-300 hover:underline font-semibold cursor-pointer"
                    >
                      İptal Et
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Input Mode Selector: Primary Live Paste vs Secondary File Upload */}
            <div className="flex items-center justify-center">
              <div className="inline-flex p-1 bg-slate-100 rounded-xl border border-slate-200 shadow-2xs">
                <button
                  type="button"
                  id="tab-mode-paste"
                  onClick={() => setInputMode('paste')}
                  className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    inputMode === 'paste'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                  }`}
                >
                  <Zap className="w-4 h-4 text-amber-300" />
                  <span>⚡ Hızlı Log Yapıştır &amp; Tehdit Avı (Günlük SOC)</span>
                </button>
                <button
                  type="button"
                  id="tab-mode-upload"
                  onClick={() => setInputMode('upload')}
                  className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    inputMode === 'upload'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                  }`}
                >
                  <Upload className="w-4 h-4" />
                  <span>📁 Dosya / Arşiv Yükle (.log, .xlsx)</span>
                </button>
              </div>
            </div>

            {/* MODE 1: Direct Paste & Threat Hunting Console (PRIMARY SOC ANALYST WORKFLOW) */}
            {inputMode === 'paste' && (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 sm:p-6 text-left shadow-lg space-y-4">
                {/* Header & Quick Action Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span className="text-xs font-bold text-white tracking-wide uppercase">
                      Ham Log Konsolu (Windows 4625/4688, WAF, Firewall, IIS)
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={handlePasteFromClipboard}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                      title="Panodaki metni doğrudan yapıştır"
                    >
                      <Clipboard className="w-3.5 h-3.5 text-blue-400" />
                      <span>Panodan Yapıştır</span>
                    </button>
                    {rawLogInput && (
                      <button
                        type="button"
                        onClick={() => setRawLogInput('')}
                        className="px-2 py-1.5 text-slate-400 hover:text-red-400 text-[11px] font-medium transition-colors cursor-pointer"
                        title="Metin kutusunu temizle"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline mr-1" />
                        Temizle
                      </button>
                    )}
                  </div>
                </div>

                {/* Main Textarea */}
                <div className="relative">
                  <textarea
                    id="direct-threat-hunting-raw-textarea"
                    value={rawLogInput}
                    onChange={(e) => setRawLogInput(e.target.value)}
                    onKeyDown={(e) => {
                      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                        e.preventDefault();
                        handleStartHuntingWithLogs();
                      }
                    }}
                    placeholder="Buraya analiz edilecek SIEM alarmı, ticket veya müşteri logunu yapıştırın (Ctrl + V)..."
                    className="w-full min-h-[220px] max-h-[420px] bg-slate-950/90 text-emerald-400 font-mono text-xs sm:text-sm p-4 rounded-xl border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 focus:outline-none transition-all placeholder:text-slate-600 leading-relaxed resize-y shadow-inner"
                    spellCheck={false}
                  />
                  {!rawLogInput && (
                    <div className="absolute bottom-3 right-3 text-[11px] text-slate-500 pointer-events-none font-mono">
                      Ctrl + V ile doğrudan yapıştırabilirsiniz
                    </div>
                  )}
                </div>

                {/* Footer Controls & Primary Action */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
                  <div className="flex items-center gap-3 text-xs text-slate-400">
                    <span className="font-mono text-slate-300 font-semibold">
                      {rawLogInput ? rawLogInput.split('\n').filter((l) => l.trim().length > 0).length : 0} satır log
                    </span>
                    <span className="text-slate-600">•</span>
                    <span className="text-[11px] text-slate-400">
                      Kısayol: <kbd className="px-1.5 py-0.5 bg-slate-800 rounded border border-slate-700 text-slate-300 font-mono text-[10px]">Ctrl + Enter</kbd>
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {onOpenQuickLogModal && (
                      <button
                        type="button"
                        onClick={onOpenQuickLogModal}
                        className="px-3.5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
                        title="Eski modal görünümünde önizleme yap"
                      >
                        Ayrı Pencerede Aç
                      </button>
                    )}

                    <button
                      type="button"
                      id="start-threat-hunting-direct-btn"
                      onClick={() => handleStartHuntingWithLogs()}
                      disabled={!rawLogInput.trim() || isProcessing}
                      className={`inline-flex items-center gap-2 px-6 py-2.5 rounded-xl text-xs sm:text-sm font-bold shadow-md transition-all cursor-pointer ${
                        !rawLogInput.trim() || isProcessing
                          ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                          : 'bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-500 text-white shadow-blue-500/25 hover:shadow-lg hover:scale-[1.01]'
                      }`}
                    >
                      <Zap className="w-4 h-4 text-amber-300" />
                      <span>⚡ Tehdit Avını Başlat &amp; Analiz Et</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* MODE 2: File / Archive Upload (SECONDARY / INFREQUENT WORKFLOW) */}
            {inputMode === 'upload' && (
              <div
                onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-2xl p-8 sm:p-10 transition-all ${
                  isDragOver ? 'border-blue-500 bg-blue-50/80 scale-[1.01]' : 'border-slate-300 hover:border-slate-400 bg-slate-50/60'
                }`}
              >
                <Upload className="w-10 h-10 text-blue-600 mx-auto mb-3" />
                <h3 className="text-base font-bold text-slate-800">
                  Log veya Excel (.xlsx) Dosyalarını Buraya Bırakın
                </h3>
                <p className="text-xs text-slate-500 mt-1 mb-5">
                  .log, .txt, .csv, .json, .gz, .eve, .xlsx, .xls
                </p>

                <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                  <label className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-xl shadow-xs cursor-pointer transition-all hover:shadow-md">
                    <Upload className="w-4 h-4" />
                    <span>Bilgisayardan Log Dosyası Seç</span>
                    <input
                      type="file"
                      multiple
                      accept=".log,.txt,.csv,.json,.gz,.eve,.evtx,.tsv,.xlsx,.xls,.xlsm,.xlsb,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,text/*"
                      className="hidden"
                      onChange={e => {
                        if (e.target.files && e.target.files.length > 0) onUploadFiles(e.target.files);
                      }}
                    />
                  </label>

                  {onOpenQuickLogModal && (
                    <button
                      type="button"
                      onClick={onOpenQuickLogModal}
                      className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-xl shadow-xs cursor-pointer transition-all hover:shadow-md"
                    >
                      <FileText className="w-4 h-4 text-emerald-100" />
                      <span>Hızlı Log Yapıştır &amp; Analiz Et</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Active Files & Ingestion Control Bar */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Yüklü Log Dosyaları ({activeFiles.length})
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-200">
                  {summary.toplam_olay.toLocaleString()} Olay Analiz Edildi
                </span>
                {isProcessing && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-200 animate-pulse">
                    <Loader2 className="w-3 h-3 animate-spin text-blue-600" />
                    <span>İşleniyor ({progress?.percent ?? 0}%)</span>
                  </span>
                )}
              </div>

              {onClearAllFiles && (
                <button
                  onClick={onClearAllFiles}
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-600 hover:text-red-700 hover:underline cursor-pointer"
                  title="Yüklü tüm log dosyalarını temizle"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Tüm Logları Temizle
                </button>
              )}
            </div>

            {/* File chips with auto-detected format badge and multi-file selection */}
            <div className="flex flex-wrap items-center gap-2">
              {activeFiles.length > 1 && (
                <button
                  onClick={() => setSelectedFileFilter(null)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-2xs ${
                    selectedFileFilter === null
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                  }`}
                  title="Tüm dosyaların birleştirilmiş ortak analizi"
                >
                  <Files className="w-3.5 h-3.5" />
                  <span>Tüm Dosyalar ({activeFiles.length})</span>
                  <span className="text-[10px] opacity-80 font-mono">
                    • {parseFloat(totalGb) >= 1 ? `${totalGb} GB` : `${(summary.toplam_transfer_byte / (1024 * 1024)).toFixed(0)} MB`}
                  </span>
                </button>
              )}

              {activeFiles.map((fn, idx) => {
                const detected = report.detected_formats?.find(d => d.fileName === fn);
                const isSelected = selectedFileFilter === fn;
                const fileTransfer = detected?.transferBytes || 0;
                const fileGb = (fileTransfer / (1024 * 1024 * 1024)).toFixed(2);
                const fileMb = (fileTransfer / (1024 * 1024)).toFixed(1);

                return (
                  <span
                    key={idx}
                    className={`inline-flex items-center gap-2 border px-3 py-1.5 rounded-xl text-xs font-mono shadow-2xs transition-all ${
                      isSelected
                        ? 'bg-blue-50 border-blue-400 text-blue-900 ring-2 ring-blue-500/20'
                        : 'bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-800'
                    }`}
                  >
                    <button
                      onClick={() => setSelectedFileFilter(isSelected ? null : fn)}
                      className="inline-flex items-center gap-1.5 text-left cursor-pointer hover:underline"
                      title={isSelected ? 'Filtreyi kaldır (Tümünü göster)' : `Yalnızca ${fn} dosyasını incele`}
                    >
                      <FileText className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-blue-700' : 'text-blue-600'}`} />
                      <span className="font-semibold">{fn}</span>
                    </button>
                    {detected && (
                      <span className="inline-flex items-center gap-1 font-sans text-[10px] font-bold px-2 py-0.5 rounded-md bg-blue-50 text-blue-700 border border-blue-200 shadow-2xs">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                        {detected.formatDisplayName}
                        {detected.lineCount > 0 && (
                          <span className="text-slate-400 font-normal ml-0.5">
                            ({detected.lineCount.toLocaleString()} satır)
                          </span>
                        )}
                      </span>
                    )}
                    {fileTransfer > 0 && (
                      <span className="font-sans text-[10px] font-semibold px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200">
                        {parseFloat(fileGb) >= 1 ? `${fileGb} GB` : `${fileMb} MB`}
                      </span>
                    )}
                    {onRemoveFile && (
                      <button
                        onClick={() => {
                          if (selectedFileFilter === fn) setSelectedFileFilter(null);
                          onRemoveFile(fn);
                        }}
                        className="ml-0.5 text-slate-400 hover:text-red-600 rounded p-0.5 hover:bg-red-50 cursor-pointer"
                        title={`${fn} dosyasını kaldır`}
                      >
                        <X className="w-3 h-3" />
                      </button>
                    )}
                  </span>
                );
              })}

              <button
                type="button"
                onClick={() => setIsHeaderPasteOpen(!isHeaderPasteOpen)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-xl border cursor-pointer shadow-2xs transition-all ${
                  isHeaderPasteOpen
                    ? 'bg-blue-600 text-white border-blue-700 ring-2 ring-blue-500/20'
                    : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white border-transparent'
                }`}
                title="Panodaki veya yeni gelen logu doğrudan yapıştırıp analiz edin"
              >
                <Zap className="w-3.5 h-3.5 text-amber-300" />
                <span>Yeni Log Yapıştır</span>
              </button>

              <label className="inline-flex items-center gap-1 px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-bold rounded-xl border border-blue-200 cursor-pointer shadow-2xs transition-colors">
                <Plus className="w-3.5 h-3.5" />
                <span>Dosya Ekle</span>
                <input
                  type="file"
                  multiple
                  accept=".log,.txt,.csv,.json,.gz,.eve,.evtx,.tsv,.xlsx,.xls,.xlsm,.xlsb,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,text/*"
                  className="hidden"
                  onChange={e => {
                    if (e.target.files) onUploadFiles(e.target.files);
                  }}
                />
              </label>

              {activeFiles.length > 1 && (
                <button
                  onClick={() => setIsFileBreakdownOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-purple-50 hover:bg-purple-100 text-purple-700 text-xs font-bold rounded-xl border border-purple-200 cursor-pointer shadow-2xs transition-colors"
                  title="Yüklenen dosyaların satır ve transfer dağılım tablosunu görüntüle"
                >
                  <Files className="w-3.5 h-3.5 text-purple-600" />
                  <span>Dosya Dağılımı ({activeFiles.length} Dosya)</span>
                </button>
              )}

              {onNavigateToPolicyComparison && (
                <button
                  type="button"
                  onClick={onNavigateToPolicyComparison}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 text-xs font-bold rounded-xl border border-emerald-300 cursor-pointer shadow-2xs transition-colors"
                  title="Önceki ay ile bu ay arasındaki WAF Alert ➔ Block kural etkinlik kıyaslamasını aç"
                >
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Kural Etki &amp; Kıyaslama (WAF)</span>
                </button>
              )}

              {(activeFiles.length > 0 || (report.quarantine && report.quarantine.totalLinesRead > 0)) && (
                <button
                  onClick={() => setIsQuarantineModalOpen(true)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-xl border cursor-pointer shadow-2xs transition-colors ${
                    (report.quarantine?.quarantinedCount || 0) > 0
                      ? 'bg-amber-50 hover:bg-amber-100 text-amber-800 border-amber-300'
                      : 'bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border-emerald-300'
                  }`}
                  title="Ayrıştırılamayan satırlar"
                >
                  <Scale className="w-3.5 h-3.5" />
                  <span>
                    {(report.quarantine?.quarantinedCount || 0) > 0
                      ? `Ayrıştırılamayan (${report.quarantine?.quarantinedCount})`
                      : 'Kayıp Yok (%100)'}
                  </span>
                </button>
              )}
            </div>

            {selectedFileFilter && (
              <div className="mt-2.5 flex items-center justify-between bg-blue-50/90 border border-blue-200 rounded-xl px-3 py-2 text-xs text-blue-900 shadow-2xs">
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>
                    Filtre Devrede: Yalnızca <strong className="font-mono text-blue-950">{selectedFileFilter}</strong> dosyasının transfer ve olay kayıtları filtreleniyor.
                  </span>
                </div>
                <button
                  onClick={() => setSelectedFileFilter(null)}
                  className="font-bold text-blue-700 hover:text-blue-900 underline cursor-pointer shrink-0 ml-2"
                >
                  Tüm Dosyaların Birleşik Raporuna Dön ({totalGb} GB)
                </button>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start lg:self-center">
            {onOpenAiModal && (
              <button
                onClick={() => onOpenAiModal()}
                className="inline-flex items-center gap-1.5 px-3.5 py-2.5 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer"
                title="AI SOC Asistanı ile Tehdit Analizi ve Rapor Hazırla"
              >
                <Sparkles className="w-4 h-4 text-indigo-200" />
                <span>AI SOC Asistanı</span>
              </button>
            )}

            <button
              onClick={handleDownloadHtml}
              className="inline-flex items-center gap-1.5 px-3.5 py-2.5 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors shadow-xs cursor-pointer"
            >
              <Download className="w-4 h-4" />
              Rapor İndir (HTML/PDF)
            </button>

            <button
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-1.5 px-3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              <FileCode className="w-4 h-4 text-slate-600" />
              JSON İndir
            </button>
          </div>
        </div>

        {/* Collapsible Live SOC Log Paste Box */}
        {isHeaderPasteOpen && (
          <div className="mt-4 pt-4 border-t border-slate-200">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-left shadow-lg space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    ⚡ Hızlı Log Yapıştır &amp; Tehdit Avını Güncelle
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handlePasteFromClipboard}
                    className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-semibold flex items-center gap-1 cursor-pointer"
                  >
                    <Clipboard className="w-3.5 h-3.5 text-blue-400" />
                    <span>Panodan Yapıştır</span>
                  </button>
                  {rawLogInput && (
                    <button
                      type="button"
                      onClick={() => setRawLogInput('')}
                      className="px-2 py-1 text-slate-400 hover:text-red-400 text-xs cursor-pointer"
                    >
                      Temizle
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setIsHeaderPasteOpen(false)}
                    className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <textarea
                value={rawLogInput}
                onChange={(e) => setRawLogInput(e.target.value)}
                onKeyDown={(e) => {
                  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    handleStartHuntingWithLogs();
                  }
                }}
                placeholder="Yeni gelen SIEM alarmını veya uç nokta logunu yapıştırın (Ctrl + V)..."
                className="w-full min-h-[140px] max-h-[300px] bg-slate-950 text-emerald-400 font-mono text-xs p-3 rounded-lg border border-slate-800 focus:border-blue-500 focus:outline-none placeholder:text-slate-600 leading-relaxed shadow-inner"
              />

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
                <div className="text-xs text-slate-400 flex items-center gap-2">
                  <span className="font-mono text-slate-300 font-bold">
                    {rawLogInput ? rawLogInput.split('\n').filter((l) => l.trim().length > 0).length : 0} satır
                  </span>
                  <span>•</span>
                  <span>Kısayol: <kbd className="px-1 py-0.5 bg-slate-800 rounded border border-slate-700 text-[10px] text-slate-300">Ctrl + Enter</kbd></span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setIsHeaderPasteOpen(false)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold cursor-pointer"
                  >
                    Kapat
                  </button>
                  <button
                    type="button"
                    onClick={() => handleStartHuntingWithLogs()}
                    disabled={!rawLogInput.trim() || isProcessing}
                    className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                      !rawLogInput.trim() || isProcessing
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                        : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-xs'
                    }`}
                  >
                    <Zap className="w-3.5 h-3.5 text-amber-300" />
                    <span>Tehdit Avını Başlat</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Filters & Thresholds */}
        <div className="mt-4 pt-4 border-t border-slate-100 grid grid-cols-1 sm:grid-cols-3 gap-4 items-center">
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-slate-700 whitespace-nowrap">
              Sızdırma Eşiği:
            </label>
            <div className="flex items-center gap-1.5 flex-1">
              <input
                type="number"
                min={1}
                max={5000}
                value={exfiltrationMb}
                onChange={e => setExfiltrationMb(Math.max(1, parseInt(e.target.value, 10) || 10))}
                className="w-18 px-2 py-1 text-xs border border-slate-300 rounded font-mono text-center bg-white"
              />
              <span className="text-xs text-slate-500 font-medium">MB</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-slate-700 whitespace-nowrap">
              Brute Force:
            </label>
            <div className="flex items-center gap-1.5 flex-1">
              <input
                type="number"
                min={2}
                max={500}
                value={failedAttempts}
                onChange={e => setFailedAttempts(Math.max(1, parseInt(e.target.value, 10) || 5))}
                className="w-18 px-2 py-1 text-xs border border-slate-300 rounded font-mono text-center bg-white"
              />
              <span className="text-xs text-slate-500 font-medium">Deneme</span>
            </div>
          </div>

          <div className="flex items-center gap-2 justify-start sm:justify-end">
            <input
              type="checkbox"
              id="allowlist-toggle"
              checked={useAllowlist}
              onChange={e => setUseAllowlist(e.target.checked)}
              className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500 cursor-pointer"
            />
            <label htmlFor="allowlist-toggle" className="text-xs font-semibold text-slate-700 cursor-pointer select-none">
              Allowlist Filtresi
            </label>
          </div>
        </div>
      </div>

      {/* Ayrıştırma ve Satır Durumu */}
      {(activeFiles.length > 0 || summary.toplam_olay > 0 || (report.quarantine && report.quarantine.totalLinesRead > 0)) && (
        <div
          className={`border rounded-xl p-3.5 shadow-2xs transition-all ${
            (report.quarantine?.quarantinedCount || 0) > 0
              ? 'bg-amber-50/90 border-amber-300 text-amber-950'
              : 'bg-emerald-50/90 border-emerald-300 text-emerald-950'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-3 flex-1">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-xs text-slate-900">
                    Ayrıştırma Durumu:
                  </span>
                  <span className="text-xs font-semibold text-slate-800">
                    {report.quarantine?.footnoteText ||
                      ((report.quarantine?.quarantinedCount || 0) > 0
                        ? `${report.quarantine?.quarantinedCount} satır ayrıştırılamadı.`
                        : 'Ayrıştırılan %100, sorun yok.')}
                  </span>
                </div>

                {report.quarantine && report.quarantine.totalLinesRead > 0 && (
                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-600 flex-wrap pt-0.5">
                    <span>Okunan: <strong className="text-slate-800">{report.quarantine.totalLinesRead.toLocaleString('tr-TR')}</strong></span>
                    <span>•</span>
                    <span>Olay: <strong className="text-emerald-700">{report.quarantine.parsedEventsCount.toLocaleString('tr-TR')}</strong></span>
                    <span>•</span>
                    <span>Karantina: <strong className={(report.quarantine?.quarantinedCount || 0) > 0 ? 'text-amber-700 font-bold' : 'text-slate-600'}>{report.quarantine.quarantinedCount.toLocaleString('tr-TR')}</strong></span>
                  </div>
                )}
              </div>
            </div>

            {(report.quarantine?.quarantinedCount || 0) > 0 && (
              <div className="flex items-center gap-2 self-start md:self-center shrink-0">
                <button
                  onClick={() => setIsQuarantineModalOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg cursor-pointer shadow-2xs transition-colors bg-amber-600 hover:bg-amber-700 text-white"
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Karantina Satırları ({report.quarantine?.quarantinedCount})</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* AI Analiz Çubuğu */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 px-4 py-3 text-white flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/20 text-indigo-300 rounded-lg border border-indigo-400/30 shrink-0">
            <Sparkles className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-xs">
            <span className="font-bold text-white">AI Log Analizi</span>
            <span className="text-slate-400 ml-2">
              ({summary.toplam_olay.toLocaleString()} olay / {summary.farkli_ip_sayisi} IP)
            </span>
          </div>
        </div>

        <button
          onClick={() => onOpenAiModal()}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-all cursor-pointer shrink-0"
        >
          <Sparkles className="w-3.5 h-3.5 text-indigo-200" />
          <span>Analiz Et</span>
        </button>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase block">Toplam Olay</span>
          <span className="text-xl font-extrabold text-slate-900 mt-1 block">
            {summary.toplam_olay.toLocaleString()}
          </span>
          <span className="text-[10px] text-slate-400 mt-0.5 block truncate" title={`${summary.ilk_tarih} - ${summary.son_tarih}`}>
            {summary.ilk_tarih ? summary.ilk_tarih.substring(5, 16) : '-'}
          </span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase block">Kaynak IP</span>
          <span className="text-xl font-extrabold text-blue-600 mt-1 block">
            {summary.farkli_ip_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-slate-400 mt-0.5 block">Benzersiz İstemci</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase block">Hedef IP</span>
          <span className="text-xl font-extrabold text-indigo-600 mt-1 block">
            {summary.farkli_hedef_ip_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-slate-400 mt-0.5 block">Sunucu / VIP</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-slate-500 uppercase block">Sunucular</span>
          <span className="text-xl font-extrabold text-slate-800 mt-1 block">
            {summary.farkli_sunucu_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-slate-400 mt-0.5 block">Farklı Host</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-emerald-600 uppercase block">Accept</span>
          <span className="text-xl font-extrabold text-emerald-700 mt-1 block">
            {summary.accept_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-emerald-600 mt-0.5 block">Geçirilen Bağlantı</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-rose-600 uppercase block">Deny / Blok</span>
          <span className="text-xl font-extrabold text-rose-700 mt-1 block">
            {summary.deny_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-rose-600 mt-0.5 block">Reddedilen İstek</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-amber-600 uppercase block">5xx Hata</span>
          <span className="text-xl font-extrabold text-amber-700 mt-1 block">
            {summary.server_error_sayisi.toLocaleString()}
          </span>
          <span className="text-[10px] text-amber-600 mt-0.5 block">Sunucu Çökmesi / Hata</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3 shadow-xs">
          <span className="text-[11px] font-bold tracking-wider text-purple-600 uppercase block">Transfer</span>
          <span
            className="text-xl font-extrabold text-purple-700 mt-1 block truncate"
            title={`${summary.toplam_transfer_byte.toLocaleString('tr-TR')} Bayt başarılı veri transferi`}
          >
            {parseFloat(totalGb) >= 1 ? `${totalGb} GB` : `${(summary.toplam_transfer_byte / (1024 * 1024)).toFixed(1)} MB`}
          </span>
          <span
            className="text-[10px] text-purple-600 mt-0.5 block truncate"
            title={`${summary.toplam_transfer_byte.toLocaleString('tr-TR')} Bayt`}
          >
            {parseFloat(totalGb) >= 1
              ? `(${(summary.toplam_transfer_byte / (1024 * 1024)).toLocaleString('tr-TR', { maximumFractionDigits: 0 })} MB)`
              : `(${totalGb} GB)`}
          </span>
        </div>
      </div>

      {/* Visual Charts (Hourly traffic & Port Distribution) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-blue-600" />
              Saatlik Trafik Dağılımı ve Hata Oranları
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">
              {report.hourly_traffic.length} Saatlik Dilim
            </span>
          </div>
          <div className="h-56 w-full">
            {report.hourly_traffic.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={report.hourly_traffic} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorErr" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <XAxis dataKey="saatlik_dilim" tick={{ fontSize: 10 }} tickFormatter={t => t.substring(5, 13)} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Area type="monotone" dataKey="toplam_istek" name="Toplam İstek" stroke="#3b82f6" fillOpacity={1} fill="url(#colorTotal)" />
                  <Area type="monotone" dataKey="hata_4xx" name="4xx Auth/Bulunamadı" stroke="#f59e0b" fillOpacity={0.2} fill="#f59e0b" />
                  <Area type="monotone" dataKey="hata_5xx" name="5xx Sunucu Hatası" stroke="#ef4444" fillOpacity={1} fill="url(#colorErr)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                Grafik oluşturulacak veri bulunamadı.
              </div>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide flex items-center gap-1.5">
              <Server className="w-4 h-4 text-indigo-600" />
              Hedef Port Dağılımı (Bağlantı Sayısı)
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">Top Portlar</span>
          </div>
          <div className="h-56 w-full">
            {report.port_analysis.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={report.port_analysis.slice(0, 6)} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e2e8f0" />
                  <XAxis type="number" tick={{ fontSize: 10 }} />
                  <YAxis dataKey="port" type="category" tick={{ fontSize: 10 }} width={45} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                    formatter={(val, name, item) => [
                      `${val} bağlantı (${item.payload.servis_tahmini})`,
                      'Bağlantı Sayısı',
                    ]}
                  />
                  <Bar dataKey="baglanti_sayisi" fill="#6366f1" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                Port verisi bulunamadı.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Prominent Raw Log Triage Banner (When logs were imported from Quick Log Paste) */}
      {report.raw_log_triage && (
        <div className="bg-gradient-to-r from-indigo-900/90 via-slate-900 to-blue-950 border border-indigo-700/50 rounded-xl p-4 text-white shadow-md flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 shadow-xs ${
              report.raw_log_triage.overallPosture === 'CRITICAL_THREAT'
                ? 'bg-red-600 text-white animate-pulse'
                : report.raw_log_triage.overallPosture === 'SUSPICIOUS_ACTIVITY'
                ? 'bg-amber-600 text-white'
                : 'bg-indigo-600 text-white'
            }`}>
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                  Ham Log Ön İnceleme &amp; Triage Raporu Aktarıldı
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  report.raw_log_triage.overallPosture === 'CRITICAL_THREAT'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : report.raw_log_triage.overallPosture === 'SUSPICIOUS_ACTIVITY'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}>
                  {report.raw_log_triage.postureTitle}
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  ({report.raw_log_triage.totalEvents} satır incelendi)
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed max-w-3xl line-clamp-2">
                {report.raw_log_triage.evidenceBasedSummary}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              id="threat-hunting-view-raw-triage-btn"
              type="button"
              onClick={() => setActiveSubTab('raw_log_triage')}
              className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all shadow-xs ${
                activeSubTab === 'raw_log_triage'
                  ? 'bg-indigo-600 text-white ring-2 ring-indigo-400'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
              <span>Triage Detayı &amp; QRadar Studio</span>
            </button>
            {onOpenQuickLogModal && (
              <button
                id="threat-hunting-open-quick-log-btn"
                type="button"
                onClick={onOpenQuickLogModal}
                className="px-3 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700/80 transition-colors"
                title="Yeni ham log yapıştır veya analiz et"
              >
                Yeni Log Yapıştır
              </button>
            )}
          </div>
        </div>
      )}

      {/* Sub-Tabs Navigation */}
      <div className="border-b border-slate-200 flex flex-wrap gap-1">
        {subTabButtons.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveSubTab(tab.key)}
            className={`px-3 py-2 text-xs font-bold rounded-t-lg transition-all border-b-2 flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === tab.key
                ? 'border-blue-600 text-blue-700 bg-white shadow-xs'
                : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                  activeSubTab === tab.key ? 'bg-blue-100 text-blue-800' : 'bg-slate-200 text-slate-700'
                }`}
              >
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Sub-Tab Search Bar */}
      <div className="flex items-center justify-between">
        <div className="relative w-full max-w-sm">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Tabloda filtrele (IP, kullanıcı, komut)..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
          />
        </div>
      </div>

      {/* Sub-Tab Content Views */}

      {/* 0. Raw Log SOC Triage & QRadar Studio */}
      {activeSubTab === 'raw_log_triage' && report.raw_log_triage && (
        <div className="space-y-6">
          {/* Triage Overview Card */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-5 py-4 bg-slate-900 text-white flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono uppercase tracking-wider ${
                    report.raw_log_triage.overallPosture === 'CRITICAL_THREAT'
                      ? 'bg-red-600 text-white'
                      : report.raw_log_triage.overallPosture === 'SUSPICIOUS_ACTIVITY'
                      ? 'bg-amber-600 text-white'
                      : 'bg-emerald-600 text-white'
                  }`}>
                    {report.raw_log_triage.postureTitle}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    İncelenen Satır: {report.raw_log_triage.totalEvents} | Aday Olaylar: {report.raw_log_triage.incidentCandidatesCount}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">
                  Log Triage &amp; Olay Analiz Raporu
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  id="raw-triage-regenerate-ai-btn"
                  type="button"
                  disabled={isRegeneratingAiReport}
                  onClick={handleRegenerateAiTriageReport}
                  className="px-3 py-1.5 bg-indigo-900/60 hover:bg-indigo-800/80 text-indigo-200 border border-indigo-700/60 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                  title="Gemini 3.8 Flash akıl yürütme (ThinkingLevel.HIGH) ile adli raporu yeniden sentezle"
                >
                  {isRegeneratingAiReport ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-300" />
                      <span>Gemini Sentezliyor...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5 text-indigo-300" />
                      <span>Gemini 3.8 Flash ile Üret</span>
                    </>
                  )}
                </button>
                <button
                  id="raw-triage-copy-report-btn"
                  type="button"
                  onClick={handleCopyTriageReport}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                  <span>{copiedTriageReport ? 'AI Raporu Kopyalandı!' : 'Raporu Kopyala'}</span>
                </button>
              </div>
            </div>

            <div className="p-5 space-y-4">
              {/* Evidence Based Summary */}
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Olay Özeti
                </h4>
                <p className="text-xs text-slate-700 leading-relaxed">
                  {report.raw_log_triage.evidenceBasedSummary}
                </p>
              </div>

              {/* Findings & Actions Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-amber-50/50 border border-amber-200/80 rounded-lg p-4">
                  <h4 className="text-xs font-bold text-amber-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-amber-600" />
                    <span>Bulgular ({report.raw_log_triage.overallFindings.length})</span>
                  </h4>
                  <ul className="space-y-1.5 text-xs text-slate-700">
                    {report.raw_log_triage.overallFindings.map((finding, fIdx) => (
                      <li key={fIdx} className="flex items-start gap-2">
                        <span className="text-amber-600 font-bold">•</span>
                        <span>{finding}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="bg-blue-50/50 border border-blue-200/80 rounded-lg p-4">
                  <h4 className="text-xs font-bold text-blue-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-blue-600" />
                    <span>Önerilen Aksiyonlar ({report.raw_log_triage.analystActions.length})</span>
                  </h4>
                  <ul className="space-y-1.5 text-xs text-slate-700">
                    {report.raw_log_triage.analystActions.map((act, aIdx) => (
                      <li key={aIdx} className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">✓</span>
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Full Formatted Report */}
              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-4 h-4 text-indigo-600" />
                    <span>Gemini 3.8 Flash Adli Olay &amp; Triage Raporu</span>
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Deep Reasoning (ThinkingLevel.HIGH) • MITRE ATT&amp;CK • IoC
                  </span>
                </div>
                <textarea
                  readOnly
                  rows={14}
                  value={currentTriageReport}
                  className="w-full font-mono text-xs p-3.5 bg-slate-950 text-slate-200 rounded-lg border border-slate-800 focus:outline-hidden leading-relaxed select-all"
                />
              </div>
            </div>
          </div>

          {/* Integrated Multi-SIEM & Detection Rule Studio */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
            <div>
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Çoklu SIEM (Splunk, Sentinel, Elastic, Sigma, QRadar) Avcılık ve Kural Stüdyosu
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                İncelenen log verisine göre tek tıkla Splunk (SPL), Microsoft Sentinel (KQL), Elasticsearch (KQL/EQL), Sigma Kuralı (YAML) ve QRadar (AQL) sorguları üretin.
              </p>
            </div>

            <QradarAqlStudio
              rawLogSample={report.raw_log_triage.rawText || ''}
              contextParams={{
                ip: report.top_ips?.[0]?.ip_adresi,
                destIp: report.destination_ip_analysis?.[0]?.hedef_ip,
                port: report.port_analysis?.[0]?.port,
              }}
            />
          </div>
        </div>
      )}

      {/* 1. Öncelikli Risk Kuyruğu */}
      {activeSubTab === 'risk_queue' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🚨 Öncelikli Varlık Risk Kuyruğu (0 - 100 Puanlama)
              </h4>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Veri sızdırma hacmi, webshell aktiviteleri, auth hataları ve tarama sinyallerine göre dinamik puanlanmıştır.
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                  <th className="p-2.5 font-semibold">Risk Seviyesi</th>
                  <th className="p-2.5 font-semibold">Varlık (IP / Host)</th>
                  <th className="p-2.5 font-semibold">Hedef &amp; Bölge</th>
                  <th className="p-2.5 font-semibold text-right">İstek &amp; Transfer</th>
                  <th className="p-2.5 font-semibold text-center">Auth &amp; Shell</th>
                  <th className="p-2.5 font-semibold text-center">Güven &amp; Sinyal</th>
                  <th className="p-2.5 font-semibold">Gerekçe / Açıklama</th>
                  <th className="p-2.5 font-semibold text-center">İşlem</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {riskQueuePage.paginatedItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/90 transition-colors">
                    <td className="p-2.5 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadge(item.risk_seviyesi)}`}>
                        {item.risk_seviyesi} ({item.risk_puani})
                      </span>
                    </td>
                    <td className="p-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-bold text-slate-900">{item.ip_adresi}</span>
                        {item.network_zone === 'internal' && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
                            İç Ağ
                          </span>
                        )}
                        {item.network_zone === 'external' && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-purple-50 text-purple-700 border border-purple-200">
                            Dış Ağ
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500 font-sans mt-0.5">{item.ip_kategori}</div>
                    </td>
                    <td className="p-2.5">
                      <div className="font-mono text-slate-700 font-semibold">{item.sunucu_ismi}</div>
                      {item.device && item.device !== 'Unknown' && (
                        <div className="text-[10px] text-slate-500 font-mono">Cihaz: {item.device}</div>
                      )}
                    </td>
                    <td className="p-2.5 text-right font-mono">
                      <div className="font-semibold text-slate-800">{item.toplam_istek.toLocaleString()} req</div>
                      <div className="text-[11px] text-purple-700 font-semibold">
                        {(item.basarili_byte / (1024 * 1024)).toFixed(2)} MB
                      </div>
                    </td>
                    <td className="p-2.5 text-center font-mono">
                      <div className="flex items-center justify-center gap-1.5">
                        {item.auth_hatasi > 0 && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
                            {item.auth_hatasi} Hata
                          </span>
                        )}
                        {item.webshell_sinyali > 0 && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                            Shell ({item.webshell_sinyali})
                          </span>
                        )}
                        {item.auth_hatasi === 0 && item.webshell_sinyali === 0 && (
                          <span className="text-slate-400 text-[11px]">-</span>
                        )}
                      </div>
                    </td>
                    <td className="p-2.5 text-center whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        item.confidence === 'YÜKSEK'
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : item.confidence === 'DÜŞÜK'
                          ? 'bg-slate-100 text-slate-600 border-slate-200'
                          : 'bg-amber-50 text-amber-700 border-amber-200'
                      }`}>
                        {item.confidence === 'YÜKSEK' ? 'Yüksek' : item.confidence === 'DÜŞÜK' ? 'Düşük' : 'Orta'}
                      </span>
                      {item.signals && item.signals.length > 0 && (
                        <div className="text-[10px] text-slate-500 font-sans mt-0.5">
                          {item.signals.length} Sinyal
                        </div>
                      )}
                    </td>
                    <td className="p-2.5 text-slate-700 max-w-xs truncate" title={item.explainability_summary || item.risk_gerekcesi}>
                      {item.explainability_summary || item.risk_gerekcesi}
                    </td>
                    <td className="p-2.5 text-center">
                      <div className="flex items-center justify-center gap-1">
                        <button
                          onClick={() => setExplainModalItem(item)}
                          className="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 rounded text-[11px] font-semibold transition-colors shadow-2xs cursor-pointer inline-flex items-center gap-1"
                          title="Puanlama Formülünü ve SOC Açıklamasını Gör"
                        >
                          <Info className="w-3 h-3 text-slate-600" />
                          Açıkla
                        </button>
                        {onOpenAiModal && (
                          <button
                            onClick={() => onOpenAiModal(item, item.ip_adresi)}
                            className="px-2 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded text-[11px] font-semibold transition-colors shadow-2xs cursor-pointer inline-flex items-center gap-1"
                            title="AI SOC ile Tehdit Analizi ve Rapor Oluştur"
                          >
                            <Sparkles className="w-3 h-3 text-indigo-600" />
                            AI
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {riskQueuePage.totalItems === 0 && (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-slate-500">
                      Mevcut log kayıtlarında eşik değerlerini aşan şüpheli varlık bulunamadı.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <TablePagination
            totalItems={riskQueuePage.totalItems}
            currentPage={riskQueuePage.currentPage}
            pageSize={riskQueuePage.pageSize}
            onPageChange={riskQueuePage.setCurrentPage}
            onPageSizeChange={riskQueuePage.setPageSize}
            itemName="risk varlığı"
          />
        </div>
      )}

      {/* 2. Hedef IP & Port Analizi */}
      {activeSubTab === 'dest_ports' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🎯 Hedef IP Dağılımı ve Red/Engelleme (Deny) Oranları
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Hedef IP</th>
                    <th className="p-2.5 font-semibold text-right">Toplam Bağlantı</th>
                    <th className="p-2.5 font-semibold text-center">Erişen Kaynak IP</th>
                    <th className="p-2.5 font-semibold">Kullanılan Portlar</th>
                    <th className="p-2.5 font-semibold text-center text-emerald-700">Accept</th>
                    <th className="p-2.5 font-semibold text-center text-rose-700">Deny</th>
                    <th className="p-2.5 font-semibold text-center">Deny Oranı</th>
                    <th className="p-2.5 font-semibold text-right">Toplam Transfer</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {destIpPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-slate-900">{item.hedef_ip}</td>
                      <td className="p-2.5 text-right font-mono font-semibold">{item.toplam_baglanti.toLocaleString()}</td>
                      <td className="p-2.5 text-center font-mono">{item.erisen_kaynak_ip_sayisi}</td>
                      <td className="p-2.5">
                        <PortBadgesCell
                          portString={item.portlar}
                          hedefIp={item.hedef_ip}
                          onOpenModal={(ip, pStr) => setPortModalData({ isOpen: true, hedefIp: ip, portString: pStr })}
                          onFilterByPort={(port) => {
                            setSelectedPortFilter(port);
                            const portTableEl = document.getElementById('port-service-table');
                            if (portTableEl) {
                              portTableEl.scrollIntoView({ behavior: 'smooth' });
                            }
                          }}
                        />
                      </td>
                      <td className="p-2.5 text-center font-mono text-emerald-700 font-semibold">{item.accept_sayisi}</td>
                      <td className="p-2.5 text-center font-mono text-rose-700 font-semibold">{item.deny_sayisi}</td>
                      <td className="p-2.5 text-center">
                        <span className={`font-mono font-bold ${item.deny_orani > 50 ? 'text-red-600' : 'text-slate-700'}`}>
                          %{item.deny_orani}
                        </span>
                      </td>
                      <td className="p-2.5 text-right font-mono text-purple-700 font-semibold">{item.toplam_transfer_mb} MB</td>
                    </tr>
                  ))}
                  {destIpPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={8} className="p-6 text-center text-slate-500">
                        Arama kriterlerine uygun hedef IP kaydı bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={destIpPage.totalItems}
              currentPage={destIpPage.currentPage}
              pageSize={destIpPage.pageSize}
              onPageChange={destIpPage.setCurrentPage}
              onPageSizeChange={destIpPage.setPageSize}
              itemName="hedef IP"
            />
          </div>

          <div id="port-service-table" className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🔌 Port Servis Dağılımı ve Güvenlik Duvarı Aksiyonları
              </h4>
              {selectedPortFilter && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-md font-medium">
                    Filtrelenen Port: <strong className="text-blue-700 font-mono">{selectedPortFilter}</strong>
                  </span>
                  <button
                    onClick={() => setSelectedPortFilter(null)}
                    className="text-[11px] px-2.5 py-0.5 rounded-md bg-slate-200 hover:bg-slate-300 text-slate-700 font-semibold cursor-pointer transition-colors"
                  >
                    ✕ Filtreyi Kaldır (Tüm Portlar)
                  </button>
                </div>
              )}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Hedef Port</th>
                    <th className="p-2.5 font-semibold">Tahmini Servis</th>
                    <th className="p-2.5 font-semibold text-right">Toplam İstek</th>
                    <th className="p-2.5 font-semibold text-center text-emerald-700">Accept</th>
                    <th className="p-2.5 font-semibold text-center text-rose-700">Deny / Drop</th>
                    <th className="p-2.5 font-semibold text-center">Erişen İstemci Sayısı</th>
                    <th className="p-2.5 font-semibold text-right">Veri Hacmi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {portPage.paginatedItems.map((p, idx) => (
                    <tr key={idx} className={`hover:bg-slate-50 transition-colors ${selectedPortFilter === p.port ? 'bg-blue-50/50' : ''}`}>
                      <td className="p-2.5 font-mono font-bold text-blue-700">{p.port}</td>
                      <td className="p-2.5 font-medium text-slate-800">{p.servis_tahmini}</td>
                      <td className="p-2.5 text-right font-mono font-semibold">{p.baglanti_sayisi.toLocaleString()}</td>
                      <td className="p-2.5 text-center font-mono text-emerald-700 font-semibold">{p.accept_sayisi}</td>
                      <td className="p-2.5 text-center font-mono text-rose-700 font-semibold">{p.deny_sayisi}</td>
                      <td className="p-2.5 text-center font-mono">{p.erisen_istemci_sayisi}</td>
                      <td className="p-2.5 text-right font-mono text-purple-700">{p.toplam_mb} MB</td>
                    </tr>
                  ))}
                  {portPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={7} className="p-6 text-center text-slate-500 text-xs">
                        Filtrelenen port (<span className="font-mono font-bold text-blue-700">{selectedPortFilter}</span>) için güvenlik duvarı kaydı bulunamadı.
                        <button
                          onClick={() => setSelectedPortFilter(null)}
                          className="ml-2 text-blue-600 underline font-semibold cursor-pointer"
                        >
                          Tüm portları göster
                        </button>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={portPage.totalItems}
              currentPage={portPage.currentPage}
              pageSize={portPage.pageSize}
              onPageChange={portPage.setCurrentPage}
              onPageSizeChange={portPage.setPageSize}
              itemName="port kaydı"
            />
          </div>
        </div>
      )}

      {/* 3. Günler Arası Korelasyon */}
      {activeSubTab === 'cross_day' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              📅 Çok Günlü Tehdit Avı ve Saldırı Aşaması Korelasyonu
            </h4>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Farklı günlere yayılan, keşiften veri sızdırmaya kadar aşama izleri (Keşif &rarr; Parola Denemesi &rarr; Webshell &rarr; Veri Sızdırma) bırakan IP adresleri.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                  <th className="p-2.5 font-semibold">IP Adresi</th>
                  <th className="p-2.5 font-semibold">Kullanıcı</th>
                  <th className="p-2.5 font-semibold">Sunucular</th>
                  <th className="p-2.5 font-semibold text-center">Gün / Dosya</th>
                  <th className="p-2.5 font-semibold text-right">İstek</th>
                  <th className="p-2.5 font-semibold text-center">Auth Hata</th>
                  <th className="p-2.5 font-semibold">Saldırı Aşama İzi (Progression)</th>
                  <th className="p-2.5 font-semibold">İlk - Son Aktivite</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {crossDayPage.paginatedItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 transition-colors">
                    <td className="p-2.5 font-mono font-bold text-slate-900">{item.ip_adresi}</td>
                    <td className="p-2.5 font-mono text-slate-700">{item.kullanici_adi}</td>
                    <td className="p-2.5 font-mono text-slate-600">{item.sunucular}</td>
                    <td className="p-2.5 text-center font-mono">
                      <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 font-bold border border-blue-200">
                        {item.gun_sayisi} Gün / {item.dosya_sayisi} Dosya
                      </span>
                    </td>
                    <td className="p-2.5 text-right font-mono font-semibold">{item.toplam_istek.toLocaleString()}</td>
                    <td className="p-2.5 text-center font-mono text-amber-700 font-bold">{item.basarisiz_auth_sayisi}</td>
                    <td className="p-2.5">
                      <div className="flex flex-wrap items-center gap-1">
                        {item.asama_izleri.split(' -> ').map((step, sidx) => (
                          <React.Fragment key={sidx}>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              step.includes('Sızdırma')
                                ? 'bg-red-100 text-red-800 border border-red-200'
                                : step.includes('Webshell')
                                ? 'bg-orange-100 text-orange-800 border border-orange-200'
                                : step.includes('Parola')
                                ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                : 'bg-blue-100 text-blue-800 border border-blue-200'
                            }`}>
                              {step}
                            </span>
                            {sidx < item.asama_izleri.split(' -> ').length - 1 && (
                              <ArrowRight className="w-3 h-3 text-slate-400" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-slate-600">
                      {item.ilk_aktivite} &rarr; {item.son_aktivite}
                    </td>
                  </tr>
                ))}
                {crossDayPage.totalItems === 0 && (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-slate-500">
                      Çapraz gün korelasyonu gösteren şüpheli aktivite bulunamadı.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <TablePagination
            totalItems={crossDayPage.totalItems}
            currentPage={crossDayPage.currentPage}
            pageSize={crossDayPage.pageSize}
            onPageChange={crossDayPage.setCurrentPage}
            onPageSizeChange={crossDayPage.setPageSize}
            itemName="korelasyon kaydı"
          />
        </div>
      )}

      {/* 4. Veri Transfer Kanıtları */}
      {activeSubTab === 'data_transfer' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                💾 Gruplanmış Veri Transfer Detayları (IP + Kullanıcı + Sunucu)
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Kaynak IP</th>
                    <th className="p-2.5 font-semibold">Kullanıcı</th>
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold text-right">Başarılı İstek</th>
                    <th className="p-2.5 font-semibold text-right">Toplam Transfer</th>
                    <th className="p-2.5 font-semibold text-right">En Büyük Tekil</th>
                    <th className="p-2.5 font-semibold text-center">Genel Pay</th>
                    <th className="p-2.5 font-semibold">Zaman Aralığı</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {dataTransferPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-slate-900">{item.ip_adresi}</td>
                      <td className="p-2.5 font-mono text-slate-700">{item.kullanici_adi}</td>
                      <td className="p-2.5 font-mono text-slate-600">{item.sunucu_ismi}</td>
                      <td className="p-2.5 text-right font-mono">{item.basarili_istek_sayisi}</td>
                      <td className="p-2.5 text-right font-mono font-bold text-purple-700">
                        {item.toplam_transfer_mb} MB ({item.toplam_transfer_gb} GB)
                      </td>
                      <td className="p-2.5 text-right font-mono text-indigo-600 font-semibold">{item.en_buyuk_tekil_transfer_mb} MB</td>
                      <td className="p-2.5 text-center font-mono font-bold">%{item.toplam_transfer_yuzdesi}</td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-600">{item.ilk_transfer} &rarr; {item.son_transfer}</td>
                    </tr>
                  ))}
                  {dataTransferPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={8} className="p-6 text-center text-slate-500">
                        Veri transfer kriterine uyan kayıt bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={dataTransferPage.totalItems}
              currentPage={dataTransferPage.currentPage}
              pageSize={dataTransferPage.pageSize}
              onPageChange={dataTransferPage.setCurrentPage}
              onPageSizeChange={dataTransferPage.setPageSize}
              itemName="transfer grubu"
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                📦 En Yüksek Hacimli Tekil İstek Transfer Kanıtı
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-100">
                  <tr className="border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Tarih</th>
                    <th className="p-2.5 font-semibold">IP Adresi</th>
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold">İşlem / URI</th>
                    <th className="p-2.5 font-semibold text-center">Status</th>
                    <th className="p-2.5 font-semibold text-right">Transfer Hacmi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {largestRequestsPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2 font-mono text-slate-600">{item.tarih}</td>
                      <td className="p-2 font-mono font-bold text-slate-900">{item.ip_adresi}</td>
                      <td className="p-2 font-mono text-slate-700">{item.sunucu_ismi}</td>
                      <td className="p-2 font-mono text-blue-600 max-w-sm truncate" title={item.islem_komutu}>
                        {item.islem_komutu}
                      </td>
                      <td className="p-2 text-center font-mono font-bold text-emerald-600">{item.status_code}</td>
                      <td className="p-2 text-right font-mono font-bold text-purple-700">{item.transfer_mb} MB</td>
                    </tr>
                  ))}
                  {largestRequestsPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={6} className="p-6 text-center text-slate-500">
                        Transfer kanıtı kaydı bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={largestRequestsPage.totalItems}
              currentPage={largestRequestsPage.currentPage}
              pageSize={largestRequestsPage.pageSize}
              onPageChange={largestRequestsPage.setCurrentPage}
              onPageSizeChange={largestRequestsPage.setPageSize}
              itemName="istek kaydı"
            />
          </div>
        </div>
      )}

      {/* 5. Webshell & Dosya Yönetimi */}
      {activeSubTab === 'webshell' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🪓 Webshell ve Yetkisiz Dosya Yönetim Erişimi
              </h4>
              <p className="text-[11px] text-slate-500 mt-0.5">
                /filemanagement, c:\inetpub, cmd.exe, whoami, net user, web.config gibi hassas dizin ve komut çalıştırma teşebbüsleri.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">IP Adresi</th>
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold text-right">İstek Sayısı</th>
                    <th className="p-2.5 font-semibold text-center">Hatalar (4xx / 5xx)</th>
                    <th className="p-2.5 font-semibold">Eylem Örnekleri</th>
                    <th className="p-2.5 font-semibold">Son Görülme</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {webshellPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-red-600">{item.ip_adresi}</td>
                      <td className="p-2.5 font-mono text-slate-700">{item.sunucu_ismi}</td>
                      <td className="p-2.5 text-right font-mono font-semibold">{item.istek_sayisi}</td>
                      <td className="p-2.5 text-center font-mono">
                        {item.hata_sayisi} (5xx: <strong className="text-red-600">{item.server_hatasi}</strong>)
                      </td>
                      <td className="p-2.5 font-mono text-amber-800 text-[11px] max-w-md truncate" title={item.eylem_ornekleri}>
                        {item.eylem_ornekleri}
                      </td>
                      <td className="p-2.5 font-mono text-slate-600">{item.son_gorulme}</td>
                    </tr>
                  ))}
                  {webshellPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={6} className="p-6 text-center text-slate-500">
                        Webshell veya şüpheli dosya yönetim aktivitesi bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={webshellPage.totalItems}
              currentPage={webshellPage.currentPage}
              pageSize={webshellPage.pageSize}
              onPageChange={webshellPage.setCurrentPage}
              onPageSizeChange={webshellPage.setPageSize}
              itemName="webshell kaydı"
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                ⏱️ Webshell Kronolojik Aktivite Akışı (Timeline)
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-100">
                  <tr className="border-b border-slate-200 text-slate-700">
                    <th className="p-2 font-semibold">Tarih</th>
                    <th className="p-2 font-semibold">IP Adresi</th>
                    <th className="p-2 font-semibold">Sunucu</th>
                    <th className="p-2 font-semibold">Method</th>
                    <th className="p-2 font-semibold">İşlem / Komut</th>
                    <th className="p-2 font-semibold text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {webshellTimelinePage.paginatedItems.map((t, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 font-mono text-[11px]">
                      <td className="p-2 text-slate-600">{t.tarih}</td>
                      <td className="p-2 font-bold text-red-600">{t.ip_adresi}</td>
                      <td className="p-2 text-slate-700">{t.sunucu_ismi}</td>
                      <td className="p-2 font-bold text-blue-600">{t.http_method}</td>
                      <td className="p-2 text-slate-900 max-w-md truncate" title={t.islem_komutu}>{t.islem_komutu}</td>
                      <td className="p-2 text-center font-bold">{t.status_code}</td>
                    </tr>
                  ))}
                  {webshellTimelinePage.totalItems === 0 && (
                    <tr>
                      <td colSpan={6} className="p-6 text-center text-slate-500">
                        Webshell zaman çizelgesi kaydı bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={webshellTimelinePage.totalItems}
              currentPage={webshellTimelinePage.currentPage}
              pageSize={webshellTimelinePage.pageSize}
              onPageChange={webshellTimelinePage.setCurrentPage}
              onPageSizeChange={webshellTimelinePage.setPageSize}
              itemName="zaman çizelgesi olayı"
            />
          </div>
        </div>
      )}

      {/* 6. Bot & Tarayıcı Tespiti */}
      {activeSubTab === 'bots' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              🤖 Otomatize Araçlar, Scannerlar ve Bot İmzaları
            </h4>
            <p className="text-[11px] text-slate-500 mt-0.5">
              SQLMap, Nikto, Nmap, Masscan, Gobuster, yüksek hata oranı ve anormal HTTP metodları (PROPFIND, TRACK, vb.) kullanan istemciler.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                  <th className="p-2.5 font-semibold">IP Adresi</th>
                  <th className="p-2.5 font-semibold">User-Agent</th>
                  <th className="p-2.5 font-semibold text-right">Toplam İstek</th>
                  <th className="p-2.5 font-semibold text-center">Farklı Komut</th>
                  <th className="p-2.5 font-semibold text-center">Hata Oranı</th>
                  <th className="p-2.5 font-semibold text-center">Hassas Yol</th>
                  <th className="p-2.5 font-semibold">Bot Tespit Nedeni</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {scannersPage.paginatedItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 transition-colors">
                    <td className="p-2.5 font-mono font-bold text-slate-900">{item.ip_adresi}</td>
                    <td className="p-2.5 font-mono text-slate-700 max-w-xs truncate" title={item.user_agent}>
                      {item.user_agent}
                    </td>
                    <td className="p-2.5 text-right font-mono font-semibold">{item.toplam_istek}</td>
                    <td className="p-2.5 text-center font-mono">{item.farkli_komut_sayisi}</td>
                    <td className="p-2.5 text-center font-mono font-bold text-amber-700">%{item.hata_yuzdesi}</td>
                    <td className="p-2.5 text-center font-mono text-red-600 font-bold">{item.hassas_sayisi}</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200">
                        {item.bot_sebebi}
                      </span>
                    </td>
                  </tr>
                ))}
                {scannersPage.totalItems === 0 && (
                  <tr>
                    <td colSpan={7} className="p-6 text-center text-slate-500">
                      Tespit edilen bot veya tarayıcı aracı bulunamadı.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <TablePagination
            totalItems={scannersPage.totalItems}
            currentPage={scannersPage.currentPage}
            pageSize={scannersPage.pageSize}
            onPageChange={scannersPage.setCurrentPage}
            onPageSizeChange={scannersPage.setPageSize}
            itemName="bot kaydı"
          />
        </div>
      )}

      {/* 7. FTP Operasyonları */}
      {activeSubTab === 'ftp' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                📁 FTP Dosya Hareketleri (STOR, RETR, DELE, RNTO)
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">IP Adresi</th>
                    <th className="p-2.5 font-semibold">Kullanıcı</th>
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold text-center">Yükleme (STOR)</th>
                    <th className="p-2.5 font-semibold text-center">İndirme (RETR)</th>
                    <th className="p-2.5 font-semibold text-center">Silme (DELE)</th>
                    <th className="p-2.5 font-semibold text-right">Transfer Byte</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {ftpFilesPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-slate-900">{item.ip_adresi}</td>
                      <td className="p-2.5 font-mono text-slate-700">{item.kullanici_adi}</td>
                      <td className="p-2.5 font-mono text-slate-600">{item.sunucu_ismi}</td>
                      <td className="p-2.5 text-center font-mono text-blue-700 font-bold">{item.yukleme_sayisi}</td>
                      <td className="p-2.5 text-center font-mono text-emerald-700 font-bold">{item.indirme_sayisi}</td>
                      <td className="p-2.5 text-center font-mono text-red-700 font-bold">{item.silme_sayisi}</td>
                      <td className="p-2.5 text-right font-mono text-purple-700">{(item.toplam_byte / 1024).toFixed(1)} KB</td>
                    </tr>
                  ))}
                  {ftpFilesPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={7} className="p-6 text-center text-slate-500">FTP dosya işlemi bulunamadı.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={ftpFilesPage.totalItems}
              currentPage={ftpFilesPage.currentPage}
              pageSize={ftpFilesPage.pageSize}
              onPageChange={ftpFilesPage.setCurrentPage}
              onPageSizeChange={ftpFilesPage.setPageSize}
              itemName="FTP dosya hareketi"
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🛡️ Şüpheli FTP Komutları ve Başarısız Girişler (530 / 550)
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-100">
                  <tr className="border-b border-slate-200 text-slate-700">
                    <th className="p-2 font-semibold">Tarih</th>
                    <th className="p-2 font-semibold">IP Adresi</th>
                    <th className="p-2 font-semibold">Kullanıcı</th>
                    <th className="p-2 font-semibold">Komut</th>
                    <th className="p-2 font-semibold text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {ftpSuspiciousPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 font-mono text-[11px]">
                      <td className="p-2 text-slate-600">{item.tarih}</td>
                      <td className="p-2 font-bold text-slate-900">{item.ip_adresi}</td>
                      <td className="p-2 text-slate-700">{item.kullanici_adi}</td>
                      <td className="p-2 text-red-600 font-bold">{item.islem_komutu}</td>
                      <td className="p-2 text-center font-bold">{item.status_code}</td>
                    </tr>
                  ))}
                  {ftpSuspiciousPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-slate-500">Şüpheli FTP aktivitesi bulunamadı.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={ftpSuspiciousPage.totalItems}
              currentPage={ftpSuspiciousPage.currentPage}
              pageSize={ftpSuspiciousPage.pageSize}
              onPageChange={ftpSuspiciousPage.setCurrentPage}
              onPageSizeChange={ftpSuspiciousPage.setPageSize}
              itemName="FTP şüpheli komut"
            />
          </div>
        </div>
      )}

      {/* 8. Brute Force & Password Spraying */}
      {activeSubTab === 'brute_force' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🔑 Kaba Kuvvet (Brute Force) Girişimleri
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">IP Adresi</th>
                    <th className="p-2.5 font-semibold">Kullanıcı</th>
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold text-center">Başarısız Deneme Sayısı</th>
                    <th className="p-2.5 font-semibold">İlk ve Son Deneme</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {bruteForcePage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-red-600">{item.ip_adresi}</td>
                      <td className="p-2.5 font-mono text-slate-800">{item.kullanici_adi}</td>
                      <td className="p-2.5 font-mono text-slate-600">{item.sunucu_ismi}</td>
                      <td className="p-2.5 text-center font-mono font-extrabold text-red-700 text-sm">
                        {item.basarisiz_deneme_sayisi}
                      </td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-600">{item.ilk_deneme} &rarr; {item.son_deneme}</td>
                    </tr>
                  ))}
                  {bruteForcePage.totalItems === 0 && (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-slate-500">
                        Eşik değerini ({failedAttempts}) aşan kaba kuvvet denemesi bulunamadı.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={bruteForcePage.totalItems}
              currentPage={bruteForcePage.currentPage}
              pageSize={bruteForcePage.pageSize}
              onPageChange={bruteForcePage.setCurrentPage}
              onPageSizeChange={bruteForcePage.setPageSize}
              itemName="kaba kuvvet girişimi"
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🎯 Parola Püskürtme (Password Spraying) Analizi
              </h4>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Tek bir IP adresinden çok sayıda farklı kullanıcı adına yapılan eşzamanlı oturum açma denemeleri.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Saldırgan IP</th>
                    <th className="p-2.5 font-semibold text-center">Farklı Kullanıcı</th>
                    <th className="p-2.5 font-semibold text-center">Başarısız Deneme</th>
                    <th className="p-2.5 font-semibold text-center">Hedef Sunucu</th>
                    <th className="p-2.5 font-semibold">Hedeflenen Kullanıcılar</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {passwordSprayingPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono font-bold text-red-600">{item.ip_adresi}</td>
                      <td className="p-2.5 text-center font-mono font-bold text-purple-700">{item.farkli_kullanici_sayisi}</td>
                      <td className="p-2.5 text-center font-mono text-red-600 font-bold">{item.basarisiz_deneme_sayisi}</td>
                      <td className="p-2.5 text-center font-mono">{item.hedef_sunucu_sayisi}</td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-700">{item.hedeflenen_kullanicilar}</td>
                    </tr>
                  ))}
                  {passwordSprayingPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-slate-500">Parola püskürtme modeli tespit edilmedi.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={passwordSprayingPage.totalItems}
              currentPage={passwordSprayingPage.currentPage}
              pageSize={passwordSprayingPage.pageSize}
              onPageChange={passwordSprayingPage.setCurrentPage}
              onPageSizeChange={passwordSprayingPage.setPageSize}
              itemName="parola püskürtme vakası"
            />
          </div>
        </div>
      )}

      {/* 9. Şüpheli Komutlar & Hassas Yollar */}
      {activeSubTab === 'suspicious_cmds' && (
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                ⚡ 500 Çöküşleri, SQL Injection ve RCE Şüpheli Komutlar
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold">İşlem / Komut</th>
                    <th className="p-2.5 font-semibold text-center">Status</th>
                    <th className="p-2.5 font-semibold text-center">Tekrar</th>
                    <th className="p-2.5 font-semibold text-center">Farklı IP</th>
                    <th className="p-2.5 font-semibold text-right">Analiz &amp; Açıklama</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {commandsPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono text-slate-700">{item.sunucu_ismi}</td>
                      <td className="p-2.5 font-mono text-red-600 font-semibold max-w-lg truncate" title={item.islem_komutu}>
                        {item.islem_komutu}
                      </td>
                      <td className="p-2.5 text-center font-mono font-bold text-red-700">{item.status_code}</td>
                      <td className="p-2.5 text-center font-mono">{item.tekrar_sayisi}</td>
                      <td className="p-2.5 text-center font-mono">{item.erisen_farkli_ip_sayisi}</td>
                      <td className="p-2.5 text-right">
                        {onOpenCommandExplainer && (
                          <button
                            type="button"
                            onClick={() =>
                              onOpenCommandExplainer(item.islem_komutu, {
                                host: item.sunucu_ismi,
                                logSource: 'Threat Hunting Correlated Events',
                              })
                            }
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-lg transition-colors cursor-pointer"
                            title="Bu komutu anında incele ve açıkla"
                          >
                            <Terminal className="w-3 h-3 text-indigo-600" />
                            <span>Komutu Açıkla</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {commandsPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={6} className="p-6 text-center text-slate-500">Şüpheli komut veya 500 hatası bulunamadı.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={commandsPage.totalItems}
              currentPage={commandsPage.currentPage}
              pageSize={commandsPage.pageSize}
              onPageChange={commandsPage.setCurrentPage}
              onPageSizeChange={commandsPage.setPageSize}
              itemName="şüpheli komut"
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                🔍 Hassas Dosya ve Yapılandırma Yolu Taramaları
              </h4>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-700">
                    <th className="p-2.5 font-semibold">Sunucu</th>
                    <th className="p-2.5 font-semibold">Hassas Yol</th>
                    <th className="p-2.5 font-semibold text-center">Status</th>
                    <th className="p-2.5 font-semibold text-center">İstek Sayısı</th>
                    <th className="p-2.5 font-semibold text-center">Erişen IP Sayısı</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {endpointsPage.paginatedItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="p-2.5 font-mono text-slate-700">{item.sunucu_ismi}</td>
                      <td className="p-2.5 font-mono text-amber-700 font-semibold">{item.islem_komutu}</td>
                      <td className="p-2.5 text-center font-mono font-bold">{item.status_code}</td>
                      <td className="p-2.5 text-center font-mono">{item.istek_sayisi}</td>
                      <td className="p-2.5 text-center font-mono">{item.farkli_ip_sayisi}</td>
                    </tr>
                  ))}
                  {endpointsPage.totalItems === 0 && (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-slate-500">Hassas yol taraması bulunamadı.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              totalItems={endpointsPage.totalItems}
              currentPage={endpointsPage.currentPage}
              pageSize={endpointsPage.pageSize}
              onPageChange={endpointsPage.setCurrentPage}
              onPageSizeChange={endpointsPage.setPageSize}
              itemName="hassas yol"
            />
          </div>
        </div>
      )}

      {/* 10. DuckDB SQL Hunting Console */}
      {activeSubTab === 'duckdb_sql' && (
        <DuckDbHuntingConsole totalEvents={summary.toplam_olay} />
      )}

      {/* Detaylı Port İnceleme Modalı */}
      <PortDetailsModal
        isOpen={portModalData.isOpen}
        onClose={() => setPortModalData(prev => ({ ...prev, isOpen: false }))}
        hedefIp={portModalData.hedefIp}
        portString={portModalData.portString}
        onFilterByPort={(port) => {
          setSelectedPortFilter(port);
          const portTableEl = document.getElementById('port-service-table');
          if (portTableEl) {
            portTableEl.scrollIntoView({ behavior: 'smooth' });
          }
        }}
      />

      {/* Çoklu Dosya Dağılımı ve Doğrulama Modalı */}
      <FileBreakdownModal
        isOpen={isFileBreakdownOpen}
        onClose={() => setIsFileBreakdownOpen(false)}
        detectedFormats={report.detected_formats || []}
        totalTransferBytes={summary.toplam_transfer_byte}
        selectedFileFilter={selectedFileFilter}
        onSelectFileFilter={setSelectedFileFilter}
        quarantine={report.quarantine}
        onOpenQuarantine={() => setIsQuarantineModalOpen(true)}
      />

      {/* Ayrıştırılamayan / Bozuk Satırlar Karantinası Modalı */}
      <ForensicQuarantineModal
        isOpen={isQuarantineModalOpen}
        onClose={() => setIsQuarantineModalOpen(false)}
        quarantine={report.quarantine}
      />

      {/* SOC Analist Açıklanabilirlik ve Karar Gerekçesi Modalı */}
      <RiskExplainModal
        isOpen={!!explainModalItem}
        onClose={() => setExplainModalItem(null)}
        item={explainModalItem}
        onOpenAiModal={onOpenAiModal}
      />
    </div>
  );
};
