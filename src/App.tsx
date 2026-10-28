import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Header } from './components/Header';
import { ThreatHuntingTab } from './components/ThreatHuntingTab';
import { AllowlistTab } from './components/AllowlistTab';
import { SqlModal } from './components/SqlModal';
import { AiSocAssistantModal } from './components/AiSocAssistantModal';
import { QuickLogPasteModal } from './components/QuickLogPasteModal';
import { CommandExplainerModal } from './components/CommandExplainerModal';
import { AiLogUnderstandingModal } from './components/AiLogUnderstandingModal';
import { CommandExplainerContext } from './services/commandExplainer';
import { AnalysisProgressBar } from './components/AnalysisProgressBar';
import { createEmptyReport } from './services/socEngine';
import {
  logWorkerController,
  LogFileEntry,
  AnalysisProgress,
} from './services/logWorkerController';
import { isExcelFile, convertExcelFileToCsv } from './services/excelConverter';
import { StreamEventSample } from './services/streamingParser';
import { defaultAllowlistManager } from './services/allowlistManager';
import { duckdbClient } from './services/duckdbClient';
import { analyzeRawLogText } from './services/quickLogAnalyzer';
import { runDirectGeminiHunt } from './services/geminiDirectHunter';
import {
  HuntingReport,
  RiskQueueItem,
  DetectionProfile,
  RawLogTriageSummary,
} from './types';
import {
  Crosshair,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react';
import { PolicyComparisonTab } from './components/PolicyComparisonTab';

type MainTab = 'hunting' | 'policy_comparison' | 'allowlist';

export default function App() {
  const [activeTab, setActiveTab] = useState<MainTab>('hunting');

  // Input log files state - strictly user uploaded, zero static/sample data
  const [logFiles, setLogFiles] = useState<LogFileEntry[]>([]);
  const [activeFileNames, setActiveFileNames] = useState<string[]>([]);

  // Web Worker Background Analysis States
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [liveSample, setLiveSample] = useState<StreamEventSample[]>([]);
  const isFirstMount = useRef(true);

  // Analysis Parameters
  const [exfiltrationMb, setExfiltrationMb] = useState<number>(10);
  const [failedAttempts, setFailedAttempts] = useState<number>(5);
  const [useAllowlist, setUseAllowlist] = useState<boolean>(false);
  const [detectionProfile, setDetectionProfile] = useState<DetectionProfile>('BALANCED');

  // Dynamic Hunting Report calculated directly from user uploaded files
  const [report, setReport] = useState<HuntingReport>(() => createEmptyReport());
  const rawLogTriageRef = useRef<RawLogTriageSummary | undefined>(undefined);
  const geminiReportRef = useRef<HuntingReport | null>(null);

  // Modals
  const [isSqlModalOpen, setIsSqlModalOpen] = useState(false);
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [isQuickLogModalOpen, setIsQuickLogModalOpen] = useState(false);
  const [isCommandExplainerOpen, setIsCommandExplainerOpen] = useState(false);
  const [isAiLogUnderstandingOpen, setIsAiLogUnderstandingOpen] = useState(false);
  const [targetExplainerCommand, setTargetExplainerCommand] = useState<string>('');
  const [targetExplainerContext, setTargetExplainerContext] = useState<CommandExplainerContext | null>(null);
  const [aiTargetRiskItem, setAiTargetRiskItem] = useState<RiskQueueItem | null>(null);
  const [aiTargetIp, setAiTargetIp] = useState<string | null>(null);

  const handleOpenAiModal = (item?: RiskQueueItem, ip?: string) => {
    setAiTargetRiskItem(item || null);
    setAiTargetIp(ip || item?.ip_adresi || null);
    setIsAiModalOpen(true);
  };

  const handleOpenCommandExplainer = (cmd?: string, context?: CommandExplainerContext) => {
    setTargetExplainerCommand(cmd || '');
    setTargetExplainerContext(context || null);
    setIsCommandExplainerOpen(true);
  };

  // Core Worker Pipeline: Stream and correlate user files in background
  const runWorkerAnalysis = useCallback(
    async (files: LogFileEntry[]) => {
      if (!files || files.length === 0) {
        logWorkerController.clear();
        setReport(createEmptyReport());
        setLiveSample([]);
        setProgress(null);
        setIsProcessing(false);
        return;
      }

      setIsProcessing(true);
      try {
        const allowlistData = useAllowlist ? defaultAllowlistManager.getData() : null;
        const res = await logWorkerController.processFiles(
          files,
          {
            exfiltrationBytes: exfiltrationMb * 1024 * 1024,
            failedAttempts,
            allowlistData,
            detectionProfile,
          },
          (prog) => setProgress(prog)
        );

        setReport({
          ...(geminiReportRef.current || res.report),
          raw_log_triage: rawLogTriageRef.current || res.report.raw_log_triage,
          detected_formats: res.report.detected_formats || geminiReportRef.current?.detected_formats,
        });
        setLiveSample(res.liveSample);

        // Populate DuckDB-Wasm in background with zero disruption to main thread / SOC engine
        if (res.rawLogs && res.rawLogs.length > 0) {
          duckdbClient.loadLogs(res.rawLogs).catch((e) => {
            console.warn('[DuckDB] Log ingestion warning:', e);
          });
        }
      } catch (err: unknown) {
        console.error('Log analizi hatası:', err);
      } finally {
        setIsProcessing(false);
      }
    },
    [exfiltrationMb, failedAttempts, useAllowlist, detectionProfile]
  );

  // Fast Re-analysis when sliders or allowlist toggle change
  useEffect(() => {
    if (isFirstMount.current) {
      isFirstMount.current = false;
      return;
    }
    if (logFiles.length === 0) return;

    let isMounted = true;
    setIsProcessing(true);
    const allowlistData = useAllowlist ? defaultAllowlistManager.getData() : null;

    logWorkerController
      .reAnalyze(
        {
          exfiltrationBytes: exfiltrationMb * 1024 * 1024,
          failedAttempts,
          allowlistData,
          detectionProfile,
        },
        (prog) => {
          if (isMounted) setProgress(prog);
        }
      )
      .then((res) => {
        if (isMounted) {
          setReport({
            ...res.report,
            raw_log_triage: rawLogTriageRef.current || res.report.raw_log_triage,
          });
          setLiveSample(res.liveSample);
          setIsProcessing(false);
        }
      })
      .catch((err) => {
        console.error('Yeniden analiz hatası:', err);
        if (isMounted) setIsProcessing(false);
      });

    return () => {
      isMounted = false;
    };
  }, [exfiltrationMb, failedAttempts, useAllowlist, detectionProfile]);

  // Refresh triggered by Allowlist tab updates
  const refreshReport = useCallback(() => {
    if (logFiles.length === 0) return;
    setIsProcessing(true);
    const allowlistData = useAllowlist ? defaultAllowlistManager.getData() : null;
    logWorkerController
      .reAnalyze(
        {
          exfiltrationBytes: exfiltrationMb * 1024 * 1024,
          failedAttempts,
          allowlistData,
          detectionProfile,
        },
        (prog) => setProgress(prog)
      )
      .then((res) => {
        setReport({
          ...res.report,
          raw_log_triage: rawLogTriageRef.current || res.report.raw_log_triage,
        });
        setLiveSample(res.liveSample);
        setIsProcessing(false);
      })
      .catch(() => setIsProcessing(false));
  }, [logFiles.length, exfiltrationMb, failedAttempts, useAllowlist, detectionProfile]);

  // Handle user file uploads (directly passing File objects with Excel support)
  const handleUploadFiles = async (fileList: FileList | File[]) => {
    const newEntries: LogFileEntry[] = [];
    const existing = new Set(logFiles.map((f) => f.name));

    setIsProcessing(true);
    setProgress({
      percent: 5,
      stage: 'PARSING',
      stageMessage: 'Dosyalar hazırlanıyor ve inceleniyor...',
      linesRead: 0,
      totalFiles: fileList.length,
    });

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      if (!existing.has(file.name)) {
        if (isExcelFile(file.name)) {
          try {
            setProgress({
              percent: 10,
              stage: 'PARSING',
              stageMessage: `${file.name} Excel tablosu okunuyor ve dönüştürülüyor...`,
              linesRead: 0,
              fileName: file.name,
              totalFiles: fileList.length,
            });
            const csvText = await convertExcelFileToCsv(file);
            newEntries.push({
              name: file.name,
              content: csvText,
              file,
            });
          } catch (excelErr) {
            console.error('Excel dönüştürme hatası:', excelErr);
            newEntries.push({
              name: file.name,
              file,
            });
          }
        } else {
          newEntries.push({
            name: file.name,
            file,
          });
        }
      }
    }

    if (newEntries.length === 0) {
      setIsProcessing(false);
      return;
    }

    const updated = [...logFiles, ...newEntries];
    setLogFiles(updated);
    setActiveFileNames(updated.map((f) => f.name));
    runWorkerAnalysis(updated);
  };

  // Remove a specific uploaded file
  const handleRemoveFile = (fileName: string) => {
    const updated = logFiles.filter((f) => f.name !== fileName);
    setLogFiles(updated);
    setActiveFileNames(updated.map((f) => f.name));
    runWorkerAnalysis(updated);
  };

  // Clear all uploaded files
  const handleClearAllFiles = () => {
    rawLogTriageRef.current = undefined;
    geminiReportRef.current = null;
    logWorkerController.abort();
    logWorkerController.clear();
    duckdbClient.reset().catch(() => {});
    setLogFiles([]);
    setActiveFileNames([]);
    setReport(createEmptyReport());
    setLiveSample([]);
    setProgress(null);
    setIsProcessing(false);
  };

  // Abort ongoing analysis
  const handleAbortAnalysis = () => {
    logWorkerController.abort();
    setIsProcessing(false);
    setProgress(null);
  };

  // Direct paste into Threat Hunting (Direct background Gemini AI workflow)
  const handlePasteAndHunt = async (rawText: string) => {
    if (!rawText.trim()) return;

    setIsProcessing(true);
    setProgress({
      percent: 15,
      stage: 'PARSING',
      stageMessage: 'Log yapısı ve adli semantik analiz ediliyor...',
      linesRead: 0,
      totalFiles: 1,
    });

    try {
      // Execute Gemini AI semantic log pipeline directly in the background
      const directResult = await runDirectGeminiHunt(rawText);
      geminiReportRef.current = directResult.report;
      rawLogTriageRef.current = directResult.triageSummary;

      setReport(directResult.report);

      setProgress({
        percent: 60,
        stage: 'CORRELATING',
        stageMessage: 'Adli kanıtlar ve analitik tablolar hazırlanıyor...',
        linesRead: directResult.triageSummary.totalEvents,
        totalFiles: 1,
      });

      handleUploadFiles([directResult.file]);
    } catch (err) {
      console.warn('Doğrudan Gemini analizi hatası, yerel ayrıştırmaya geçiliyor:', err);
      const fallbackResult = analyzeRawLogText(rawText);
      if (fallbackResult) {
        rawLogTriageRef.current = fallbackResult.triageSummary;
        setReport((prev) => ({
          ...prev,
          raw_log_triage: fallbackResult.triageSummary,
        }));
        handleUploadFiles([fallbackResult.file]);
      }
    } finally {
      setActiveTab('hunting');
    }
  };

  return (
    <div className="min-h-screen bg-slate-100/75 text-slate-900 flex flex-col font-sans antialiased">
      {/* Top Application Header */}
      <Header
        logCount={report.summary.toplam_olay}
        fileCount={activeFileNames.length}
      />

      {/* Main Navigation Bar */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-2xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center space-x-1 sm:space-x-2 py-2 overflow-x-auto">
            <button
              onClick={() => setActiveTab('hunting')}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs sm:text-sm font-bold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'hunting'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Crosshair className="w-4 h-4" />
              <span>Tehdit Avı (Threat Hunting &amp; SIEM)</span>
            </button>

            <button
              onClick={() => setActiveTab('policy_comparison')}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs sm:text-sm font-bold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'policy_comparison'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              <span>Kural Etki &amp; Kıyaslama (Before / After)</span>
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-300">
                WAF
              </span>
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'hunting' && (
          <ThreatHuntingTab
            report={report}
            onUploadFiles={handleUploadFiles}
            onRemoveFile={handleRemoveFile}
            onClearAllFiles={handleClearAllFiles}
            exfiltrationMb={exfiltrationMb}
            setExfiltrationMb={setExfiltrationMb}
            failedAttempts={failedAttempts}
            setFailedAttempts={setFailedAttempts}
            useAllowlist={useAllowlist}
            setUseAllowlist={setUseAllowlist}
            detectionProfile={detectionProfile}
            setDetectionProfile={setDetectionProfile}
            onOpenAiModal={handleOpenAiModal}
            onOpenQuickLogModal={() => setIsQuickLogModalOpen(true)}
            onPasteAndHunt={handlePasteAndHunt}
            onOpenCommandExplainer={handleOpenCommandExplainer}
            activeFiles={activeFileNames}
            isProcessing={isProcessing}
            progress={progress}
            onAbort={handleAbortAnalysis}
            onNavigateToPolicyComparison={() => setActiveTab('policy_comparison')}
          />
        )}

        {activeTab === 'policy_comparison' && (
          <PolicyComparisonTab
            availableUploadedFiles={logFiles.map((f) => ({ name: f.name, content: f.content }))}
          />
        )}

        {activeTab === 'allowlist' && (
          <AllowlistTab
            allowlistMgr={defaultAllowlistManager}
            onRefresh={refreshReport}
          />
        )}
      </main>

      {/* Floating Worker Analysis Progress Bar */}
      <AnalysisProgressBar
        progress={progress}
        isProcessing={isProcessing}
        onAbort={handleAbortAnalysis}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SOC Log Lens &copy; 2026 — DuckDB SQL Çok Günlü Korelasyon &amp; Tehdit Avı Platformu</span>
          <span className="text-slate-400">%100 Dinamik Kullanıcı Logu Analiz Modu</span>
        </div>
      </footer>

      {/* DuckDB SQL Query Modal */}
      <SqlModal
        isOpen={isSqlModalOpen}
        onClose={() => setIsSqlModalOpen(false)}
        totalEvents={report.summary.toplam_olay}
      />

      {/* AI SOC Assistant Modal */}
      <AiSocAssistantModal
        isOpen={isAiModalOpen}
        onClose={() => setIsAiModalOpen(false)}
        report={report}
        initialRiskItem={aiTargetRiskItem}
        initialTargetIp={aiTargetIp}
      />

      {/* Quick Log Paste & Customer Triage Modal */}
      <QuickLogPasteModal
        isOpen={isQuickLogModalOpen}
        onClose={() => setIsQuickLogModalOpen(false)}
        onOpenCommandExplainer={handleOpenCommandExplainer}
        onOpenAiLogUnderstanding={() => {
          setIsQuickLogModalOpen(false);
          setIsAiLogUnderstandingOpen(true);
        }}
        onImportToHunting={(file, triageSummary) => {
          if (triageSummary) {
            rawLogTriageRef.current = triageSummary;
            setReport((prev) => ({
              ...prev,
              raw_log_triage: triageSummary,
            }));
          }
          handleUploadFiles([file]);
        }}
      />

      {/* Offline Deterministic Command Explainer Modal */}
      <CommandExplainerModal
        isOpen={isCommandExplainerOpen}
        onClose={() => setIsCommandExplainerOpen(false)}
        initialCommand={targetExplainerCommand}
        context={targetExplainerContext}
      />

      {/* Phase 4: AI Forensic Log Understanding Modal */}
      <AiLogUnderstandingModal
        isOpen={isAiLogUnderstandingOpen}
        onClose={() => setIsAiLogUnderstandingOpen(false)}
      />
    </div>
  );
}
