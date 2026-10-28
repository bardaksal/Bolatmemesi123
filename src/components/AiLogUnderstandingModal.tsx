import React, { useState, useMemo } from 'react';
import {
  X,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Copy,
  Check,
  Search,
  Code2,
  Layers,
  Activity,
  ArrowRight,
  Database,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import {
  runAiLogUnderstandingPipeline,
  analyzeLogStructureLocally,
} from '../services/aiLogUnderstandingEngine';
import {
  runAiSemanticLogPipeline,
} from '../services/aiSemanticLogEngine';
import {
  FullLogUnderstandingPipelineResult,
  SemanticForensicPipelineResult,
} from '../types/aiLogUnderstanding';

interface AiLogUnderstandingModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialLogText?: string;
}

export const AiLogUnderstandingModal: React.FC<AiLogUnderstandingModalProps> = ({
  isOpen,
  onClose,
  initialLogText = '',
}) => {
  const [rawText, setRawText] = useState(initialLogText);
  const [isProcessing, setIsProcessing] = useState(false);
  const [useRemoteAi, setUseRemoteAi] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'spans' | 'evidence' | 'hypotheses' | 'decisions'>('overview');
  const [selectedRecordIndex, setSelectedRecordIndex] = useState(0);
  const [pipelineResult, setPipelineResult] = useState<FullLogUnderstandingPipelineResult | null>(null);
  const [semanticResult, setSemanticResult] = useState<SemanticForensicPipelineResult | null>(null);
  const [copied, setCopied] = useState(false);

  // Sync initial log text if provided
  React.useEffect(() => {
    if (initialLogText && !rawText) {
      setRawText(initialLogText);
    }
  }, [initialLogText]);

  const handleRunPipeline = async () => {
    if (!rawText.trim()) return;
    setIsProcessing(true);
    try {
      const [res, semRes] = await Promise.all([
        runAiLogUnderstandingPipeline({
          rawInput: rawText,
          useRemoteAi,
        }),
        runAiSemanticLogPipeline({
          rawInput: rawText,
          useRemoteAi,
        }),
      ]);
      setPipelineResult(res);
      setSemanticResult(semRes);
      setSelectedRecordIndex(0);
    } catch (err: any) {
      console.error('Pipeline execution error:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/80 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-6xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-linear-to-r from-slate-900 via-indigo-950 to-slate-900 text-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/20 border border-indigo-400/30 rounded-xl">
              <Sparkles className="w-5 h-5 text-indigo-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  AI Forensic Log Understanding Engine
                </h2>
                <span className="px-2 py-0.5 text-[10px] font-bold bg-indigo-500/30 text-indigo-200 border border-indigo-400/30 rounded-full uppercase tracking-wider">
                  Phase 4.5
                </span>
                <span className="px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-400/30 rounded-full">
                  Zero Regex / Zero Format-Rule Architecture
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                AI Log Understanding → AI Semantic Event Analysis → Universal Evidence → Raw-Span Validation → Forensic Reasoning → Correlation → Final Decision
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Phase 4.5 Mandatory Architecture Pipeline Banner */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
            <div className="flex flex-col gap-2">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                Phase 4.5 Zorunlu 8 Aşamalı Adli Pipeline:
              </div>
              <div className="flex flex-wrap items-center gap-1.5 text-xs font-semibold">
                <span className="px-2 py-1 bg-slate-200 text-slate-800 rounded-md font-mono text-[11px]">1. RAW INPUT</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-indigo-100 text-indigo-800 rounded-md font-mono text-[11px]">2. AI LOG UNDERSTANDING</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-purple-100 text-purple-800 rounded-md font-mono text-[11px]">3. AI SEMANTIC ANALYSIS</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded-md font-mono text-[11px]">4. UNIVERSAL EVIDENCE</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-teal-100 text-teal-800 rounded-md font-mono text-[11px]">5. RAW-SPAN VALIDATION</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-amber-100 text-amber-800 rounded-md font-mono text-[11px]">6. FORENSIC REASONING</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-orange-100 text-orange-800 rounded-md font-mono text-[11px]">7. CORRELATION</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="px-2 py-1 bg-rose-100 text-rose-800 rounded-md font-mono text-[11px]">8. FINAL DECISION</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                AI bilmediği alanı tahmin etmez. UNKNOWN ≠ BENIGN ve UNKNOWN ≠ ATTACK. Her kanıt ham log rawSpan ile doğrulanır.
              </div>
            </div>
          </div>

          {/* Input Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-indigo-600" />
                Ham Log / Veri Girdisi (Herhangi bir format)
              </label>
            </div>

            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Analiz edilecek ham log metnini buraya yapıştırın (Windows, Linux, Apache, CEF, JSON, veya bilinmeyen herhangi bir format)..."
              rows={6}
              className="w-full px-4 py-3 text-xs font-mono text-slate-800 bg-slate-900/5 border border-slate-300 rounded-xl focus:outline-hidden focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono transition-all resize-y"
            />

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-700 font-medium cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useRemoteAi}
                    onChange={(e) => setUseRemoteAi(e.target.checked)}
                    className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  <span>Gemini 3.8 Flash Sunucu Modelini Kullan (Aktifse)</span>
                </label>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setRawText('')}
                  disabled={isProcessing || !rawText}
                  className="px-3 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                >
                  Temizle
                </button>
                <button
                  onClick={handleRunPipeline}
                  disabled={isProcessing || !rawText.trim()}
                  className="inline-flex items-center gap-2 px-5 py-2.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl shadow-md transition-all cursor-pointer disabled:opacity-50"
                >
                  {isProcessing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>AI Analizi &amp; Doğrulama Yürütülüyor...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-indigo-200" />
                      <span>AI Anlamlandırma &amp; Raw-Span Doğrula</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Results Section */}
          {pipelineResult && (
            <div className="space-y-4 pt-4 border-t border-slate-200">
              {/* Tab Navigation */}
              <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveTab('overview')}
                    className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                      activeTab === 'overview'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    1. Doğrulama Özeti (Validation Report)
                  </button>
                  <button
                    onClick={() => setActiveTab('spans')}
                    className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                      activeTab === 'spans'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    2. Raw-Span &amp; Olay Sınırları ({pipelineResult.validationReport.acceptedRecordsCount})
                  </button>
                  <button
                    onClick={() => setActiveTab('evidence')}
                    className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                      activeTab === 'evidence'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    3. Universal Evidence ({pipelineResult.universalEvidences.length})
                  </button>
                  <button
                    onClick={() => setActiveTab('decisions')}
                    className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                      activeTab === 'decisions'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    4. Deterministik Kararlar ({pipelineResult.deterministicDecisions.length})
                  </button>
                  <button
                    onClick={() => setActiveTab('hypotheses')}
                    className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                      activeTab === 'hypotheses'
                        ? 'bg-indigo-600 text-white shadow-xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    5. Adli Hipotezler &amp; Semantik ({semanticResult?.hypotheses?.length || 0})
                  </button>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  <span className="font-semibold text-slate-500">Format:</span>
                  <span className="px-2 py-0.5 bg-slate-100 text-slate-800 font-bold border border-slate-200 rounded-md">
                    {pipelineResult.aiResponse.formatAssessment.format}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded-md font-bold text-[10px] ${
                      pipelineResult.aiResponse.formatAssessment.confidence === 'HIGH'
                        ? 'bg-emerald-100 text-emerald-800'
                        : pipelineResult.aiResponse.formatAssessment.confidence === 'MEDIUM'
                        ? 'bg-blue-100 text-blue-800'
                        : 'bg-amber-100 text-amber-800'
                    }`}
                  >
                    {pipelineResult.aiResponse.formatAssessment.confidence} GÜVEN
                  </span>
                </div>
              </div>

              {/* Tab 1: Overview */}
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  {/* KPI Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
                      <div className="text-[11px] font-semibold text-slate-500">Toplam Logical Event</div>
                      <div className="text-xl font-bold text-slate-900 mt-1">
                        {pipelineResult.validationReport.totalCandidateRecords}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {pipelineResult.rawLinesCount} ham satırdan çıkarıldı
                      </div>
                    </div>

                    <div className="p-3.5 bg-emerald-50 border border-emerald-200 rounded-xl">
                      <div className="text-[11px] font-semibold text-emerald-700">Doğrulanan Raw-Span</div>
                      <div className="text-xl font-bold text-emerald-800 mt-1">
                        {pipelineResult.validationReport.acceptedRecordsCount}
                      </div>
                      <div className="text-[10px] text-emerald-600 mt-0.5">
                        Kanıt sadakati: %{pipelineResult.validationReport.provenanceAdherenceRate}
                      </div>
                    </div>

                    <div className="p-3.5 bg-blue-50 border border-blue-200 rounded-xl">
                      <div className="text-[11px] font-semibold text-blue-700">Halüsinasyon / Uydurma Alan</div>
                      <div className="text-xl font-bold text-blue-800 mt-1">
                        {pipelineResult.validationReport.hallucinationsDetected}
                      </div>
                      <div className="text-[10px] text-blue-600 mt-0.5">
                        {pipelineResult.validationReport.hallucinationsDetected === 0
                          ? '✅ Sıfır halüsinasyon'
                          : '⚠️ Reddedildi'}
                      </div>
                    </div>

                    <div className="p-3.5 bg-purple-50 border border-purple-200 rounded-xl">
                      <div className="text-[11px] font-semibold text-purple-700">Çapraz Olay Bulaşması</div>
                      <div className="text-xl font-bold text-purple-800 mt-1">
                        {pipelineResult.validationReport.crossEventContaminationsDetected}
                      </div>
                      <div className="text-[10px] text-purple-600 mt-0.5">
                        {pipelineResult.validationReport.crossEventContaminationsDetected === 0
                          ? '✅ Sıfır veri sızıntısı'
                          : '⚠️ İzolasyon engellendi'}
                      </div>
                    </div>
                  </div>

                  {/* Summary Card */}
                  <div className="p-4 bg-slate-900 text-slate-100 rounded-xl font-mono text-xs whitespace-pre-line leading-relaxed shadow-inner">
                    {pipelineResult.validationReport.summaryMarkdown}
                  </div>
                </div>
              )}

              {/* Tab 2: Raw Spans & Records */}
              {activeTab === 'spans' && (
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
                  {/* Left: Record List */}
                  <div className="md:col-span-4 border border-slate-200 rounded-xl overflow-hidden flex flex-col max-h-[420px]">
                    <div className="p-2.5 bg-slate-50 border-b border-slate-200 font-bold text-xs text-slate-700">
                      Mantıksal Kayıtlar ({pipelineResult.validationReport.validatedRecords.length})
                    </div>
                    <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
                      {pipelineResult.validationReport.validatedRecords.map((rec, i) => (
                        <button
                          key={rec.recordIndex}
                          onClick={() => setSelectedRecordIndex(i)}
                          className={`w-full text-left p-3 transition-colors cursor-pointer text-xs ${
                            selectedRecordIndex === i
                              ? 'bg-indigo-50/70 border-l-4 border-indigo-600'
                              : 'hover:bg-slate-50'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-slate-800">
                              Olay #{rec.recordIndex}
                            </span>
                            <span
                              className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${
                                rec.recordStatus === 'ACCEPTED'
                                  ? 'bg-emerald-100 text-emerald-800'
                                  : rec.recordStatus === 'REJECTED'
                                  ? 'bg-rose-100 text-rose-800'
                                  : 'bg-amber-100 text-amber-800'
                              }`}
                            >
                              {rec.recordStatus}
                            </span>
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">
                            [{rec.rawStart}..{rec.rawEnd}] {rec.rawText.slice(0, 40)}...
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            {rec.fields.length} alan ({rec.acceptedFieldsCount} kabul)
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Right: Record Details */}
                  {pipelineResult.validationReport.validatedRecords[selectedRecordIndex] && (
                    <div className="md:col-span-8 border border-slate-200 rounded-xl p-4 space-y-4">
                      {(() => {
                        const rec =
                          pipelineResult.validationReport.validatedRecords[selectedRecordIndex];
                        return (
                          <>
                            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                              <div>
                                <h4 className="font-bold text-sm text-slate-900">
                                  Olay #{rec.recordIndex} — Raw Span Detayları
                                </h4>
                                <div className="text-xs text-slate-500 font-mono mt-0.5">
                                  Girdi İndisleri: [{rec.rawStart} .. {rec.rawEnd}] | Uzunluk: {rec.rawText.length} karakter
                                </div>
                              </div>
                              <span
                                className={`px-2 py-1 text-xs font-bold rounded-md ${
                                  rec.spanIntegrity === 'VALID'
                                    ? 'bg-emerald-100 text-emerald-800'
                                    : 'bg-rose-100 text-rose-800'
                                }`}
                              >
                                {rec.spanIntegrity}
                              </span>
                            </div>

                            {/* Raw Text Box */}
                            <div>
                              <div className="text-xs font-semibold text-slate-600 mb-1">
                                Olayın Ham Metni (Raw Text):
                              </div>
                              <div className="p-3 bg-slate-900 text-slate-200 rounded-lg font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                                {rec.rawText}
                              </div>
                            </div>

                            {/* Fields Table */}
                            <div>
                              <div className="text-xs font-semibold text-slate-600 mb-1">
                                Çıkarılan Alan Semantikleri &amp; Raw-Span Doğrulaması:
                              </div>
                              <div className="border border-slate-200 rounded-lg overflow-hidden">
                                <table className="w-full text-left text-xs divide-y divide-slate-200">
                                  <thead className="bg-slate-50 font-semibold text-slate-700">
                                    <tr>
                                      <th className="px-3 py-2">Alan Adı</th>
                                      <th className="px-3 py-2">Değer</th>
                                      <th className="px-3 py-2">Durum</th>
                                      <th className="px-3 py-2">Doğrulama</th>
                                      <th className="px-3 py-2">Span Konumu</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-100 font-mono">
                                    {rec.fields.map((f, fIdx) => (
                                      <tr key={fIdx} className="hover:bg-slate-50">
                                        <td className="px-3 py-1.5 font-bold text-indigo-700">
                                          {f.fieldName}
                                        </td>
                                        <td className="px-3 py-1.5 text-slate-900 truncate max-w-xs">
                                          {f.value || <span className="text-slate-400 font-normal italic">yok</span>}
                                        </td>
                                        <td className="px-3 py-1.5">
                                          <span
                                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                              f.validatedStatus === 'OBSERVED'
                                                ? 'bg-emerald-100 text-emerald-800'
                                                : f.validatedStatus === 'DERIVED'
                                                ? 'bg-purple-100 text-purple-800'
                                                : f.validatedStatus === 'NOT_PRESENT'
                                                ? 'bg-slate-100 text-slate-600'
                                                : 'bg-amber-100 text-amber-800'
                                            }`}
                                          >
                                            {f.validatedStatus}
                                          </span>
                                        </td>
                                        <td className="px-3 py-1.5">
                                          <span
                                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                              f.decision === 'ACCEPTED'
                                                ? 'bg-emerald-100 text-emerald-800'
                                                : f.decision === 'REJECTED'
                                                ? 'bg-rose-100 text-rose-800'
                                                : 'bg-amber-100 text-amber-800'
                                            }`}
                                          >
                                            {f.decision}
                                          </span>
                                        </td>
                                        <td className="px-3 py-1.5 text-slate-500 text-[11px]">
                                          {f.resolvedSourceSpan
                                            ? `[${f.resolvedSourceSpan.start}..${f.resolvedSourceSpan.end}]`
                                            : '-'}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          </>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Universal Evidence */}
              {activeTab === 'evidence' && (
                <div className="space-y-4">
                  <div className="text-xs text-slate-600">
                    AI tarafından çıkarılan ve Raw-Span doğrulaması tamamlanan her mantıksal kayıt,
                    sıkı kurallarla kanıt modeline (UniversalEvidence) dönüştürülmüştür:
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[460px] overflow-y-auto">
                    {pipelineResult.universalEvidences.map((ev, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 border border-slate-200 rounded-xl bg-white space-y-2.5 text-xs font-mono shadow-xs"
                      >
                        <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                          <span className="font-bold text-slate-800">
                            Universal Evidence #{idx + 1}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              ev.admissibility.isSecurityEvidence
                                ? 'bg-emerald-100 text-emerald-800'
                                : 'bg-slate-100 text-slate-600'
                            }`}
                          >
                            {ev.admissibility.classification}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[11px]">
                          <div>
                            <span className="text-slate-400">Aktör / Kullanıcı:</span>
                            <div className="font-bold text-slate-800">
                              {ev.actor.value || 'NOT_PRESENT'} ({ev.actor.status})
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Kaynak Uç Nokta:</span>
                            <div className="font-bold text-slate-800">
                              {ev.sourceEndpoint.ip.value || 'NOT_PRESENT'}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Süreç / Komut:</span>
                            <div className="font-bold text-slate-800 truncate">
                              {ev.process.commandLine.value || ev.process.name.value || 'NOT_PRESENT'}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Üst Süreç (Parent):</span>
                            <div className="font-bold text-slate-800 truncate">
                              {ev.process.parentProcess.value || 'NOT_PRESENT'}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Aksiyon &amp; Sonuç:</span>
                            <div className="font-bold text-slate-800">
                              {ev.action.value || 'Yok'} → {ev.outcome.value}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400">Event ID:</span>
                            <div className="font-bold text-slate-800">
                              {ev.telemetry.eventId.value || 'Yok'}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 4: Deterministic Decisions & Correlation */}
              {activeTab === 'decisions' && (
                <div className="space-y-4">
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900">
                    <strong>Adli İlke Doğrulaması:</strong> Aşağıdaki tüm güvenlik kararları yapay zeka tarafından DEĞİL,
                    mevcut deterministik güvenlik motoru tarafından gerçek kanıtlara dayalı olarak verilmiştir.
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-h-[460px] overflow-y-auto">
                    {pipelineResult.deterministicDecisions.map((dec, idx) => (
                      <div
                        key={idx}
                        className="p-3 border border-slate-200 rounded-xl bg-white space-y-1.5 shadow-xs text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-800">Olay #{idx + 1}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              dec.verdict === 'AUTHORIZED_ACTIVITY'
                                ? 'bg-emerald-100 text-emerald-800'
                                : dec.verdict === 'SUSPICIOUS_ANOMALY'
                                ? 'bg-amber-100 text-amber-800'
                                : dec.verdict === 'BLOCKED_ATTACK_ATTEMPT'
                                ? 'bg-rose-100 text-rose-800'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                          >
                            {dec.verdict}
                          </span>
                        </div>
                        <div className="font-semibold text-slate-900 text-xs">
                          {dec.threatTitle}
                        </div>
                        <p className="text-[11px] text-slate-500 line-clamp-3">
                          {dec.summaryReason}
                        </p>
                      </div>
                    ))}
                  </div>

                  {pipelineResult.secondaryCorrelation && (
                    <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-2">
                      <div className="font-bold text-slate-900">
                        İkincil Korelasyon Durumu:{' '}
                        <span className="text-indigo-700">
                          {pipelineResult.secondaryCorrelation.postureTitle}
                        </span>
                      </div>
                      <p className="text-slate-600">
                        {pipelineResult.secondaryCorrelation.evidenceBasedSummary}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 5: Adli Hipotezler & Semantik Ayrım (Phase 4.5) */}
              {activeTab === 'hypotheses' && (
                <div className="space-y-4">
                  <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-xl text-xs text-indigo-950 space-y-2">
                    <div className="font-bold flex items-center gap-1.5 text-indigo-900">
                      <Sparkles className="w-4 h-4 text-indigo-600" />
                      Phase 4.5: True AI Semantic Interpretation &amp; Forensic Hypothesis Pipeline
                    </div>
                    <p className="text-slate-700 leading-relaxed">
                      AI sadece sınırları bulmaz; bağlamı ve semantiği anlar. Sıfır format-spesifik kod ile:
                      <strong> &quot;Connection closed&quot;</strong> (SSH sunucu telemetrisi = WAF block değil),
                      <strong> &quot;GET /etc/passwd&quot;</strong> (HTTP_REQUEST_URI = komut çalıştırma değil),
                      <strong> &quot;HTTP 403&quot;</strong> (tek başına WAF engeli değil),
                      <strong> &quot;Event 7045&quot;</strong> (servis yükleme = otomatik benign değil) prensipleriyle adli hipotezler üretilir.
                    </p>
                  </div>

                  {semanticResult && semanticResult.hypotheses.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[460px] overflow-y-auto">
                      {semanticResult.hypotheses.map((hyp, hIdx) => (
                        <div
                          key={hIdx}
                          className="p-4 border border-slate-200 rounded-xl bg-white shadow-xs space-y-3 text-xs"
                        >
                          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                            <span className="font-bold text-slate-900 text-sm">
                              {hyp.hypothesis}
                            </span>
                            <span
                              className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider ${
                                hyp.status === 'BLOCKED_ATTEMPT'
                                  ? 'bg-purple-100 text-purple-800 border border-purple-200'
                                  : hyp.status === 'CONFIRMED'
                                  ? 'bg-rose-100 text-rose-800 border border-rose-200'
                                  : hyp.status === 'UNCONFIRMED'
                                  ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                  : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                              }`}
                            >
                              {hyp.status}
                            </span>
                          </div>

                          <div>
                            <div className="font-semibold text-slate-700 mb-1 flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                              Gözlemlenen Olgular (Observed Facts):
                            </div>
                            <ul className="list-disc list-inside space-y-0.5 text-slate-600 pl-1">
                              {hyp.observedFacts.map((fact, fIdx) => (
                                <li key={fIdx} className="font-mono text-[11px]">
                                  {fact}
                                </li>
                              ))}
                            </ul>
                          </div>

                          <div>
                            <div className="font-semibold text-slate-700 mb-1 flex items-center gap-1">
                              <Search className="w-3.5 h-3.5 text-indigo-600" />
                              Doğrulama İçin Gereken Kanıtlar (Required Evidence):
                            </div>
                            <ul className="list-disc list-inside space-y-0.5 text-slate-600 pl-1">
                              {hyp.requiredEvidence.map((req, rIdx) => (
                                <li key={rIdx} className="text-[11px]">
                                  {req}
                                </li>
                              ))}
                            </ul>
                          </div>

                          <div className="pt-2 border-t border-slate-100">
                            <span className="font-semibold text-slate-500">Adli Muhakeme (Forensic Reasoning):</span>
                            <p className="text-slate-800 font-medium mt-0.5 leading-snug">
                              {hyp.reasoning}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-6 text-center border border-dashed border-slate-200 rounded-xl text-slate-500 text-xs">
                      İncelenen loglar rutin sistem aktivitelerinden oluşmaktadır; özel bir saldırı hipotezi tetiklenmedi.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-xs text-slate-500">
            Phase 4.5: True AI Semantic Log Engine &amp; Universal Forensic Pipeline
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors cursor-pointer"
          >
            Kapat
          </button>
        </div>
      </div>
    </div>
  );
};
