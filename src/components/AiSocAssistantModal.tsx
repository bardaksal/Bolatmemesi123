import React, { useState, useEffect, useRef } from 'react';
import {
  X,
  Sparkles,
  Mail,
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  Building2,
  UserCheck,
  RotateCw,
  FileText,
  AlertTriangle,
  ShieldCheck,
  Flame,
  ArrowRight,
  Printer,
  Activity,
  Layers,
  Server,
  Globe,
  HelpCircle,
} from 'lucide-react';
import Markdown from 'react-markdown';
import {
  HuntingReport,
  RiskQueueItem,
  AiSocAnalysisResult,
  CustomerEmailResult,
  MitreAttackItem,
  ThreatActorFinding,
} from '../types';
import { requestAiSocAnalysis, requestCustomerEmail } from '../services/aiService';

interface AiSocAssistantModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: HuntingReport;
  initialRiskItem?: RiskQueueItem | null;
  initialTargetIp?: string | null;
}

export const AiSocAssistantModal: React.FC<AiSocAssistantModalProps> = ({
  isOpen,
  onClose,
  report,
  initialRiskItem,
  initialTargetIp,
}) => {
  // Workflow Stage: 'forensic' (1. Aşama - Ana Log Analizi) vs 'mitre' vs 'email' (2. Aşama - Müşteri Bildirimi)
  const [activeStage, setActiveStage] = useState<'forensic' | 'mitre' | 'email'>('forensic');

  // Customer / Organization details (used exclusively for 2nd stage customer email reporting)
  const [companyName, setCompanyName] = useState('');
  const [analystName, setAnalystName] = useState('SOC Seviye-3 Tehdit Avı Ekibi');
  const [emailAnalysisType, setEmailAnalysisType] = useState<'customer_email' | 'executive_summary' | 'deep_technical'>('customer_email');
  const [emailCustomNotes, setEmailCustomNotes] = useState('');

  // Customer Email generation state
  const [customerEmail, setCustomerEmail] = useState<CustomerEmailResult | null>(null);
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);

  const riskQueue = report.entity_risk_queue || report.risk_queue || [];
  const [selectedIp, setSelectedIp] = useState<string>(
    initialTargetIp || initialRiskItem?.ip_adresi || ''
  );
  const [customNotes, setCustomNotes] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AiSocAnalysisResult | null>(null);

  const [copiedField, setCopiedField] = useState<string | null>(null);
  const hasAutoTriggered = useRef(false);

  // Sync initial target IP if changed from props
  useEffect(() => {
    if (initialTargetIp) {
      setSelectedIp(initialTargetIp);
    } else if (initialRiskItem?.ip_adresi) {
      setSelectedIp(initialRiskItem.ip_adresi);
    }
  }, [initialTargetIp, initialRiskItem]);

  // Reset stage when modal reopens
  useEffect(() => {
    if (isOpen) {
      if (!analysisResult) {
        setActiveStage('forensic');
      }
    } else {
      hasAutoTriggered.current = false;
    }
  }, [isOpen, analysisResult]);

  const handleCopy = (text: string, fieldKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldKey);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  // Stage 1: Objective Forensic Log Analysis (NO company assumptions)
  const handleGenerate = async (overrideTargetIp?: string) => {
    setLoading(true);
    setError(null);
    try {
      const ipToUse = overrideTargetIp !== undefined ? overrideTargetIp : selectedIp;
      const riskItem = riskQueue.find((r) => r.ip_adresi === ipToUse) || initialRiskItem || null;

      const result = await requestAiSocAnalysis({
        targetIp: ipToUse || undefined,
        report,
        selectedRiskItem: riskItem || undefined,
        customNotes: customNotes.trim() || undefined,
      });

      setAnalysisResult(result);
    } catch (err: any) {
      setError(err.message || 'Adli analiz oluşturulurken beklenmeyen bir hata meydana geldi.');
    } finally {
      setLoading(false);
    }
  };

  // Stage 2: Customer Email Generation (Requires companyName)
  const handleGenerateCustomerEmail = async () => {
    if (!companyName.trim()) {
      setEmailError('Lütfen önce müşteri kurum veya şirket adını giriniz.');
      return;
    }
    setEmailLoading(true);
    setEmailError(null);
    try {
      const primaryEntity = riskQueue[0] || initialRiskItem;
      const emailResult = await requestCustomerEmail({
        companyName: companyName.trim(),
        analystName: analystName.trim() || 'SOC Seviye-3 Tehdit Avı Ekibi',
        analysisType: emailAnalysisType,
        customNotes: emailCustomNotes.trim() || undefined,
        forensicData: {
          threatLevel: analysisResult?.threatLevel || 'KRİTİK',
          executiveSummary: analysisResult?.executiveSummary || '',
          targetIp: selectedIp || primaryEntity?.ip_adresi,
          primaryIp: selectedIp || primaryEntity?.ip_adresi,
          targetServers: analysisResult?.threatActors?.[0]?.targetedServers || primaryEntity?.sunucu_ismi,
          transferredMb:
            analysisResult?.threatActors?.[0]?.transferredMb ||
            (primaryEntity?.basarili_byte
              ? (primaryEntity.basarili_byte / (1024 * 1024)).toFixed(1)
              : undefined),
          recommendedActions: analysisResult?.recommendedActions,
        },
      });

      setCustomerEmail(emailResult);
    } catch (err: any) {
      setEmailError(err.message || 'Müşteri e-postası üretilirken bir hata meydana geldi.');
    } finally {
      setEmailLoading(false);
    }
  };

  // Auto-run on first open if logs are available and no analysis exists yet
  useEffect(() => {
    if (
      isOpen &&
      !analysisResult &&
      !loading &&
      report.summary.toplam_olay > 0 &&
      !hasAutoTriggered.current
    ) {
      hasAutoTriggered.current = true;
      handleGenerate();
    }
  }, [isOpen, report.summary.toplam_olay]);

  if (!isOpen) return null;

  const hasLogs = report.summary.toplam_olay > 0;

  const fullEmailContent = customerEmail
    ? `Konu: ${customerEmail.emailSubject}\n\n${customerEmail.emailGreeting}\n\n${customerEmail.emailBody}\n\n${customerEmail.emailClosing}`
    : '';

  const getThreatBadgeClass = (level?: string) => {
    switch (level?.toUpperCase()) {
      case 'KRİTİK':
        return 'bg-rose-500 text-white shadow-rose-500/20';
      case 'YÜKSEK':
        return 'bg-amber-500 text-white shadow-amber-500/20';
      case 'ORTA':
        return 'bg-blue-500 text-white shadow-blue-500/20';
      default:
        return 'bg-emerald-500 text-white shadow-emerald-500/20';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-950/70 backdrop-blur-xs">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-5xl w-full max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Modal Top Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-900 text-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/20 text-indigo-300 rounded-lg border border-indigo-400/30">
              <Sparkles className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  AI Log Analizi
                </h3>
                {analysisResult?.threatLevel && (
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase font-mono tracking-wider shadow-xs ${getThreatBadgeClass(
                      analysisResult.threatLevel
                    )}`}
                  >
                    {analysisResult.threatLevel}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Log analizi, MITRE haritalama ve aksiyon çıktısı.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
            title="Kapat"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Workflow Stepper Tabs Header */}
        <div className="bg-slate-900 border-b border-slate-800 px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 overflow-x-auto">
            {/* Step 1: Ana Analiz */}
            <button
              onClick={() => setActiveStage('forensic')}
              className={`px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-2 transition-all cursor-pointer ${
                activeStage === 'forensic'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Activity className="w-4 h-4 text-indigo-300" />
              <span>1. Log Analizi</span>
              {analysisResult && (
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              )}
            </button>

            {/* Step 2: MITRE ATT&CK */}
            <button
              onClick={() => setActiveStage('mitre')}
              className={`px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-2 transition-all cursor-pointer ${
                activeStage === 'mitre'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Layers className="w-4 h-4 text-indigo-300" />
              <span>2. MITRE ATT&amp;CK</span>
              {analysisResult?.mitreAttacks && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-700 text-indigo-200 font-mono">
                  {analysisResult.mitreAttacks.length}
                </span>
              )}
            </button>

            {/* Step 3: Bildirim Metni */}
            <button
              onClick={() => setActiveStage('email')}
              className={`px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-2 transition-all cursor-pointer ${
                activeStage === 'email'
                  ? 'bg-emerald-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Mail className="w-4 h-4 text-emerald-300" />
              <span>3. Bildirim Metni</span>
              {customerEmail && (
                <span className="w-2 h-2 rounded-full bg-emerald-300"></span>
              )}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400 font-mono">
              {report.summary.toplam_olay.toLocaleString()} Kayıt • {report.summary.farkli_ip_sayisi} IP
            </span>
          </div>
        </div>

        {/* Modal Content Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 bg-slate-50 space-y-6">
          
          {/* If No Logs are Uploaded */}
          {!hasLogs && (
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-6 text-center space-y-3">
              <AlertTriangle className="w-8 h-8 text-amber-600 mx-auto" />
              <h4 className="text-base font-bold text-amber-900">
                Henüz Analiz Edilecek Log Dosyası Yüklenmedi
              </h4>
              <p className="text-xs text-amber-800 max-w-lg mx-auto leading-relaxed">
                Güvenlik değerlendirmesi ve e-posta taslağı oluşturmak için lütfen önce Tehdit Avı sekmesinden log dosyalarınızı yükleyin.
              </p>
              <button
                onClick={onClose}
                className="inline-flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-bold transition-colors cursor-pointer"
              >
                Log Yüklemek İçin Kapat
              </button>
            </div>
          )}

          {/* Loading Indicator */}
          {loading && (
            <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-xs text-center space-y-4">
              <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center mx-auto shadow-inner">
                <RotateCw className="w-6 h-6 animate-spin text-indigo-600" />
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-slate-900">
                  Güvenlik Analizi Yapılıyor...
                </h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                  Tüm log havuzu taranıyor; MITRE ATT&amp;CK teknikleri, saldırı zinciri aşamaları (Kill Chain) ve yüksek riskli IP tehdit aktörleri analiz ediliyor.
                </p>
              </div>
              <div className="flex items-center justify-center gap-2 text-[11px] font-mono text-slate-400 pt-2">
                <span className="w-2 h-2 rounded-full bg-indigo-500 animate-ping"></span>
                <span>Analiz Devam Ediyor</span>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && !loading && (
            <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-900 flex items-start justify-between gap-2.5">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block">Analiz Hatası:</span>
                  <span>{error}</span>
                </div>
              </div>
              <button
                onClick={() => handleGenerate()}
                className="px-3 py-1 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-bold cursor-pointer transition-colors shrink-0"
              >
                Tekrar Dene
              </button>
            </div>
          )}

          {/* Fallback Notice if active */}
          {analysisResult?.fallbackActive && !loading && (
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>
                  <strong>Güvenlik Değerlendirmesi:</strong> {analysisResult.fallbackNotice || 'Tüm güvenlik bulguları listelenmiştir.'}
                </span>
              </div>
              <button
                onClick={() => handleGenerate()}
                disabled={loading}
                className="inline-flex items-center gap-1.5 px-3 py-1 bg-amber-200 hover:bg-amber-300 text-amber-900 rounded-lg text-xs font-bold transition-colors cursor-pointer shrink-0"
              >
                <RotateCw className="w-3.5 h-3.5" />
                <span>Yeniden Analiz Et</span>
              </button>
            </div>
          )}

          {/* STAGE 1: ANA LOG ADLİ & TEHDİT ANALİZİ (FORENSIC ASSESSMENT) */}
          {hasLogs && activeStage === 'forensic' && (
            <div className="space-y-6">
              
              {/* Quick Action Toolbar */}
              <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-indigo-50 text-indigo-600 rounded-lg">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Adli Analiz Kapsamı &amp; Odak Ayarı
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      Tüm logların ortak korelasyonu veya tekil saldırgan IP analizi
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <select
                    value={selectedIp}
                    onChange={(e) => {
                      setSelectedIp(e.target.value);
                      handleGenerate(e.target.value);
                    }}
                    className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 bg-white font-mono focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="">Tüm Loglar (Kapsamlı Siber Tehdit Avı)</option>
                    {riskQueue.map((r, rIdx) => (
                      <option key={`${r.ip_adresi}_${rIdx}`} value={r.ip_adresi}>
                        {r.ip_adresi} ({r.risk_seviyesi} - Puan: {r.risk_puani})
                      </option>
                    ))}
                  </select>

                  <button
                    onClick={() => handleGenerate()}
                    disabled={loading}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold transition-all shadow-2xs cursor-pointer disabled:opacity-50"
                  >
                    <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                    <span>Yeniden Analiz Et</span>
                  </button>

                  <button
                    onClick={() => setActiveStage('email')}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold transition-all shadow-2xs cursor-pointer"
                  >
                    <Mail className="w-3.5 h-3.5" />
                    <span>Müşteri E-Postasına Geç</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Analysis Results */}
              {analysisResult && !loading && (
                <>
                  {/* Executive Summary Card */}
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                        <Flame className="w-4 h-4 text-rose-500" />
                        <span>🔎 Teknik Adli İnceleme &amp; Tehdit Özeti (Forensic Assessment)</span>
                      </span>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase font-mono tracking-wider ${getThreatBadgeClass(
                          analysisResult.threatLevel
                        )}`}
                      >
                        {analysisResult.threatLevel} SEVİYE
                      </span>
                    </div>

                    <p className="text-sm font-medium text-slate-800 leading-relaxed bg-slate-50 p-3.5 rounded-lg border border-slate-200/80">
                      {analysisResult.executiveSummary}
                    </p>

                    {/* Quick Stats Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                      <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-2.5 text-center">
                        <span className="text-[10px] uppercase font-bold text-slate-500 block">
                          İncelenen Toplam Olay
                        </span>
                        <span className="text-sm font-extrabold text-slate-900 font-mono">
                          {report.summary.toplam_olay.toLocaleString()}
                        </span>
                      </div>
                      <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-2.5 text-center">
                        <span className="text-[10px] uppercase font-bold text-slate-500 block">
                          Şüpheli Aktör Sayısı
                        </span>
                        <span className="text-sm font-extrabold text-rose-600 font-mono">
                          {analysisResult.threatActors?.length || report.entity_risk_queue.length}
                        </span>
                      </div>
                      <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-2.5 text-center">
                        <span className="text-[10px] uppercase font-bold text-slate-500 block">
                          MITRE ATT&amp;CK Teknikleri
                        </span>
                        <span className="text-sm font-extrabold text-indigo-600 font-mono">
                          {analysisResult.mitreAttacks?.length || 0} Tespit
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Attack Narrative (Saldırı Hikayesi & Siber Harekât Aşamaları) */}
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-indigo-600" />
                        <span>⛓️ Saldırı Senaryosu &amp; Harekât Zinciri (Attack Narrative &amp; Kill Chain)</span>
                      </span>
                      <button
                        onClick={() => handleCopy(analysisResult.attackNarrative || '', 'attackNarrative')}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold inline-flex items-center gap-1 cursor-pointer"
                      >
                        {copiedField === 'attackNarrative' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-500" />
                            <span>Kopyalandı</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Metni Kopyala</span>
                          </>
                        )}
                      </button>
                    </div>

                    <div className="prose prose-sm max-w-none text-xs text-slate-700 leading-relaxed bg-slate-50/50 p-4 rounded-xl border border-slate-200/70">
                      <Markdown>{analysisResult.attackNarrative || 'Saldırı zinciri bilgisi hazırlandı.'}</Markdown>
                    </div>
                  </div>

                  {/* Threat Actors (Kritik Tehdit Aktörleri Tablosu) */}
                  {analysisResult.threatActors && analysisResult.threatActors.length > 0 && (
                    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                        <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                          <Globe className="w-4 h-4 text-rose-600" />
                          <span>🚨 Tespit Edilen Kritik Tehdit Aktörleri ({analysisResult.threatActors.length})</span>
                        </span>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead>
                            <tr className="border-b border-slate-200 bg-slate-50 text-slate-600">
                              <th className="py-2.5 px-3 font-semibold">Saldırgan IP</th>
                              <th className="py-2.5 px-3 font-semibold">Risk Seviyesi</th>
                              <th className="py-2.5 px-3 font-semibold">Skor</th>
                              <th className="py-2.5 px-3 font-semibold">Hedef Sunucu</th>
                              <th className="py-2.5 px-3 font-semibold">Tespit Gerekçesi</th>
                              <th className="py-2.5 px-3 font-semibold">Transfer</th>
                              <th className="py-2.5 px-3 font-semibold text-right">İşlem</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {analysisResult.threatActors.map((actor, idx) => (
                              <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                                <td className="py-2.5 px-3 font-mono font-bold text-rose-700">
                                  {actor.ip}
                                </td>
                                <td className="py-2.5 px-3">
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase font-mono ${
                                      actor.threatLevel === 'KRİTİK'
                                        ? 'bg-rose-100 text-rose-800 border border-rose-200'
                                        : 'bg-amber-100 text-amber-800 border border-amber-200'
                                    }`}
                                  >
                                    {actor.threatLevel}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-mono font-extrabold text-slate-800">
                                  {actor.riskScore}/100
                                </td>
                                <td className="py-2.5 px-3 text-slate-600 font-mono text-[11px]">
                                  {actor.targetedServers || 'Muhtelif Sunucular'}
                                </td>
                                <td className="py-2.5 px-3 text-slate-700 max-w-xs">
                                  {actor.reason}
                                </td>
                                <td className="py-2.5 px-3 text-slate-600 font-mono text-[11px]">
                                  {actor.transferredMb || actor.exfiltratedMb ? `${actor.transferredMb || actor.exfiltratedMb} MB` : '-'}
                                </td>
                                <td className="py-2.5 px-3 text-right">
                                  <button
                                    onClick={() => {
                                      setSelectedIp(actor.ip);
                                      handleGenerate(actor.ip);
                                    }}
                                    className="px-2 py-1 bg-slate-100 hover:bg-indigo-50 hover:text-indigo-600 text-slate-700 rounded text-[11px] font-semibold cursor-pointer transition-colors"
                                  >
                                    Bu IP'ye Odaklan
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Recommended Actions Plan (Müdahale & İyileştirme Planı) */}
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span>📋 SOC Müdahale &amp; İyileştirme Yol Haritası</span>
                      </span>
                    </div>

                    <div className="space-y-2">
                      {analysisResult.recommendedActions && analysisResult.recommendedActions.length > 0 ? (
                        analysisResult.recommendedActions.map((action, idx) => (
                          <div
                            key={idx}
                            className="flex items-start gap-3 p-3 bg-slate-50 rounded-xl border border-slate-200/80 text-xs"
                          >
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-100 text-emerald-800 font-mono font-bold text-[11px] shrink-0 mt-0.5">
                              {idx + 1}
                            </span>
                            <span className="text-slate-800 font-medium leading-relaxed">
                              {action}
                            </span>
                          </div>
                        ))
                      ) : (
                        <p className="text-xs text-slate-500">Aksiyon listesi hazırlandı.</p>
                      )}
                    </div>
                  </div>

                  {/* Technical Deep Dive (Ayrıntılı Adli Analiz) */}
                  <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                        <Server className="w-4 h-4 text-blue-600" />
                        <span>🔬 Ayrıntılı Adli Kanıtlar &amp; HTTP/Ağ Parametreleri</span>
                      </span>
                      <button
                        onClick={() => handleCopy(analysisResult.technicalDetails || '', 'techDetails')}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold inline-flex items-center gap-1 cursor-pointer"
                      >
                        {copiedField === 'techDetails' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-500" />
                            <span>Kopyalandı</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Kopyala</span>
                          </>
                        )}
                      </button>
                    </div>

                    <div className="prose prose-sm max-w-none text-xs text-slate-700 leading-relaxed bg-slate-50/50 p-4 rounded-xl border border-slate-200/70">
                      <Markdown>{analysisResult.technicalDetails || 'Teknik detaylar hazırlandı.'}</Markdown>
                    </div>
                  </div>

                  {/* Call To Action: Proceed to Stage 2 Customer Email */}
                  <div className="p-4 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white rounded-xl shadow-md flex flex-col sm:flex-row items-center justify-between gap-4 border border-indigo-900/50">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 bg-emerald-500/20 text-emerald-300 rounded-xl border border-emerald-500/30">
                        <Mail className="w-5 h-5 text-emerald-400" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-white">Log Adli Analizi Tamamlandı</h4>
                        <p className="text-xs text-slate-300 mt-0.5">
                          Şimdi müşteri kurum adını girerek bu teknik bulguları kurumsal bir olay bildirim e-postasına dönüştürün.
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => setActiveStage('email')}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs flex items-center gap-2 cursor-pointer shrink-0"
                    >
                      <span>2. Adım: Müşteri E-Postasına Geç</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* STAGE 1b: MITRE ATT&CK TAB */}
          {hasLogs && activeStage === 'mitre' && (
            <div className="space-y-6">
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                      <Layers className="w-4 h-4 text-indigo-600" />
                      <span>MITRE ATT&amp;CK Enterprise Taktik &amp; Teknik Eşleşmeleri</span>
                    </h4>
                    <p className="text-[11px] text-slate-500 mt-0.5">
                      Loglardaki deliller (URI, durum kodları, bayt transferleri) temel alınarak eşleştirilen saldırı teknikleri.
                    </p>
                  </div>

                  <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                    {analysisResult?.mitreAttacks?.length || 0} Teknik Tespit Edildi
                  </span>
                </div>

                {analysisResult?.mitreAttacks && analysisResult.mitreAttacks.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-700">
                          <th className="py-2.5 px-3 font-semibold">Taktik</th>
                          <th className="py-2.5 px-3 font-semibold">Teknik ID</th>
                          <th className="py-2.5 px-3 font-semibold">Teknik Adı</th>
                          <th className="py-2.5 px-3 font-semibold">Loglardaki Somut Kanıt (Evidence)</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {analysisResult.mitreAttacks.map((item, idx) => (
                          <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                            <td className="py-3 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-800 border border-slate-200">
                                {item.tactic}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-mono font-bold text-indigo-600">
                              {item.techniqueId}
                            </td>
                            <td className="py-3 px-3 font-semibold text-slate-900">
                              {item.techniqueName}
                            </td>
                            <td className="py-3 px-3 text-slate-700 leading-relaxed max-w-md">
                              {item.evidence}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="p-8 text-center text-xs text-slate-400">
                    Henüz MITRE teknik analizi oluşturulmadı. Lütfen 1. Adımdan analizi başlatın.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* STAGE 2: MÜŞTERİ BİLDİRİM E-POSTASI (CLIENT EMAIL ADVISORY) */}
          {hasLogs && activeStage === 'email' && (
            <div className="space-y-6">
              
              {/* Email Parameters Input Form */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-100 pb-3 gap-2">
                  <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-indigo-600" />
                    <span>📧 Müşteriye Özel E-Posta Parametreleri</span>
                  </span>
                  <span className="text-[11px] text-slate-500">
                    Müşteri kurum adını girerek adli log bulgularını resmi bir bildirim metnine dönüştürün.
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
                  {/* Müşteri Adı (Zorunlu) */}
                  <div>
                    <label className="block text-xs font-bold text-slate-800 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1.5">
                        <Building2 className="w-3.5 h-3.5 text-indigo-600" />
                        <span>Müşteri Kurum / Şirket Adı</span>
                      </span>
                      <span className="text-[10px] text-rose-600 font-semibold">* Zorunlu</span>
                    </label>
                    <input
                      type="text"
                      value={companyName}
                      onChange={(e) => {
                        setCompanyName(e.target.value);
                        if (emailError) setEmailError(null);
                      }}
                      placeholder="Örn: Acme Holding A.Ş., FinansBank..."
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 bg-white shadow-2xs font-medium"
                    />
                  </div>

                  {/* Analist / Ekip Adı */}
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1 flex items-center gap-1.5">
                      <UserCheck className="w-3.5 h-3.5 text-slate-400" />
                      <span>Raporlayan Analist / SOC Ekibi</span>
                    </label>
                    <input
                      type="text"
                      value={analystName}
                      onChange={(e) => setAnalystName(e.target.value)}
                      placeholder="Örn: SOC Seviye-3 Tehdit Avı Ekibi"
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 bg-white"
                    />
                  </div>

                  {/* Rapor Türü */}
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-slate-400" />
                      <span>E-Posta Tonu &amp; Formatı</span>
                    </label>
                    <select
                      value={emailAnalysisType}
                      onChange={(e: any) => setEmailAnalysisType(e.target.value)}
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 bg-white"
                    >
                      <option value="customer_email">Resmi Müşteri Bildirimi (Önerilen)</option>
                      <option value="executive_summary">CISO &amp; Üst Yönetim Özeti</option>
                      <option value="deep_technical">Ayrıntılı Teknik Adli Rapor</option>
                    </select>
                  </div>
                </div>

                {/* Ek Notlar & Buton */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3.5 pt-1">
                  <div className="sm:col-span-3">
                    <label className="block text-xs font-semibold text-slate-700 mb-1 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-slate-400" />
                      <span>Özel Analist Notu / Direktifi (İsteğe Bağlı)</span>
                    </label>
                    <input
                      type="text"
                      value={emailCustomNotes}
                      onChange={(e) => setEmailCustomNotes(e.target.value)}
                      placeholder="Örn: İlgili web sunucusunda WAF kuralı aktif edildiği ve IIS güncellemesi gerektiği belirtilsin."
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 bg-white"
                    />
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={handleGenerateCustomerEmail}
                      disabled={emailLoading || !companyName.trim()}
                      className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <RotateCw className={`w-4 h-4 ${emailLoading ? 'animate-spin' : ''}`} />
                      <span>{customerEmail ? 'E-Postayı Yeniden Üret' : 'Müşteriye Özel E-Posta Oluştur'}</span>
                    </button>
                  </div>
                </div>

                {emailError && (
                  <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-800 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>{emailError}</span>
                  </div>
                )}
              </div>

              {/* Email Loading State */}
              {emailLoading && (
                <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-xs text-center space-y-3">
                  <div className="w-10 h-10 bg-emerald-50 text-emerald-600 rounded-xl flex items-center justify-center mx-auto">
                    <RotateCw className="w-5 h-5 animate-spin text-emerald-600" />
                  </div>
                  <h4 className="text-xs font-bold text-slate-800">
                    "{companyName}" Kurumuna Özel Bildirim E-Postası Hazırlanıyor...
                  </h4>
                  <p className="text-[11px] text-slate-500">
                    Log adli bulguları kurumsal dille derleniyor ve aksiyon maddeleri yapılandırılıyor.
                  </p>
                </div>
              )}

              {/* Ready-to-Send Email Preview Card */}
              {customerEmail && !emailLoading && (
                <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
                  {/* Top Action Bar */}
                  <div className="px-6 py-3 bg-slate-900 text-white flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <Mail className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-bold tracking-tight">
                        Resmi Müşteri Bildirimi • {customerEmail.companyName}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleCopy(fullEmailContent, 'fullEmail')}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold transition-colors cursor-pointer shadow-2xs"
                      >
                        {copiedField === 'fullEmail' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-white" />
                            <span>Tüm E-Posta Kopyalandı!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Tüm E-Postayı Kopyala</span>
                          </>
                        )}
                      </button>

                      <button
                        onClick={handlePrint}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors cursor-pointer border border-slate-700"
                        title="Raporu Yazdır veya PDF Olarak Kaydet"
                      >
                        <Printer className="w-3.5 h-3.5" />
                        <span>Yazdır / PDF</span>
                      </button>
                    </div>
                  </div>

                  {/* Email Content */}
                  <div className="p-6 space-y-4">
                    {/* Subject Line */}
                    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                          Konu:
                        </span>
                        <span className="text-xs font-bold text-slate-900 font-mono">
                          {customerEmail.emailSubject}
                        </span>
                      </div>
                      <button
                        onClick={() => handleCopy(customerEmail.emailSubject, 'emailSubject')}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold inline-flex items-center gap-1 cursor-pointer shrink-0"
                      >
                        {copiedField === 'emailSubject' ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-500" />
                            <span>Kopyalandı</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Konuyu Kopyala</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* Email Greeting */}
                    <div className="text-xs font-bold text-slate-900">
                      {customerEmail.emailGreeting}
                    </div>

                    {/* Email Body */}
                    <div className="prose prose-sm max-w-none text-xs text-slate-700 leading-relaxed bg-slate-50/50 p-4 rounded-xl border border-slate-200/80">
                      <Markdown>{customerEmail.emailBody}</Markdown>
                    </div>

                    {/* Email Closing */}
                    <div className="text-xs text-slate-700 font-mono whitespace-pre-line border-t border-slate-100 pt-3">
                      {customerEmail.emailClosing}
                    </div>
                  </div>
                </div>
              )}

              {/* Initial Empty State for Stage 2 (when no email generated yet) */}
              {!customerEmail && !emailLoading && (
                <div className="bg-white border border-slate-200 rounded-xl p-8 text-center space-y-3 shadow-xs">
                  <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center mx-auto">
                    <Mail className="w-6 h-6 text-indigo-600" />
                  </div>
                  <h4 className="text-sm font-bold text-slate-900">
                    Henüz Müşteri Bildirim E-Postası Oluşturulmadı
                  </h4>
                  <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                    1. Adımdaki teknik log analizi tamamlandı. Müşterinize göndermek üzere resmi bir bilgilendirme metni oluşturmak için yukarıdaki kutuya <strong>Müşteri Kurum / Şirket Adı</strong>'nı yazıp <strong>"Müşteriye Özel E-Posta Oluştur"</strong> butonuna tıklayınız.
                  </p>
                </div>
              )}

            </div>
          )}

        </div>

        {/* Modal Bottom Footer */}
        <div className="px-6 py-3 bg-white border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span>
              SOC Seviye-3 Standartlarında Gerçek Log Kanıtı ve MITRE ATT&amp;CK Uyumlu
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg border border-slate-300 text-slate-700 font-semibold hover:bg-slate-50 transition-colors cursor-pointer"
            >
              Kapat
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
