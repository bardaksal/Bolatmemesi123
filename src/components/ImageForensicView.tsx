import React, { useState } from 'react';
import {
  Image as ImageIcon,
  Check,
  Copy,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Database,
  HelpCircle,
  Eye,
  Lock,
  ZoomIn,
  Trash2,
  ChevronDown,
  ChevronUp,
  Info,
  ArrowRight,
  Shield,
  FileCheck,
  Globe,
} from 'lucide-react';
import { ImageForensicResult } from '../services/imageForensicService';
import {
  generateAnalysisFirstReport,
  AnalysisFirstForensicReport,
  ForensicSecurityVerdict,
} from '../services/analysisFirstForensicReporting';
import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
} from '../services/httpRequestAnalyzer';

interface ImageForensicViewProps {
  result: ImageForensicResult;
  imagePreviewUrl?: string | null;
  onClearImage?: () => void;
  onOpenCommandExplainer?: (cmd: string, context?: any) => void;
}

export const ImageForensicView: React.FC<ImageForensicViewProps> = ({
  result,
  imagePreviewUrl,
  onClearImage,
  onOpenCommandExplainer,
}) => {
  const [activeQueryTab, setActiveQueryTab] = useState<'splunk' | 'kql' | 'elastic' | 'qradar'>('splunk');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [showFullImageModal, setShowFullImageModal] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  // Ensure analysisReport is always available
  const report: AnalysisFirstForensicReport =
    result.analysisReport ||
    generateAnalysisFirstReport({
      observed: result.observedFromImage,
      visualPlatform: result.visualPlatform,
      confidence: result.confidence,
      structuredTableRows: result.structuredTableRows,
      fallbackLimitation: result.fallbackLimitation,
      rawOcrText: result.provenance?.rawOcrText,
    });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(id);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const getQueryContent = () => {
    switch (activeQueryTab) {
      case 'splunk':
        return result.queries?.splunk || '';
      case 'kql':
        return result.queries?.kql || '';
      case 'elastic':
        return result.queries?.elastic || '';
      case 'qradar':
        return result.queries?.qradarAql || '';
    }
  };

  const getVerdictStyle = (verdict: ForensicSecurityVerdict) => {
    switch (verdict) {
      case 'ENGELLENMİŞ SALDIRI GİRİŞİMİ':
        return {
          bg: 'bg-rose-500/15 border-rose-500/40 text-rose-300',
          badgeText: 'Engellenmiş Saldırı Girişimi',
          icon: <ShieldAlert className="w-4 h-4 text-rose-400" />,
        };
      case 'SALDIRI BELİRTİSİ':
        return {
          bg: 'bg-red-500/20 border-red-500/50 text-red-200',
          badgeText: 'Saldırı Belirtisi',
          icon: <AlertTriangle className="w-4 h-4 text-red-400" />,
        };
      case 'SALDIRI BAŞARISI KANITLANMADI':
        return {
          bg: 'bg-amber-500/20 border-amber-500/40 text-amber-200',
          badgeText: 'Saldırı Başarısı Kanıtlanmadı',
          icon: <HelpCircle className="w-4 h-4 text-amber-300" />,
        };
      case 'ŞÜPHELİ ETKİNLİK':
        return {
          bg: 'bg-amber-500/15 border-amber-500/30 text-amber-300',
          badgeText: 'Şüpheli Etkinlik',
          icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
        };
      case 'MUHTEMEL YANLIŞ ALARM':
        return {
          bg: 'bg-sky-500/15 border-sky-500/30 text-sky-300',
          badgeText: 'Muhtemel Yanlış Alarm',
          icon: <Info className="w-4 h-4 text-sky-400" />,
        };
      case 'MEŞRU / BEKLENEN ETKİNLİK':
      case 'BİLGİ AMAÇLI / GÜVENLİK SONUCU YOK':
        return {
          bg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300',
          badgeText: 'Bilgi Amaçlı / Meşru',
          icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
        };
      case 'YETERSİZ KANIT':
      default:
        return {
          bg: 'bg-slate-500/15 border-slate-500/30 text-slate-300',
          badgeText: 'Yetersiz Kanıt',
          icon: <HelpCircle className="w-4 h-4 text-slate-400" />,
        };
    }
  };

  const verdictStyle = getVerdictStyle(report.securityVerdict);
  const facts = report.observedFacts;
  const interp = report.securityInterpretation;

  return (
    <div className="space-y-6">
      {/* ========================================================================= */}
      {/* 1. HERO HEADER: ANALYSIS-FIRST SECURITY BANNER */}
      {/* ========================================================================= */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 text-slate-100 shadow-xl space-y-4">
        <div className="flex items-start justify-between gap-4 flex-wrap pb-4 border-b border-slate-800">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5 flex-wrap">
              {/* Security Verdict Badge */}
              <div
                className={`px-3 py-1 rounded-lg text-xs font-bold border flex items-center gap-1.5 shadow-xs ${verdictStyle.bg}`}
              >
                {verdictStyle.icon}
                <span>{report.securityVerdict}</span>
              </div>

              {/* Observed Platform Badge */}
              <div className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                <ImageIcon className="w-3.5 h-3.5 text-indigo-400" />
                <span>{result.visualPlatform}</span>
              </div>
            </div>

            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              Görsel Güvenlik Analizi
            </h1>
            <p className="text-xs text-slate-400">
              Görüntüdeki olay, kanıtlanan olgular ve güvenlik açısından analist değerlendirmesi.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {imagePreviewUrl && (
              <button
                type="button"
                onClick={() => setShowFullImageModal(true)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <ZoomIn className="w-3.5 h-3.5" />
                <span>Görseli Büyüt</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => handleCopy(report.markdownReport || result.fullReportMarkdown, 'full_report')}
              className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-xs"
            >
              {copiedSection === 'full_report' ? <Check className="w-4 h-4 text-emerald-300" /> : <Copy className="w-4 h-4" />}
              <span>{copiedSection === 'full_report' ? 'Kopyalandı' : 'Raporu Kopyala'}</span>
            </button>
            {onClearImage && (
              <button
                type="button"
                onClick={onClearImage}
                className="p-1.5 bg-slate-800 hover:bg-rose-950/60 hover:text-rose-300 text-slate-400 border border-slate-700 rounded-lg text-xs transition-colors cursor-pointer"
                title="Görseli temizle"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Fallback Limitation Notice */}
        {Boolean(result.fallbackLimitation || result.evidenceSource === 'FALLBACK_NON_VISUAL' || report.securityVerdict === 'YETERSİZ KANIT') && (
          <div className="bg-amber-950/50 border border-amber-600/50 rounded-xl p-3.5 text-xs text-amber-200 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <strong className="block text-amber-300">Görsel Güvenlik Telemetrisi Doğrulanamadı</strong>
              <p className="text-[11px] text-amber-100/90 leading-relaxed">
                {result.fallbackLimitation?.warningMessage ||
                  'Görsel üzerinde doğrulanabilir güvenlik telemetrisi tespit edilemediği için durum YETERSİZ KANIT olarak değerlendirilmiştir.'}
              </p>
            </div>
          </div>
        )}

        {/* Conflict Warning if text and screenshot contradict */}
        {result.sourceConflict && result.sourceConflict.hasConflict && (
          <div className="bg-rose-950/40 border border-rose-600/50 rounded-xl p-3.5 text-xs text-rose-200 space-y-2">
            <div className="flex items-center gap-2 font-bold text-rose-300">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>Görsel ile Sağlanan Metin Arasında Çelişki Tespit Edildi</span>
            </div>
            <ul className="space-y-1 text-xs">
              {result.sourceConflict.conflicts.map((c, idx) => (
                <li key={idx} className="bg-black/30 p-2 rounded border border-rose-500/30">
                  <span className="font-semibold text-rose-200">{c.field}:</span> Görüntüde{' '}
                  <span className="font-mono text-white">{c.screenshotValue}</span>, metinde{' '}
                  <span className="font-mono text-white">{c.textValue}</span> ({c.impact})
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 2. SECTION 1: ANALİZ ÖZETİ (EXECUTIVE SUMMARY) */}
      {/* ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <FileCheck className="w-4 h-4 text-indigo-600" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              1. Analiz Özeti
            </h2>
          </div>
          <span className="text-[11px] text-slate-400 font-medium">Olay Değerlendirmesi</span>
        </div>

        <p className="text-sm text-slate-800 leading-relaxed font-sans whitespace-pre-wrap">
          {report.executiveSummary}
        </p>

        {report.verdictRationale && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-700 space-y-1">
            <strong className="text-slate-900 block font-semibold">Değerlendirme Gerekçesi:</strong>
            <p>{report.verdictRationale}</p>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 3. SECTION 2: GÖRSELDE NE VAR? (WHAT IS SEEN) */}
      {/* ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-indigo-600" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              2. Görselde Ne Var? (Gözlemlenen Bulgular)
            </h2>
          </div>
          <span className="text-[10px] font-mono bg-indigo-50 text-indigo-700 font-bold px-2 py-0.5 rounded border border-indigo-200">
            Doğrulanan Olay Parametreleri
          </span>
        </div>

        {/* Visual Summary Box */}
        <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 block">
            Ne Görülüyor?
          </span>
          <p className="text-xs text-slate-800 leading-relaxed font-medium">
            {interp.whatIsSeen}
          </p>
        </div>

        {/* Facts Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Kaynak IP</span>
            <span
              className={`font-bold block break-all ${
                facts.sourceIp === 'NOT OBSERVED' ? 'text-slate-400 italic font-sans font-normal' : 'text-indigo-700'
              }`}
            >
              {facts.sourceIp}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Hedef IP / Host</span>
            <span
              className={`font-bold block break-all ${
                facts.destinationIp === 'NOT OBSERVED' && facts.hostOrEndpoint === 'NOT OBSERVED'
                  ? 'text-slate-400 italic font-sans font-normal'
                  : 'text-slate-800'
              }`}
            >
              {facts.destinationIp !== 'NOT OBSERVED'
                ? facts.destinationIp
                : facts.hostOrEndpoint !== 'NOT OBSERVED'
                ? facts.hostOrEndpoint
                : 'NOT OBSERVED'}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Zaman Damgası</span>
            <span
              className={`font-medium block break-all ${
                facts.timestamp === 'NOT OBSERVED' ? 'text-slate-400 italic font-sans font-normal' : 'text-slate-800'
              }`}
            >
              {facts.timestamp}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Cihaz / Platform</span>
            <span className="text-slate-800 font-semibold block break-all">
              {facts.deviceOrPlatform}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Aksiyon (Action)</span>
            <span
              className={`font-bold block break-all ${
                facts.action === 'NOT OBSERVED'
                  ? 'text-slate-400 italic font-sans font-normal'
                  : facts.action.toUpperCase().includes('BLOCK') || facts.action.toUpperCase().includes('DENY')
                  ? 'text-rose-700'
                  : 'text-emerald-700'
              }`}
            >
              {facts.action}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Durum Kodu / Hata</span>
            <span
              className={`font-bold block break-all ${
                facts.statusCode === 'NOT OBSERVED' ? 'text-slate-400 italic font-sans font-normal' : 'text-slate-800'
              }`}
            >
              {facts.statusCode}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Kullanıcı / Hesap</span>
            <span
              className={`font-bold block break-all ${
                facts.userOrAccount === 'NOT OBSERVED' ? 'text-slate-400 italic font-sans font-normal' : 'text-slate-900'
              }`}
            >
              {facts.userOrAccount}
            </span>
          </div>

          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-slate-400 block text-[10px] uppercase font-sans">Süreç (Process)</span>
            <span
              className={`font-bold block break-all ${
                result.observedFromImage?.processName ? 'text-slate-800' : 'text-slate-400 italic font-sans font-normal'
              }`}
            >
              {result.observedFromImage?.processName || 'NOT OBSERVED'}
            </span>
          </div>
        </div>

        {/* Observed Request or Command Line */}
        {facts.requestOrCommand !== 'NOT OBSERVED' && (() => {
          const isHttp = isHttpRequestPattern(facts.requestOrCommand) || Boolean(result.observedFromImage?.httpRequest);
          const httpDetails = result.observedFromImage?.httpRequest || (isHttp ? parseHttpRequestSemantics(facts.requestOrCommand) : null);

          if (isHttp && httpDetails) {
            return (
              <div className="p-3.5 bg-slate-900 text-slate-100 rounded-xl space-y-2 border border-slate-800">
                <div className="flex items-center justify-between text-xs flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <Globe className="w-3.5 h-3.5 text-sky-400" />
                    <span className="text-sky-400 font-bold uppercase tracking-wider text-[10px]">
                      Gözlemlenen HTTP Ağ İsteği (HTTP Request)
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 font-mono">
                      {httpDetails.method}
                    </span>
                  </div>
                  {httpDetails.targetTechnology && (
                    <span className="text-[11px] font-semibold text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                      Hedef: {httpDetails.targetTechnology}
                    </span>
                  )}
                </div>
                <code className="block font-mono text-xs text-sky-300 break-all bg-slate-950 p-2.5 rounded border border-slate-800">
                  {facts.requestOrCommand}
                </code>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-400 font-mono pt-1">
                  <div>
                    <span className="text-slate-500">Endpoint:</span>{' '}
                    <span className="text-slate-200">{httpDetails.endpoint}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Protokol:</span>{' '}
                    <span className="text-slate-200">{httpDetails.protocol}</span>
                  </div>
                  {httpDetails.query && (
                    <div className="sm:col-span-2">
                      <span className="text-slate-500">Sorgu Parametresi:</span>{' '}
                      <span className="text-amber-300">{httpDetails.query}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          }

          return (
            <div className="p-3.5 bg-slate-900 text-slate-100 rounded-xl space-y-1.5 border border-slate-800">
              <div className="flex items-center justify-between text-xs">
                <span className="text-indigo-400 font-bold uppercase tracking-wider text-[10px]">
                  Görüntüde Okunan Komut Satırı (CommandLine)
                </span>
                {onOpenCommandExplainer && facts.requestOrCommand.length > 5 && (
                  <button
                    type="button"
                    onClick={() => onOpenCommandExplainer(facts.requestOrCommand)}
                    className="inline-flex items-center gap-1 text-[11px] font-bold text-amber-300 hover:text-white underline cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Komut Açıklayıcıda İncele &rarr;</span>
                  </button>
                )}
              </div>
              <code className="block font-mono text-xs text-emerald-300 break-all bg-slate-950 p-2.5 rounded border border-slate-800">
                {facts.requestOrCommand}
              </code>
            </div>
          );
        })()}

        {/* Structured Table Rows extracted from SIEM / WAF */}
        {result.structuredTableRows && result.structuredTableRows.length > 0 && (
          <div className="pt-2 border-t border-slate-100 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-indigo-600" />
                <span>Görsel Tablodan Ayrıştırılan Olay Satırları (Satır x Kolon)</span>
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                {result.structuredTableRows.length} olay satırı
              </span>
            </div>
            <div className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 text-[11px] font-mono">
              <table className="w-full text-left">
                <thead className="bg-slate-100 text-slate-700 border-b border-slate-200 text-[10px]">
                  <tr>
                    <th className="p-2">Zaman</th>
                    <th className="p-2">Kaynak IP</th>
                    <th className="p-2">Hedef IP</th>
                    <th className="p-2">Port</th>
                    <th className="p-2">Aksiyon</th>
                    <th className="p-2">Kural / Olay</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {result.structuredTableRows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-100/70">
                      <td className="p-2 text-slate-600 whitespace-nowrap">{row.timestamp || '-'}</td>
                      <td className="p-2 text-indigo-700 font-bold whitespace-nowrap">{row.sourceIp || '-'}</td>
                      <td className="p-2 text-slate-800 whitespace-nowrap">{row.destinationIp || '-'}</td>
                      <td className="p-2 text-slate-600">{row.port || '-'}</td>
                      <td className="p-2 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            row.action?.toUpperCase().includes('DENY') || row.action?.toUpperCase().includes('BLOCK')
                              ? 'bg-rose-100 text-rose-800'
                              : 'bg-emerald-100 text-emerald-800'
                          }`}
                        >
                          {row.action || '-'}
                        </span>
                      </td>
                      <td className="p-2 text-slate-900 font-sans">{row.ruleOrEvent || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 4. SECTION 3 & 4: BU NE ANLAMA GELİYOR? & NEDEN ÖNEMLİ? */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Section 3: Bu Ne Anlama Geliyor? */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
            <Info className="w-4 h-4 text-indigo-600" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              3. Bu Ne Anlama Geliyor?
            </h2>
          </div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 block">
            Olay Senaryosu / Ne Olmuş Olabilir?
          </span>
          <p className="text-xs text-slate-800 leading-relaxed font-medium">
            {interp.whatMightHaveHappened}
          </p>
        </div>

        {/* Section 4: Neden Önemli? */}
        <div className="bg-indigo-50/40 border border-indigo-200 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-indigo-200/60">
            <Shield className="w-4 h-4 text-indigo-700" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              4. Neden Önemli?
            </h2>
          </div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-700 block">
            Güvenlik Açısından Anlamı ve Risk
          </span>
          <p className="text-xs text-indigo-950 leading-relaxed font-medium">
            {interp.securityMeaning}
          </p>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 5. SECTION 5: KANIT DURUMU (NE KANITLANDI? vs NE KANITLANMADI?) */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left Column: Ne Kanıtlandı? */}
        <div className="bg-white border-2 border-emerald-500/30 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <h3 className="text-sm font-bold text-slate-900">
              ✅ Ne Kanıtlandı? (Doğrulanan Kanıtlar)
            </h3>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Görüntü üzerinde doğrudan tespit edilen nesnel olay kayıtları:
          </p>
          <ul className="text-xs text-slate-800 space-y-2">
            {interp.supportingEvidence.map((ev, i) => (
              <li key={i} className="flex items-start gap-2 bg-emerald-50/50 p-2.5 rounded-lg border border-emerald-200/60">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <span className="font-medium">{ev}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Right Column: Ne Kanıtlanmadı? */}
        <div className="bg-white border-2 border-amber-500/30 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <h3 className="text-sm font-bold text-slate-900">
              ❌ Ne Kanıtlanmadı? (Neyi Kanıtlamıyor?)
            </h3>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Adli tarafsızlık gereği, tek bir görüntü üzerinden varsayılamayacak ve ek kanıt gerektiren unsurlar:
          </p>
          <ul className="text-xs text-slate-800 space-y-2">
            {report.unprovenAspects.map((unp, i) => (
              <li key={i} className="flex items-start gap-2 bg-amber-50/50 p-2.5 rounded-lg border border-amber-200/60">
                <span className="text-amber-500 font-bold shrink-0 mt-0.5">•</span>
                <span className="font-medium text-slate-800">{unp}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 6. SECTION 6: ŞİMDİ NE YAPILMALI? (RECOMMENDED INVESTIGATION STEPS) */}
      {/* ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-600" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              6. Şimdi Ne Yapılmalı? (Önerilen İnceleme Adımları)
            </h2>
          </div>
          <span className="text-xs text-slate-500">Kanıt boşluklarını doldurmak için gerekli kontroller</span>
        </div>

        <ol className="text-xs text-slate-700 space-y-2">
          {report.recommendedInvestigationSteps.map((step, i) => (
            <li key={i} className="flex items-start gap-2.5 bg-slate-50 p-3 rounded-xl border border-slate-200">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white font-bold text-xs flex items-center justify-center shrink-0">
                {i + 1}
              </span>
              <span className="leading-relaxed font-medium text-slate-800 pt-0.5">{step}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* ========================================================================= */}
      {/* 7. SECTION 7: SIEM AVLANMA SORGULARI (HUNTING QUERIES) */}
      {/* ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-600" />
            <h2 className="text-sm font-bold text-slate-900 tracking-wide uppercase">
              7. SIEM Avlanma Sorguları (Hunting Queries)
            </h2>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(getQueryContent(), activeQueryTab)}
            className="px-3 py-1 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copiedSection === activeQueryTab ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedSection === activeQueryTab ? 'Kopyalandı' : 'Sorguyu Kopyala'}</span>
          </button>
        </div>

        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
          {(['splunk', 'kql', 'elastic', 'qradar'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveQueryTab(tab)}
              className={`px-3 py-1 rounded-md font-semibold uppercase tracking-wider transition-colors cursor-pointer ${
                activeQueryTab === tab
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab === 'splunk'
                ? 'Splunk (SPL)'
                : tab === 'kql'
                ? 'Sentinel (KQL)'
                : tab === 'elastic'
                ? 'Elastic'
                : 'QRadar (AQL)'}
            </button>
          ))}
        </div>

        <pre className="p-3.5 bg-slate-950 text-emerald-300 font-mono text-xs rounded-xl overflow-x-auto border border-slate-800 whitespace-pre-wrap leading-relaxed max-h-48">
          {getQueryContent() || '// Bu sorgu için arama deseni oluşturulamadı'}
        </pre>
      </div>

      {/* Full Image Modal Zoom */}
      {showFullImageModal && imagePreviewUrl && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/90 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="relative max-w-6xl max-h-[92vh] flex flex-col items-center justify-center">
            <button
              type="button"
              onClick={() => setShowFullImageModal(false)}
              className="absolute -top-10 right-0 text-white hover:text-slate-300 text-sm font-bold px-3 py-1 bg-slate-800 rounded-lg cursor-pointer"
            >
              Kapat ✕
            </button>
            <img
              src={imagePreviewUrl}
              alt="Adli Ekran Görüntüsü Büyütülmüş"
              className="max-h-[85vh] max-w-full rounded-xl border border-slate-700 shadow-2xl object-contain"
            />
          </div>
        </div>
      )}
    </div>
  );
};
