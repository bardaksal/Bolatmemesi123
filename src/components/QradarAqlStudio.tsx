import React, { useState, useMemo } from 'react';
import {
  Search,
  Code,
  Copy,
  Check,
  Sparkles,
  Terminal,
  Shield,
  Layers,
  Wand2,
  Clock,
  HelpCircle,
  ExternalLink,
  ChevronRight,
  Filter,
  Monitor,
  Globe,
  Radio,
  AlertTriangle,
  Zap,
  Server,
  FileCode,
  Tag,
  Cpu,
} from 'lucide-react';
import {
  generateQradarAqlQueries,
  generateQradarCustomRules,
  generateQradarRegexForField,
  extractCandidateFieldsForQradar,
  detectLogNature,
  QradarAqlQueryItem,
  QradarCustomRuleDefinition,
  RegexExtractionCandidate,
  DetectedLogCategory,
} from '../services/qradarAqlHelper';
import {
  generateSplunkQueries,
  generateSentinelKqlQueries,
  generateElasticQueries,
  generateSigmaRule,
  MultiSiemQueryItem,
  SiemPlatform,
} from '../services/multiSiemConverter';

interface QradarAqlStudioProps {
  rawLogSample?: string;
  contextParams?: {
    ip?: string;
    destIp?: string;
    user?: string;
    port?: number | string;
    method?: string;
    url?: string;
    statusCode?: number | string;
    eventId?: number | string;
    processName?: string;
    hostname?: string;
  };
}

export type HuntingStudioMode =
  | 'aql'
  | 'splunk'
  | 'sentinel'
  | 'elastic'
  | 'sigma'
  | 'rules'
  | 'regex';

export const QradarAqlStudio: React.FC<QradarAqlStudioProps> = ({
  rawLogSample = '',
  contextParams = {},
}) => {
  const [activeMode, setActiveMode] = useState<HuntingStudioMode>('aql');
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [activeLogFilter, setActiveLogFilter] = useState<'ALL' | DetectedLogCategory>('ALL');
  const [selectedField, setSelectedField] = useState<string>('');
  const [customFieldName, setCustomFieldName] = useState<string>('');
  const [customSelectionText, setCustomSelectionText] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedRegex, setCopiedRegex] = useState(false);
  const [copiedCep, setCopiedCep] = useState(false);
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  // Detect Log Nature (Windows vs Web vs Network)
  const logNature = useMemo(() => {
    return detectLogNature({
      rawLog: rawLogSample,
      eventId: contextParams.eventId,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
    });
  }, [rawLogSample, contextParams]);

  // 1. Generate QRadar AQL Queries
  const aqlQueries = useMemo<QradarAqlQueryItem[]>(() => {
    return generateQradarAqlQueries({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  // 2. Generate Splunk SPL Queries
  const splunkQueries = useMemo<MultiSiemQueryItem[]>(() => {
    return generateSplunkQueries({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  // 3. Generate Microsoft Sentinel KQL Queries
  const sentinelQueries = useMemo<MultiSiemQueryItem[]>(() => {
    return generateSentinelKqlQueries({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  // 4. Generate Elasticsearch KQL & EQL Queries
  const elasticQueries = useMemo<MultiSiemQueryItem[]>(() => {
    return generateElasticQueries({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  // 5. Generate Universal Sigma Rules (YAML)
  const sigmaRules = useMemo<MultiSiemQueryItem[]>(() => {
    return generateSigmaRule({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  // 6. Generate Tailored QRadar CRE Detection Rules
  const customRules = useMemo<QradarCustomRuleDefinition[]>(() => {
    return generateQradarCustomRules({
      rawLog: rawLogSample,
      ip: contextParams.ip,
      destIp: contextParams.destIp,
      user: contextParams.user,
      port: contextParams.port,
      method: contextParams.method,
      url: contextParams.url,
      statusCode: contextParams.statusCode,
      eventId: contextParams.eventId,
      processName: contextParams.processName,
      hostname: contextParams.hostname,
    });
  }, [rawLogSample, contextParams]);

  const filteredAqlQueries = useMemo(() => {
    return aqlQueries.filter((q) => {
      const matchCat = activeCategory === 'ALL' || q.category === activeCategory;
      const matchLog = activeLogFilter === 'ALL' || q.logType === activeLogFilter;
      return matchCat && matchLog;
    });
  }, [aqlQueries, activeCategory, activeLogFilter]);

  // Candidate Fields extracted from current raw log line
  const candidateFields = useMemo<RegexExtractionCandidate[]>(() => {
    if (!rawLogSample) return [];
    return extractCandidateFieldsForQradar(rawLogSample);
  }, [rawLogSample]);

  // Custom Regex Extraction Result
  const activeExtraction = useMemo(() => {
    const target = customSelectionText.trim() || selectedField;
    if (!target || !rawLogSample) return null;
    return generateQradarRegexForField(
      rawLogSample,
      target,
      customFieldName || 'Custom_Field'
    );
  }, [rawLogSample, selectedField, customSelectionText, customFieldName]);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopyRegex = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRegex(true);
    setTimeout(() => setCopiedRegex(false), 2000);
  };

  const handleCopyCep = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCep(true);
    setTimeout(() => setCopiedCep(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-white shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-indigo-600/30 text-indigo-400 rounded-lg border border-indigo-500/30 shrink-0">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Çoklu SIEM & EDR Avcılık ve Kural Stüdyosu
                </h3>
                <span
                  className={`px-2 py-0.5 rounded-md text-[10px] font-bold border flex items-center gap-1 ${
                    logNature.category === 'WINDOWS'
                      ? 'bg-sky-500/20 text-sky-300 border-sky-400/40'
                      : logNature.category === 'WEB'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400/40'
                      : 'bg-amber-500/20 text-amber-300 border-amber-400/40'
                  }`}
                >
                  {logNature.category === 'WINDOWS' ? (
                    <Monitor className="w-3 h-3" />
                  ) : logNature.category === 'WEB' ? (
                    <Globe className="w-3 h-3" />
                  ) : (
                    <Radio className="w-3 h-3" />
                  )}
                  <span>Tür: {logNature.displayName}</span>
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                İncelenen log bağlamına uygun Splunk (SPL), Microsoft Sentinel (KQL), Elastic (KQL/EQL), Sigma (YAML) ve QRadar (AQL) sorguları.
              </p>
            </div>
          </div>

          {/* Platform & Mode Switcher */}
          <div className="flex items-center gap-1 bg-slate-800/90 p-1.5 rounded-xl border border-slate-700/80 flex-wrap shrink-0">
            <button
              type="button"
              onClick={() => setActiveMode('aql')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'aql'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>QRadar AQL ({aqlQueries.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('splunk')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'splunk'
                  ? 'bg-emerald-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Splunk SPL ({splunkQueries.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('sentinel')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'sentinel'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Sentinel KQL ({sentinelQueries.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('elastic')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'elastic'
                  ? 'bg-amber-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Elastic ({elasticQueries.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('sigma')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'sigma'
                  ? 'bg-rose-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Sigma YAML ({sigmaRules.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('rules')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'rules'
                  ? 'bg-violet-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>CRE Kuralı ({customRules.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveMode('regex')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeMode === 'regex'
                  ? 'bg-teal-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`}
            >
              <Wand2 className="w-3.5 h-3.5" />
              <span>Regex</span>
            </button>
          </div>
        </div>
      </div>

      {/* --- MODE 1: QRADAR AQL QUERIES --- */}
      {activeMode === 'aql' && (
        <div className="space-y-3">
          {/* Category Filter Pills */}
          <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-semibold text-slate-500 mr-1 flex items-center gap-1">
                  <Filter className="w-3 h-3" />
                  Kategori:
                </span>
                {(['ALL', 'INVESTIGATION', 'HUNTING', 'AGGREGATION'] as const).map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setActiveCategory(cat)}
                    className={`px-2 py-0.8 text-xs font-bold rounded-lg border transition-colors cursor-pointer ${
                      activeCategory === cat
                        ? 'bg-indigo-50 text-indigo-700 border-indigo-300 shadow-2xs'
                        : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {cat === 'ALL'
                      ? `Tümü (${aqlQueries.length})`
                      : cat === 'INVESTIGATION'
                      ? 'Olay İnceleme'
                      : cat === 'HUNTING'
                      ? 'Tehdit Avı (Pivot/Hunting)'
                      : 'Agregasyon & Trend'}
                  </button>
                ))}
              </div>

              {/* Log Platform Filter */}
              <div className="flex items-center gap-1 pl-2 border-l border-slate-200">
                <span className="text-xs font-semibold text-slate-500">Kaynak:</span>
                {(['ALL', 'WINDOWS', 'WEB', 'FIREWALL'] as const).map((lType) => {
                  const count = lType === 'ALL' ? aqlQueries.length : aqlQueries.filter(q => q.logType === lType).length;
                  if (lType !== 'ALL' && count === 0) return null;
                  return (
                    <button
                      key={lType}
                      type="button"
                      onClick={() => setActiveLogFilter(lType)}
                      className={`px-2 py-0.8 text-xs font-bold rounded-lg border transition-colors cursor-pointer flex items-center gap-1 ${
                        activeLogFilter === lType
                          ? 'bg-sky-50 text-sky-800 border-sky-300 shadow-2xs'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      {lType === 'WINDOWS' && <Monitor className="w-2.5 h-2.5 text-sky-600" />}
                      {lType === 'WEB' && <Globe className="w-2.5 h-2.5 text-emerald-600" />}
                      {lType === 'FIREWALL' && <Radio className="w-2.5 h-2.5 text-amber-600" />}
                      <span>{lType === 'ALL' ? 'Tümü' : lType} ({count})</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="text-[11px] text-slate-500 font-mono">
              IBM QRadar V7.3 - V7.5+ Ariel Query Language
            </div>
          </div>

          {/* Queries Grid */}
          <div className="grid grid-cols-1 gap-3.5">
            {filteredAqlQueries.map((q) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs hover:border-indigo-300 transition-colors"
              >
                <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900">
                        {q.title}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                          q.logType === 'WINDOWS'
                            ? 'bg-sky-50 text-sky-800 border-sky-200'
                            : q.logType === 'WEB'
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                            : 'bg-amber-50 text-amber-800 border-amber-200'
                        }`}
                      >
                        {q.logType}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                          q.category === 'HUNTING'
                            ? 'bg-amber-50 text-amber-800 border-amber-200'
                            : q.category === 'INVESTIGATION'
                            ? 'bg-blue-50 text-blue-800 border-blue-200'
                            : 'bg-purple-50 text-purple-800 border-purple-200'
                        }`}
                      >
                        {q.category}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600">
                      {q.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1 text-[11px] text-slate-500 font-mono">
                      <Clock className="w-3 h-3 text-slate-400" />
                      <span>{q.recommendedTimeWindow}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopy(q.id, q.aql)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer ${
                        copiedId === q.id
                          ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                          : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:text-slate-900'
                      }`}
                    >
                      {copiedId === q.id ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>Kopyalandı!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Sorguyu Kopyala</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <div className="p-3 bg-slate-950 font-mono text-xs overflow-x-auto">
                  <pre className="text-slate-200 leading-relaxed whitespace-pre-wrap select-all">
                    {q.aql}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- MODE 2: SPLUNK SPL --- */}
      {activeMode === 'splunk' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 px-1 text-xs text-slate-600">
            <span className="font-semibold text-slate-800 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-emerald-600" />
              Splunk Search Processing Language (SPL) Hazır Avcılık Sorguları
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              Splunk Enterprise & Splunk Cloud Uyumlu
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3.5">
            {splunkQueries.map((q) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs hover:border-emerald-300 transition-colors"
              >
                <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900">{q.title}</span>
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-emerald-50 text-emerald-800 border-emerald-200">
                        SPLUNK
                      </span>
                      {q.mitreTechnique && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-red-50 text-red-700 border-red-200 flex items-center gap-1">
                          <Tag className="w-2.5 h-2.5" />
                          MITRE: {q.mitreTechnique}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-600">{q.description}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Hedef Kaynak / Sourcetype: <span className="text-slate-700 font-semibold">{q.targetLogSource}</span> | Zaman: {q.timeWindow}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(q.id, q.query)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                      copiedId === q.id
                        ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    {copiedId === q.id ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Kopyalandı!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>SPL Kopyala</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-3 bg-slate-950 font-mono text-xs overflow-x-auto">
                  <pre className="text-emerald-300 leading-relaxed whitespace-pre-wrap select-all">
                    {q.query}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- MODE 3: MICROSOFT SENTINEL KQL --- */}
      {activeMode === 'sentinel' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 px-1 text-xs text-slate-600">
            <span className="font-semibold text-slate-800 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-600" />
              Microsoft Sentinel & Azure Log Analytics (KQL) Avcılık Sorguları
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              Kusto Query Language (Azure Monitor / Sentinel)
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3.5">
            {sentinelQueries.map((q) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs hover:border-blue-300 transition-colors"
              >
                <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900">{q.title}</span>
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-blue-50 text-blue-800 border-blue-200">
                        SENTINEL KQL
                      </span>
                      {q.mitreTechnique && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-red-50 text-red-700 border-red-200 flex items-center gap-1">
                          <Tag className="w-2.5 h-2.5" />
                          MITRE: {q.mitreTechnique}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-600">{q.description}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Tablo Adı: <span className="text-slate-700 font-semibold">{q.targetLogSource}</span> | Pencere: {q.timeWindow}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(q.id, q.query)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                      copiedId === q.id
                        ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    {copiedId === q.id ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Kopyalandı!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>KQL Kopyala</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-3 bg-slate-950 font-mono text-xs overflow-x-auto">
                  <pre className="text-sky-300 leading-relaxed whitespace-pre-wrap select-all">
                    {q.query}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- MODE 4: ELASTICSEARCH KQL / EQL --- */}
      {activeMode === 'elastic' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 px-1 text-xs text-slate-600">
            <span className="font-semibold text-slate-800 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-amber-600" />
              Elasticsearch, Kibana & Elastic SIEM (ECS Uyumlu KQL & EQL)
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              Elastic Common Schema (ECS) & Kibana Discover
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3.5">
            {elasticQueries.map((q) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs hover:border-amber-300 transition-colors"
              >
                <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900">{q.title}</span>
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-amber-50 text-amber-800 border-amber-200">
                        ELASTICSEARCH
                      </span>
                      {q.mitreTechnique && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-red-50 text-red-700 border-red-200 flex items-center gap-1">
                          <Tag className="w-2.5 h-2.5" />
                          MITRE: {q.mitreTechnique}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-600">{q.description}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      İndeks Deseni: <span className="text-slate-700 font-semibold">{q.targetLogSource}</span> | Zaman: {q.timeWindow}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(q.id, q.query)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                      copiedId === q.id
                        ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    {copiedId === q.id ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Kopyalandı!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Sorguyu Kopyala</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-3 bg-slate-950 font-mono text-xs overflow-x-auto">
                  <pre className="text-amber-200 leading-relaxed whitespace-pre-wrap select-all">
                    {q.query}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- MODE 5: SIGMA RULE (YAML) --- */}
      {activeMode === 'sigma' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 px-1 text-xs text-slate-600">
            <span className="font-semibold text-slate-800 flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-rose-600" />
              Evrensel Sigma Tespit Kuralları (Universal Vendor-Agnostic YAML)
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              Splunk, QRadar, Sentinel, ArcSight & Elastic'e Dönüştürülebilir
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3.5">
            {sigmaRules.map((q) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs hover:border-rose-300 transition-colors"
              >
                <div className="px-4 py-3 bg-slate-50/80 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900">{q.title}</span>
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-rose-50 text-rose-800 border-rose-200">
                        SIGMA YAML
                      </span>
                      {q.mitreTechnique && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border bg-red-50 text-red-700 border-red-200 flex items-center gap-1">
                          <Tag className="w-2.5 h-2.5" />
                          MITRE: {q.mitreTechnique}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-600">{q.description}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Log Kaynağı: <span className="text-slate-700 font-semibold">{q.targetLogSource}</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(q.id, q.query)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                      copiedId === q.id
                        ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    {copiedId === q.id ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Kopyalandı!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>YAML Kopyala</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-3 bg-slate-950 font-mono text-xs overflow-x-auto">
                  <pre className="text-rose-200 leading-relaxed whitespace-pre-wrap select-all">
                    {q.query}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- MODE 6: QRADAR CRE DETECTION RULES --- */}
      {activeMode === 'rules' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 px-1 text-xs text-slate-600">
            <span className="font-semibold text-slate-800">
              QRadar Özel Kural Motoru (Custom Rules Engine - CRE) Yapılandırma Rehberi
            </span>
            <span className="font-mono text-[11px] text-slate-500">
              Admin &gt; Custom Rules (CRE) Sihirbazı
            </span>
          </div>

          <div className="space-y-3">
            {customRules.map((rule) => {
              const isExpanded = expandedRuleId === rule.id;
              return (
                <div
                  key={rule.id}
                  className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs transition-all"
                >
                  <div
                    className="p-4 bg-slate-50/70 border-b border-slate-200 cursor-pointer flex items-center justify-between gap-3"
                    onClick={() =>
                      setExpandedRuleId(isExpanded ? null : rule.id)
                    }
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-slate-900">
                          {rule.ruleName}
                        </span>
                        <span
                          className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                            rule.severity >= 8
                              ? 'bg-red-50 text-red-700 border-red-200'
                              : rule.severity >= 5
                              ? 'bg-amber-50 text-amber-800 border-amber-200'
                              : 'bg-blue-50 text-blue-800 border-blue-200'
                          }`}
                        >
                          Önem: {rule.severity}/10
                        </span>
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border bg-purple-50 text-purple-700 border-purple-200">
                          {rule.mitreTechnique}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        {rule.summary}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <ChevronRight
                        className={`w-4 h-4 text-slate-400 transition-transform ${
                          isExpanded ? 'rotate-90' : ''
                        }`}
                      />
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-4 space-y-3 bg-white text-xs">
                      <div>
                        <h4 className="font-bold text-slate-800 mb-1.5 flex items-center gap-1.5">
                          <Filter className="w-3.5 h-3.5 text-indigo-600" />
                          Test Koşulları (Apply On / Test Conditions):
                        </h4>
                        <ul className="space-y-1 pl-2">
                          {rule.ruleTestConditions.map((cond, idx) => (
                            <li
                              key={idx}
                              className="text-slate-700 flex items-start gap-1.5 font-mono text-[11px]"
                            >
                              <span className="text-indigo-600 font-bold">•</span>
                              <span className="bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                                {cond}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="space-y-0.5">
                          <span className="font-bold text-slate-800">
                            Tetiklendiğinde Üretilecek Aksiyon:
                          </span>
                          <p className="text-slate-600 font-mono text-[11px]">
                            {rule.ruleActionDescription}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(rule.id, rule.qradarAqlRuleCondition || rule.qradarCREExpression);
                          }}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer self-start sm:self-center shrink-0 ${
                            copiedId === rule.id
                              ? 'bg-emerald-600 text-white border-emerald-600 shadow-2xs'
                              : 'bg-indigo-50 text-indigo-700 border-indigo-200 hover:bg-indigo-100'
                          }`}
                        >
                          {copiedId === rule.id ? (
                            <>
                              <Check className="w-3.5 h-3.5" />
                              <span>Filtre Kopyalandı!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>AQL Filtresini Kopyala</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* --- MODE 7: REGEX & CUSTOM PROPERTY EXTRACTOR --- */}
      {activeMode === 'regex' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 space-y-3">
            <h4 className="text-xs font-bold text-slate-800 flex items-center gap-2">
              <Wand2 className="w-4 h-4 text-teal-600" />
              1. Ham Log İçinden Ayıklanacak Değeri Seçin:
            </h4>

            {candidateFields.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {candidateFields.map((cand) => (
                  <button
                    key={`${cand.fieldName}_${cand.value}`}
                    type="button"
                    onClick={() => {
                      setSelectedField(cand.value);
                      setCustomFieldName(cand.fieldName);
                      setCustomSelectionText('');
                    }}
                    className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-all cursor-pointer flex items-center gap-1.5 ${
                      selectedField === cand.value
                        ? 'bg-teal-50 text-teal-800 border-teal-300 ring-1 ring-teal-200'
                        : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    <span className="font-bold text-slate-900">{cand.fieldName}:</span>
                    <span className="text-slate-600 truncate max-w-xs">{cand.value}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">
                Ayrıştırılabilir aday alan bulunamadı veya ham log boş.
              </p>
            )}

            <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row gap-3">
              <div className="flex-1">
                <label className="text-[11px] font-bold text-slate-600 block mb-1">
                  Özel Seçim (Metni yapıştırın veya üzerine tıklayın):
                </label>
                <input
                  type="text"
                  value={customSelectionText}
                  onChange={(e) => setCustomSelectionText(e.target.value)}
                  placeholder="Örn: cmd.exe veya /api/v1/auth"
                  className="w-full px-3 py-1.5 text-xs font-mono border border-slate-300 rounded-lg focus:outline-hidden focus:ring-1 focus:ring-teal-500"
                />
              </div>

              <div className="w-full sm:w-64">
                <label className="text-[11px] font-bold text-slate-600 block mb-1">
                  Özel Özellik Adı (Custom Property):
                </label>
                <input
                  type="text"
                  value={customFieldName}
                  onChange={(e) => setCustomFieldName(e.target.value)}
                  placeholder="Örn: Attacker_Command"
                  className="w-full px-3 py-1.5 text-xs font-mono border border-slate-300 rounded-lg focus:outline-hidden focus:ring-1 focus:ring-teal-500"
                />
              </div>
            </div>
          </div>

          {activeExtraction && (
            <div className="bg-slate-900 text-white rounded-xl p-4 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">
                      QRadar Custom Property Regex Çıktısı
                    </span>
                    <span className="text-[10px] font-mono bg-teal-500/20 text-teal-300 px-1.5 py-0.2 rounded border border-teal-400/30">
                      Capture Group 1
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    QRadar DSM Editor &gt; Custom Properties penceresine doğrudan yapıştırılabilir.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopyRegex(activeExtraction.regexPattern)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-all cursor-pointer ${
                    copiedRegex
                      ? 'bg-teal-600 text-white border-teal-600 shadow-2xs'
                      : 'bg-slate-800 text-teal-300 border-teal-500/30 hover:bg-slate-700'
                  }`}
                >
                  {copiedRegex ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Kopyalandı!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Regex'i Kopyala</span>
                    </>
                  )}
                </button>
              </div>

              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-teal-400 overflow-x-auto">
                <pre className="whitespace-pre-wrap select-all">
                  {activeExtraction.regexPattern}
                </pre>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-300">
                    AQL İçi Kullanım (REGEXSEARCH / REGEXMATCH):
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopyCep(`SELECT UTF8(payload) FROM events WHERE REGEXSEARCH('${activeExtraction.regexPattern}', payload)`)
                    }
                    className="text-[11px] text-teal-400 hover:text-teal-300 font-bold flex items-center gap-1 cursor-pointer"
                  >
                    {copiedCep ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCep ? 'Kopyalandı' : 'Kopyala'}</span>
                  </button>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  <code>{`SELECT UTF8(payload) FROM events WHERE REGEXSEARCH('${activeExtraction.regexPattern}', payload)`}</code>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
