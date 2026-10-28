import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  Terminal,
  Search,
  Database,
  Layers,
  ArrowRight,
  ChevronRight,
  ExternalLink,
  Lock,
  Server,
  User,
  Clock,
  Sparkles,
  HelpCircle,
  Activity,
  FileText,
} from 'lucide-react';
import { L2InvestigationPlan } from '../services/l2InvestigationEngine';

interface L2InvestigationPlanViewProps {
  plan: L2InvestigationPlan;
}

export const L2InvestigationPlanView: React.FC<L2InvestigationPlanViewProps> = ({ plan }) => {
  const [activeQueryTab, setActiveQueryTab] = useState<'splunk' | 'kql' | 'elastic' | 'qradar' | 'sigma'>('splunk');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleCopy = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const getQueryContent = () => {
    switch (activeQueryTab) {
      case 'splunk':
        return plan.queries.splunk;
      case 'kql':
        return plan.queries.kql;
      case 'elastic':
        return plan.queries.elastic;
      case 'qradar':
        return plan.queries.qradarAql;
      case 'sigma':
        return plan.queries.sigmaRule;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner & Log Classification */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 text-slate-100 shadow-lg">
        <div className="flex items-start justify-between gap-4 flex-wrap pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                {plan.classification.platform}
              </span>
              <span className="text-xs font-mono text-slate-400">
                Kaynak: <strong className="text-white">{plan.classification.logSource}</strong>
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Doğruluk: {plan.classification.confidence}
              </span>
            </div>
            <h2 className="text-base sm:text-lg font-bold text-white pt-1">
              {plan.classification.observedBehavior}
            </h2>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(plan.summaryMarkdown, 'full_markdown')}
            className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-xs shrink-0"
          >
            {copiedSection === 'full_markdown' ? (
              <Check className="w-4 h-4 text-emerald-300" />
            ) : (
              <Copy className="w-4 h-4" />
            )}
            <span>{copiedSection === 'full_markdown' ? 'Rapor Kopyalandı' : 'Tüm Planı Markdown Kopyala'}</span>
          </button>
        </div>

        {/* Extracted Key Parameters Matrix */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 text-xs font-mono">
          {Object.entries(plan.classification.keyFields).map(([k, v]) => (
            <div key={k} className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block text-[10px]">{k}</span>
              <span className="text-indigo-300 font-semibold truncate block" title={v}>
                {v}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 2. Platform Context & Attack Chain Significance */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
          <Server className="w-4 h-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            Platform Bağlamı &amp; Olay Zinciri Mantığı ({plan.platformContext.platformName})
          </h3>
        </div>

        <p className="text-xs text-slate-700 leading-relaxed">
          {plan.platformContext.significance}
        </p>

        {/* Forensic Caveat Banner */}
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-900 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <p className="leading-relaxed font-medium">
            {plan.platformContext.conditionalCaveat}
          </p>
        </div>

        {/* Attack Chain Pipeline */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-1.5">
          <div className="text-[11px] font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-indigo-600" />
            <span>Saldırı Zinciri Adli Akışı:</span>
          </div>
          <p className="text-xs font-mono text-slate-800 leading-relaxed">
            {plan.platformContext.attackChainContext}
          </p>
        </div>

        {/* Critical Fields Forensic Significance */}
        <div className="space-y-2 pt-2">
          <h4 className="text-xs font-bold text-slate-800">
            Kritik Alanların Neden İncelenmesi Gerektiği:
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {plan.platformContext.criticalFieldsExplained.map((f, i) => (
              <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-indigo-900">{f.field}</span>
                  <code className="text-[11px] px-1.5 py-0.5 bg-white border border-slate-200 rounded text-slate-700">
                    {f.value}
                  </code>
                </div>
                <p className="text-slate-600 leading-relaxed text-[11px]">
                  {f.forensicImportance}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Hypotheses & Validation Matrix */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Olay Hipotezleri &amp; Doğrulama Matrisi ({plan.hypotheses.length} Hipotez)
            </h3>
          </div>
          <span className="text-xs text-slate-500 italic">
            Hipotezler kesin hüküm değildir; adli delillerle doğrulanmalıdır.
          </span>
        </div>

        <div className="space-y-4">
          {plan.hypotheses.map((h) => (
            <div
              key={h.id}
              className={`border rounded-xl p-4 space-y-3 ${
                h.type === 'ATTACK'
                  ? 'border-rose-200 bg-rose-50/20'
                  : 'border-slate-200 bg-slate-50/50'
              }`}
            >
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-900 text-white">
                    {h.id}
                  </span>
                  <h4 className="text-sm font-bold text-slate-900">{h.title}</h4>
                </div>
                <span
                  className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                    h.likelihood === 'YÜKSEK'
                      ? 'bg-rose-100 text-rose-800 border-rose-300'
                      : h.likelihood === 'ORTA'
                      ? 'bg-amber-100 text-amber-800 border-amber-300'
                      : 'bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  Olasılık: {h.likelihood}
                </span>
              </div>

              <p className="text-xs text-slate-700 leading-relaxed font-medium">
                {h.statement}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                {/* Strengthening Findings */}
                <div className="bg-emerald-50/60 border border-emerald-200 rounded-lg p-3 space-y-1.5">
                  <div className="text-[11px] font-bold text-emerald-900 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Hipotezi Güçlendiren Bulgular (Aranacaklar):</span>
                  </div>
                  <ul className="text-xs text-emerald-950 space-y-1">
                    {h.strengtheningFindings.map((sf, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-emerald-600 font-bold">•</span>
                        <span>{sf}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Weakening Findings */}
                <div className="bg-slate-100/70 border border-slate-200 rounded-lg p-3 space-y-1.5">
                  <div className="text-[11px] font-bold text-slate-800 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Hipotezi Zayıflatan Bulgular (Meşru Senaryolar):</span>
                  </div>
                  <ul className="text-xs text-slate-700 space-y-1">
                    {h.weakeningFindings.map((wf, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-slate-400 font-bold">•</span>
                        <span>{wf}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3.5. Universal Evidence & Dynamic Fact/Hypothesis Verification */}
      {((plan.provenFacts && plan.provenFacts.length > 0) ||
        (plan.unprovenHypotheses && plan.unprovenHypotheses.length > 0) ||
        (plan.missingInformation && plan.missingInformation.length > 0)) && (
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-bold text-slate-900">
                Adli Kanıt Doğrulama &amp; Hipotez Ayrımı (Universal Evidence Pipeline)
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">
              OBSERVED vs. UNPROVEN vs. MISSING
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Proven Facts */}
            <div className="bg-emerald-50/70 border border-emerald-200 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-emerald-900 pb-1 border-b border-emerald-200/60">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Doğrulanmış Olgular (Proven Facts)</span>
              </div>
              <ul className="text-xs text-emerald-950 space-y-1.5 pt-1">
                {(plan.provenFacts || []).map((fact, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-emerald-600 font-bold">•</span>
                    <span>{fact}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Unproven Hypotheses */}
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-amber-900 pb-1 border-b border-amber-200/60">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                <span>Kanıtlanmamış Olasılıklar</span>
              </div>
              <ul className="text-xs text-amber-950 space-y-1.5 pt-1">
                {(plan.unprovenHypotheses || []).map((hypo, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-amber-600 font-bold">•</span>
                    <span>{hypo}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Missing Evidence Required */}
            <div className="bg-indigo-50/70 border border-indigo-200 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-indigo-900 pb-1 border-b border-indigo-200/60">
                <HelpCircle className="w-4 h-4 text-indigo-600" />
                <span>Gerekli Ek Telemetri &amp; Deliller</span>
              </div>
              <ul className="text-xs text-indigo-950 space-y-1.5 pt-1">
                {(plan.missingInformation || []).map((info, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-indigo-600 font-bold">•</span>
                    <span>{info}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* 4. Concrete L2 Investigation Steps Roadmap */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
          <Terminal className="w-4 h-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            L2 Soruşturma Yol Haritası (Investigation Roadmap)
          </h3>
        </div>

        <div className="space-y-4">
          {plan.investigationSteps.map((step) => (
            <div
              key={step.stepNumber}
              className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 space-y-2.5 transition-all hover:border-indigo-300"
            >
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-indigo-600 text-white font-bold text-xs flex items-center justify-center shrink-0">
                    {step.stepNumber}
                  </span>
                  <h4 className="text-sm font-bold text-slate-900">{step.title}</h4>
                </div>
                <span className="text-xs font-mono px-2 py-0.5 bg-slate-200 text-slate-800 rounded font-semibold">
                  {step.category}
                </span>
              </div>

              <p className="text-xs text-slate-700 leading-relaxed font-medium">
                <strong>Amaç:</strong> {step.objective}
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono bg-white p-2.5 rounded-lg border border-slate-200">
                <div>
                  <span className="text-slate-400 block text-[10px]">Hedef Host:</span>
                  <span className="text-slate-800 font-bold">{step.targetEntities.host}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">Hedef Kullanıcı:</span>
                  <span className="text-slate-800 font-bold">{step.targetEntities.user}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">Zaman Penceresi:</span>
                  <span className="text-slate-800 font-bold">{step.targetEntities.timeWindow}</span>
                </div>
              </div>

              <div className="space-y-1 text-xs">
                <div className="text-slate-600">
                  <strong>İncelenecek Log &amp; Event ID'ler:</strong>{' '}
                  <span className="font-mono text-indigo-700">{step.eventIdsAndLogsToInspect.join(', ')}</span>
                </div>
                <div className="text-slate-600">
                  <strong>İncelenecek Parametreler:</strong>{' '}
                  <span className="text-slate-800">{step.fieldsToCheck.join(', ')}</span>
                </div>
              </div>

              <div className="bg-indigo-50/70 border border-indigo-200 rounded-lg p-2.5 text-xs text-indigo-950 flex items-start gap-2">
                <ArrowRight className="w-3.5 h-3.5 text-indigo-600 shrink-0 mt-0.5" />
                <div>
                  <strong>Pivoting / Yönlendirme Kuralı:</strong> {step.pivotingGuidance}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Multi-SIEM Query Terminal */}
      <div className="bg-slate-950 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3 text-slate-200">
        <div className="flex items-center justify-between flex-wrap gap-2 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">
              Doğrudan Çalıştırılabilir SIEM Sorguları (L2 Hunting Queries)
            </h3>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(getQueryContent(), activeQueryTab)}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copiedSection === activeQueryTab ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            <span>{copiedSection === activeQueryTab ? 'Kopyalandı' : 'Sorguyu Kopyala'}</span>
          </button>
        </div>

        {/* Tab switchers */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 overflow-x-auto text-xs">
          {(['splunk', 'kql', 'elastic', 'qradar', 'sigma'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveQueryTab(tab)}
              className={`px-3 py-1.5 rounded-md font-semibold uppercase tracking-wider transition-colors cursor-pointer shrink-0 ${
                activeQueryTab === tab
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab === 'splunk'
                ? 'Splunk (SPL)'
                : tab === 'kql'
                ? 'Sentinel / Defender (KQL)'
                : tab === 'elastic'
                ? 'Elastic / Lucene'
                : tab === 'qradar'
                ? 'IBM QRadar (AQL)'
                : 'Sigma Kuralı'}
            </button>
          ))}
        </div>

        {/* Code block */}
        <pre className="p-4 bg-slate-900 text-emerald-300 font-mono text-xs rounded-xl overflow-x-auto border border-slate-800 whitespace-pre-wrap leading-relaxed max-h-64">
          {getQueryContent()}
        </pre>
      </div>

      {/* 6. Detection Logic & L2 Containment Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Detection Recommendation */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
            <ShieldAlert className="w-4 h-4 text-indigo-600" />
            <h4 className="text-sm font-bold text-slate-900">
              Kalıcı Tespit &amp; SIEM Kuralı Önerisi
            </h4>
          </div>
          <div className="space-y-2 text-xs text-slate-700">
            <div>
              <strong className="text-slate-900">SIEM Korelasyon Mantığı:</strong>
              <p className="mt-0.5 leading-relaxed bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono">
                {plan.detection.siemLogic}
              </p>
            </div>
            <div>
              <strong className="text-slate-900">Ağ / WAF Önlemi:</strong>
              <p className="mt-0.5 leading-relaxed">{plan.detection.wafOrFirewallRule}</p>
            </div>
            <div>
              <strong className="text-slate-900">False Positive Tuning:</strong>
              <p className="mt-0.5 leading-relaxed text-slate-600">{plan.detection.tuningAdvice}</p>
            </div>
          </div>
        </div>

        {/* L2 Containment & Incident Response */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-rose-600" />
              <h4 className="text-sm font-bold text-slate-900">
                Acil Müdahale &amp; İzolasyon (L2 Containment)
              </h4>
            </div>
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                plan.containment.severity === 'KRİTİK'
                  ? 'bg-rose-100 text-rose-800'
                  : 'bg-amber-100 text-amber-800'
              }`}
            >
              {plan.containment.severity} ÖNCELİK
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <strong className="text-slate-900 block mb-1">Müdahale Aksiyonları:</strong>
              <ul className="space-y-1.5 text-slate-700">
                {plan.containment.containmentActions.map((act, i) => (
                  <li key={i} className="flex items-start gap-2 bg-rose-50/30 p-2 rounded border border-rose-100">
                    <span className="w-4 h-4 rounded-full bg-rose-600 text-white text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span className="leading-relaxed">{act}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <strong className="text-slate-900 block mb-1">Toplanacak Adli Deliller (Artifacts):</strong>
              <ul className="space-y-1 text-slate-600">
                {plan.containment.forensicArtifactsToCollect.map((art, i) => (
                  <li key={i} className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                    <span>{art}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
