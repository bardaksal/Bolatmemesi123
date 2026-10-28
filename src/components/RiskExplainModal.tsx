import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Sparkles,
  ShieldCheck,
  Network,
  Cpu,
  Server,
  Layers,
  Info,
  CheckCircle2,
  AlertTriangle,
  TrendingUp,
  Activity,
  Copy,
  Check,
} from 'lucide-react';
import { RiskQueueItem } from '../types';
import { defaultAllowlistManager } from '../services/allowlistManager';

interface RiskExplainModalProps {
  isOpen: boolean;
  onClose: () => void;
  item: RiskQueueItem | null;
  onOpenAiModal?: (item: RiskQueueItem, ip: string) => void;
  onAllowlistUpdated?: () => void;
}

export const RiskExplainModal: React.FC<RiskExplainModalProps> = ({
  isOpen,
  onClose,
  item,
  onOpenAiModal,
  onAllowlistUpdated,
}) => {
  const [copied, setCopied] = useState(false);
  const [allowlistAdded, setAllowlistAdded] = useState(false);

  if (!isOpen || !item) return null;

  const getSeverityColor = (level: string) => {
    switch (level) {
      case 'KRİTİK':
        return 'bg-red-500 text-white border-red-600';
      case 'YÜKSEK':
        return 'bg-orange-500 text-white border-orange-600';
      case 'ORTA':
        return 'bg-amber-500 text-white border-amber-600';
      case 'DÜŞÜK':
        return 'bg-blue-500 text-white border-blue-600';
      default:
        return 'bg-slate-500 text-white border-slate-600';
    }
  };

  const getConfidenceBadge = (confidence?: string) => {
    switch (confidence) {
      case 'YÜKSEK':
        return { label: 'Yüksek Güven', color: 'bg-emerald-100 text-emerald-800 border-emerald-300' };
      case 'ORTA':
        return { label: 'Orta Güven', color: 'bg-amber-100 text-amber-800 border-amber-300' };
      case 'DÜŞÜK':
        return { label: 'Düşük Güven (Şüphe)', color: 'bg-slate-100 text-slate-700 border-slate-300' };
      default:
        return { label: 'Orta Güven', color: 'bg-amber-100 text-amber-800 border-amber-300' };
    }
  };

  const getZoneLabel = (zone?: string) => {
    switch (zone) {
      case 'internal':
        return { label: 'İç Ağ (RFC1918)', color: 'bg-blue-50 text-blue-700 border-blue-200' };
      case 'external':
        return { label: 'Dış Ağ (İnternet)', color: 'bg-purple-50 text-purple-700 border-purple-200' };
      case 'loopback':
        return { label: 'Yerel Loopback (127.0.0.1)', color: 'bg-slate-50 text-slate-700 border-slate-200' };
      default:
        return { label: 'Bilinmeyen Bölge', color: 'bg-slate-50 text-slate-700 border-slate-200' };
    }
  };

  const getSourceLabel = (src?: string) => {
    switch (src) {
      case 'trusted-proxy-forwarded':
        return { label: 'Doğrulanmış Proxy XFF', color: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
      case 'direct-peer':
        return { label: 'Doğrudan Peer Bağlantı', color: 'bg-slate-50 text-slate-700 border-slate-200' };
      case 'untrusted-spoofed-ignored':
        return { label: 'Güvenilmeyen / Yoksayılan Header', color: 'bg-rose-50 text-rose-700 border-rose-200' };
      case 'parsed-client':
        return { label: 'Ayrıştırılmış İstemci', color: 'bg-indigo-50 text-indigo-700 border-indigo-200' };
      default:
        return { label: 'Doğrudan IP', color: 'bg-slate-50 text-slate-700 border-slate-200' };
    }
  };

  const handleCopyIoc = () => {
    const text = `[SOC TEHDİT RAPORU]
Varlık IP: ${item.ip_adresi} (${item.ip_kategori})
Hedef Sunucu / Host: ${item.sunucu_ismi}
Risk Seviyesi: ${item.risk_seviyesi} (Puan: ${item.risk_puani}/100)
Ağ Bölgesi: ${item.network_zone || 'Bilinmiyor'} | İstemci Tipi: ${item.ip_source || 'Doğrudan'}
Tespit Güveni: ${item.confidence || 'MEDIUM'}
Özet: ${item.explainability_summary || item.risk_gerekcesi}
İstek Sayısı: ${item.toplam_istek} | Veri Hacmi: ${(item.basarili_byte / (1024 * 1024)).toFixed(2)} MB | Auth Hata: ${item.auth_hatasi} | Webshell: ${item.webshell_sinyali}`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAddToAllowlist = () => {
    defaultAllowlistManager.addEntry('ips', item.ip_adresi);
    defaultAllowlistManager.save();
    setAllowlistAdded(true);
    if (onAllowlistUpdated) onAllowlistUpdated();
    setTimeout(() => setAllowlistAdded(false), 3000);
  };

  const confidenceBadge = getConfidenceBadge(item.confidence);
  const zoneBadge = getZoneLabel(item.network_zone);
  const sourceBadge = getSourceLabel(item.ip_source);

  return (
    <div
      id="risk-explain-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        id="risk-explain-modal-container"
        className="bg-white border border-slate-200 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden text-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-50/80 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-50 border border-indigo-200 rounded-xl text-indigo-700">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 font-mono">
                  {item.ip_adresi}
                </h3>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityColor(item.risk_seviyesi)}`}>
                  {item.risk_seviyesi} ({item.risk_puani}/100)
                </span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${confidenceBadge.color}`}>
                  {confidenceBadge.label}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5 flex items-center gap-2">
                <span>Hedef: <strong className="text-slate-700 font-mono">{item.sunucu_ismi}</strong></span>
                {item.device && <span>• Cihaz: <strong className="text-slate-700 font-mono">{item.device}</strong></span>}
                <span>• IP Sınıfı: <span className="text-slate-700">{item.ip_kategori}</span></span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="copy-ioc-btn"
              onClick={handleCopyIoc}
              className="p-2 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors border border-slate-200"
              title="Analist IOC Özetini Kopyala"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
              <span>{copied ? 'Kopyalandı' : 'IOC Kopyala'}</span>
            </button>
            <button
              id="close-explain-modal-btn"
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs">
          {/* Network & Source Context Badges */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center gap-3">
              <Network className="w-5 h-5 text-blue-600 shrink-0" />
              <div>
                <div className="text-[11px] text-slate-500 font-medium">Ağ Bölgesi</div>
                <div className="font-bold text-slate-800 text-xs mt-0.5">{zoneBadge.label}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center gap-3">
              <Server className="w-5 h-5 text-purple-600 shrink-0" />
              <div>
                <div className="text-[11px] text-slate-500 font-medium">İstemci IP Kaynağı</div>
                <div className="font-bold text-slate-800 text-xs mt-0.5">{sourceBadge.label}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center gap-3">
              <Cpu className="w-5 h-5 text-emerald-600 shrink-0" />
              <div>
                <div className="text-[11px] text-slate-500 font-medium">Trafik &amp; Aktivite</div>
                <div className="font-bold text-slate-800 text-xs mt-0.5">
                  {item.toplam_istek.toLocaleString()} İstek • {(item.basarili_byte / (1024 * 1024)).toFixed(2)} MB
                </div>
              </div>
            </div>
          </div>

          {/* Section 1: Explainability Summary Narrative */}
          <div className="bg-blue-50/70 border border-blue-200 rounded-xl p-4">
            <div className="flex items-center gap-2 text-blue-900 font-bold mb-2">
              <Info className="w-4 h-4 text-blue-600" />
              <span>SOC Analist Açıklanabilirlik ve Karar Gerekçesi</span>
            </div>
            <p className="text-blue-950 leading-relaxed text-xs">
              {item.explainability_summary || item.risk_gerekcesi || 'Bu varlık için risk puanı hesaplanırken çoklu sinyaller ve ağ bağlamı değerlendirilmiştir.'}
            </p>
          </div>

          {/* Section 2: Scoring Breakdown Table */}
          {item.scoring_breakdown && item.scoring_breakdown.length > 0 && (
            <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-indigo-600" />
                  <h4 className="font-bold text-slate-800">
                    Puanlama Matrisi &amp; Formül Dağılımı ({item.risk_puani}/100)
                  </h4>
                </div>
                <span className="text-[11px] text-slate-500">
                  {item.scoring_breakdown.length} adet faktör / kural uygulandı
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-100/75 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                      <th className="py-2 px-3">Kural / Sinyal Türü</th>
                      <th className="py-2 px-3 text-center">Puan Etkisi</th>
                      <th className="py-2 px-3">Gerekçe &amp; Kanıt Detayı</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {item.scoring_breakdown.map((b, idx) => {
                      const isPositive = b.points > 0;
                      const isZero = b.points === 0;
                      return (
                        <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="py-2.5 px-3 font-semibold text-slate-800 whitespace-nowrap">
                            {b.item}
                          </td>
                          <td className="py-2.5 px-3 text-center whitespace-nowrap font-mono font-bold">
                            {isZero ? (
                              <span className="text-slate-400">0</span>
                            ) : isPositive ? (
                              <span className="text-rose-600 bg-rose-50 px-2 py-0.5 rounded border border-rose-200">
                                +{b.points}
                              </span>
                            ) : (
                              <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                                {b.points}
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-slate-600 leading-normal">
                            {b.note}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Section 3: Extracted Active Signals */}
          {item.signals && item.signals.length > 0 && (
            <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-rose-600" />
                  <h4 className="font-bold text-slate-800">
                    Tespit Edilen Bağımsız Sinyaller ({item.signals.length})
                  </h4>
                </div>
                <span className="text-[11px] text-slate-500">
                  Kill-chain aşamalarına göre sınıflandırılmıştır
                </span>
              </div>
              <div className="divide-y divide-slate-100">
                {item.signals.map((sig, sIdx) => {
                  const getCategoryBadge = (cat: string) => {
                    switch (cat) {
                      case 'EXPLOIT':
                        return 'bg-red-100 text-red-800 border-red-200';
                      case 'EXFILTRATION':
                        return 'bg-purple-100 text-purple-800 border-purple-200';
                      case 'RECON':
                        return 'bg-amber-100 text-amber-800 border-amber-200';
                      default:
                        return 'bg-slate-100 text-slate-800 border-slate-200';
                    }
                  };

                  return (
                    <div key={sIdx} className="p-3.5 hover:bg-slate-50/70 transition-colors">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getCategoryBadge(sig.category)}`}>
                            {sig.category}
                          </span>
                          <span className="font-bold text-slate-900 text-xs">
                            {sig.label || sig.description}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-500">
                          Puan: +{sig.points} • Güven: {sig.confidence}
                        </span>
                      </div>
                      <p className="mt-1 text-slate-600 text-[11px] leading-relaxed">
                        {sig.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <button
              id="modal-add-allowlist-btn"
              onClick={handleAddToAllowlist}
              disabled={allowlistAdded}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all cursor-pointer flex items-center gap-1.5 ${
                allowlistAdded
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-300'
                  : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300 shadow-2xs'
              }`}
            >
              {allowlistAdded ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <ShieldCheck className="w-4 h-4 text-emerald-600" />}
              <span>{allowlistAdded ? "Allowlist'e Eklendi!" : "Bu IP'yi Güvenli Listeye Ekle"}</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            {onOpenAiModal && (
              <button
                id="modal-ai-analiz-btn"
                onClick={() => {
                  onClose();
                  onOpenAiModal(item, item.ip_adresi);
                }}
                className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs flex items-center gap-1.5 cursor-pointer"
              >
                <Sparkles className="w-4 h-4" />
                <span>AI SOC ile Derin İnceleme Yap</span>
              </button>
            )}

            <button
              id="modal-close-btn"
              onClick={onClose}
              className="px-4 py-1.5 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Kapat
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
