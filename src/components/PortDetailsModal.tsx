import React, { useState, useMemo } from 'react';
import {
  X,
  Search,
  Copy,
  Check,
  Radio,
  Layers,
  ShieldAlert,
  ArrowDownRight,
} from 'lucide-react';
import {
  parseAndSortPorts,
  detectPortRanges,
  getPortServiceName,
} from '../utils/portUtils';

interface PortDetailsModalProps {
  isOpen: boolean;
  onClose: () => void;
  hedefIp: string;
  portString: string;
  onFilterByPort?: (port: number) => void;
}

export const PortDetailsModal: React.FC<PortDetailsModalProps> = ({
  isOpen,
  onClose,
  hedefIp,
  portString,
  onFilterByPort,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [copied, setCopied] = useState(false);

  const sortedPorts = useMemo(() => {
    return parseAndSortPorts(portString);
  }, [portString]);

  const { ranges } = useMemo(() => {
    return detectPortRanges(sortedPorts);
  }, [sortedPorts]);

  const filteredPorts = useMemo(() => {
    if (!searchTerm.trim()) return sortedPorts;
    const term = searchTerm.toLowerCase().trim();
    return sortedPorts.filter(p => {
      const pStr = p.toString();
      const sName = getPortServiceName(p).toLowerCase();
      return pStr.includes(term) || sName.includes(term);
    });
  }, [sortedPorts, searchTerm]);

  if (!isOpen) return null;

  const handleCopyAll = () => {
    navigator.clipboard.writeText(sortedPorts.join(', '));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const minPort = sortedPorts.length > 0 ? sortedPorts[0] : 0;
  const maxPort = sortedPorts.length > 0 ? sortedPorts[sortedPorts.length - 1] : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-4xl w-full max-h-[88vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 text-blue-700 rounded-xl">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <span>Hedef IP:</span>
                <span className="font-mono text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                  {hedefIp}
                </span>
                <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-slate-200 text-slate-700">
                  {sortedPorts.length} Port Kullanıldı
                </span>
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Kullanılan tüm portlar küçükten büyüğe sayısal olarak sıralanmış ve servis tanımlarıyla eşleştirilmiştir.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-200/60 transition-colors cursor-pointer"
            title="Kapat"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Stats & Range Detection Alert */}
        <div className="p-6 border-b border-slate-100 bg-white space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">Toplam Port</span>
              <span className="text-xl font-extrabold text-slate-900 font-mono mt-0.5 block">{sortedPorts.length}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">En Düşük Port</span>
              <span className="text-xl font-extrabold text-blue-600 font-mono mt-0.5 block">{minPort || '-'}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">En Yüksek Port</span>
              <span className="text-xl font-extrabold text-blue-600 font-mono mt-0.5 block">{maxPort || '-'}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">Ardışık Aralık</span>
              <span className="text-xl font-extrabold text-amber-600 font-mono mt-0.5 block">{ranges.length} Aralık</span>
            </div>
          </div>

          {/* Consecutive Port Range Warning (common for port scan / passive FTP) */}
          {ranges.length > 0 && (
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 flex items-start gap-2.5">
              <ShieldAlert className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block">
                  Tespit Edilen Ardışık Port Blokları ({ranges.length} Adet):
                </span>
                <span className="text-amber-800 block mt-0.5">
                  Bu portların ardışık olması genellikle bir <strong>Port Taraması (Port Scan / Sweep)</strong> veya <strong>FTP Pasif Veri Transferi (PASV)</strong> havuzuna işaret eder.
                </span>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {ranges.map((r, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 bg-amber-100 text-amber-900 font-mono font-bold rounded border border-amber-300 text-[11px]"
                    >
                      {r.start} &ndash; {r.end} ({r.count} port)
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Toolbar: Search and Copy All */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Port numarası veya servis adı ile ara (örn: 2749, HTTP, FTP)..."
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-300 focus:outline-hidden focus:ring-2 focus:ring-blue-500 font-sans"
              />
            </div>

            <button
              onClick={handleCopyAll}
              className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg border border-slate-300 transition-colors cursor-pointer shadow-2xs shrink-0"
              title="Tüm portları sıralı liste olarak kopyala"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-700 font-bold">Kopyalandı!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-600" />
                  <span>Tüm Portları Kopyala ({sortedPorts.length})</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scrollable Grid of Ports */}
        <div className="p-6 overflow-y-auto max-h-[50vh] bg-slate-50/50">
          {filteredPorts.length === 0 ? (
            <div className="text-center py-10 text-slate-400 text-xs">
              Aramanızla eşleşen port bulunamadı.
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {filteredPorts.map(p => {
                const sName = getPortServiceName(p);
                const isKnown = sName !== 'Diğer / Özel' && sName !== 'Dinamik / Ephemeral';
                return (
                  <div
                    key={p}
                    className={`p-2 rounded-lg border transition-all flex flex-col justify-between ${
                      isKnown
                        ? 'bg-blue-50/70 border-blue-200 hover:border-blue-300 shadow-2xs'
                        : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-sm text-slate-900">{p}</span>
                      {onFilterByPort && (
                        <button
                          onClick={() => {
                            onFilterByPort(p);
                            onClose();
                          }}
                          className="text-slate-400 hover:text-blue-600 p-0.5 rounded hover:bg-blue-100 transition-colors cursor-pointer"
                          title="Aşağıdaki Port Tablosunda Filtrele"
                        >
                          <ArrowDownRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                    <span
                      className={`text-[10px] font-medium truncate mt-1 ${
                        isKnown ? 'text-blue-700 font-semibold' : 'text-slate-500'
                      }`}
                      title={sName}
                    >
                      {sName}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-white flex items-center justify-between text-xs text-slate-500">
          <span>Gösterilen: <strong>{filteredPorts.length}</strong> / {sortedPorts.length} Port</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-xs"
          >
            Kapat
          </button>
        </div>
      </div>
    </div>
  );
};
