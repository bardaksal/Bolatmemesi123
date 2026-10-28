import React, { useState, useMemo } from 'react';
import {
  X,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Search,
  Copy,
  Check,
  Download,
  Scale,
  FileCode,
} from 'lucide-react';
import { ForensicQuarantineReport, QuarantinedLineItem } from '../types';

interface ForensicQuarantineModalProps {
  isOpen: boolean;
  onClose: () => void;
  quarantine?: ForensicQuarantineReport;
}

export const ForensicQuarantineModal: React.FC<ForensicQuarantineModalProps> = ({
  isOpen,
  onClose,
  quarantine,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const filteredLines = useMemo(() => {
    if (!quarantine?.quarantinedLines) return [];
    if (!searchTerm.trim()) return quarantine.quarantinedLines;
    const term = searchTerm.toLowerCase();
    return quarantine.quarantinedLines.filter(
      (item) =>
        item.fileName.toLowerCase().includes(term) ||
        item.rawText.toLowerCase().includes(term) ||
        item.reason.toLowerCase().includes(term) ||
        String(item.lineNumber).includes(term)
    );
  }, [quarantine?.quarantinedLines, searchTerm]);

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1800);
  };

  const handleExportQuarantine = () => {
    if (!quarantine?.quarantinedLines || quarantine.quarantinedLines.length === 0) return;
    const header = '# ADLI BILISIM KARANTINA VE HARIC TUTULAN SATIR RAPORU\r\n' +
      `# Toplam Okunan: ${quarantine.totalLinesRead}\r\n` +
      `# Basariyla Ayristirilan: ${quarantine.parsedEventsCount}\r\n` +
      `# Baslik/Yorum Satirlari: ${quarantine.headerCommentLinesCount}\r\n` +
      `# Karantinaya Alinan: ${quarantine.quarantinedCount}\r\n` +
      `# Adli Dipnot: ${quarantine.footnoteText}\r\n\r\n` +
      'Dosya_Adi\tSatir_No\tNeden\tHam_Satir\r\n';

    const rows = quarantine.quarantinedLines.map(
      (q) => `${q.fileName}\t${q.lineNumber}\t${q.reason}\t${q.rawText}`
    ).join('\r\n');

    const blob = new Blob([header + rows], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `adli_karantina_raporu_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  const totalLines = quarantine?.totalLinesRead || 0;
  const parsedCount = quarantine?.parsedEventsCount || 0;
  const headerCount = quarantine?.headerCommentLinesCount || 0;
  const emptyCount = quarantine?.emptyLinesCount || 0;
  const quarantinedCount = quarantine?.quarantinedCount || 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 overflow-y-auto">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-100 border border-amber-200 flex items-center justify-center text-amber-700 shadow-2xs">
              <Scale className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <span>Ayrıştırılamayan / Bozuk Satırlar Karantinası &amp; Adli Bütünlük</span>
                {quarantinedCount === 0 ? (
                  <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                    <ShieldCheck className="w-3 h-3" /> %100 Eksiksiz
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300">
                    <AlertTriangle className="w-3 h-3" /> {quarantinedCount} Hariç Tutulan Satır
                  </span>
                )}
              </h2>
              <p className="text-xs text-slate-500">
                Logta yer almayan hiçbir varsayımsal veri üretilmez. Standart dışı satırlar adli kanıt zinciriyle karantinaya ayrılır.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-lg transition-colors cursor-pointer"
            title="Kapat"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Adli Metrik Kartları */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">
                Toplam Okunan
              </span>
              <span className="text-lg font-black text-slate-900 font-mono mt-0.5 block">
                {totalLines.toLocaleString('tr-TR')}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Ham Log Satırı</span>
            </div>

            <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 block">
                Ayrıştırılan Olay
              </span>
              <span className="text-lg font-black text-emerald-800 font-mono mt-0.5 block">
                {parsedCount.toLocaleString('tr-TR')}
              </span>
              <span className="text-[10px] text-emerald-600 mt-0.5 block">
                {totalLines > 0 ? `%${((parsedCount / totalLines) * 100).toFixed(1)} Veri` : 'Olay'}
              </span>
            </div>

            <div className="bg-blue-50 border border-blue-200 rounded-xl p-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 block">
                Başlık / Direktif
              </span>
              <span className="text-lg font-black text-blue-800 font-mono mt-0.5 block">
                {headerCount.toLocaleString('tr-TR')}
              </span>
              <span className="text-[10px] text-blue-600 mt-0.5 block">#Fields, #Version vb.</span>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">
                Boş Satırlar
              </span>
              <span className="text-lg font-black text-slate-700 font-mono mt-0.5 block">
                {emptyCount.toLocaleString('tr-TR')}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Atlanan Satır Boşlukları</span>
            </div>

            <div className={`rounded-xl p-3 border ${
              quarantinedCount > 0
                ? 'bg-amber-50 border-amber-300 ring-2 ring-amber-500/10'
                : 'bg-emerald-50/60 border-emerald-200'
            }`}>
              <span className={`text-[10px] font-bold uppercase tracking-wider block ${
                quarantinedCount > 0 ? 'text-amber-800' : 'text-emerald-700'
              }`}>
                Karantina / Hariç
              </span>
              <span className={`text-lg font-black font-mono mt-0.5 block ${
                quarantinedCount > 0 ? 'text-amber-900' : 'text-emerald-800'
              }`}>
                {quarantinedCount.toLocaleString('tr-TR')}
              </span>
              <span className={`text-[10px] mt-0.5 block ${
                quarantinedCount > 0 ? 'text-amber-700 font-medium' : 'text-emerald-600'
              }`}>
                {quarantinedCount > 0 ? 'Standart Dışı Satır' : 'Sıfır Hata / Kayıp'}
              </span>
            </div>
          </div>

          {/* Ayrıştırma Durumu */}
          <div className={`rounded-xl p-3.5 border flex items-center justify-between gap-3 shadow-2xs ${
            quarantinedCount > 0
              ? 'bg-amber-50/80 border-amber-300 text-amber-950'
              : 'bg-emerald-50/80 border-emerald-300 text-emerald-950'
          }`}>
            <div className="text-xs">
              <span className="font-bold text-slate-900">Durum: </span>
              <span>{quarantine?.footnoteText || 'Ayrıştırılan %100, sorun yok.'}</span>
            </div>
            <span className="font-mono text-[11px] text-slate-500">
              {quarantinedCount > 0 ? `${quarantinedCount} satır hariç tutuldu` : 'Hatasız ayrıştırma'}
            </span>
          </div>

          {/* Karantina Tablosu & Arama */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-slate-700" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Ayrıştırılamayan / Bozuk Satırlar ({quarantinedCount})
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Dosya, satır no veya metin ara..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 w-64"
                  />
                  {searchTerm && (
                    <button
                      onClick={() => setSearchTerm('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs"
                    >
                      ✕
                    </button>
                  )}
                </div>

                {quarantinedCount > 0 && (
                  <button
                    onClick={handleExportQuarantine}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg border border-slate-300 transition-colors cursor-pointer"
                    title="Karantina satırlarını adli kanıt metin dosyası olarak indir"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Dışa Aktar (.txt)</span>
                  </button>
                )}
              </div>
            </div>

            {quarantinedCount === 0 ? (
              <div className="border border-emerald-200 bg-emerald-50/40 rounded-xl p-8 text-center space-y-2">
                <div className="w-12 h-12 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center mx-auto">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-bold text-emerald-900">Mükemmel Adli Bütünlük</h4>
                <p className="text-xs text-emerald-700 max-w-lg mx-auto">
                  Yüklenen dosyalardaki tüm içerik satırları başarıyla ve eksiksiz olarak ayrıştırıldı. Standart dışı, bozuk veya atlanan hiçbir satır bulunmamaktadır.
                </p>
              </div>
            ) : filteredLines.length === 0 ? (
              <div className="border border-slate-200 rounded-xl p-6 text-center text-xs text-slate-500">
                "{searchTerm}" aramasına uygun karantina satırı bulunamadı.
              </div>
            ) : (
              <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
                <div className="max-h-80 overflow-y-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-slate-100 text-slate-700 font-semibold border-b border-slate-200 sticky top-0 z-10">
                      <tr>
                        <th className="py-2.5 px-3 w-12 text-center">#</th>
                        <th className="py-2.5 px-3 w-40">Kaynak Dosya</th>
                        <th className="py-2.5 px-3 w-20 text-center">Satır</th>
                        <th className="py-2.5 px-3 w-64">Hariç Tutulma Nedeni</th>
                        <th className="py-2.5 px-3">Orijinal Ham Log Satırı</th>
                        <th className="py-2.5 px-3 w-12 text-center">Kopya</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {filteredLines.map((item: QuarantinedLineItem, idx: number) => {
                        const isCopied = copiedIndex === idx;
                        return (
                          <tr key={idx} className="hover:bg-amber-50/40 transition-colors">
                            <td className="py-2 px-3 text-center text-slate-400 font-mono text-[11px]">
                              {idx + 1}
                            </td>
                            <td className="py-2 px-3 font-mono font-medium text-slate-800 truncate max-w-[160px]" title={item.fileName}>
                              <div className="flex items-center gap-1.5">
                                <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                <span className="truncate">{item.fileName}</span>
                              </div>
                            </td>
                            <td className="py-2 px-3 text-center font-mono font-bold text-amber-800">
                              L{item.lineNumber}
                            </td>
                            <td className="py-2 px-3 text-slate-700 font-medium">
                              <span className="inline-block px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-900 text-[11px]">
                                {item.reason}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-mono text-[11px] text-slate-900 break-all select-all bg-slate-50/50">
                              {item.rawText}
                            </td>
                            <td className="py-2 px-3 text-center">
                              <button
                                onClick={() => handleCopy(item.rawText, idx)}
                                className={`p-1.5 rounded-md transition-colors cursor-pointer ${
                                  isCopied
                                    ? 'bg-emerald-100 text-emerald-700'
                                    : 'text-slate-400 hover:text-slate-700 hover:bg-slate-200/60'
                                }`}
                                title="Ham satırı panoya kopyala"
                              >
                                {isCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-3.5 border-t border-slate-200 bg-slate-50/80">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Scale className="w-4 h-4 text-slate-400" />
            <span>Adli İnceleme Standartları: RFC 3164/5424, W3C Extended Log, NIST SP 800-86</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-xl transition-colors cursor-pointer shadow-2xs"
          >
            Anladım / Kapat
          </button>
        </div>
      </div>
    </div>
  );
};
