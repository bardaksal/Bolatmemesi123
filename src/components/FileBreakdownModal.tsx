import React from 'react';
import { X, CheckCircle2, Files, Database, ArrowRight, HardDrive, ShieldCheck, Filter, AlertTriangle, Scale } from 'lucide-react';
import { DetectedFormatItem, ForensicQuarantineReport } from '../types';

interface FileBreakdownModalProps {
  isOpen: boolean;
  onClose: () => void;
  detectedFormats: DetectedFormatItem[];
  totalTransferBytes: number;
  selectedFileFilter: string | null;
  onSelectFileFilter: (fileName: string | null) => void;
  quarantine?: ForensicQuarantineReport;
  onOpenQuarantine?: () => void;
}

export const FileBreakdownModal: React.FC<FileBreakdownModalProps> = ({
  isOpen,
  onClose,
  detectedFormats,
  totalTransferBytes,
  selectedFileFilter,
  onSelectFileFilter,
  quarantine,
  onOpenQuarantine,
}) => {
  if (!isOpen) return null;

  const totalLines = detectedFormats.reduce((acc, f) => acc + (f.lineCount || 0), 0);
  const totalEvents = detectedFormats.reduce((acc, f) => acc + (f.eventCount || 0), 0);
  const totalHeaders = detectedFormats.reduce((acc, f) => acc + (f.headerCommentCount || 0), 0);
  const totalQuarantined = detectedFormats.reduce((acc, f) => acc + (f.quarantinedCount || 0), 0);
  const totalGb = (totalTransferBytes / (1024 * 1024 * 1024)).toFixed(2);
  const totalMb = (totalTransferBytes / (1024 * 1024)).toFixed(1);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-5xl w-full max-h-[90vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-slate-200 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-600 text-white flex items-center justify-center shadow-xs">
              <Files className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-black text-slate-900">
                  Dosya Dağılımı ve Doğrulama Raporu
                </h3>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-100 text-purple-700 border border-purple-200">
                  {detectedFormats.length} Dosya Yüklendi
                </span>
                {totalQuarantined > 0 ? (
                  <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> {totalQuarantined} Karantinada
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300 flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3" /> %100 Bütünlük
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Yüklenen tüm log dosyalarının satır ayrıştırma durumu, karantina adli kaydı ve transfer dağılımı.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-2 rounded-xl hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
              <span className="text-[11px] font-bold text-slate-500 uppercase block">Toplam Dosya</span>
              <span className="text-xl font-black text-slate-900 mt-1 block">
                {detectedFormats.length} Adet
              </span>
              <span className="text-[11px] text-slate-500 mt-0.5 block">Tümü Bütünleşik Analizde</span>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
              <span className="text-[11px] font-bold text-slate-500 uppercase block">Okunan Satır</span>
              <span className="text-xl font-black text-blue-600 mt-1 block">
                {totalLines.toLocaleString('tr-TR')}
              </span>
              <span className="text-[11px] text-slate-500 mt-0.5 block">Ham Log Satırları</span>
            </div>

            <div className="bg-emerald-50/70 border border-emerald-200 rounded-xl p-3.5">
              <span className="text-[11px] font-bold text-emerald-700 uppercase block">Ayrıştırılan Olay</span>
              <span className="text-xl font-black text-emerald-800 mt-1 block">
                {totalEvents.toLocaleString('tr-TR')}
              </span>
              <span className="text-[11px] text-emerald-600 mt-0.5 block">Standarda Uygun</span>
            </div>

            <div className={`border rounded-xl p-3.5 ${
              totalQuarantined > 0
                ? 'bg-amber-50/80 border-amber-300 ring-2 ring-amber-500/10'
                : 'bg-slate-50 border-slate-200'
            }`}>
              <span className={`text-[11px] font-bold uppercase block ${
                totalQuarantined > 0 ? 'text-amber-800' : 'text-slate-500'
              }`}>
                Karantina (Hariç)
              </span>
              <span className={`text-xl font-black mt-1 block ${
                totalQuarantined > 0 ? 'text-amber-900 font-mono' : 'text-slate-700'
              }`}>
                {totalQuarantined.toLocaleString('tr-TR')}
              </span>
              <span className={`text-[11px] mt-0.5 block ${
                totalQuarantined > 0 ? 'text-amber-700 font-semibold' : 'text-slate-500'
              }`}>
                {totalQuarantined > 0 ? 'Standart Dışı Satır' : '0 Hariç Tutulan'}
              </span>
            </div>

            <div className="bg-purple-50/70 border border-purple-200 rounded-xl p-3.5">
              <span className="text-[11px] font-bold text-purple-700 uppercase block">Başarılı Transfer</span>
              <span className="text-xl font-black text-purple-800 mt-1 block">
                {parseFloat(totalGb) >= 1 ? `${totalGb} GB` : `${totalMb} MB`}
              </span>
              <span className="text-[11px] text-purple-600 mt-0.5 block font-mono truncate" title={`${totalTransferBytes} B`}>
                {totalTransferBytes.toLocaleString('tr-TR')} B
              </span>
            </div>
          </div>

          {/* Ayrıştırma Durumu */}
          <div className={`border rounded-xl p-3.5 text-xs flex items-center justify-between gap-3 shadow-2xs ${
            totalQuarantined > 0
              ? 'bg-amber-50/90 border-amber-300 text-amber-950'
              : 'bg-emerald-50/90 border-emerald-300 text-emerald-950'
          }`}>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-900">Durum:</span>
              <span>{quarantine?.footnoteText || 'Ayrıştırılan %100, sorun yok.'}</span>
            </div>
            {totalQuarantined > 0 && onOpenQuarantine && (
              <button
                onClick={() => {
                  onClose();
                  onOpenQuarantine();
                }}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white font-bold rounded-lg text-xs shrink-0 cursor-pointer shadow-2xs"
              >
                Karantina Satırları ({totalQuarantined})
              </button>
            )}
          </div>

          {/* Per File Table */}
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Yüklenen Dosyaların Bireysel Adli Ayrıştırma Metrikleri
              </h4>
              {selectedFileFilter && (
                <button
                  onClick={() => onSelectFileFilter(null)}
                  className="text-xs font-semibold text-blue-600 hover:text-blue-800 underline cursor-pointer"
                >
                  Filtreyi Temizle (Tümünü Göster)
                </button>
              )}
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/80 border-b border-slate-200 text-slate-700">
                    <th className="p-3 font-semibold">Dosya Adı</th>
                    <th className="p-3 font-semibold">Format &amp; Kolon</th>
                    <th className="p-3 font-semibold text-right">Okunan</th>
                    <th className="p-3 font-semibold text-right">Olay</th>
                    <th className="p-3 font-semibold text-right">Başlık (#)</th>
                    <th className="p-3 font-semibold text-right">Karantina</th>
                    <th className="p-3 font-semibold text-right">Başarılı Transfer</th>
                    <th className="p-3 font-semibold text-center">Genel Payı</th>
                    <th className="p-3 font-semibold text-center">Benzersiz IP</th>
                    <th className="p-3 font-semibold text-center">İşlem</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {detectedFormats.map((f, idx) => {
                    const bytes = f.transferBytes || 0;
                    const gb = (bytes / (1024 * 1024 * 1024)).toFixed(2);
                    const mb = (bytes / (1024 * 1024)).toFixed(1);
                    const pct = totalTransferBytes > 0 ? ((bytes / totalTransferBytes) * 100).toFixed(1) : '0.0';
                    const isFiltered = selectedFileFilter === f.fileName;
                    const fileQuarantined = f.quarantinedCount || 0;

                    return (
                      <tr
                        key={idx}
                        className={`hover:bg-slate-50 transition-colors ${isFiltered ? 'bg-blue-50/60 font-semibold' : ''}`}
                      >
                        <td className="p-3 font-mono font-bold text-slate-900">
                          <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span>
                            <span className="truncate max-w-[160px]" title={f.fileName}>{f.fileName}</span>
                          </div>
                        </td>
                        <td className="p-3 text-slate-600">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-sans text-[11px] font-medium border border-slate-200">
                            {f.formatDisplayName}
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono text-slate-700">
                          {f.lineCount.toLocaleString('tr-TR')}
                        </td>
                        <td className="p-3 text-right font-mono text-emerald-700 font-semibold">
                          {(f.eventCount || f.lineCount).toLocaleString('tr-TR')}
                        </td>
                        <td className="p-3 text-right font-mono text-slate-500">
                          {(f.headerCommentCount || 0).toLocaleString('tr-TR')}
                        </td>
                        <td className="p-3 text-right font-mono">
                          {fileQuarantined > 0 ? (
                            <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 font-bold">
                              {fileQuarantined.toLocaleString('tr-TR')}
                            </span>
                          ) : (
                            <span className="text-slate-400">0</span>
                          )}
                        </td>
                        <td className="p-3 text-right font-mono font-bold text-purple-700">
                          {parseFloat(gb) >= 1 ? `${gb} GB` : `${mb} MB`}
                          <span className="block text-[10px] text-slate-400 font-normal font-mono">
                            {bytes.toLocaleString('tr-TR')} B
                          </span>
                        </td>
                        <td className="p-3 text-center font-mono font-bold text-slate-700">
                          %{pct}
                        </td>
                        <td className="p-3 text-center font-mono text-slate-700">
                          {f.uniqueIps ? f.uniqueIps.toLocaleString('tr-TR') : '-'}
                        </td>
                        <td className="p-3 text-center">
                          <button
                            onClick={() => {
                              onSelectFileFilter(isFiltered ? null : f.fileName);
                              onClose();
                            }}
                            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                              isFiltered
                                ? 'bg-blue-600 text-white'
                                : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                            }`}
                          >
                            <Filter className="w-3 h-3" />
                            <span>{isFiltered ? 'Filtreyi Kaldır' : 'Yalnızca Bunu Gör'}</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
          <div className="text-xs text-slate-500">
            {selectedFileFilter ? (
              <span>
                Şu anda <strong className="text-slate-800">{selectedFileFilter}</strong> dosyası filtrelenmiş durumda.
              </span>
            ) : (
              <span>Tüm dosyalar birleşik olarak ana gösterge panelinde görüntüleniyor.</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {selectedFileFilter && (
              <button
                onClick={() => {
                  onSelectFileFilter(null);
                  onClose();
                }}
                className="px-3.5 py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 rounded-xl text-xs font-bold transition-colors cursor-pointer"
              >
                Tüm Dosyaları Göster
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold transition-colors cursor-pointer"
            >
              Kapat
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
