import React from 'react';
import { Loader2, XCircle, HardDrive, Cpu } from 'lucide-react';
import { AnalysisProgress } from '../services/logWorkerController';

interface AnalysisProgressBarProps {
  progress: AnalysisProgress | null;
  isProcessing: boolean;
  onAbort?: () => void;
}

export const AnalysisProgressBar: React.FC<AnalysisProgressBarProps> = ({
  progress,
  isProcessing,
  onAbort,
}) => {
  if (!isProcessing || !progress) return null;

  const pct = Math.min(100, Math.max(0, progress.percent));
  const isCorrelating = progress.stage === 'CORRELATING';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full bg-slate-900/95 text-white rounded-2xl p-5 shadow-2xl border border-slate-700 backdrop-blur-md animate-in fade-in slide-in-from-bottom-5 duration-200">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-blue-500/20 border border-blue-400/30 flex items-center justify-center shrink-0">
            {isCorrelating ? (
              <Cpu className="w-4 h-4 text-purple-400 animate-pulse" />
            ) : (
              <HardDrive className="w-4 h-4 text-blue-400" />
            )}
          </div>
          <div>
            <div className="text-xs font-bold text-white flex items-center gap-2">
              <span>{isCorrelating ? 'Tehdit Avı Korelasyonu' : 'Büyük Log Ayrıştırma (Worker)'}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono font-bold">
                %{pct}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate max-w-[240px]">
              {progress.stageMessage || (progress.fileName ? `${progress.fileName} işleniyor...` : 'Loglar işleniyor...')}
            </p>
          </div>
        </div>

        {onAbort && (
          <button
            onClick={onAbort}
            className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors cursor-pointer"
            title="Analizi İptal Et"
          >
            <XCircle className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Progress Bar Track */}
      <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-700">
        <div
          className={`h-full rounded-full transition-all duration-150 ${
            isCorrelating
              ? 'bg-gradient-to-r from-indigo-500 to-purple-500'
              : 'bg-gradient-to-r from-blue-500 to-emerald-400'
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* Footer Metrics */}
      <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5 font-mono">
          <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />
          <span className="text-slate-300 font-bold">{progress.linesRead.toLocaleString()}</span>
          <span>satır işlendi</span>
        </div>

        {progress.totalFiles && progress.totalFiles > 1 && (
          <span className="text-slate-400">
            Dosya {progress.fileIndex || 1} / {progress.totalFiles}
          </span>
        )}

        {onAbort && (
          <button
            onClick={onAbort}
            className="text-xs text-red-400 hover:text-red-300 hover:underline font-semibold cursor-pointer"
          >
            İptal Et
          </button>
        )}
      </div>
    </div>
  );
};
