import React from 'react';
import { ShieldAlert, Database, Terminal, Code2, Sparkles, FileText, HelpCircle } from 'lucide-react';

interface HeaderProps {
  onOpenSqlModal?: () => void;
  onOpenAiModal?: () => void;
  onOpenQuickLogModal?: () => void;
  onOpenCommandExplainer?: (initialCommand?: string) => void;
  onOpenAiLogUnderstanding?: () => void;
  logCount: number;
  fileCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  logCount,
  fileCount,
}) => {
  return (
    <header className="border-b border-slate-200 bg-white shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
              SOC Log Lens
            </h1>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Log analiz, korelasyon ve tehdit tespit platformu.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center">
            <div className="flex items-center gap-2 px-3.5 py-2 bg-slate-900 text-slate-200 rounded-lg text-xs font-mono shadow-xs">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              {logCount > 0 ? (
                <span>
                  Analiz Edilen: <strong className="text-emerald-300">{logCount.toLocaleString()}</strong> Olay
                  {fileCount !== undefined && fileCount > 0 && (
                    <span className="text-slate-400 ml-1.5">({fileCount} Dosya)</span>
                  )}
                </span>
              ) : (
                <span className="text-amber-400">Log Yüklenmedi</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
