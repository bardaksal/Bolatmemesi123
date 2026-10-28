import React, { useState, useEffect, useMemo } from 'react';
import { Terminal, Play, RotateCcw, AlertTriangle, CheckCircle2, Clock, Layers, Table as TableIcon, Copy, Check } from 'lucide-react';
import { duckdbClient, QueryResult } from '../services/duckdbClient';
import { DUCKDB_QUERIES } from '../services/socEngine';

interface DuckDbHuntingConsoleProps {
  totalEvents: number;
}

const PRESET_QUERIES = [
  {
    name: 'Top 10 Kaynak IP (Hacim Dağılımı)',
    sql: `SELECT c_ip, COUNT(*) AS istek_sayisi, 
       ROUND(SUM(COALESCE(sc_bytes, 0)) / (1024.0 * 1024.0), 2) AS toplam_mb
FROM logs 
WHERE c_ip IS NOT NULL AND c_ip != '-'
GROUP BY c_ip 
ORDER BY istek_sayisi DESC 
LIMIT 10;`,
  },
  {
    name: 'HTTP 4xx / 5xx Hata Veren İstekler',
    sql: `SELECT tarih, c_ip, http_method, islem_komutu, sc_status, kaynak_dosya
FROM logs 
WHERE sc_status >= 400 
ORDER BY row_id DESC 
LIMIT 50;`,
  },
  {
    name: 'Webshell / Komut Çalıştırma Şüphelileri',
    sql: `SELECT tarih, c_ip, islem_komutu, sc_status, user_agent
FROM logs 
WHERE islem_komutu LIKE '%.php%' 
   OR islem_komutu LIKE '%.aspx%' 
   OR islem_komutu LIKE '%cmd%' 
   OR islem_komutu LIKE '%powershell%' 
   OR islem_komutu LIKE '%whoami%'
ORDER BY row_id DESC 
LIMIT 50;`,
  },
  {
    name: 'Yüksek Veri Transferi (Sızıntı Adayları)',
    sql: `SELECT c_ip, cs_username, COUNT(*) AS istekler, 
       ROUND(SUM(COALESCE(sc_bytes, 0)) / (1024.0 * 1024.0), 2) AS transfer_mb
FROM logs 
GROUP BY c_ip, cs_username
HAVING transfer_mb > 5.0
ORDER BY transfer_mb DESC 
LIMIT 20;`,
  },
  {
    name: 'Tüm Kolonlar (Son 100 Log)',
    sql: `SELECT row_id, tarih, c_ip, cs_username, http_method, islem_komutu, sc_status, sc_bytes
FROM logs 
ORDER BY row_id DESC 
LIMIT 100;`,
  },
];

export const DuckDbHuntingConsole: React.FC<DuckDbHuntingConsoleProps> = ({ totalEvents }) => {
  const [sql, setSql] = useState<string>(PRESET_QUERIES[0].sql);
  const [isRunning, setIsRunning] = useState(false);
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [duckStatus, setDuckStatus] = useState(duckdbClient.getStatus());
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setDuckStatus(duckdbClient.getStatus());
    }, 1500);
    return () => clearInterval(timer);
  }, []);

  const handleRunQuery = async () => {
    if (!sql.trim()) return;
    setIsRunning(true);
    setError(null);

    try {
      const result = await duckdbClient.query(sql.trim(), 500);
      setQueryResult(result);
      setDuckStatus(duckdbClient.getStatus());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setQueryResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  const handleCopySql = () => {
    navigator.clipboard.writeText(sql);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-lg overflow-hidden flex flex-col my-6">
      {/* Header */}
      <div className="px-5 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-wide">DuckDB SQL Konsolu</h3>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                WASM
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Yüklenen {duckStatus.totalRows.toLocaleString('tr-TR')} log kaydı üzerinde SQL sorguları çalıştırın.
            </p>
          </div>
        </div>

        {/* Database stats badge */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            <span>Tablo: <strong className="text-white font-semibold">logs</strong> ({duckStatus.totalRows.toLocaleString('tr-TR')} satır)</span>
          </div>
          <button
            onClick={handleCopySql}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors text-xs cursor-pointer"
            title="SQL Kopyala"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Kopyalandı' : 'Kopyala'}</span>
          </button>
        </div>
      </div>

      {/* Preset Queries Bar */}
      <div className="px-5 py-2.5 bg-slate-900/90 border-b border-slate-800/80 flex items-center gap-2 overflow-x-auto text-xs">
        <span className="text-slate-500 font-medium whitespace-nowrap text-[11px]">Hazır Şablonlar:</span>
        {PRESET_QUERIES.map((preset, idx) => (
          <button
            key={idx}
            onClick={() => {
              setSql(preset.sql);
              setError(null);
            }}
            className="px-2.5 py-1 rounded-md bg-slate-800/70 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors whitespace-nowrap border border-slate-700/50 cursor-pointer text-[11px]"
          >
            {preset.name}
          </button>
        ))}
      </div>

      {/* SQL Input Area */}
      <div className="p-4 bg-slate-950 flex flex-col gap-3">
        <div className="relative">
          <textarea
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            rows={4}
            className="w-full bg-slate-900 text-amber-200 font-mono text-xs p-3 rounded-lg border border-slate-800 focus:outline-hidden focus:ring-1 focus:ring-amber-400/50 focus:border-amber-400/50 resize-y leading-relaxed"
            placeholder="SELECT * FROM logs LIMIT 50;"
            spellCheck={false}
          />
        </div>

        <div className="flex items-center justify-between">
          <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Güvenlik: Yalnızca <strong className="text-slate-300">SELECT, WITH, EXPLAIN</strong> sorguları çalıştırılabilir (Read-Only).</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setSql('');
                setQueryResult(null);
                setError(null);
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors cursor-pointer flex items-center gap-1"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Temizle
            </button>
            <button
              onClick={handleRunQuery}
              disabled={isRunning || !sql.trim()}
              className="px-4 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-600 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-semibold text-xs transition-all shadow-md flex items-center gap-1.5 cursor-pointer disabled:cursor-not-allowed"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isRunning ? 'Çalıştırılıyor...' : 'Sorguyu Çalıştır (F5/Run)'}
            </button>
          </div>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mx-4 my-3 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <strong className="font-semibold block">SQL Çalıştırma Hatası:</strong>
            <span className="font-mono">{error}</span>
          </div>
        </div>
      )}

      {/* Query Result Section */}
      {queryResult && (
        <div className="border-t border-slate-800 flex flex-col">
          {/* Result meta bar */}
          <div className="px-5 py-2.5 bg-slate-900 flex items-center justify-between text-xs text-slate-400 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Başarılı
              </span>
              <span>Dönen Satır: <strong className="text-white">{queryResult.rows.length}</strong> / Toplam: {queryResult.rowCount}</span>
              {queryResult.truncated && (
                <span className="text-amber-400 text-[11px]">(İlk 500 satır gösteriliyor)</span>
              )}
            </div>
            <div className="flex items-center gap-1 text-slate-400 font-mono">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>{queryResult.durationMs} ms</span>
            </div>
          </div>

          {/* Results Table */}
          {queryResult.rows.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs">
              Sorgu başarıyla çalıştırıldı ancak eşleşen satır bulunamadı (0 rows).
            </div>
          ) : (
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                    {queryResult.columns.map((col, idx) => (
                      <th key={idx} className="py-2.5 px-3.5 font-semibold text-slate-300 tracking-wider">
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {queryResult.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-800/50 transition-colors">
                      {queryResult.columns.map((col, cIdx) => {
                        const val = row[col];
                        const displayVal = val === null || val === undefined ? (
                          <span className="text-slate-600 italic">null</span>
                        ) : typeof val === 'object' ? (
                          JSON.stringify(val)
                        ) : (
                          String(val)
                        );

                        return (
                          <td key={cIdx} className="py-2 px-3.5 whitespace-nowrap max-w-xs truncate">
                            {displayVal}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
