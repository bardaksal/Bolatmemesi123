import React, { useState } from 'react';
import { X, Copy, Check, Database, Terminal, Play, CheckCircle2, Clock, AlertTriangle } from 'lucide-react';
import { DUCKDB_QUERIES } from '../services/socEngine';
import { duckdbClient, QueryResult } from '../services/duckdbClient';

interface SqlModalProps {
  isOpen: boolean;
  onClose: () => void;
  totalEvents?: number;
}

export const SqlModal: React.FC<SqlModalProps> = ({ isOpen, onClose, totalEvents = 0 }) => {
  const [activeTab, setActiveTab] = useState<'console' | 'reference'>('console');
  const [selectedKey, setSelectedKey] = useState<string>('entity_risk_queue');
  const [copied, setCopied] = useState(false);

  // Interactive DuckDB Query States
  const [customSql, setCustomSql] = useState<string>(
    `SELECT c_ip, COUNT(*) AS istek_sayisi, \n       ROUND(SUM(COALESCE(sc_bytes, 0)) / (1024.0 * 1024.0), 2) AS toplam_mb\nFROM logs \nWHERE c_ip IS NOT NULL AND c_ip != '-'\nGROUP BY c_ip \nORDER BY istek_sayisi DESC \nLIMIT 10;`
  );
  const [isRunning, setIsRunning] = useState(false);
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const queryTitles: Record<string, string> = {
    entity_risk_queue: '1. Öncelikli Risk Kuyruğu (0-100 Puanlama)',
    cross_day_correlation: '2. Günler Arası Korelasyon (Cross-Day Attack)',
    webshell_and_file_management: '3. Webshell & Dosya Yöneticisi Tespiti',
    exfiltration_anomalies: '4. Veri Sızdırma Anomalileri (HAVING SUM)',
    scanner_and_bots: '5. Bot & Otomatize Tarayıcı Analizi',
    destination_ip_analysis: '6. Hedef IP & Port Dağılımı (Accept/Deny)',
  };

  const currentSql = DUCKDB_QUERIES[selectedKey] || '';

  const handleCopy = () => {
    const textToCopy = activeTab === 'console' ? customSql : currentSql;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRunQuery = async () => {
    if (!customSql.trim()) return;
    setIsRunning(true);
    setError(null);

    try {
      const res = await duckdbClient.query(customSql.trim(), 500);
      setQueryResult(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setQueryResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  const duckStatus = duckdbClient.getStatus();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 overflow-y-auto">
      <div className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-5xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-slate-800 text-base">DuckDB-Wasm SQL Hunting & Analiz Konsolu</h3>
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                  Client-Side WASM
                </span>
              </div>
              <p className="text-xs text-slate-500">
                100% Tarayıcı içi bellek • Yüklenen {duckStatus.totalRows.toLocaleString('tr-TR')} log üzerinde ad-hoc SQL sorguları
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Switching (Interactive Console vs SOC Dialect Reference) */}
        <div className="px-6 pt-3 border-b border-slate-200 bg-slate-50 flex items-center gap-2">
          <button
            onClick={() => setActiveTab('console')}
            className={`px-3 py-2 text-xs font-bold rounded-t-lg transition-colors border-b-2 cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'console'
                ? 'border-blue-600 text-blue-700 bg-white'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>İnteraktif SQL Hunting Konsolu (Çalıştır)</span>
          </button>
          <button
            onClick={() => setActiveTab('reference')}
            className={`px-3 py-2 text-xs font-bold rounded-t-lg transition-colors border-b-2 cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'reference'
                ? 'border-blue-600 text-blue-700 bg-white'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Hazır Analitik SQL Şablonları</span>
          </button>
        </div>

        {/* Content Area */}
        <div className="p-6 overflow-y-auto flex-1 flex flex-col gap-4">
          {activeTab === 'console' ? (
            /* Tab 1: Interactive Live SQL Runner */
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between text-xs text-slate-600">
                <span>Tablo: <strong className="font-mono text-slate-900">logs</strong> ({duckStatus.totalRows.toLocaleString('tr-TR')} satır)</span>
                <span className="text-[11px] text-slate-500">Güvenlik: Sadece SELECT/WITH sorguları (Read-Only)</span>
              </div>

              {/* Preset buttons */}
              <div className="flex flex-wrap gap-1.5">
                <span className="text-xs text-slate-500 self-center mr-1">Hazır Şablonlar:</span>
                <button
                  onClick={() =>
                    setCustomSql(
                      `SELECT c_ip, COUNT(*) AS istek_sayisi, \n       ROUND(SUM(COALESCE(sc_bytes, 0)) / (1024.0 * 1024.0), 2) AS toplam_mb\nFROM logs \nWHERE c_ip IS NOT NULL AND c_ip != '-'\nGROUP BY c_ip \nORDER BY istek_sayisi DESC \nLIMIT 10;`
                    )
                  }
                  className="px-2.5 py-1 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md border border-slate-200 font-medium cursor-pointer"
                >
                  Top 10 IP
                </button>
                <button
                  onClick={() =>
                    setCustomSql(
                      `SELECT tarih, c_ip, islem_komutu, sc_status \nFROM logs \nWHERE islem_komutu LIKE '%.php%' \n   OR islem_komutu LIKE '%.aspx%' \n   OR islem_komutu LIKE '%cmd%' \n   OR islem_komutu LIKE '%powershell%'\nLIMIT 50;`
                    )
                  }
                  className="px-2.5 py-1 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md border border-slate-200 font-medium cursor-pointer"
                >
                  Webshell Şüphelileri
                </button>
                <button
                  onClick={() =>
                    setCustomSql(
                      `SELECT c_ip, cs_username, COUNT(*) AS istek_sayisi, \n       ROUND(SUM(COALESCE(sc_bytes, 0)) / (1024.0 * 1024.0), 2) AS transfer_mb\nFROM logs \nGROUP BY c_ip, cs_username\nHAVING transfer_mb > 5.0\nORDER BY transfer_mb DESC;`
                    )
                  }
                  className="px-2.5 py-1 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md border border-slate-200 font-medium cursor-pointer"
                >
                  Veri Sızıntısı &gt; 5MB
                </button>
                <button
                  onClick={() =>
                    setCustomSql(
                      `SELECT row_id, tarih, c_ip, cs_username, http_method, islem_komutu, sc_status, sc_bytes\nFROM logs\nORDER BY row_id DESC\nLIMIT 50;`
                    )
                  }
                  className="px-2.5 py-1 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md border border-slate-200 font-medium cursor-pointer"
                >
                  Tüm Kolonlar (Son 50)
                </button>
              </div>

              {/* SQL Input Box */}
              <div className="relative rounded-lg overflow-hidden border border-slate-800 bg-slate-950">
                <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-xs font-mono text-slate-300">
                  <div className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-amber-400" />
                    <span>SQL Query</span>
                  </div>
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1 text-slate-300 hover:text-white px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 cursor-pointer transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Kopyalandı' : 'Kopyala'}</span>
                  </button>
                </div>
                <textarea
                  value={customSql}
                  onChange={(e) => setCustomSql(e.target.value)}
                  rows={5}
                  className="w-full bg-slate-950 text-amber-200 font-mono text-xs p-3.5 focus:outline-hidden resize-y leading-relaxed"
                  placeholder="SELECT * FROM logs LIMIT 50;"
                  spellCheck={false}
                />
              </div>

              {/* Execution Controls */}
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-500 font-mono">
                  {duckStatus.totalRows === 0 ? '⚠️ Henüz log yüklenmedi. Sorgulamak için önce log yükleyin.' : 'Hazır'}
                </span>
                <button
                  onClick={handleRunQuery}
                  disabled={isRunning || !customSql.trim()}
                  className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 disabled:text-slate-500 text-white font-semibold text-xs transition-colors flex items-center gap-2 cursor-pointer disabled:cursor-not-allowed shadow-xs"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isRunning ? 'Çalıştırılıyor...' : 'Sorguyu Çalıştır'}</span>
                </button>
              </div>

              {/* Error box */}
              {error && (
                <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <strong className="font-semibold block">Hata:</strong>
                    <span className="font-mono">{error}</span>
                  </div>
                </div>
              )}

              {/* Result Table */}
              {queryResult && (
                <div className="border border-slate-200 rounded-lg overflow-hidden bg-white shadow-xs">
                  <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-xs text-slate-600">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                      <span>Sonuç: <strong>{queryResult.rows.length}</strong> / {queryResult.rowCount} satır</span>
                    </div>
                    <div className="flex items-center gap-1 font-mono text-[11px] text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span>{queryResult.durationMs} ms</span>
                    </div>
                  </div>

                  {queryResult.rows.length === 0 ? (
                    <div className="p-6 text-center text-slate-400 text-xs">Eşleşen satır bulunamadı.</div>
                  ) : (
                    <div className="overflow-x-auto max-h-72">
                      <table className="w-full text-left border-collapse text-xs font-mono">
                        <thead>
                          <tr className="bg-slate-100 border-b border-slate-200 text-slate-700">
                            {queryResult.columns.map((c, i) => (
                              <th key={i} className="py-2 px-3 font-semibold whitespace-nowrap">
                                {c}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {queryResult.rows.map((row, rIdx) => (
                            <tr key={rIdx} className="hover:bg-slate-50">
                              {queryResult.columns.map((c, cIdx) => (
                                <td key={cIdx} className="py-1.5 px-3 whitespace-nowrap max-w-xs truncate">
                                  {row[c] === null || row[c] === undefined ? '-' : String(row[c])}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            /* Tab 2: Reference Analytical Dialect Queries */
            <div>
              <p className="text-xs text-slate-600 mb-4">
                Aşağıdaki sorgular, log verilerini filtrelemek, gruplamak ve tehdit analizi gerçekleştirmek için tasarlanmış analitik SQL şablonlarıdır.
              </p>

              <div className="flex flex-wrap gap-1.5 mb-4">
                {Object.entries(queryTitles).map(([key, title]) => (
                  <button
                    key={key}
                    onClick={() => setSelectedKey(key)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors cursor-pointer ${
                      selectedKey === key
                        ? 'bg-blue-600 text-white shadow-xs'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    {title}
                  </button>
                ))}
              </div>

              <div className="relative">
                <div className="flex items-center justify-between bg-slate-900 text-slate-300 px-4 py-2 text-xs font-mono rounded-t-lg border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    <span>DuckDB SQL / dialect</span>
                  </div>
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1 text-slate-300 hover:text-white px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 transition-colors cursor-pointer"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Kopyalandı</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>SQL Kopyala</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-950 text-emerald-400 p-4 rounded-b-lg font-mono text-xs overflow-x-auto max-h-80 leading-relaxed border border-slate-900">
                  <code>{currentSql}</code>
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-50 border-t border-slate-200 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
          >
            Kapat
          </button>
        </div>
      </div>
    </div>
  );
};
