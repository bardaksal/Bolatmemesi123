import React, { useState } from 'react';
import { AllowlistData } from '../types';
import { AllowlistManager } from '../services/allowlistManager';
import { Shield, Plus, Trash2, CheckCircle2, XCircle, Search } from 'lucide-react';

interface AllowlistTabProps {
  allowlistMgr: AllowlistManager;
  onRefresh: () => void;
}

export const AllowlistTab: React.FC<AllowlistTabProps> = ({ allowlistMgr, onRefresh }) => {
  const [data, setData] = useState<AllowlistData>(allowlistMgr.getData());
  const [newIp, setNewIp] = useState('');
  const [newCidr, setNewCidr] = useState('');
  const [newAccount, setNewAccount] = useState('');
  const [newServer, setNewServer] = useState('');

  // Interactive IP Test tool
  const [testIp, setTestIp] = useState('');
  const [testResult, setTestResult] = useState<{ isAllowed: boolean; reason: string } | null>(null);

  const handleAdd = (key: keyof AllowlistData, value: string, resetFn: (val: string) => void) => {
    if (!value.trim()) return;
    const ok = allowlistMgr.addEntry(key, value.trim());
    if (ok) {
      setData({ ...allowlistMgr.getData() });
      resetFn('');
      onRefresh();
    }
  };

  const handleRemove = (key: keyof AllowlistData, value: string) => {
    const ok = allowlistMgr.removeEntry(key, value);
    if (ok) {
      setData({ ...allowlistMgr.getData() });
      onRefresh();
    }
  };

  const handleTestIp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!testIp.trim()) return;
    const clean = testIp.trim();
    const isAllowed = allowlistMgr.isIpAllowed(clean);
    if (isAllowed) {
      setTestResult({
        isAllowed: true,
        reason: 'Bu IP adresi allowlist listesinde doğrudan veya tanımlı bir CIDR bloğu içerisinde yer alıyor. Analizlerde otomatik göz ardı edilir.',
      });
    } else {
      setTestResult({
        isAllowed: false,
        reason: 'Bu IP adresi allowlist içinde yer almıyor. Analizlerde değerlendirilir.',
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-emerald-600 mt-0.5" />
          <div>
            <h3 className="text-base font-bold text-slate-900">Allowlist (Güvenli Varlıklar) Yönetimi</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-3xl leading-relaxed">
              Zararsız sistem içi IP adreslerini, şirket içi CIDR ağ bloklarını, yetkili servis hesaplarını (NT AUTHORITY\SYSTEM, vb.) veya güvenilen sunucuları tanımlayarak tehdit avı analizinde yanlış pozitifleri (False Positive) filtreleyebilirsiniz.
            </p>
          </div>
        </div>

        {/* IP Quick Checker */}
        <form onSubmit={handleTestIp} className="mt-4 pt-4 border-t border-slate-100 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center gap-2 flex-1">
            <span className="text-xs font-semibold text-slate-700 whitespace-nowrap">IP Doğrulama Testi:</span>
            <input
              type="text"
              placeholder="Örn: 10.54.206.10 veya 192.168.100.25"
              value={testIp}
              onChange={e => {
                setTestIp(e.target.value);
                setTestResult(null);
              }}
              className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1.5"
          >
            <Search className="w-3.5 h-3.5" />
            Kontrol Et
          </button>
        </form>

        {testResult && (
          <div className={`mt-3 p-3 rounded-lg border text-xs flex items-center gap-2.5 ${
            testResult.isAllowed
              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
              : 'bg-amber-50 text-amber-800 border-amber-200'
          }`}>
            {testResult.isAllowed ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-amber-600 shrink-0" />
            )}
            <div>
              <strong className="block">{testResult.isAllowed ? 'GÜVENLİ (Allowlist Eşleşmesi Var)' : 'LİSTEDE YOK (Tehdit Analizine Dahil Edilir)'}</strong>
              <span className="text-[11px] opacity-90">{testResult.reason}</span>
            </div>
          </div>
        )}
      </div>

      {/* Grid of 4 categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* 1. Güvenli IP Adresleri */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              🌐 Güvenli Tekil IP Adresleri ({data.ips.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 min-h-24 max-h-48 overflow-y-auto p-2 bg-slate-50 rounded-lg border border-slate-100">
              {data.ips.map((ip, idx) => (
                <span key={idx} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-white text-slate-800 border border-slate-200 shadow-2xs">
                  {ip}
                  <button onClick={() => handleRemove('ips', ip)} className="text-slate-400 hover:text-red-600 cursor-pointer">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex gap-2">
            <input
              type="text"
              placeholder="Yeni IP (Örn: 10.0.0.1)"
              value={newIp}
              onChange={e => setNewIp(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd('ips', newIp, setNewIp); }}
              className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
            />
            <button
              onClick={() => handleAdd('ips', newIp, setNewIp)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
            >
              Ekle
            </button>
          </div>
        </div>

        {/* 2. CIDR Blokları */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              🧱 Güvenli CIDR Ağ Blokları ({data.cidrs.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 min-h-24 max-h-48 overflow-y-auto p-2 bg-slate-50 rounded-lg border border-slate-100">
              {data.cidrs.map((cidr, idx) => (
                <span key={idx} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-white text-slate-800 border border-slate-200 shadow-2xs">
                  {cidr}
                  <button onClick={() => handleRemove('cidrs', cidr)} className="text-slate-400 hover:text-red-600 cursor-pointer">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex gap-2">
            <input
              type="text"
              placeholder="Yeni CIDR (Örn: 172.16.0.0/16)"
              value={newCidr}
              onChange={e => setNewCidr(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd('cidrs', newCidr, setNewCidr); }}
              className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
            />
            <button
              onClick={() => handleAdd('cidrs', newCidr, setNewCidr)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
            >
              Ekle
            </button>
          </div>
        </div>

        {/* 3. Servis Hesapları */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              🛡️ Yetkili Servis Hesapları ({data.service_accounts.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 min-h-24 max-h-48 overflow-y-auto p-2 bg-slate-50 rounded-lg border border-slate-100">
              {data.service_accounts.map((acc, idx) => (
                <span key={idx} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-white text-slate-800 border border-slate-200 shadow-2xs">
                  {acc}
                  <button onClick={() => handleRemove('service_accounts', acc)} className="text-slate-400 hover:text-red-600 cursor-pointer">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex gap-2">
            <input
              type="text"
              placeholder="Yeni Hesap (Örn: s_ad_sync)"
              value={newAccount}
              onChange={e => setNewAccount(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd('service_accounts', newAccount, setNewAccount); }}
              className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
            />
            <button
              onClick={() => handleAdd('service_accounts', newAccount, setNewAccount)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
            >
              Ekle
            </button>
          </div>
        </div>

        {/* 4. Güvenli Sunucular */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
              🖥️ Güvenli Sunucu İsimleri ({data.trusted_servers.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 min-h-24 max-h-48 overflow-y-auto p-2 bg-slate-50 rounded-lg border border-slate-100">
              {data.trusted_servers.map((srv, idx) => (
                <span key={idx} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-white text-slate-800 border border-slate-200 shadow-2xs">
                  {srv}
                  <button onClick={() => handleRemove('trusted_servers', srv)} className="text-slate-400 hover:text-red-600 cursor-pointer">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex gap-2">
            <input
              type="text"
              placeholder="Yeni Sunucu (Örn: SRV-CORE-02)"
              value={newServer}
              onChange={e => setNewServer(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAdd('trusted_servers', newServer, setNewServer); }}
              className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-white"
            />
            <button
              onClick={() => handleAdd('trusted_servers', newServer, setNewServer)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
            >
              Ekle
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
