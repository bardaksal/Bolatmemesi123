import { AllowlistData, ScopedAllowlistRule, NormalizedLog } from '../types';
import { isIpInCidr } from './proxyResolver';

const STORAGE_KEY = 'soc_log_lens_allowlist';

export const DEFAULT_ALLOWLIST_DATA: AllowlistData = {
  ips: [],
  cidrs: [],
  service_accounts: [
    'NT AUTHORITY\\SYSTEM',
    'LOCAL SERVICE',
    'NETWORK SERVICE',
  ],
  trusted_servers: [],
  scoped_rules: [],
};

export class AllowlistManager {
  private data: AllowlistData;

  constructor() {
    this.data = this.load();
  }

  public getData(): AllowlistData {
    return this.data;
  }

  private load(): AllowlistData {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        const ips = (Array.isArray(parsed.ips) ? parsed.ips : DEFAULT_ALLOWLIST_DATA.ips)
          .filter((ip: string) => ip !== '10.54.206.10' && ip !== '127.0.0.1');
        const cidrs = (Array.isArray(parsed.cidrs) ? parsed.cidrs : DEFAULT_ALLOWLIST_DATA.cidrs)
          .filter((c: string) => c !== '127.0.0.0/8');
        return {
          ips,
          cidrs,
          service_accounts: Array.isArray(parsed.service_accounts) ? parsed.service_accounts : DEFAULT_ALLOWLIST_DATA.service_accounts,
          trusted_servers: Array.isArray(parsed.trusted_servers) ? parsed.trusted_servers : DEFAULT_ALLOWLIST_DATA.trusted_servers,
          scoped_rules: Array.isArray(parsed.scoped_rules) ? parsed.scoped_rules : [],
        };
      }
    } catch {
      // ignore
    }
    return JSON.parse(JSON.stringify(DEFAULT_ALLOWLIST_DATA));
  }

  public save(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.data));
    } catch (err) {
      console.error('Allowlist save error:', err);
    }
  }

  public addEntry(key: keyof AllowlistData, value: string): boolean {
    const trimmed = value.trim();
    if (!trimmed) return false;
    if (key === 'scoped_rules') return false;
    if (!this.data[key].includes(trimmed)) {
      this.data[key].push(trimmed);
      this.save();
      return true;
    }
    return false;
  }

  public removeEntry(key: keyof AllowlistData, value: string): boolean {
    if (key === 'scoped_rules') return false;
    const idx = this.data[key].indexOf(value);
    if (idx !== -1) {
      this.data[key].splice(idx, 1);
      this.save();
      return true;
    }
    return false;
  }

  public addScopedRule(rule: ScopedAllowlistRule): boolean {
    if (!this.data.scoped_rules) {
      this.data.scoped_rules = [];
    }
    this.data.scoped_rules.push(rule);
    this.save();
    return true;
  }

  public removeScopedRule(ruleId: string): boolean {
    if (!this.data.scoped_rules) return false;
    const idx = this.data.scoped_rules.findIndex(r => r.id === ruleId);
    if (idx !== -1) {
      this.data.scoped_rules.splice(idx, 1);
      this.save();
      return true;
    }
    return false;
  }

  public isIpInCidr(ip: string, cidr: string): boolean {
    return isIpInCidr(ip, cidr);
  }

  public isIpAllowed(ipStr: string | null | undefined): boolean {
    if (!ipStr || ipStr === '-' || ipStr === '' || ipStr === 'null') return false;
    const cleanIp = ipStr.trim();
    if (this.data.ips.includes(cleanIp)) return true;
    for (const cidr of this.data.cidrs) {
      if (this.isIpInCidr(cleanIp, cidr)) return true;
    }
    return false;
  }

  public isAccountAllowed(accountStr: string | null | undefined): boolean {
    if (!accountStr || accountStr === '-' || accountStr === '' || accountStr === 'null') return false;
    const acc = accountStr.trim().toLowerCase();
    return this.data.service_accounts.some(s => s.trim().toLowerCase() === acc);
  }

  public isServerAllowed(serverStr: string | null | undefined): boolean {
    if (!serverStr || serverStr === '-' || serverStr === '' || serverStr === 'null') return false;
    const srv = serverStr.trim().toLowerCase();
    return this.data.trusted_servers.some(s => s.trim().toLowerCase() === srv);
  }

  public isAllowed(ip?: string | null, account?: string | null, server?: string | null): boolean {
    if (ip && this.isIpAllowed(ip)) return true;
    if (account && this.isAccountAllowed(account)) return true;
    if (server && this.isServerAllowed(server)) return true;
    return false;
  }
}

export function isItemAllowed(
  data: AllowlistData | null | undefined,
  ip?: string | null,
  account?: string | null,
  server?: string | null
): boolean {
  if (!data) return false;
  if (ip && ip !== '-' && ip !== '') {
    const cleanIp = ip.trim();
    if (data.ips.includes(cleanIp)) return true;
    for (const cidr of data.cidrs) {
      if (isIpInCidr(cleanIp, cidr)) return true;
    }
  }
  if (account && account !== '-' && account !== '') {
    const acc = account.trim().toLowerCase();
    if (data.service_accounts.some(s => s.trim().toLowerCase() === acc)) return true;
  }
  if (server && server !== '-' && server !== '') {
    const srv = server.trim().toLowerCase();
    if (data.trusted_servers.some(s => s.trim().toLowerCase() === srv)) return true;
  }
  return false;
}

/**
 * Checks if a specific normalized log matches any allowlist entry (global or scoped).
 */
export function isLogAllowedByAllowlist(
  log: NormalizedLog,
  data: AllowlistData | null | undefined
): boolean {
  if (!data) return false;

  // 1. Global IP, Service Account, or Trusted Server matches
  if (isItemAllowed(data, log.ip_adresi, log.kullanici_adi, log.sunucu_ismi)) {
    return true;
  }

  // 2. Scoped rules matching
  if (data.scoped_rules && data.scoped_rules.length > 0) {
    const now = Date.now();
    for (const rule of data.scoped_rules) {
      // Check expiration
      if (rule.expiresAt) {
        const expTime = new Date(rule.expiresAt).getTime();
        if (!isNaN(expTime) && expTime < now) {
          continue; // Rule has expired
        }
      }

      const scope = rule.scope;
      let matched = true;

      if (scope.ip) {
        const targetIp = (log.ip_adresi || '').trim();
        if (targetIp !== scope.ip.trim()) {
          matched = false;
        }
      }

      if (matched && scope.cidr) {
        const targetIp = (log.ip_adresi || '').trim();
        if (!isIpInCidr(targetIp, scope.cidr)) {
          matched = false;
        }
      }

      if (matched && scope.user) {
        const logUser = (log.kullanici_adi || '').trim().toLowerCase();
        if (logUser !== scope.user.trim().toLowerCase()) {
          matched = false;
        }
      }

      if (matched && scope.device) {
        const logDev = (log.device || log.sunucu_ismi || '').trim().toLowerCase();
        if (logDev !== scope.device.trim().toLowerCase()) {
          matched = false;
        }
      }

      if (matched && scope.endpoint) {
        const logUri = (log.islem_komutu || '').toLowerCase();
        const ruleUri = scope.endpoint.trim().toLowerCase();
        if (!logUri.startsWith(ruleUri) && !logUri.includes(ruleUri)) {
          matched = false;
        }
      }

      if (matched && scope.method) {
        const logMethod = (log.http_method || '').toUpperCase();
        if (logMethod !== scope.method.trim().toUpperCase()) {
          matched = false;
        }
      }

      if (matched && scope.network_zone) {
        if (log.network_zone !== scope.network_zone) {
          matched = false;
        }
      }

      if (matched) {
        return true;
      }
    }
  }

  return false;
}

export const defaultAllowlistManager = new AllowlistManager();
