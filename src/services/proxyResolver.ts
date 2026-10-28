import { NetworkZone, IpSourceType } from '../types';

export const DEFAULT_TRUSTED_PROXIES: string[] = [
  '127.0.0.1',
  '::1',
  '127.0.0.0/8',
  '10.0.0.1',
  '10.0.0.2',
  '172.16.0.1',
  '172.17.0.1',
  '192.168.1.1',
  '192.168.100.1',
];

export function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bitsStr] = cidr.split('/');
    if (!bitsStr) {
      return ip.trim() === range.trim();
    }
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;

    const ipParts = ip.trim().split('.').map(Number);
    const rangeParts = range.trim().split('.').map(Number);
    if (ipParts.length !== 4 || rangeParts.length !== 4) return false;
    if (ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    if (rangeParts.some(p => isNaN(p) || p < 0 || p > 255)) return false;

    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const rangeNum = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
    const mask = bits === 0 ? 0 : (~0 << (32 - bits));

    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

export function classifyNetworkZone(ipStr: string | null | undefined): NetworkZone {
  if (!ipStr || ipStr === '-' || ipStr === 'null' || ipStr.trim() === '') {
    return 'external';
  }

  const cleanIp = ipStr.trim();

  // Loopback check
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp.startsWith('127.') || cleanIp === 'localhost') {
    return 'loopback';
  }

  // IPv4 check
  const parts = cleanIp.split('.').map(p => parseInt(p, 10));
  if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    // 10.0.0.0/8
    if (parts[0] === 10) return 'internal';
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return 'internal';
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return 'internal';
    // 169.254.0.0/16 (Link Local)
    if (parts[0] === 169 && parts[1] === 254) return 'internal';
  }

  // IPv6 ULA (fc00::/7) or link-local (fe80::/10)
  if (cleanIp.toLowerCase().startsWith('fc') || cleanIp.toLowerCase().startsWith('fd') || cleanIp.toLowerCase().startsWith('fe80')) {
    return 'internal';
  }

  return 'external';
}

export function isTrustedProxy(
  peerIp: string | null | undefined,
  trustedProxyList: string[] = DEFAULT_TRUSTED_PROXIES
): boolean {
  if (!peerIp || peerIp === '-' || peerIp.trim() === '') return false;
  const cleanPeer = peerIp.trim();

  for (const proxyDef of trustedProxyList) {
    const trimmed = proxyDef.trim();
    if (!trimmed) continue;
    if (trimmed.includes('/')) {
      if (isIpInCidr(cleanPeer, trimmed)) return true;
    } else {
      if (cleanPeer === trimmed) return true;
    }
  }

  return false;
}

export interface ClientIpResolution {
  clientIp: string | null;
  immediatePeer: string | null;
  forwardedClientIp: string | null;
  ipSource: IpSourceType;
  forwardedChain: string | null;
}

/**
 * Resolves the client IP safely considering X-Forwarded-For or Client-IP headers.
 * XFF header is only trusted if the immediate peer is a verified trusted proxy / WAF.
 */
export function resolveClientIp(
  peerIp: string | null | undefined,
  forwardedHeader: string | null | undefined,
  trustedProxies: string[] = DEFAULT_TRUSTED_PROXIES
): ClientIpResolution {
  const cleanPeer = peerIp && peerIp !== '-' && peerIp.trim() !== '' ? peerIp.trim() : null;

  if (!forwardedHeader || forwardedHeader === '-' || forwardedHeader.trim() === '') {
    return {
      clientIp: cleanPeer,
      immediatePeer: cleanPeer,
      forwardedClientIp: null,
      ipSource: 'direct-peer',
      forwardedChain: null,
    };
  }

  // Clean and parse forwarded chain (comma separated IPs)
  const chain = forwardedHeader
    .split(',')
    .map(ip => ip.trim())
    .filter(ip => ip && ip !== '-');

  const firstForwardedIp = chain[0] || null;

  if (!firstForwardedIp) {
    return {
      clientIp: cleanPeer,
      immediatePeer: cleanPeer,
      forwardedClientIp: null,
      ipSource: 'direct-peer',
      forwardedChain: forwardedHeader.trim(),
    };
  }

  const peerIsTrusted = isTrustedProxy(cleanPeer, trustedProxies);

  if (peerIsTrusted) {
    return {
      clientIp: firstForwardedIp,
      immediatePeer: cleanPeer,
      forwardedClientIp: firstForwardedIp,
      ipSource: 'trusted-proxy-forwarded',
      forwardedChain: forwardedHeader.trim(),
    };
  } else {
    // Untrusted immediate peer sent a forwarded header -> potential spoofing attempt!
    return {
      clientIp: cleanPeer,
      immediatePeer: cleanPeer,
      forwardedClientIp: firstForwardedIp,
      ipSource: 'untrusted-spoofed-ignored',
      forwardedChain: forwardedHeader.trim(),
    };
  }
}
