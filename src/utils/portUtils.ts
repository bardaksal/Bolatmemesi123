export interface PortRange {
  start: number;
  end: number;
  count: number;
}

export const COMMON_PORT_SERVICES: Record<number, string> = {
  20: 'FTP Data',
  21: 'FTP Control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP Server',
  68: 'DHCP Client',
  69: 'TFTP',
  80: 'HTTP',
  88: 'Kerberos',
  110: 'POP3',
  123: 'NTP',
  135: 'MS RPC',
  137: 'NetBIOS Name',
  138: 'NetBIOS Datagram',
  139: 'NetBIOS Session',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  500: 'IPSec ISAKMP',
  514: 'Syslog',
  587: 'SMTP Submission',
  636: 'LDAPS',
  873: 'Rsync',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MS SQL Server',
  1521: 'Oracle DB',
  2049: 'NFS',
  3306: 'MySQL',
  3389: 'RDP (Remote Desktop)',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  7000: 'AFS / Storage',
  7002: 'WebLogic Admin',
  8000: 'HTTP Alt / Dev',
  8001: 'HTTP Alt',
  8002: 'HTTP Alt',
  8080: 'HTTP Proxy / Tomcat',
  8443: 'HTTPS Alt',
  8511: 'App Service',
  8512: 'App Service',
  8890: 'SPARQL / Custom',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
};

export function getPortServiceName(port: number): string {
  if (COMMON_PORT_SERVICES[port]) {
    return COMMON_PORT_SERVICES[port];
  }
  if (port >= 50000 && port <= 60000) {
    return 'FTP (Passive Data)';
  }
  if (port >= 49152 && port <= 65535) {
    return 'Dinamik / Ephemeral';
  }
  return 'Diğer / Özel';
}

/**
 * Extracts, deduplicates, and numerically sorts ports from a comma or space-separated string.
 */
export function parseAndSortPorts(portStr: string | null | undefined): number[] {
  if (!portStr || portStr.trim() === '-' || portStr.trim() === '') return [];
  const parts = portStr.split(/[,\s|;]+/);
  const portSet = new Set<number>();

  for (const part of parts) {
    const clean = part.trim();
    if (!clean) continue;
    const n = parseInt(clean, 10);
    if (!isNaN(n) && n > 0 && n <= 65535) {
      portSet.add(n);
    }
  }

  return Array.from(portSet).sort((a, b) => a - b);
}

/**
 * Detects consecutive port ranges (e.g. 2730-2750 [21 ports]) to quickly identify
 * port scans, contiguous sweeps, or FTP passive data port pools.
 */
export function detectPortRanges(sortedPorts: number[]): {
  ranges: PortRange[];
  isolated: number[];
} {
  const ranges: PortRange[] = [];
  const isolated: number[] = [];

  if (sortedPorts.length === 0) return { ranges, isolated };

  let rangeStart = sortedPorts[0];
  let prev = sortedPorts[0];
  let count = 1;

  for (let i = 1; i < sortedPorts.length; i++) {
    const cur = sortedPorts[i];
    if (cur === prev + 1) {
      prev = cur;
      count++;
    } else {
      // If 4 or more consecutive ports, consider it a range
      if (count >= 4) {
        ranges.push({ start: rangeStart, end: prev, count });
      } else {
        for (let p = rangeStart; p <= prev; p++) {
          isolated.push(p);
        }
      }
      rangeStart = cur;
      prev = cur;
      count = 1;
    }
  }

  if (count >= 4) {
    ranges.push({ start: rangeStart, end: prev, count });
  } else {
    for (let p = rangeStart; p <= prev; p++) {
      isolated.push(p);
    }
  }

  return { ranges, isolated };
}
