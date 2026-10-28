export const KNOWN_ATTACK_TOOLS = [
  'sqlmap',
  'nikto',
  'nmap',
  'masscan',
  'acunetix',
  'dirbuster',
  'gobuster',
  'hydra',
  'wfuzz',
  'zgrab',
  'shodan',
  'censys',
  'burpcollaborator',
  'metasploit',
  'nuclei',
];

export const SENSITIVE_PATHS = [
  '/filemanagement',
  'web.config',
  'appsettings',
  '/.env',
  '/admin',
  '/swagger',
  '/actuator',
  '/backup',
  '/debug',
  'c:\\inetpub',
  'cmd.exe',
  'powershell',
  '/etc/passwd',
  '../',
  '..\\',
];

export interface ClassifiedIP {
  ip: string;
  kategori: string;
  is_private: boolean;
  is_public: boolean;
  is_loopback: boolean;
  risk_faktoru: number;
  aciklama: string;
}

export function classifyIP(ipStr: string | null | undefined): ClassifiedIP {
  if (!ipStr || ipStr === '-' || ipStr === 'null' || ipStr.trim() === '') {
    return {
      ip: ipStr || '-',
      kategori: 'Bilinmiyor',
      is_private: false,
      is_public: false,
      is_loopback: false,
      risk_faktoru: 0,
      aciklama: 'Geçersiz veya boş IP',
    };
  }

  const cleanIp = ipStr.trim();

  // Loopback
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp.startsWith('127.')) {
    return {
      ip: cleanIp,
      kategori: 'Loopback (Yerel)',
      is_private: true,
      is_public: false,
      is_loopback: true,
      risk_faktoru: 0,
      aciklama: 'Sunucu içi geri dönüş (127.0.0.1 / ::1)',
    };
  }

  // IPv4 Private check (RFC 1918)
  const parts = cleanIp.split('.').map(p => parseInt(p, 10));
  if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    // 10.0.0.0/8
    if (parts[0] === 10) {
      return {
        ip: cleanIp,
        kategori: 'Özel / Dahili Ağ (RFC 1918)',
        is_private: true,
        is_public: false,
        is_loopback: false,
        risk_faktoru: 10,
        aciklama: 'Kurumsal iç ağ veya VPN IP adresi (10.x.x.x)',
      };
    }
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return {
        ip: cleanIp,
        kategori: 'Özel / Dahili Ağ (RFC 1918)',
        is_private: true,
        is_public: false,
        is_loopback: false,
        risk_faktoru: 10,
        aciklama: 'Kurumsal iç ağ veya Docker/K8s IP adresi (172.16-31.x.x)',
      };
    }
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) {
      return {
        ip: cleanIp,
        kategori: 'Özel / Dahili Ağ (RFC 1918)',
        is_private: true,
        is_public: false,
        is_loopback: false,
        risk_faktoru: 10,
        aciklama: 'Kurumsal iç ağ veya yerel kullanıcı ağı (192.168.x.x)',
      };
    }
    // 169.254.0.0/16 (Link Local)
    if (parts[0] === 169 && parts[1] === 254) {
      return {
        ip: cleanIp,
        kategori: 'Ayrılmış / Link-Local',
        is_private: true,
        is_public: false,
        is_loopback: false,
        risk_faktoru: 5,
        aciklama: 'APIPA Link-Local adresi (169.254.x.x)',
      };
    }

    // Public Internet IP
    let risk = 35;
    let desc = 'Genel internet adresi';
    // Known threat simulator IP prefixes
    if (cleanIp.startsWith('185.220.') || cleanIp.startsWith('194.26.')) {
      risk = 90;
      desc = 'Bilinen Tor Exit Node / Saldırgan Barındırma Ağı';
    } else if (cleanIp.startsWith('45.154.') || cleanIp.startsWith('89.248.')) {
      risk = 85;
      desc = 'Şüpheli VPS / Brute-Force Botnet İmzası';
    }

    return {
      ip: cleanIp,
      kategori: 'Kamusal Ağ (Public Internet)',
      is_private: false,
      is_public: true,
      is_loopback: false,
      risk_faktoru: risk,
      aciklama: desc,
    };
  }

  return {
    ip: cleanIp,
    kategori: 'Diğer / IPv6',
    is_private: false,
    is_public: true,
    is_loopback: false,
    risk_faktoru: 25,
    aciklama: 'Genel ağ adresi',
  };
}
