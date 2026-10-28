export interface SampleLogFile {
  name: string;
  type: 'w3c_iis' | 'checkpoint_firewall' | 'ftp' | 'csv';
  content: string;
}

export const SAMPLE_LOGS: SampleLogFile[] = [
  {
    name: 'u_ex260909_iis.log',
    type: 'w3c_iis',
    content: `#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-09-09 08:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken s-sitename s-computername
2026-09-09 08:14:12 10.0.0.5 GET /default.aspx - 443 - 185.220.101.5 Mozilla/5.0 - 200 0 0 4520 840 25 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:14:14 10.0.0.5 GET /admin - 443 - 185.220.101.5 Mozilla/5.0 - 404 0 0 1200 450 15 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:14:15 10.0.0.5 GET /.env - 443 - 185.220.101.5 Mozilla/5.0 - 404 0 0 1200 430 14 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:14:16 10.0.0.5 GET /web.config - 443 - 185.220.101.5 Mozilla/5.0 - 404 0 0 1200 440 12 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:14:20 10.0.0.5 GET /swagger - 443 - 185.220.101.5 Mozilla/5.0 - 403 0 0 1800 480 30 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:15:01 10.0.0.5 POST /api/login user=admin 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 920 45 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:15:04 10.0.0.5 POST /api/login user=root 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 910 42 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:15:08 10.0.0.5 POST /api/login user=sysadmin 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 930 40 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:15:12 10.0.0.5 POST /api/login user=test 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 900 38 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:15:16 10.0.0.5 POST /api/login user=support 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 915 39 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:20:00 10.0.0.5 GET /api/health - 443 - 10.54.206.10 HealthProbe/1.0 - 200 0 0 450 150 5 W3SVC1 SRV-PROD-WEB01
2026-09-09 08:25:00 10.0.0.5 GET /api/health - 443 - 10.54.206.10 HealthProbe/1.0 - 200 0 0 450 150 5 W3SVC1 SRV-PROD-WEB01
`,
  },
  {
    name: 'u_ex260910_iis.log',
    type: 'w3c_iis',
    content: `#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-09-10 09:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken s-sitename s-computername
2026-09-10 09:12:00 10.0.0.5 POST /api/login user=operator 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 910 40 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:12:05 10.0.0.5 POST /api/login user=manager 443 - 194.26.29.112 Mozilla/5.0 - 401 0 0 650 920 41 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:12:10 10.0.0.5 POST /api/login user=admin_sys 443 - 194.26.29.112 Mozilla/5.0 - 200 0 0 1540 980 65 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:15:30 10.0.0.5 GET /filemanagement browse=c:\\inetpub\\wwwroot 443 admin_sys 194.26.29.112 Mozilla/5.0 - 200 0 0 35400 620 120 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:16:12 10.0.0.5 GET /filemanagement download=web.config 443 admin_sys 194.26.29.112 Mozilla/5.0 - 200 0 0 8420 540 85 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:17:45 10.0.0.5 POST /filemanagement upload=cmd.aspx 443 admin_sys 194.26.29.112 Mozilla/5.0 - 200 0 0 1240 185400 450 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:18:20 10.0.0.5 GET /cmd.aspx cmd=whoami 443 - 194.26.29.112 Mozilla/5.0 - 200 0 0 1420 560 75 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:18:50 10.0.0.5 GET /cmd.aspx cmd=net+user 443 - 194.26.29.112 Mozilla/5.0 - 200 0 0 3240 580 82 W3SVC1 SRV-PROD-WEB01
2026-09-10 09:22:15 10.0.0.5 GET /export/db_backup.zip - 443 admin_sys 194.26.29.112 Mozilla/5.0 - 200 0 0 854000000 650 18450 W3SVC1 SRV-PROD-WEB01
2026-09-10 11:00:10 10.0.0.5 GET /search q=1'+union+select+1,2,password+from+users-- 443 - 185.220.101.5 sqlmap/1.6 - 500 0 0 4500 890 320 W3SVC1 SRV-PROD-WEB01
2026-09-10 11:00:15 10.0.0.5 GET /search q=1'+union+select+null,username,password+from+admin-- 443 - 185.220.101.5 sqlmap/1.6 - 500 0 0 4500 910 310 W3SVC1 SRV-PROD-WEB01
2026-09-10 14:00:00 10.0.0.5 GET /storage/customer_archive.tar.gz - 443 d_transfer 88.255.210.45 Python-urllib/3.9 - 200 0 0 820000000 450 14200 W3SVC1 SRV-BACKUP-NODE
`,
  },
  {
    name: 'checkpoint_firewall_events.csv',
    type: 'checkpoint_firewall',
    content: `firewall_event,sunucu_ismi,rule_id,tarih_raw,firewall_action,ip_adresi,kaynak_port,hedef_ip,hedef_port,user_agent,byte_degeri
Firewall,FW-EDGE-01,104,2026-09-10 08:30:12,Drop,45.154.255.89,45120,10.0.0.8,22,-,0
Firewall,FW-EDGE-01,104,2026-09-10 08:30:14,Drop,45.154.255.89,45122,10.0.0.8,22,-,0
Firewall,FW-EDGE-01,104,2026-09-10 08:30:16,Drop,45.154.255.89,45124,10.0.0.8,3389,-,0
Firewall,FW-EDGE-01,104,2026-09-10 08:30:18,Drop,45.154.255.89,45126,10.0.0.8,445,-,0
Firewall,FW-EDGE-01,101,2026-09-10 09:00:00,Accept,194.26.29.112,51230,10.0.0.5,443,Mozilla/5.0,854000000
Firewall,FW-EDGE-01,101,2026-09-10 09:10:00,Accept,88.255.210.45,53210,10.0.0.5,443,Python-urllib/3.9,820000000
Firewall,FW-EDGE-01,102,2026-09-10 10:15:00,Accept,45.154.255.89,49100,10.0.0.9,21,-,1500
Firewall,FW-EDGE-01,104,2026-09-10 10:20:00,Deny,185.220.101.5,58410,10.0.0.5,80,sqlmap/1.6,0
Firewall,FW-EDGE-01,104,2026-09-10 10:20:02,Deny,185.220.101.5,58412,10.0.0.5,80,sqlmap/1.6,0
Firewall,FW-EDGE-01,101,2026-09-10 12:00:00,Accept,10.54.206.10,61200,10.0.0.5,443,HealthProbe/1.0,450
`,
  },
  {
    name: 'u_msftpsvc_20260910.log',
    type: 'ftp',
    content: `#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-09-10 10:00:00
#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-win32-status sc-bytes cs-bytes time-taken s-sitename s-computername cs-username s-ip s-port
2026-09-10 10:12:00 45.154.255.89 USER administrator 331 0 0 0 10 MSFTPSVC1 SRV-FTP01 - 10.0.0.9 21
2026-09-10 10:12:01 45.154.255.89 PASS *** 530 1326 0 0 15 MSFTPSVC1 SRV-FTP01 administrator 10.0.0.9 21
2026-09-10 10:12:05 45.154.255.89 USER backup 331 0 0 0 10 MSFTPSVC1 SRV-FTP01 - 10.0.0.9 21
2026-09-10 10:12:06 45.154.255.89 PASS *** 530 1326 0 0 12 MSFTPSVC1 SRV-FTP01 backup 10.0.0.9 21
2026-09-10 10:12:10 45.154.255.89 USER ftpuser 331 0 0 0 10 MSFTPSVC1 SRV-FTP01 - 10.0.0.9 21
2026-09-10 10:12:11 45.154.255.89 PASS *** 230 0 0 0 20 MSFTPSVC1 SRV-FTP01 ftpuser 10.0.0.9 21
2026-09-10 10:12:15 45.154.255.89 STOR /pub/exploit_payload.asp 226 0 0 45200 120 MSFTPSVC1 SRV-FTP01 ftpuser 10.0.0.9 21
2026-09-10 10:12:20 45.154.255.89 RETR /pub/private_keys.key 226 0 12500 0 85 MSFTPSVC1 SRV-FTP01 ftpuser 10.0.0.9 21
`,
  },
];
