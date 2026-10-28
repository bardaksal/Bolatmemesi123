/**
 * Comprehensive Security Test Suite for DuckDB Read-Only SQL Hunting
 * 
 * Verifies:
 * 1. Allowed Read-Only commands: SELECT, WITH, DESCRIBE, SHOW, EXPLAIN
 * 2. Explicit disallowance of PRAGMA
 * 3. Prevention of semicolon-chained multi-statements (e.g., SELECT 1; DROP TABLE logs;)
 * 4. Prevention of comment-based bypasses (-- and /* ... * / with DROP/DELETE/INSERT/etc.)
 * 5. Strict rejection of mutating statements: DROP, DELETE, UPDATE, INSERT, ALTER, CREATE, COPY, TRUNCATE, etc.
 * 6. Edge cases: comments inside string literals, semicolons inside strings.
 */

import { DuckDbClientService } from '../services/duckdbClient';

console.log('===============================================================');
console.log('DUCKDB READ-ONLY SQL GÜVENLİK VE BYPASS DOĞRULAMA TESTLERİ');
console.log('===============================================================');

let passCount = 0;
let failCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passCount++;
  } else {
    console.error(`[FAIL] ${testName} -> ${detail || 'Koşul sağlanamadı'}`);
    failCount++;
  }
}

// 1. İZİN VERİLEN READ-ONLY SORGULARI
console.log('\n--- BÖLÜM 1: İzin Verilen Read-Only Komutlar ---');
const allowedCases = [
  { sql: 'SELECT * FROM logs LIMIT 10;', desc: 'Standart SELECT' },
  { sql: '  select c_ip, count(*) from logs group by c_ip;  ', desc: 'Küçük harf SELECT ve boşluklar' },
  { sql: 'WITH attack_ips AS (SELECT c_ip FROM logs WHERE sc_status = 403) SELECT * FROM attack_ips;', desc: 'WITH CTE sorgusu' },
  { sql: 'DESCRIBE logs;', desc: 'DESCRIBE logs tablosu' },
  { sql: 'SHOW TABLES;', desc: 'SHOW TABLES sorgusu' },
  { sql: 'EXPLAIN SELECT * FROM logs WHERE sc_status = 200;', desc: 'EXPLAIN sorgusu' },
  { sql: '/* Yorum başı */ SELECT * FROM logs WHERE c_ip = "192.168.1.1";', desc: 'Yorum ile başlayan geçerli SELECT' },
  { sql: '-- Tek satır yorum\nSELECT row_id FROM logs;', desc: 'Tek satırlı yorumla başlayan geçerli SELECT' },
  { sql: "SELECT * FROM logs WHERE islem_komutu = '; DROP TABLE logs; ';", desc: 'String literal içinde noktalı virgül ve DROP içeren SELECT' },
  { sql: "SELECT * FROM logs WHERE user_agent = '/* comment */';", desc: 'String literal içinde yorum içeren SELECT' },
];

for (const tc of allowedCases) {
  const res = DuckDbClientService.validateReadOnlySql(tc.sql);
  assert(res.valid === true, `${tc.desc}: "${tc.sql.replace(/\n/g, ' ')}" -> İzin verildi.`);
}

// 2. PRAGMA KISITLAMASI
console.log('\n--- BÖLÜM 2: PRAGMA İfadesinin Engellenmesi ---');
const pragmaCases = [
  'PRAGMA version;',
  'pragma database_list;',
  'PRAGMA table_info(logs);',
  'SELECT 1; PRAGMA version;',
  '/* bypass */ PRAGMA show_tables;',
];

for (const sql of pragmaCases) {
  const res = DuckDbClientService.validateReadOnlySql(sql);
  assert(res.valid === false, `PRAGMA engellendi: "${sql}"`, res.reason);
}

// 3. ÇOKLU STATEMENT (SEMICOLON CHAINED) BYPASS TESTLERİ
console.log('\n--- BÖLÜM 3: Çoklu Statement (Semicolon Chaining) Engellemesi ---');
const multiStatementCases = [
  'SELECT 1; DROP TABLE logs;',
  'SELECT * FROM logs; DELETE FROM logs;',
  'SELECT 1; SELECT 2;',
  'SELECT * FROM logs;\nDROP TABLE logs;',
  'WITH x AS (SELECT 1) SELECT * FROM x; TRUNCATE logs;',
  'DESCRIBE logs; ALTER TABLE logs DROP COLUMN c_ip;',
];

for (const sql of multiStatementCases) {
  const res = DuckDbClientService.validateReadOnlySql(sql);
  assert(res.valid === false, `Çoklu SQL statement engellendi: "${sql.replace(/\n/g, ' ')}"`, res.reason);
}

// 4. YORUMLARLA VE GİZLEME TEKNİKLERİYLE BYPASS TESTLERİ
console.log('\n--- BÖLÜM 4: Yorumlar ile Gizleme (Comment Bypasses) Engellemesi ---');
const commentBypassCases = [
  '/* comment */ DROP TABLE logs;',
  '-- comment\nDROP TABLE logs;',
  'SELECT 1; /* comment */ DROP TABLE logs;',
  'SELECT 1; -- line comment\nDROP TABLE logs;',
  'SELECT 1; /*!50000 DROP TABLE logs*/;',
  '/* leading */ DROP TABLE logs; /* trailing */',
  '-- comment\nDELETE FROM logs WHERE 1=1;',
  '/* nested */ /* comments */ UPDATE logs SET c_ip = "0.0.0.0";',
];

for (const sql of commentBypassCases) {
  const res = DuckDbClientService.validateReadOnlySql(sql);
  assert(res.valid === false, `Yorum gizlemesi engellendi: "${sql.replace(/\n/g, ' ')}"`, res.reason);
}

// 5. DEĞİŞTİRİCİ İŞLEMLERİN ENGELLENMESİ (DROP, DELETE, UPDATE, INSERT, ALTER, CREATE, COPY, vb.)
console.log('\n--- BÖLÜM 5: Değiştirici (Mutating/DDL/DML) SQL İfadelerinin Engellenmesi ---');
const mutatingCases = [
  { sql: 'DROP TABLE logs;', op: 'DROP' },
  { sql: 'DROP SCHEMA public CASCADE;', op: 'DROP SCHEMA' },
  { sql: 'DELETE FROM logs WHERE row_id = 1;', op: 'DELETE' },
  { sql: 'UPDATE logs SET c_ip = "1.2.3.4";', op: 'UPDATE' },
  { sql: 'INSERT INTO logs (row_id, c_ip) VALUES (999, "bad.ip");', op: 'INSERT' },
  { sql: 'ALTER TABLE logs ADD COLUMN injected INT;', op: 'ALTER' },
  { sql: 'CREATE TABLE backdoor (id INT);', op: 'CREATE' },
  { sql: 'COPY logs TO "dump.csv";', op: 'COPY' },
  { sql: 'COPY (SELECT * FROM logs) TO "/tmp/leak.parquet";', op: 'COPY (SELECT...)' },
  { sql: 'TRUNCATE logs;', op: 'TRUNCATE' },
  { sql: 'VACUUM;', op: 'VACUUM' },
  { sql: 'ATTACH "external.db";', op: 'ATTACH' },
  { sql: 'DETACH external;', op: 'DETACH' },
  { sql: 'CALL some_procedure();', op: 'CALL' },
  { sql: 'GRANT ALL PRIVILEGES ON logs TO public;', op: 'GRANT' },
  { sql: 'REVOKE ALL ON logs FROM public;', op: 'REVOKE' },
];

for (const tc of mutatingCases) {
  const res = DuckDbClientService.validateReadOnlySql(tc.sql);
  assert(res.valid === false, `${tc.op} işlemi engellendi: "${tc.sql}"`, res.reason);
}

// 6. GEÇERSİZ VE BOŞ GİRDİ TESTLERİ
console.log('\n--- BÖLÜM 6: Boş ve Geçersiz Girdi Davranışı ---');
const edgeCases = [
  { sql: '', desc: 'Tamamen boş string' },
  { sql: '   \n\t  ', desc: 'Sadece boşluklar' },
  { sql: '/* Sadece yorum */', desc: 'Sadece blok yorum' },
  { sql: '-- Sadece tek satır yorum', desc: 'Sadece satır yorumu' },
  { sql: ';', desc: 'Yalnızca noktalı virgül' },
  { sql: ';;;;', desc: 'Birden çok noktalı virgül' },
];

for (const tc of edgeCases) {
  const res = DuckDbClientService.validateReadOnlySql(tc.sql);
  assert(res.valid === false, `${tc.desc} reddedildi.`);
}

console.log('\n===============================================================');
console.log(`SONUÇ: ${passCount} PASSED, ${failCount} FAILED`);
console.log('===============================================================');

if (failCount > 0) {
  process.exit(1);
}
