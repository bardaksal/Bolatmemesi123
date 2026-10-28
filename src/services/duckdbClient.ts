/**
 * DuckDB-Wasm Client Service for Client-Side Log Hunting
 *
 * Privacy & Security:
 * - Runs 100% locally inside the browser's WebAssembly container.
 * - ZERO customer data is transmitted to external servers, backend, or Gemini.
 * - Strictly isolated from existing SOC engine and correlation logic.
 * - If DuckDB fails to instantiate or load, the main application remains 100% functional.
 */

import * as duckdb from '@duckdb/duckdb-wasm';
import * as arrow from 'apache-arrow';
import { NormalizedLog } from '../types';

export interface DuckDBStatus {
  isInitialized: boolean;
  isLoading: boolean;
  error: string | null;
  totalRows: number;
  tableName: string;
}

export interface QueryResult {
  columns: string[];
  rows: Array<Record<string, unknown>>;
  rowCount: number;
  durationMs: number;
  truncated: boolean;
}

class DuckDbClientService {
  private db: duckdb.AsyncDuckDB | null = null;
  private conn: duckdb.AsyncDuckDBConnection | null = null;
  private isInitializing = false;
  private initPromise: Promise<boolean> | null = null;
  private status: DuckDBStatus = {
    isInitialized: false,
    isLoading: false,
    error: null,
    totalRows: 0,
    tableName: 'logs',
  };

  public getStatus(): DuckDBStatus {
    return { ...this.status };
  }

  /**
   * Initializes the DuckDB-Wasm instance.
   * Safe to call multiple times (memoized promise).
   */
  public async initialize(): Promise<boolean> {
    if (this.db && this.conn) {
      return true;
    }
    if (this.isInitializing && this.initPromise) {
      return this.initPromise;
    }

    this.isInitializing = true;
    this.status.isLoading = true;
    this.status.error = null;

    this.initPromise = (async () => {
      try {
        // Select official bundles via jsdelivr or bundled paths
        const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
        const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);

        const worker = await duckdb.createWorker(bundle.mainWorker!);
        const logger = new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING);
        const db = new duckdb.AsyncDuckDB(logger, worker);

        await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
        await db.open({
          query: {
            castBigIntToDouble: true,
          },
        });

        const conn = await db.connect();

        this.db = db;
        this.conn = conn;
        this.status.isInitialized = true;
        this.status.isLoading = false;
        this.status.error = null;

        await this.createSchema();
        return true;
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.warn('[DuckDB-Wasm] Initialization failed (graceful fallback):', errorMsg);
        this.status.isInitialized = false;
        this.status.isLoading = false;
        this.status.error = `DuckDB başlatılamadı: ${errorMsg}`;
        return false;
      } finally {
        this.isInitializing = false;
      }
    })();

    return this.initPromise;
  }

  /**
   * Creates the initial forensic log table schema.
   */
  private async createSchema(): Promise<void> {
    if (!this.conn) return;

    await this.conn.query(`
      CREATE TABLE IF NOT EXISTS logs (
        row_id INTEGER,
        kaynak_dosya VARCHAR,
        tarih VARCHAR,
        c_ip VARCHAR,
        hedef_ip VARCHAR,
        hedef_port INTEGER,
        kaynak_port INTEGER,
        sunucu_ismi VARCHAR,
        islem_komutu VARCHAR,
        http_method VARCHAR,
        user_agent VARCHAR,
        sc_bytes BIGINT,
        cs_bytes BIGINT,
        sc_status INTEGER,
        baglanti_karari VARCHAR,
        cs_username VARCHAR,
        referer VARCHAR,
        response_time_ms INTEGER,
        session_cookie VARCHAR
      );
    `);
  }

  /**
   * Batch loads normalized logs into DuckDB using Apache Arrow columnar vectors.
   * Excludes heavy unbounded fields (raw_text, details) to prevent browser memory spikes.
   */
  public async loadLogs(logs: NormalizedLog[]): Promise<number> {
    const initialized = await this.initialize();
    if (!initialized || !this.conn) {
      throw new Error(this.status.error || 'DuckDB bağlantısı aktif değil');
    }

    try {
      this.status.isLoading = true;

      // Reset logs table
      await this.conn.query(`DROP TABLE IF EXISTS logs;`);

      if (logs.length === 0) {
        await this.createSchema();
        this.status.totalRows = 0;
        this.status.isLoading = false;
        return 0;
      }

      // Build columnar Arrow Table in chunks to avoid single massive allocation
      const CHUNK_SIZE = 50000;
      for (let offset = 0; offset < logs.length; offset += CHUNK_SIZE) {
        const chunk = logs.slice(offset, offset + CHUNK_SIZE);
        const count = chunk.length;

        const rowIds: number[] = new Array(count);
        const kaynakDosyalar: (string | null)[] = new Array(count);
        const tarihler: (string | null)[] = new Array(count);
        const cIps: (string | null)[] = new Array(count);
        const hedefIps: (string | null)[] = new Array(count);
        const hedefPortlar: (number | null)[] = new Array(count);
        const kaynakPortlar: (number | null)[] = new Array(count);
        const sunucuIsimleri: (string | null)[] = new Array(count);
        const islemKomutlari: (string | null)[] = new Array(count);
        const httpMethods: (string | null)[] = new Array(count);
        const userAgents: (string | null)[] = new Array(count);
        const scBytes: (number | null)[] = new Array(count);
        const csBytes: (number | null)[] = new Array(count);
        const scStatuses: (number | null)[] = new Array(count);
        const baglantiKararlari: (string | null)[] = new Array(count);
        const csUsernames: (string | null)[] = new Array(count);
        const referers: (string | null)[] = new Array(count);
        const responseTimes: (number | null)[] = new Array(count);
        const sessionCookies: (string | null)[] = new Array(count);

        for (let i = 0; i < count; i++) {
          const l = chunk[i];
          rowIds[i] = offset + i + 1;
          kaynakDosyalar[i] = l.kaynak_dosya || null;
          tarihler[i] = l.tarih || null;
          cIps[i] = l.ip_adresi || null;
          hedefIps[i] = l.hedef_ip || null;
          hedefPortlar[i] = l.hedef_port != null ? l.hedef_port : null;
          kaynakPortlar[i] = l.kaynak_port != null ? l.kaynak_port : null;
          sunucuIsimleri[i] = l.sunucu_ismi || null;
          islemKomutlari[i] = l.islem_komutu || null;
          httpMethods[i] = l.http_method || null;
          userAgents[i] = l.user_agent ? l.user_agent.substring(0, 500) : null;
          scBytes[i] = l.byte_degeri != null ? l.byte_degeri : null;
          csBytes[i] = l.istemci_byte != null ? l.istemci_byte : null;
          scStatuses[i] = l.status_code != null ? l.status_code : null;
          baglantiKararlari[i] = l.baglanti_karari || null;
          csUsernames[i] = l.kullanici_adi || null;
          referers[i] = l.referer ? l.referer.substring(0, 500) : null;
          responseTimes[i] = l.response_time_ms != null ? l.response_time_ms : null;
          sessionCookies[i] = l.session_cookie ? l.session_cookie.substring(0, 200) : null;
        }

        const arrowTable = arrow.tableFromArrays({
          row_id: arrow.vectorFromArray(rowIds, new arrow.Int32()),
          kaynak_dosya: arrow.vectorFromArray(kaynakDosyalar, new arrow.Utf8()),
          tarih: arrow.vectorFromArray(tarihler, new arrow.Utf8()),
          c_ip: arrow.vectorFromArray(cIps, new arrow.Utf8()),
          hedef_ip: arrow.vectorFromArray(hedefIps, new arrow.Utf8()),
          hedef_port: arrow.vectorFromArray(hedefPortlar, new arrow.Int32()),
          kaynak_port: arrow.vectorFromArray(kaynakPortlar, new arrow.Int32()),
          sunucu_ismi: arrow.vectorFromArray(sunucuIsimleri, new arrow.Utf8()),
          islem_komutu: arrow.vectorFromArray(islemKomutlari, new arrow.Utf8()),
          http_method: arrow.vectorFromArray(httpMethods, new arrow.Utf8()),
          user_agent: arrow.vectorFromArray(userAgents, new arrow.Utf8()),
          sc_bytes: arrow.vectorFromArray(scBytes, new arrow.Float64()),
          cs_bytes: arrow.vectorFromArray(csBytes, new arrow.Float64()),
          sc_status: arrow.vectorFromArray(scStatuses, new arrow.Int32()),
          baglanti_karari: arrow.vectorFromArray(baglantiKararlari, new arrow.Utf8()),
          cs_username: arrow.vectorFromArray(csUsernames, new arrow.Utf8()),
          referer: arrow.vectorFromArray(referers, new arrow.Utf8()),
          response_time_ms: arrow.vectorFromArray(responseTimes, new arrow.Int32()),
          session_cookie: arrow.vectorFromArray(sessionCookies, new arrow.Utf8()),
        } as Record<string, any>);

        const ipcStream = arrow.tableToIPC(arrowTable, 'stream');
        await this.conn.insertArrowFromIPCStream(ipcStream, { name: 'logs', create: offset === 0 });
      }

      this.status.totalRows = logs.length;
      this.status.isLoading = false;
      return logs.length;
    } catch (err: unknown) {
      this.status.isLoading = false;
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.status.error = `Loglar DuckDB'ye yüklenirken hata: ${errorMsg}`;
      throw err;
    }
  }

  /**
   * Strips SQL comments (-- line comments and /* block comments * /) safely
   * while respecting literal string boundaries ('...' and "...").
   */
  public static stripSqlComments(sql: string): string {
    let inSingle = false;
    let inDouble = false;
    let inLineComment = false;
    let inBlockComment = false;
    let result = '';

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const nextChar = sql[i + 1];

      if (inLineComment) {
        if (char === '\n' || char === '\r') {
          inLineComment = false;
          result += ' ';
        }
        continue;
      }

      if (inBlockComment) {
        if (char === '*' && nextChar === '/') {
          inBlockComment = false;
          i++; // Skip '/'
          result += ' ';
        }
        continue;
      }

      if (inSingle) {
        result += char;
        if (char === '\'') {
          if (nextChar === '\'') {
            result += nextChar;
            i++;
          } else {
            inSingle = false;
          }
        }
        continue;
      }

      if (inDouble) {
        result += char;
        if (char === '"') {
          if (nextChar === '"') {
            result += nextChar;
            i++;
          } else {
            inDouble = false;
          }
        }
        continue;
      }

      if (char === '-' && nextChar === '-') {
        inLineComment = true;
        i++; // Skip second '-'
        continue;
      }

      if (char === '/' && nextChar === '*') {
        inBlockComment = true;
        i++; // Skip '*'
        continue;
      }

      if (char === '\'') {
        inSingle = true;
        result += char;
        continue;
      }

      if (char === '"') {
        inDouble = true;
        result += char;
        continue;
      }

      result += char;
    }

    return result;
  }

  /**
   * Replaces string literal contents ('...' and "...") with placeholder empty strings
   * so keywords and semicolons inside string literals are not falsely flagged.
   */
  public static stripStringLiterals(sql: string): string {
    let inSingle = false;
    let inDouble = false;
    let result = '';

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const nextChar = sql[i + 1];

      if (inSingle) {
        if (char === '\'') {
          if (nextChar === '\'') {
            i++; // skip escaped quote ''
          } else {
            inSingle = false;
          }
        }
        continue;
      }

      if (inDouble) {
        if (char === '"') {
          if (nextChar === '"') {
            i++; // skip escaped quote ""
          } else {
            inDouble = false;
          }
        }
        continue;
      }

      if (char === '\'') {
        inSingle = true;
        result += " '' ";
        continue;
      }

      if (char === '"') {
        inDouble = true;
        result += ' "" ';
        continue;
      }

      result += char;
    }

    return result;
  }

  /**
   * Splits SQL text into statements by semicolon, ignoring semicolons inside string literals.
   */
  public static splitStatements(sql: string): string[] {
    const cleanSql = DuckDbClientService.stripSqlComments(sql);
    const statements: string[] = [];
    let current = '';
    let inSingle = false;
    let inDouble = false;

    for (let i = 0; i < cleanSql.length; i++) {
      const char = cleanSql[i];
      const nextChar = cleanSql[i + 1];

      if (inSingle) {
        current += char;
        if (char === '\'') {
          if (nextChar === '\'') {
            current += nextChar;
            i++;
          } else {
            inSingle = false;
          }
        }
        continue;
      }

      if (inDouble) {
        current += char;
        if (char === '"') {
          if (nextChar === '"') {
            current += nextChar;
            i++;
          } else {
            inDouble = false;
          }
        }
        continue;
      }

      if (char === '\'') {
        inSingle = true;
        current += char;
        continue;
      }

      if (char === '"') {
        inDouble = true;
        current += char;
        continue;
      }

      if (char === ';') {
        const trimmed = current.trim();
        if (trimmed) statements.push(trimmed);
        current = '';
        continue;
      }

      current += char;
    }

    const finalTrimmed = current.trim();
    if (finalTrimmed) statements.push(finalTrimmed);
    return statements;
  }

  /**
   * Validates if the query contains only safe Read-Only SQL statements.
   * Strictly allows ONLY: SELECT, WITH, DESCRIBE, SHOW, EXPLAIN.
   * PRAGMA is explicitly DISALLOWED.
   * Multiple statements (semicolon chained) and modifying statements (DROP, DELETE, UPDATE, INSERT, ALTER, CREATE, COPY, etc.) are strictly forbidden.
   */
  public static validateReadOnlySql(sql: string): { valid: boolean; reason?: string; sanitizedSingleStatement?: string } {
    const trimmed = sql.trim();
    if (!trimmed) {
      return { valid: false, reason: 'Sorgu boş olamaz.' };
    }

    // First check: Disallow mutating keywords anywhere outside of string literals
    // (even inside comment blocks like /*!50000 DROP TABLE*/ or -- DROP TABLE)
    const rawWithoutLiterals = DuckDbClientService.stripStringLiterals(trimmed);
    const disallowedKeywords = /\b(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|COPY|TRUNCATE|REPLACE|GRANT|REVOKE|ATTACH|DETACH|VACUUM|CALL|PRAGMA|EXEC|EXECUTE)\b/i;
    if (disallowedKeywords.test(rawWithoutLiterals)) {
      return {
        valid: false,
        reason: 'Güvenlik Kısıtı: Değiştirici veya izin verilmeyen SQL ifadeleri (DROP, DELETE, UPDATE, INSERT, ALTER, CREATE, COPY, PRAGMA vb.) çalıştırılamaz.',
      };
    }

    // Second check: Parse statements after stripping standard SQL comments
    const statements = DuckDbClientService.splitStatements(trimmed);
    if (statements.length === 0) {
      return { valid: false, reason: 'Geçerli bir SQL ifadesi bulunamadı.' };
    }

    if (statements.length > 1) {
      return {
        valid: false,
        reason: 'Güvenlik Kısıtı: Çoklu SQL statement (zincirleme noktalı virgül) çalıştırılmasına izin verilmemektedir. Lütfen tek bir sorgu çalıştırın.',
      };
    }

    const singleStmt = statements[0];

    // Must strictly start with SELECT, WITH, DESCRIBE, SHOW, or EXPLAIN
    const isSafeLeading = /^(SELECT|WITH|DESCRIBE|SHOW|EXPLAIN)\b/i.test(singleStmt);
    if (!isSafeLeading) {
      return {
        valid: false,
        reason: 'Güvenlik Kısıtı: Yalnızca SELECT, WITH, DESCRIBE, SHOW ve EXPLAIN sorgularına izin verilmektedir.',
      };
    }

    return { valid: true, sanitizedSingleStatement: singleStmt };
  }

  /**
   * Executes a safe Read-Only SQL query.
   * Limits output to prevent browser DOM freezing.
   */
  public async query(sql: string, maxRows = 500): Promise<QueryResult> {
    if (!this.conn) {
      const initialized = await this.initialize();
      if (!initialized || !this.conn) {
        throw new Error(this.status.error || 'DuckDB bağlantısı aktif değil.');
      }
    }

    // Safety validation: only read-only statements allowed
    const validation = DuckDbClientService.validateReadOnlySql(sql);
    if (!validation.valid || !validation.sanitizedSingleStatement) {
      throw new Error(validation.reason || 'Güvenlik Kısıtı: İzin verilmeyen SQL ifadesi.');
    }

    const queryToExecute = validation.sanitizedSingleStatement;

    const start = performance.now();
    const resultTable = await this.conn.query(queryToExecute);
    const durationMs = Math.round(performance.now() - start);

    const schema = resultTable.schema;
    const columns = schema.fields.map(f => f.name);
    const totalCount = resultTable.numRows;

    const rowsToTake = Math.min(totalCount, maxRows);
    const rows: Array<Record<string, unknown>> = new Array(rowsToTake);

    for (let r = 0; r < rowsToTake; r++) {
      const rowObj: Record<string, unknown> = {};
      const row = resultTable.get(r);
      if (row) {
        for (const col of columns) {
          let val = row[col];
          if (typeof val === 'bigint') {
            val = Number(val);
          }
          rowObj[col] = val !== undefined ? val : null;
        }
      }
      rows[r] = rowObj;
    }

    return {
      columns,
      rows,
      rowCount: totalCount,
      durationMs,
      truncated: totalCount > maxRows,
    };
  }

  /**
   * Cleans up the DuckDB database.
   */
  public async clear(): Promise<void> {
    if (this.conn) {
      try {
        await this.conn.query(`DROP TABLE IF EXISTS logs;`);
        await this.createSchema();
        this.status.totalRows = 0;
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  public async reset(): Promise<void> {
    return this.clear();
  }

  /**
   * Closes connections and terminates worker.
   */
  public async close(): Promise<void> {
    try {
      if (this.conn) {
        await this.conn.close();
        this.conn = null;
      }
      if (this.db) {
        await this.db.terminate();
        this.db = null;
      }
      this.status.isInitialized = false;
      this.status.totalRows = 0;
    } catch {
      // Ignore termination errors
    }
  }
}

export { DuckDbClientService };
export const duckdbClient = new DuckDbClientService();
