import * as XLSX from 'xlsx';

/**
 * Checks if a given file name corresponds to an Excel spreadsheet (.xlsx, .xls, .xlsm, .xlsb)
 */
export function isExcelFile(fileName: string): boolean {
  if (!fileName) return false;
  const lower = fileName.toLowerCase().trim();
  return (
    lower.endsWith('.xlsx') ||
    lower.endsWith('.xls') ||
    lower.endsWith('.xlsm') ||
    lower.endsWith('.xlsb')
  );
}

export function cleanCell(val: unknown, isDateColumn = false): string {
  if (val === null || val === undefined) return '';

  if (val instanceof Date) {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`;
  }

  if (typeof val === 'number') {
    // If it's a numeric Excel serial date (e.g. 40000 - 60000) and column is date-related
    if (isDateColumn && val > 30000 && val < 70000) {
      try {
        const ms = (val - 25569) * 86400 * 1000;
        const d = new Date(ms);
        if (!isNaN(d.getTime())) {
          const pad = (n: number) => String(n).padStart(2, '0');
          return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
        }
      } catch {
        // fallback to standard number string
      }
    }
    return String(val);
  }

  let s = String(val).trim();
  // Strip BOM and invisible unicode zero-width spaces / non-breaking spaces
  s = s.replace(/[\uFEFF\u200B\u200C\u200D\u00A0]/g, ' ').trim();
  // Flatten multiline cell content into a single log record line
  s = s.replace(/[\r\n]+/g, ' ').replace(/\s{2,}/g, ' ');

  // Standard CSV escaping if comma, quotes or semicolons exist
  if (s.includes(',') || s.includes('"') || s.includes(';')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export interface ExcelInspectionResult {
  fileName: string;
  sheetNames: string[];
  primarySheet: string;
  totalRows: number;
  csvContent: string;
}

/**
 * Inspects and converts an Excel buffer to clean CSV text while preserving sheet metadata.
 */
export function inspectAndConvertExcel(buffer: ArrayBuffer | Uint8Array, fileName: string = 'dosya.xlsx'): ExcelInspectionResult {
  const csvContent = convertExcelBufferToCsv(buffer, fileName);
  let sheetNames: string[] = ['Sheet1'];
  let totalRows = 0;
  try {
    const workbook = XLSX.read(buffer, { type: 'array', sheetRows: 5 });
    sheetNames = workbook.SheetNames || ['Sheet1'];
    // count total rows roughly from csv
    totalRows = csvContent.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
  } catch {
    totalRows = csvContent.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
  }
  return {
    fileName,
    sheetNames,
    primarySheet: sheetNames[0] || 'Sheet1',
    totalRows,
    csvContent,
  };
}

/**
 * Converts an Excel binary buffer (ArrayBuffer or Uint8Array) to clean CSV text for log analysis.
 * Supports multiple sheets, metadata banners, multiline cell content, dates, and F5 / Security WAF log structures.
 */
export function convertExcelBufferToCsv(buffer: ArrayBuffer | Uint8Array, fileName?: string): string {
  try {
    const workbook = XLSX.read(buffer, {
      type: 'array',
      cellDates: true,
      dateNF: 'yyyy-mm-dd hh:mm:ss',
      raw: false,
    });

    const csvSheets: string[] = [];
    let globalPrimaryHeader: string | null = null;

    for (const sheetName of workbook.SheetNames) {
      const sheet = workbook.Sheets[sheetName];
      if (!sheet || !sheet['!ref']) continue;

      // Extract rows as an array of cell values
      const rawRows = XLSX.utils.sheet_to_json(sheet, {
        header: 1,
        raw: false,
        dateNF: 'yyyy-mm-dd hh:mm:ss',
        defval: '',
      }) as unknown[][];

      if (!rawRows || rawRows.length === 0) continue;

      // Find the true column header row (skips title banners or metadata top rows)
      let headerRowIndex = -1;
      const scanLimit = Math.min(rawRows.length, 25);

      for (let i = 0; i < scanLimit; i++) {
        const row = rawRows[i];
        if (!Array.isArray(row)) continue;
        const nonEmpty = row.filter(c => String(c ?? '').trim() !== '');
        if (nonEmpty.length < 2) continue;

        const strParts = nonEmpty.map(c => String(c).toLowerCase().trim());
        // Check for common security, firewall, proxy, web or F5 column names
        const matches = strParts.filter(p =>
          [
            'f5', 'host', 'ip', 'client', 'source', 'status', 'request',
            'uri', 'url', 'action', 'date', 'time', 'user', 'attack',
            'violation', 'severity', 'path', 'method', 'event', 'timestamp',
            'policy', 'threat', 'response', 'destination', 'count'
          ].some(keyword => p.includes(keyword))
        ).length;

        if (matches >= 2 || (matches >= 1 && nonEmpty.length >= 3)) {
          headerRowIndex = i;
          break;
        }
      }

      // If no distinct header was found via keywords, pick the first row with >= 2 non-empty cells
      if (headerRowIndex === -1) {
        for (let i = 0; i < scanLimit; i++) {
          const row = rawRows[i];
          if (Array.isArray(row) && row.filter(c => String(c ?? '').trim() !== '').length >= 2) {
            headerRowIndex = i;
            break;
          }
        }
      }

      if (headerRowIndex === -1) continue;

      const headerRow = rawRows[headerRowIndex];
      const headerNames = headerRow.map(c => String(c ?? '').trim());
      const dateColIndices = new Set(
        headerNames
          .map((h, idx) => ({ h: h.toLowerCase(), idx }))
          .filter(item => ['date', 'time', 'tarih', 'zaman', 'timestamp'].some(k => item.h.includes(k)))
          .map(item => item.idx)
      );

      const sheetCsvLines: string[] = [];
      const currentHeaderLine = headerNames.map(h => cleanCell(h)).join(',');

      if (globalPrimaryHeader === null) {
        globalPrimaryHeader = currentHeaderLine;
        sheetCsvLines.push(currentHeaderLine);
      } else if (currentHeaderLine !== globalPrimaryHeader) {
        sheetCsvLines.push(currentHeaderLine);
      }

      // Format data rows
      for (let r = headerRowIndex + 1; r < rawRows.length; r++) {
        const row = rawRows[r];
        if (!Array.isArray(row)) continue;
        if (row.every(c => c === null || c === undefined || String(c).trim() === '')) {
          continue; // skip completely blank lines
        }

        const line = row
          .map((val, colIdx) => cleanCell(val, dateColIndices.has(colIdx)))
          .join(',');

        sheetCsvLines.push(line);
      }

      if (sheetCsvLines.length > 0) {
        csvSheets.push(sheetCsvLines.join('\n'));
      }
    }

    if (csvSheets.length === 0) {
      // Fallback to default sheet_to_csv if no structured rows were detected
      const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
      if (firstSheet) {
        return XLSX.utils.sheet_to_csv(firstSheet);
      }
      return '';
    }

    return csvSheets.join('\n');
  } catch (err) {
    console.error(`Error converting Excel file ${fileName || ''} to CSV:`, err);
    throw new Error(`Excel dosyası (${fileName || 'dosya'}) okunamadı: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Reads a browser File object as an ArrayBuffer and converts its Excel sheets to CSV text.
 */
export async function convertExcelFileToCsv(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  return convertExcelBufferToCsv(buffer, file.name);
}
