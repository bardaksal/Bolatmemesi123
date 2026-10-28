import {
  HuntingReport,
  AllowlistData,
  DetectedFormatItem,
  QuarantinedLineItem,
  ForensicQuarantineReport,
  DetectionProfile,
  NormalizedLog,
} from '../types';
import {
  StreamEventSample,
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
  extractStreamSample,
  isLogFilteredByAllowlist,
  getQuarantineReason,
  unpackConcatenatedLines,
  isDelimitedHeaderLine,
} from './streamingParser';
import { createEmptyReport, runAnalytics, isSuccessfulTransferLog } from './socEngine';
import { isExcelFile, convertExcelFileToCsv } from './excelConverter';

export interface AnalysisProgress {
  percent: number;
  stage: 'PARSING' | 'CORRELATING' | 'DONE';
  stageMessage: string;
  linesRead: number;
  fileName?: string;
  fileIndex?: number;
  totalFiles?: number;
}

export interface AnalysisResult {
  report: HuntingReport;
  liveSample: StreamEventSample[];
  rawLogs?: NormalizedLog[];
  totalLines: number;
  durationMs: number;
}

export interface LogFileEntry {
  name: string;
  file?: File;
  content?: string;
}

class LogWorkerController {
  private worker: Worker | null = null;
  private currentReject: ((reason?: unknown) => void) | null = null;
  private onProgressCallback: ((progress: AnalysisProgress) => void) | null = null;
  private onCompleteCallback: ((result: AnalysisResult) => void) | null = null;
  private isProcessing = false;
  private lastFiles: LogFileEntry[] = [];

  constructor() {
    this.initWorker();
  }

  private initWorker() {
    if (typeof window === 'undefined') return;
    try {
      if (this.worker) {
        this.worker.terminate();
        this.worker = null;
      }
      this.worker = new Worker(new URL('../workers/logWorker.ts', import.meta.url), {
        type: 'module',
      });

      this.worker.onmessage = (e: MessageEvent) => {
        const msg = e.data;
        if (!msg) return;

        if (msg.type === 'PROGRESS') {
          if (this.onProgressCallback) {
            this.onProgressCallback({
              percent: msg.percent ?? 0,
              stage: msg.stage ?? 'PARSING',
              stageMessage: msg.stageMessage ?? '',
              linesRead: msg.linesRead ?? 0,
              fileName: msg.fileName,
              fileIndex: msg.fileIndex,
              totalFiles: msg.totalFiles,
            });
          }
        } else if (msg.type === 'COMPLETE') {
          this.isProcessing = false;
          if (this.onCompleteCallback) {
            this.onCompleteCallback({
              report: msg.report,
              liveSample: msg.liveSample ?? [],
              rawLogs: msg.rawLogs,
              totalLines: msg.totalLines ?? 0,
              durationMs: msg.durationMs ?? 0,
            });
          }
        } else if (msg.type === 'ERROR') {
          this.isProcessing = false;
          if (this.currentReject) {
            this.currentReject(new Error(msg.error || 'Log analizi sırasında hata oluştu'));
          }
        }
      };

      this.worker.onerror = (err) => {
        console.warn('LogWorker runtime error, falling back to main-thread async pipeline:', err);
        const rejectFn = this.currentReject;
        this.worker = null;
        if (rejectFn) {
          this.currentReject = null;
          rejectFn(new Error(err.message || 'LogWorker çalışma zamanı hatası'));
        }
      };
    } catch (err) {
      console.warn('Dedicated worker initialization failed, fallback will be used:', err);
      this.worker = null;
    }
  }

  public getIsProcessing(): boolean {
    return this.isProcessing;
  }

  public abort(): void {
    if (this.isProcessing) {
      this.isProcessing = false;
      this.initWorker();
      if (this.currentReject) {
        this.currentReject(new Error('Kullanıcı tarafından iptal edildi'));
        this.currentReject = null;
      }
    }
  }

  public async processFiles(
    files: LogFileEntry[],
    options: {
      exfiltrationBytes: number;
      failedAttempts: number;
      allowlistData?: AllowlistData | null;
      detectionProfile?: DetectionProfile;
    },
    onProgress?: (progress: AnalysisProgress) => void
  ): Promise<AnalysisResult> {
    this.abort();
    this.isProcessing = true;
    this.lastFiles = files;
    this.onProgressCallback = onProgress || null;

    if (!files || files.length === 0) {
      this.isProcessing = false;
      return {
        report: createEmptyReport(),
        liveSample: [],
        totalLines: 0,
        durationMs: 0,
      };
    }

    // Pre-convert any Excel files (.xlsx, .xls, .xlsm, .xlsb) to CSV text
    for (const f of files) {
      if (isExcelFile(f.name) && !f.content && f.file) {
        if (onProgress) {
          onProgress({
            percent: 5,
            stage: 'PARSING',
            stageMessage: `${f.name} Excel tablosu CSV formatına dönüştürülüyor...`,
            linesRead: 0,
            fileName: f.name,
            totalFiles: files.length,
          });
        }
        try {
          f.content = await convertExcelFileToCsv(f.file);
        } catch (err) {
          console.error(`Excel conversion failed for ${f.name}:`, err);
        }
      }
    }

    if (!this.worker) {
      this.initWorker();
    }

    if (this.worker) {
      return new Promise<AnalysisResult>((resolve, reject) => {
        this.currentReject = (err) => {
          // Fallback if worker fails mid-run
          console.warn('Worker rejected, running async fallback...', err);
          this.fallbackProcessFiles(files, options, onProgress).then(resolve).catch(reject);
        };
        this.onCompleteCallback = (res) => {
          this.currentReject = null;
          resolve(res);
        };

        try {
          this.worker.postMessage({
            type: 'PROCESS_FILES',
            files,
            options,
          });
        } catch (postErr) {
          console.warn('Failed to postMessage to worker, running fallback:', postErr);
          this.fallbackProcessFiles(files, options, onProgress).then(resolve).catch(reject);
        }
      });
    }

    // Direct fallback if worker couldn't be created
    return this.fallbackProcessFiles(files, options, onProgress);
  }

  // Robust Async Fallback that chunks processing using setTimeout(0)
  private async fallbackProcessFiles(
    files: LogFileEntry[],
    options: {
      exfiltrationBytes: number;
      failedAttempts: number;
      allowlistData?: AllowlistData | null;
      detectionProfile?: DetectionProfile;
    },
    onProgress?: (progress: AnalysisProgress) => void
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const allLogs: any[] = [];
    const liveSample: StreamEventSample[] = [];
    const detectedFormats: DetectedFormatItem[] = [];
    const quarantinedLines: QuarantinedLineItem[] = [];
    let totalLinesProcessed = 0;
    let totalEmptyLinesCount = 0;
    let totalHeaderCommentCount = 0;
    let totalQuarantinedCount = 0;
    let lastDetectedW3cFields: string[] = [];

    for (let fIdx = 0; fIdx < files.length; fIdx++) {
      const fileEntry = files[fIdx];
      const formatState = initializeFormatState(fileEntry.name);
      if (lastDetectedW3cFields.length > 0) {
        formatState.w3cFields = [...lastDetectedW3cFields];
      }
      let content = fileEntry.content;
      let fileLinesCount = 0;
      let fileEventCount = 0;
      let fileTransferBytes = 0;
      const fileUniqueIps = new Set<string>();
      let fileErrorCount = 0;
      let fileHeaderCommentCount = 0;
      let fileEmptyLineCount = 0;
      let fileQuarantinedCount = 0;

      if (!content && fileEntry.file) {
        if (onProgress) {
          onProgress({
            percent: Math.round(((fIdx + 0.1) / files.length) * 100),
            stage: 'PARSING',
            stageMessage: `${fileEntry.name} okunuyor...`,
            linesRead: totalLinesProcessed,
            fileName: fileEntry.name,
            fileIndex: fIdx + 1,
            totalFiles: files.length,
          });
        }
        if (isExcelFile(fileEntry.name)) {
          content = await convertExcelFileToCsv(fileEntry.file);
        } else {
          content = await fileEntry.file.text();
        }
      }

      if (!content) continue;

      const lines = content.split(/\r?\n/);
      const batchSize = 1000;

      for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i];
        totalLinesProcessed++;
        fileLinesCount++;

        const subLines = unpackConcatenatedLines(rawLine);
        for (const singleLine of subLines) {
          const trimmed = singleLine.replace(/^\uFEFF/, '').trim();
          if (!trimmed) {
            fileEmptyLineCount++;
            totalEmptyLinesCount++;
            continue;
          }

          if (trimmed.startsWith('#')) {
            fileHeaderCommentCount++;
            totalHeaderCommentCount++;
            if (trimmed.toLowerCase().startsWith('#fields:')) {
              formatState.isW3C = true;
              formatState.format = 'W3C_IIS';
              formatState.w3cFields = trimmed
                .replace(/^#fields:\s*/i, '')
                .trim()
                .split(/\s+/)
                .map(f => f.toLowerCase().replace(/[()]/g, '_').replace(/-+/g, '_').replace(/^_+|_+$/g, '').trim());
              formatState.detected = true;
            }
            continue;
          }

          if (!formatState.detected) {
            feedSampleLine(formatState, trimmed);
          }

          // Check if this line is the CSV column header
          if (isDelimitedHeaderLine(trimmed, formatState)) {
            fileHeaderCommentCount++;
            totalHeaderCommentCount++;
            continue;
          }

          const parsed = parseLineToNormalizedLog(trimmed, formatState);
          if (parsed) {
            allLogs.push(parsed);
            fileEventCount++;
            if (parsed.ip_adresi) fileUniqueIps.add(parsed.ip_adresi);
            if (isSuccessfulTransferLog(parsed)) {
              const b = parsed.byte_degeri || parsed.istemci_byte || 0;
              if (b > 0) fileTransferBytes += b;
            }
            if ((parsed.status_code && parsed.status_code >= 400) || parsed.baglanti_karari.startsWith('DENY')) {
              fileErrorCount++;
            }
            if (liveSample.length < 1500) {
              liveSample.push(extractStreamSample(parsed));
            }
          } else {
            fileQuarantinedCount++;
            totalQuarantinedCount++;
            if (quarantinedLines.length < 500) {
              quarantinedLines.push({
                fileName: fileEntry.name,
                lineNumber: fileLinesCount,
                rawText: trimmed.length > 300 ? trimmed.slice(0, 300) + '... (kırpıldı)' : trimmed,
                reason: getQuarantineReason(trimmed, formatState),
              });
            }
          }
        }

        if (i % batchSize === 0) {
          if (onProgress) {
            const filePct = Math.round((i / lines.length) * 80);
            onProgress({
              percent: Math.max(1, Math.min(85, filePct)),
              stage: 'PARSING',
              stageMessage: `${fileEntry.name} ayrıştırılıyor... (${totalLinesProcessed.toLocaleString()} satır)`,
              linesRead: totalLinesProcessed,
              fileName: fileEntry.name,
              fileIndex: fIdx + 1,
              totalFiles: files.length,
            });
          }
          // Yield to browser UI thread
          await new Promise((r) => setTimeout(r, 0));
        }
      }

      if (formatState.w3cFields && formatState.w3cFields.length > 0) {
        lastDetectedW3cFields = [...formatState.w3cFields];
      }

      detectedFormats.push({
        fileName: fileEntry.name,
        format: formatState.format,
        formatDisplayName: formatState.formatDisplayName,
        lineCount: fileLinesCount,
        eventCount: fileEventCount,
        headerCommentCount: fileHeaderCommentCount,
        emptyLineCount: fileEmptyLineCount,
        quarantinedCount: fileQuarantinedCount,
        transferBytes: fileTransferBytes,
        transferMb: parseFloat((fileTransferBytes / (1024 * 1024)).toFixed(2)),
        transferGb: parseFloat((fileTransferBytes / (1024 * 1024 * 1024)).toFixed(2)),
        uniqueIps: fileUniqueIps.size,
        errorCount: fileErrorCount,
      });
    }

    const footnoteText = totalQuarantinedCount > 0
      ? `${totalQuarantinedCount.toLocaleString('tr-TR')} satır ayrıştırılamadı (karantinaya alındı).`
      : 'Ayrıştırılan %100, sorun yok.';

    const quarantine: ForensicQuarantineReport = {
      totalLinesRead: totalLinesProcessed,
      parsedEventsCount: allLogs.length,
      headerCommentLinesCount: totalHeaderCommentCount,
      emptyLinesCount: totalEmptyLinesCount,
      quarantinedCount: totalQuarantinedCount,
      quarantinedLines,
      footnoteText,
    };

    if (onProgress) {
      onProgress({
        percent: 90,
        stage: 'CORRELATING',
        stageMessage: 'Tehditler korele ediliyor ve skorlanıyor...',
        linesRead: totalLinesProcessed,
        totalFiles: files.length,
      });
      await new Promise((r) => setTimeout(r, 10));
    }

    // Filter with Allowlist
    const filteredLogs = allLogs.filter((log) => {
      if (options.allowlistData && isLogFilteredByAllowlist(log, options.allowlistData)) {
        return false;
      }
      const ip = (log.ip_adresi || '').toLowerCase();
      if (['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi'].includes(ip)) return false;
      return true;
    });

    const report = runAnalytics(
      filteredLogs,
      options.exfiltrationBytes,
      options.failedAttempts,
      options.detectionProfile || 'BALANCED'
    );
    report.detected_formats = detectedFormats;
    report.quarantine = quarantine;
    const durationMs = Math.round(performance.now() - startTime);

    if (onProgress) {
      onProgress({
        percent: 100,
        stage: 'DONE',
        stageMessage: 'Analiz tamamlandı.',
        linesRead: totalLinesProcessed,
        totalFiles: files.length,
      });
    }

    this.isProcessing = false;
    return {
      report,
      liveSample,
      rawLogs: allLogs,
      totalLines: totalLinesProcessed,
      durationMs,
    };
  }

  public async reAnalyze(
    options: {
      exfiltrationBytes: number;
      failedAttempts: number;
      allowlistData?: AllowlistData | null;
      detectionProfile?: DetectionProfile;
    },
    onProgress?: (progress: AnalysisProgress) => void
  ): Promise<AnalysisResult> {
    this.isProcessing = true;
    this.onProgressCallback = onProgress || null;

    if (this.worker) {
      return new Promise<AnalysisResult>((resolve, reject) => {
        this.currentReject = reject;
        this.onCompleteCallback = (res) => {
          this.currentReject = null;
          resolve(res);
        };

        try {
          this.worker.postMessage({
            type: 'RE_ANALYZE',
            options,
          });
        } catch {
          this.fallbackProcessFiles(this.lastFiles, options, onProgress).then(resolve).catch(reject);
        }
      });
    }

    return this.fallbackProcessFiles(this.lastFiles, options, onProgress);
  }

  public clear(): void {
    this.lastFiles = [];
    if (this.worker) {
      this.worker.postMessage({ type: 'CLEAR' });
    }
  }
}

export const logWorkerController = new LogWorkerController();
