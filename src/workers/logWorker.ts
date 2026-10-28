import {
  NormalizedLog,
  HuntingReport,
  AllowlistData,
  DetectedFormatItem,
  QuarantinedLineItem,
  ForensicQuarantineReport,
  DetectionProfile,
} from '../types';
import { runAnalytics, createEmptyReport, isSuccessfulTransferLog } from '../services/socEngine';
import {
  initializeFormatState,
  feedSampleLine,
  parseLineToNormalizedLog,
  extractStreamSample,
  isLogFilteredByAllowlist,
  getQuarantineReason,
  unpackConcatenatedLines,
  isDelimitedHeaderLine,
  StreamEventSample,
} from '../services/streamingParser';

interface ProcessFilesPayload {
  files: Array<{
    name: string;
    file?: File;
    content?: string;
  }>;
  options: {
    exfiltrationBytes: number;
    failedAttempts: number;
    allowlistData?: AllowlistData | null;
    detectionProfile?: DetectionProfile;
  };
}

interface ReAnalyzePayload {
  options: {
    exfiltrationBytes: number;
    failedAttempts: number;
    allowlistData?: AllowlistData | null;
    detectionProfile?: DetectionProfile;
  };
}

// In-worker cache to allow instant re-analysis when sliders/filters change
let cachedRawLogs: NormalizedLog[] = [];
let cachedSample: StreamEventSample[] = [];
let cachedAllowlistData: AllowlistData | null | undefined = null;
let cachedDetectedFormats: DetectedFormatItem[] = [];
let cachedQuarantine: ForensicQuarantineReport | undefined = undefined;

self.onmessage = async (e: MessageEvent) => {
  const data = e.data;
  if (!data || !data.type) return;

  try {
    if (data.type === 'PROCESS_FILES') {
      const payload = data as ProcessFilesPayload & { type: string };
      await handleProcessFiles(payload.files, payload.options);
    } else if (data.type === 'RE_ANALYZE') {
      const payload = data as ReAnalyzePayload & { type: string };
      handleReAnalyze(payload.options);
    } else if (data.type === 'CLEAR') {
      cachedRawLogs = [];
      cachedSample = [];
      cachedAllowlistData = null;
      cachedDetectedFormats = [];
      cachedQuarantine = undefined;
      self.postMessage({ type: 'CLEARED' });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    self.postMessage({ type: 'ERROR', error: message });
  }
};

async function handleProcessFiles(
  files: ProcessFilesPayload['files'],
  options: ProcessFilesPayload['options']
) {
  const startTime = Date.now();
  cachedAllowlistData = options.allowlistData;

  if (!files || files.length === 0) {
    cachedRawLogs = [];
    cachedSample = [];
    self.postMessage({
      type: 'COMPLETE',
      report: createEmptyReport(),
      liveSample: [],
      totalLines: 0,
      durationMs: 0,
    });
    return;
  }

  const allLogs: NormalizedLog[] = [];
  const liveSample: StreamEventSample[] = [];
  const detectedFormats: DetectedFormatItem[] = [];
  const quarantinedLines: QuarantinedLineItem[] = [];
  let totalLinesProcessed = 0;
  let totalEmptyLinesCount = 0;
  let totalHeaderCommentCount = 0;
  let totalQuarantinedCount = 0;
  let lastProgressPost = Date.now();

  // Total size estimate across files for progress percentage
  const totalSizeBytes = files.reduce((acc, f) => {
    if (f.file) return acc + f.file.size;
    if (f.content) return acc + f.content.length;
    return acc;
  }, 0) || 1;

  let cumulativeBytesRead = 0;
  let lastDetectedW3cFields: string[] = [];

  for (let fileIndex = 0; fileIndex < files.length; fileIndex++) {
    const fileEntry = files[fileIndex];
    const formatState = initializeFormatState(fileEntry.name);
    if (lastDetectedW3cFields.length > 0) {
      formatState.w3cFields = [...lastDetectedW3cFields];
    }
    let fileLinesCount = 0;
    let fileEventCount = 0;
    let fileTransferBytes = 0;
    const fileUniqueIps = new Set<string>();
    let fileErrorCount = 0;
    let fileHeaderCommentCount = 0;
    let fileEmptyLineCount = 0;
    let fileQuarantinedCount = 0;

    const handleParsedLog = (parsed: NormalizedLog | null) => {
      if (!parsed) return;
      allLogs.push(parsed);
      if (liveSample.length < 1500) {
        liveSample.push(extractStreamSample(parsed));
      }
      fileEventCount++;
      if (parsed.ip_adresi) fileUniqueIps.add(parsed.ip_adresi);
      if (isSuccessfulTransferLog(parsed)) {
        const b = parsed.byte_degeri || parsed.istemci_byte || 0;
        if (b > 0) fileTransferBytes += b;
      }
      if ((parsed.status_code && parsed.status_code >= 400) || parsed.baglanti_karari.startsWith('DENY')) {
        fileErrorCount++;
      }
    };

    const processSingleLine = (singleLine: string) => {
      const trimmed = singleLine.replace(/^\uFEFF/, '').trim();
      if (!trimmed) {
        fileEmptyLineCount++;
        totalEmptyLinesCount++;
        return;
      }

      // W3C Directive or Comment (#Software, #Version, #Date, #Fields, etc.)
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
        return;
      }

      if (!formatState.detected) {
        feedSampleLine(formatState, trimmed);
      }

      // Delimited / CSV column header line check (never quarantine valid column definitions)
      if (isDelimitedHeaderLine(trimmed, formatState)) {
        fileHeaderCommentCount++;
        totalHeaderCommentCount++;
        return;
      }

      const parsed = parseLineToNormalizedLog(trimmed, formatState);
      if (parsed) {
        handleParsedLog(parsed);
      } else {
        // Line could not be parsed into a valid log event -> send to Forensic Quarantine
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
    };

    const processLine = (rawLine: string) => {
      totalLinesProcessed++;
      fileLinesCount++;

      const subLines = unpackConcatenatedLines(rawLine);
      for (const sub of subLines) {
        processSingleLine(sub);
      }
    };

    if (fileEntry.content) {
      // 1. TEXT STRING CHUNKING (Pre-converted CSV or text)
      const content = fileEntry.content;
      let startIdx = 0;
      const len = content.length;

      while (startIdx < len) {
        let nextNewline = content.indexOf('\n', startIdx);
        if (nextNewline === -1) nextNewline = len;

        let line = content.substring(startIdx, nextNewline);
        if (line.endsWith('\r')) line = line.slice(0, -1);
        startIdx = nextNewline + 1;

        processLine(line);

        if (totalLinesProcessed % 2000 === 0) {
          const now = Date.now();
          if (now - lastProgressPost > 80) {
            lastProgressPost = now;
            const pct = Math.min(85, Math.round(((cumulativeBytesRead + startIdx) / totalSizeBytes) * 85));
            self.postMessage({
              type: 'PROGRESS',
              percent: Math.max(1, pct),
              stage: 'PARSING',
              fileName: fileEntry.name,
              fileIndex: fileIndex + 1,
              totalFiles: files.length,
              linesRead: totalLinesProcessed,
              stageMessage: `${totalLinesProcessed.toLocaleString()} satır ayrıştırıldı...`,
            });
          }
        }
      }
      cumulativeBytesRead += len;
    } else if (fileEntry.file) {
      // 2. STREAMING FILE / BLOB CHUNKING
      const file = fileEntry.file;
      let leftover = '';

      try {
        if (typeof file.stream === 'function') {
          const stream = file.stream();
          const reader = stream.getReader();
          let decoder: TextDecoder | null = null;
          let isFirstChunk = true;

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            cumulativeBytesRead += value.byteLength;

            if (isFirstChunk) {
              isFirstChunk = false;
              // Detect UTF-16 LE / BE or default to UTF-8
              if (value.length >= 2 && value[0] === 0xff && value[1] === 0xfe) {
                decoder = new TextDecoder('utf-16le', { fatal: false, ignoreBOM: false });
              } else if (value.length >= 2 && value[0] === 0xfe && value[1] === 0xff) {
                decoder = new TextDecoder('utf-16be', { fatal: false, ignoreBOM: false });
              } else {
                decoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false });
              }
            }

            const text = (decoder || new TextDecoder('utf-8')).decode(value, { stream: true });
            const chunk = leftover + text;
            const lines = chunk.split(/\r?\n/);
            leftover = lines.pop() ?? ''; // Keep the last incomplete fragment

            for (let i = 0; i < lines.length; i++) {
              processLine(lines[i]);
            }

            const now = Date.now();
            if (now - lastProgressPost > 80) {
              lastProgressPost = now;
              const pct = Math.min(85, Math.round((cumulativeBytesRead / totalSizeBytes) * 85));
              self.postMessage({
                type: 'PROGRESS',
                percent: Math.max(1, pct),
                stage: 'PARSING',
                fileName: fileEntry.name,
                fileIndex: fileIndex + 1,
                totalFiles: files.length,
                linesRead: totalLinesProcessed,
                stageMessage: `${fileEntry.name} okunuyor (${totalLinesProcessed.toLocaleString()} satır)...`,
              });
            }
          }
        } else {
          // Fallback if file.stream() is not supported
          const text = await file.text();
          const lines = text.split(/\r?\n/);
          for (let i = 0; i < lines.length; i++) {
            processLine(lines[i]);
          }
        }
      } catch (streamErr) {
        console.warn('Stream reading error, falling back to file.text():', streamErr);
        const text = await file.text();
        const lines = text.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          processLine(lines[i]);
        }
      }

      // Process remaining leftover
      if (leftover.length > 0) {
        processLine(leftover);
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

  // Quarantine accounting & status text
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

  // Correlation & threat analytics stage
  self.postMessage({
    type: 'PROGRESS',
    percent: 90,
    stage: 'CORRELATING',
    linesRead: totalLinesProcessed,
    stageMessage: 'DuckDB Tehdit Korelasyonu & Risk Dağılımı Hesaplanıyor...',
  });

  cachedRawLogs = allLogs;
  cachedSample = liveSample;
  cachedDetectedFormats = detectedFormats;
  cachedQuarantine = quarantine;

  // Filter with allowlist if provided, and strip any accidental header row artifacts
  const isHeaderArtifact = (l: NormalizedLog) => {
    const ip = (l.ip_adresi || '').toLowerCase().trim();
    return ['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi', 'client_ip', 'ip address'].includes(ip);
  };

  const logsToAnalyze = allLogs.filter(l => {
    if (isHeaderArtifact(l)) return false;
    if (options.allowlistData && isLogFilteredByAllowlist(l, options.allowlistData)) return false;
    return true;
  });

  const report = runAnalytics(
    logsToAnalyze,
    options.exfiltrationBytes,
    options.failedAttempts,
    options.detectionProfile || 'BALANCED'
  );
  report.detected_formats = detectedFormats;
  report.quarantine = quarantine;

  const durationMs = Date.now() - startTime;

  self.postMessage({
    type: 'COMPLETE',
    report,
    liveSample,
    rawLogs: allLogs,
    totalLines: totalLinesProcessed,
    durationMs,
  });
}

function handleReAnalyze(options: ReAnalyzePayload['options']) {
  cachedAllowlistData = options.allowlistData;

  const isHeaderArtifact = (l: NormalizedLog) => {
    const ip = (l.ip_adresi || '').toLowerCase().trim();
    return ['source ip', 'c-ip', 'src_ip', 'ip', 'source', 'ip_adresi', 'client_ip', 'ip address'].includes(ip);
  };

  const logsToAnalyze = cachedRawLogs.filter(l => {
    if (isHeaderArtifact(l)) return false;
    if (options.allowlistData && isLogFilteredByAllowlist(l, options.allowlistData)) return false;
    return true;
  });

  const report = runAnalytics(
    logsToAnalyze,
    options.exfiltrationBytes,
    options.failedAttempts,
    options.detectionProfile || 'BALANCED'
  );
  report.detected_formats = cachedDetectedFormats;
  report.quarantine = cachedQuarantine;

  self.postMessage({
    type: 'COMPLETE',
    report,
    liveSample: cachedSample,
    totalLines: cachedRawLogs.length,
    durationMs: 0,
  });
}
