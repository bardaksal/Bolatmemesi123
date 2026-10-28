import crypto from 'crypto';
import zlib from 'zlib';
import { createWorker } from 'tesseract.js';
import { ObservedFromImage, StructuredTableRow, ImageHypothesis, ImageInvestigationStep } from './imageForensicService';
import {
  AnalysisFirstForensicReport,
  generateAnalysisFirstReport,
} from './analysisFirstForensicReporting';
import {
  isHttpRequestPattern,
  parseHttpRequestSemantics,
} from './httpRequestAnalyzer';

export interface ImageValidationResult {
  valid: boolean;
  format: 'png' | 'jpeg' | 'webp' | 'unknown';
  byteLength: number;
  sha256Hash: string;
  width?: number;
  height?: number;
  errorCode?: string;
  errorMessage?: string;
}

export interface RealPixelProvenance {
  sourceType: 'IMAGE_PIXEL' | 'TEXT_INPUT' | 'METADATA_ONLY';
  extractionMethod: 'VISION_MODEL' | 'LOCAL_OCR' | 'FALLBACK_NON_VISUAL';
  imageHash: string;
  imageByteLength: number;
  imageFormat: string;
  imageDimensions?: { width?: number; height?: number };
  rawOcrText?: string;
}

export interface LocalOcrExecutionResult {
  success: boolean;
  text: string;
  lines: string[];
  confidence: number;
  errorCode?: string;
  durationMs: number;
}

export interface ParsedOcrSecurityResult {
  visualPlatform: string;
  observedFromImage: ObservedFromImage;
  structuredTableRows: StructuredTableRow[];
  hypotheses: ImageHypothesis[];
  investigationSteps: ImageInvestigationStep[];
  queries: {
    splunk: string;
    kql: string;
    elastic: string;
    qradarAql: string;
  };
  iocs: string[];
  containmentActions: string[];
  fullReportMarkdown: string;
  analysisReport?: AnalysisFirstForensicReport;
  provenance: RealPixelProvenance;
}

/**
 * Validates raw image buffer checking magic bytes, headers, dimensions and SHA-256
 */
export function validateImageBuffer(buffer: Buffer): ImageValidationResult {
  if (!buffer || buffer.length === 0) {
    return {
      valid: false,
      format: 'unknown',
      byteLength: 0,
      sha256Hash: '',
      errorCode: 'IMAGE_DATA_MISSING',
      errorMessage: 'Görsel verisi alınamadı (0 byte).',
    };
  }

  const sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');
  const byteLength = buffer.length;

  // PNG Magic Bytes: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    let width: number | undefined;
    let height: number | undefined;
    if (buffer.length >= 24) {
      width = buffer.readUInt32BE(16);
      height = buffer.readUInt32BE(20);
    }
    return { valid: true, format: 'png', byteLength, sha256Hash, width, height };
  }

  // JPEG Magic Bytes: FF D8 FF
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { valid: true, format: 'jpeg', byteLength, sha256Hash };
  }

  // WebP Magic Bytes: RIFF .... WEBP
  if (
    buffer.length >= 12 &&
    buffer.toString('ascii', 0, 4) === 'RIFF' &&
    buffer.toString('ascii', 8, 12) === 'WEBP'
  ) {
    return { valid: true, format: 'webp', byteLength, sha256Hash };
  }

  return {
    valid: false,
    format: 'unknown',
    byteLength,
    sha256Hash,
    errorCode: 'UNSUPPORTED_IMAGE_FORMAT',
    errorMessage: 'Desteklenmeyen veya bozuk görsel biçimi (PNG, JPEG veya WebP bekleniyor).',
  };
}

/**
 * Executes local Tesseract OCR on raw image buffer
 */
export async function runLocalPixelOcr(
  imageBuffer: Buffer,
  timeoutMs = 12000
): Promise<LocalOcrExecutionResult> {
  const startTime = Date.now();
  let worker: any = null;

  try {
    const ocrPromise = (async () => {
      worker = await createWorker('eng');
      const ret = await worker.recognize(imageBuffer);
      await worker.terminate();
      worker = null;
      return ret;
    })();

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        const err = new Error(`OCR processing timed out after ${timeoutMs}ms`);
        err.name = 'TimeoutError';
        reject(err);
      }, timeoutMs);
    });

    const result: any = await Promise.race([ocrPromise, timeoutPromise]);
    const rawText = result.data.text ? result.data.text.trim() : '';

    return {
      success: true,
      text: rawText,
      lines: rawText.split('\n').map((l: string) => l.trim()).filter(Boolean),
      confidence: result.data.confidence || 0,
      errorCode: rawText.length === 0 ? 'NO_TEXT_DETECTED' : undefined,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    if (worker) {
      try {
        await worker.terminate();
      } catch {
        // ignore
      }
    }

    const isTimeout = err?.name === 'TimeoutError' || err?.message?.includes('timed out');
    return {
      success: false,
      text: '',
      lines: [],
      confidence: 0,
      errorCode: isTimeout ? 'OCR_TIMEOUT' : 'OCR_FAILED',
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Extracts structured cybersecurity telemetries from raw OCR text
 */
export function parseSecurityFieldsFromOcrText(
  ocrText: string,
  validation: ImageValidationResult
): ParsedOcrSecurityResult {
  let clean = ocrText || '';

  // 0. Pre-normalize common OCR character/spacing artifacts
  // Collapse spaced IP octets: e.g. "185. 123. 105. 51" -> "185.123.105.51"
  clean = clean.replace(/(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})/g, '$1.$2.$3.$4');
  // Normalize OCR letter confusions in security keywords
  clean = clean.replace(/\b(?:elocked|biocked|b1ocked|bl0cked)\b/gi, 'blocked');
  clean = clean.replace(/\b(?:alart|aleri|aler1)\b/gi, 'alert');
  clean = clean.replace(/“/g, '"').replace(/”/g, '"');

  const lines = clean.split('\n').map((l) => l.trim()).filter(Boolean);

  // 1. IP address extraction
  const ipMatch = clean.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const sourceIp = ipMatch ? ipMatch[0] : null;

  // 2. F5 or WAF Table structure detection
  // e.g. "185.123.105.51 | blocked | GET /cgi-bin/../../../../etc/passwd HTTP/1.1 | /etc/passwd"
  // e.g. "F5 Request Status: blocked" or "Request Status = blocked"
  const isBlocked = /\b(?:blocked|deny|drop|reject|reset|prevent)\b/i.test(clean);
  const isAlert = /\b(?:alert|alarm|monitor|log)\b/i.test(clean);
  const action = isBlocked ? 'DENY' : isAlert ? 'ALERT' : null;

  // 3. HTTP Request & Method (HTTP REQUEST != COMMAND)
  const httpReqMatch = clean.match(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s\r\n\|]+)(?:\s+(HTTP\/[0-9\.]+))?/i);
  const fullRequest = httpReqMatch ? httpReqMatch[0] : null;
  const requestUri = httpReqMatch ? httpReqMatch[2] : (clean.match(/\/(?:[a-zA-Z0-9_\-\.\/]+)/)?.[0] || null);
  const httpRequest = fullRequest
    ? parseHttpRequestSemantics(fullRequest)
    : requestUri
    ? parseHttpRequestSemantics(`GET ${requestUri} HTTP/1.1`)
    : null;

  // 4. Windows Event Viewer Detection
  const eventIdMatch = clean.match(/\bEvent(?:\s*ID|Id)?[:=\s]+(\d+)\b/i) || clean.match(/\b(4624|4625|4688|4672|7045|1102)\b/);
  const eventId = eventIdMatch ? eventIdMatch[1] : null;

  const userMatch = clean.match(/(?:TargetUserName|Account Name|User|kullanici_adi)[:=\s]+"?'?([a-zA-Z0-9_\-\.\\]+)/i);
  const username = userMatch ? userMatch[1] : null;

  const hostMatch = clean.match(/(?:Computer|Workstation Name|Host)[:=\s]+"?'?([a-zA-Z0-9_\-\.]+)/i);
  const host = hostMatch ? hostMatch[1] : null;

  // Genuine process command line (ONLY for process creation events or explicit CommandLine tags)
  // HTTP requests are NEVER classified as commandLine, process, or binary!
  const isProcessEvent = eventId === '4688' || /Process Information|Process Creation|Sysmon Event 1/i.test(clean);
  const cmdMatch = clean.match(/(?:Process CommandLine|CommandLine)[:=\s]+"?'?([^"\r\n]+)/i);
  let commandLine = isProcessEvent && cmdMatch ? cmdMatch[1].trim() : null;
  if (commandLine && isHttpRequestPattern(commandLine)) {
    commandLine = null;
  }

  const procMatch = clean.match(/(?:New Process Name|Process Name)[:=\s]+"?'?([a-zA-Z0-9_\-\.\\\/]+)/i);
  let processName = isProcessEvent && procMatch ? procMatch[1].trim() : null;
  if (processName && (isHttpRequestPattern(processName) || /^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$/i.test(processName))) {
    processName = null;
  }

  const subStatusMatch = clean.match(/0x[0-9a-fA-F]+/);
  const status = subStatusMatch ? subStatusMatch[0] : (isBlocked ? 'blocked' : null);

  // Platform determination
  const isF5 = clean.toLowerCase().includes('f5') || (Boolean(sourceIp) && isBlocked && (Boolean(fullRequest) || Boolean(requestUri)));
  const isWindows = Boolean(eventId) || clean.includes('Microsoft-Windows-Security-Auditing') || clean.includes('Event Viewer');
  const isLinux = clean.includes('sshd') || clean.includes('Failed password for');

  let visualPlatform = 'Bilinmeyen Güvenlik Arayüzü';
  if (isF5) visualPlatform = 'F5 BIG-IP ASM / Advanced WAF Table';
  else if (isWindows) visualPlatform = `Windows Event Viewer (Event ${eventId || 'Security'})`;
  else if (isLinux) visualPlatform = 'Linux Syslog / sshd auth.log Terminal';
  else if (isBlocked || isAlert) visualPlatform = 'WAF / Network Security Log';

  const structuredTableRows: StructuredTableRow[] = [];
  if (sourceIp || action || fullRequest || requestUri) {
    structuredTableRows.push({
      timestamp: clean.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/)?.[0] || 'Gözlemlenmedi',
      sourceIp: sourceIp || '-',
      destinationIp: host || '-',
      port: clean.match(/:\d{2,5}\b/)?.[0]?.slice(1) || '-',
      action: action || (isBlocked ? 'blocked' : 'ALLOW'),
      ruleOrEvent: fullRequest || requestUri || `Event ${eventId || 'Security Telemetry'}`,
    });
  }

  const iocs = [sourceIp, username].filter(Boolean) as string[];

  const hypotheses: ImageHypothesis[] = [];
  if (requestUri && (requestUri.includes('/etc/passwd') || requestUri.includes('../'))) {
    hypotheses.push({
      title: 'Hipotez 1: Dizin Atlama (Path Traversal / LFI) Denemesi',
      statement: `İstemci (${sourceIp || 'Bilinmeyen IP'}), web kök dizini dışındaki sistem dosyalarını okumayı amaçlayan bir HTTP URI hedeflemiştir.`,
      strengtheningEvidence: [
        `Gözlemlenen istek URI deseni: "${requestUri}".`,
        isBlocked ? 'WAF güvenlik katmanı bağlantıyı engellemiştir (DENY).' : 'İstek sunucuya iletilmiştir.',
      ],
      weakeningEvidence: [
        'Saldırının başarılı olduğuna veya sunucu dosyasının okunduğuna dair yanıt kanıtı saptanmamıştır.',
      ],
    });
  } else if (eventId === '4625') {
    hypotheses.push({
      title: 'Hipotez 1: Başarısız Kimlik Doğrulama Anomalisi',
      statement: `Hedef hesap (${username || 'Kullanıcı'}) için oturum açma işlemi başarısız olmuştur.`,
      strengtheningEvidence: [`Hata kodu: ${status || '0xC000006A'}`],
      weakeningEvidence: ['Yüzlerce ardışık istek yoksa tekil kullanıcı hatası olabilir.'],
    });
  }

  const containmentActions = isBlocked
    ? ['WAF koruması teyit edildi; IP itibar geçmişi incelenmeli ve kalıcı engelleme kuralı değerlendirilmelidir.']
    : ['Şüpheli kaynak IP adresini güvenlik duvarında geçici izolasyona alın.'];

  const observedFromImage: ObservedFromImage = {
    eventId,
    provider: isWindows ? 'Microsoft-Windows-Security-Auditing' : null,
    timestamp: clean.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/)?.[0] || null,
    host,
    username,
    sourceIp,
    destinationIp: null,
    port: null,
    processName,
    parentProcess: null,
    commandLine,
    action: isBlocked ? 'DENY' : (isAlert ? 'ALERT' : null),
    status,
    rawMessage: lines.slice(0, 3).join(' | '),
    httpRequest: httpRequest || undefined,
  };

  const analysisReport = generateAnalysisFirstReport({
    observed: observedFromImage,
    visualPlatform,
    structuredTableRows,
    rawOcrText: clean,
  });

  return {
    visualPlatform,
    observedFromImage,
    structuredTableRows,
    hypotheses,
    investigationSteps: [
      {
        step: 1,
        title: 'Kaynak IP İtibar ve İletişim Taraması',
        objective: 'Dış IP adresinin tehdit istihbaratı ve diğer sunucularla bağlantısını denetle.',
        logsToCheck: ['Firewall / NetFlow', 'WAF Access Log'],
        action: `Kaynak IP (${sourceIp || 'bilinmeyen'}) için son 24 saatlik trafik hacmini sorgulayın.`,
      },
    ],
    queries: {
      splunk: sourceIp ? `index=* src_ip="${sourceIp}" | stats count by action, uri_path` : 'index=* | head 100',
      kql: sourceIp ? `SecurityEvent | where IpAddress == "${sourceIp}"` : 'SecurityEvent | take 50',
      elastic: sourceIp ? `source.ip: "${sourceIp}"` : '*',
      qradarAql: sourceIp ? `SELECT * FROM events WHERE sourceip = '${sourceIp}'` : 'SELECT * FROM events LIMIT 50',
    },
    iocs,
    containmentActions,
    fullReportMarkdown: analysisReport.markdownReport,
    analysisReport,
    provenance: {
      sourceType: 'IMAGE_PIXEL',
      extractionMethod: 'LOCAL_OCR',
      imageHash: validation.sha256Hash,
      imageByteLength: validation.byteLength,
      imageFormat: validation.format,
      imageDimensions: { width: validation.width, height: validation.height },
      rawOcrText: clean,
    },
  };
}

/**
 * Generates a valid standard PNG buffer with pixel-rendered text for real-pixel unit testing
 */
export function generateTestPngWithText(text: string, width = 600, height = 120): Buffer {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // RGB truecolor
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace

  const ihdrCrc = crc32(Buffer.concat([Buffer.from('IHDR'), ihdrData]));
  const ihdrChunk = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from('IHDR'),
    ihdrData,
    Buffer.alloc(4),
  ]);
  ihdrChunk.writeUInt32BE(13, 0);
  ihdrChunk.writeUInt32BE(ihdrCrc, 21);

  // Scanlines: height rows of 1 filter byte + width * 3 RGB bytes
  // Fill background with white (255, 255, 255)
  const bytesPerRow = 1 + width * 3;
  const rawScanlines = Buffer.alloc(height * bytesPerRow, 0xff);

  for (let y = 0; y < height; y++) {
    rawScanlines[y * bytesPerRow] = 0; // filter None
  }

  // 5x7 Basic Bitmap Font
  const FONT: Record<string, number[]> = {
    '0': [0x1f, 0x11, 0x11, 0x11, 0x1f],
    '1': [0x00, 0x12, 0x1f, 0x10, 0x00],
    '2': [0x1d, 0x15, 0x15, 0x15, 0x17],
    '3': [0x11, 0x15, 0x15, 0x15, 0x1f],
    '4': [0x07, 0x04, 0x04, 0x1f, 0x04],
    '5': [0x17, 0x15, 0x15, 0x15, 0x1d],
    '6': [0x1f, 0x15, 0x15, 0x15, 0x1d],
    '7': [0x01, 0x01, 0x19, 0x05, 0x03],
    '8': [0x1f, 0x15, 0x15, 0x15, 0x1f],
    '9': [0x17, 0x15, 0x15, 0x15, 0x1f],
    'A': [0x1e, 0x05, 0x05, 0x05, 0x1e],
    'B': [0x1f, 0x15, 0x15, 0x15, 0x0a],
    'C': [0x0e, 0x11, 0x11, 0x11, 0x11],
    'D': [0x1f, 0x11, 0x11, 0x11, 0x0e],
    'E': [0x1f, 0x15, 0x15, 0x15, 0x11],
    'F': [0x1f, 0x05, 0x05, 0x05, 0x01],
    'G': [0x0e, 0x11, 0x15, 0x15, 0x1d],
    'H': [0x1f, 0x04, 0x04, 0x04, 0x1f],
    'I': [0x11, 0x11, 0x1f, 0x11, 0x11],
    'J': [0x08, 0x10, 0x10, 0x10, 0x0f],
    'K': [0x1f, 0x04, 0x0a, 0x11, 0x00],
    'L': [0x1f, 0x10, 0x10, 0x10, 0x10],
    'M': [0x1f, 0x02, 0x04, 0x02, 0x1f],
    'N': [0x1f, 0x02, 0x04, 0x08, 0x1f],
    'O': [0x0e, 0x11, 0x11, 0x11, 0x0e],
    'P': [0x1f, 0x05, 0x05, 0x05, 0x02],
    'Q': [0x0e, 0x11, 0x13, 0x09, 0x16],
    'R': [0x1f, 0x05, 0x0d, 0x16, 0x00],
    'S': [0x12, 0x15, 0x15, 0x15, 0x09],
    'T': [0x01, 0x01, 0x1f, 0x01, 0x01],
    'U': [0x0f, 0x10, 0x10, 0x10, 0x0f],
    'V': [0x07, 0x08, 0x10, 0x08, 0x07],
    'W': [0x1f, 0x08, 0x04, 0x08, 0x1f],
    'X': [0x11, 0x0a, 0x04, 0x0a, 0x11],
    'Y': [0x03, 0x04, 0x18, 0x04, 0x03],
    'Z': [0x11, 0x13, 0x15, 0x19, 0x11],
    ' ': [0x00, 0x00, 0x00, 0x00, 0x00],
    '.': [0x10, 0x00, 0x00, 0x00, 0x00],
    ':': [0x0a, 0x00, 0x00, 0x00, 0x00],
    '/': [0x10, 0x08, 0x04, 0x02, 0x01],
    '|': [0x00, 0x00, 0x1f, 0x00, 0x00],
    '-': [0x04, 0x04, 0x04, 0x04, 0x04],
  };

  const scale = 3; // 3x scale so letters are 15x21 pixels (crisp for OCR)
  let startX = 20;
  let startY = 30;

  const upper = text.toUpperCase();
  for (let c = 0; c < upper.length; c++) {
    const char = upper[c];
    if (char === '\n') {
      startX = 20;
      startY += 28;
      continue;
    }
    const glyph = FONT[char] || FONT[' '];

    for (let col = 0; col < glyph.length; col++) {
      const bitmask = glyph[col];
      for (let row = 0; row < 7; row++) {
        if ((bitmask & (1 << row)) !== 0) {
          // Draw black pixel block
          for (let dy = 0; dy < scale; dy++) {
            for (let dx = 0; dx < scale; dx++) {
              const px = startX + col * scale + dx;
              const py = startY + row * scale + dy;
              if (px < width && py < height) {
                const offset = py * bytesPerRow + 1 + px * 3;
                rawScanlines[offset] = 0x00;     // R
                rawScanlines[offset + 1] = 0x00; // G
                rawScanlines[offset + 2] = 0x00; // B
              }
            }
          }
        }
      }
    }
    startX += (glyph.length + 1) * scale;
  }

  const compressed = zlib.deflateSync(rawScanlines);
  const idatCrc = crc32(Buffer.concat([Buffer.from('IDAT'), compressed]));
  const idatChunk = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from('IDAT'),
    compressed,
    Buffer.alloc(4),
  ]);
  idatChunk.writeUInt32BE(compressed.length, 0);
  idatChunk.writeUInt32BE(idatCrc, 8 + compressed.length);

  const iendCrc = crc32(Buffer.from('IEND'));
  const iendChunk = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from('IEND'),
    Buffer.alloc(4),
  ]);
  iendChunk.writeUInt32BE(0, 0);
  iendChunk.writeUInt32BE(iendCrc, 8);

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (c ^ buf[n]) >>> 0;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}
