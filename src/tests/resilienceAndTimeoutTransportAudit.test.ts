import http from 'http';
import {
  executeModelWithResilience,
  classifyResilienceError,
  ResilienceErrorType,
} from '../services/geminiResilienceExecutor';

// ANSI terminal colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

let passCount = 0;
let failCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ${GREEN}✓ [PASS]${RESET} ${testName}`);
    passCount++;
  } else {
    console.error(`  ${RED}✗ [FAIL]${RESET} ${testName}${detail ? ` - ${detail}` : ''}`);
    failCount++;
  }
}

async function runTests() {
  console.log(`\n${CYAN}================================================================${RESET}`);
  console.log(`${CYAN}🛡️ PHASE 2 — TIMEOUT, CANCELLATION & TRANSPORT RESILIENCE AUDIT 🛡️${RESET}`);
  console.log(`${CYAN}================================================================${RESET}\n`);

  // -------------------------------------------------------------------------
  // TEST 1: Model çağrısı timeout süresinden önce tamamlanır: normal başarı
  // -------------------------------------------------------------------------
  console.log(`${YELLOW}--- TEST 1: Model completes before timeout (Normal Success) ---${RESET}`);
  {
    const fastAi = {
      models: {
        generateContent: async ({ model, config }: any) => {
          assert(Boolean(config?.abortSignal), 'T1.1: abortSignal must be passed to SDK config');
          assert(config?.httpOptions?.timeout === 1000, 'T1.2: timeout must be passed in httpOptions');
          return { text: JSON.stringify({ threatLevel: 'YÜKSEK', summary: 'Hızlı analiz tamamlandı' }) };
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: fastAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 1000,
      contents: 'test-prompt',
      parseResponse: (txt) => JSON.parse(txt),
      fallbackGenerator: () => ({ threatLevel: 'DÜŞÜK', fallback: true }),
    });

    assert(res.success === true, 'T1.3: Response marked success');
    assert(res.fallbackActive === false, 'T1.4: Fallback must NOT be active');
    assert(res.errorType === 'SUCCESS', 'T1.5: Error type must be SUCCESS');
    assert(res.result.threatLevel === 'YÜKSEK', 'T1.6: Result comes from model');
    assert(res.activeTimersCleared === true, 'T1.7: Timers cleared cleanly');
  }

  // -------------------------------------------------------------------------
  // TEST 2: Model çağrısı timeout süresini aşar: uygun fallback döner
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 2: Model request exceeds timeout -> Deterministic Fallback ---${RESET}`);
  {
    let signalObserved: AbortSignal | null = null;
    const hangingAi = {
      models: {
        generateContent: async ({ config }: any) => {
          signalObserved = config.abortSignal;
          return new Promise((_, reject) => {
            config.abortSignal.addEventListener('abort', () => {
              const err = new Error('This operation was aborted');
              err.name = 'AbortError';
              reject(err);
            });
          });
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: hangingAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 150,
      contents: 'test-prompt',
      fallbackGenerator: (ctx) => ({ threatLevel: 'ORTA', fallback: true, ctx }),
    });

    assert(res.success === true, 'T2.1: Operation completes via fallback');
    assert(res.fallbackActive === true, 'T2.2: Fallback marked active');
    assert(res.errorType === 'TIMEOUT', 'T2.3: Error type classified as TIMEOUT');
    assert(res.result.threatLevel === 'ORTA', 'T2.4: Deterministic fallback returned');
    assert(res.transportAborted === true, 'T2.5: Transport aborted recorded');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Timeout gerçekleştiğinde desteklenen SDK iptal mekanizmasının tetiklendiği
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 3: SDK AbortSignal trigger on timeout verification ---${RESET}`);
  {
    let abortEventTriggered = false;
    const timeoutAi = {
      models: {
        generateContent: async ({ config }: any) => {
          const sig: AbortSignal = config.abortSignal;
          sig.addEventListener('abort', () => {
            abortEventTriggered = true;
          });
          return new Promise((_, reject) => {
            sig.addEventListener('abort', () => {
              const e = new Error('AbortError');
              e.name = 'AbortError';
              reject(e);
            });
          });
        },
      },
    };

    await executeModelWithResilience({
      ai: timeoutAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 100,
      contents: 'prompt',
      fallbackGenerator: () => ({ status: 'fallback' }),
    });

    assert(abortEventTriggered === true, 'T3.1: AbortController.signal actually emitted abort event to SDK');
  }

  // -------------------------------------------------------------------------
  // TEST 4: SDK çağrısı iptal sinyalini kabul etmiyorsa sistem sahte iptal iddia etmemeli
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 4: Non-abortable SDK call does not fake transport cancellation ---${RESET}`);
  {
    // A faulty client that ignores config.abortSignal entirely
    const nonCancellingAi = {
      models: {
        generateContent: async (_params: any) => {
          // Never checks config.abortSignal, just fails after 200ms with a generic error
          await new Promise((r) => setTimeout(r, 200));
          throw new Error('Connection refused by downstream');
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: nonCancellingAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 100,
      contents: 'prompt',
      fallbackGenerator: () => ({ status: 'fallback' }),
    });

    // Timeout fired at 100ms, abort was sent, but error returned was after timeout
    assert(res.fallbackActive === true, 'T4.1: Fallback invoked');
    assert(res.serverBillingStoppageGuaranteed === false, 'T4.2: Server billing stoppage NEVER guaranteed');
  }

  // -------------------------------------------------------------------------
  // TEST 5: Model hatası fallback'e geçer ve hata türü doğru sınıflandırılır
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 5: Error classification (429, 503, invalid JSON) ---${RESET}`);
  {
    assert(
      classifyResilienceError({ status: 429 }, false, false, false) === 'RATE_LIMIT_429',
      'T5.1: HTTP 429 classified as RATE_LIMIT_429'
    );
    assert(
      classifyResilienceError({ message: 'RESOURCE_EXHAUSTED quota exceeded' }, false, false, false) === 'RATE_LIMIT_429',
      'T5.2: Quota message classified as RATE_LIMIT_429'
    );
    assert(
      classifyResilienceError({ status: 503 }, false, false, false) === 'SERVER_ERROR_5XX',
      'T5.3: HTTP 503 classified as SERVER_ERROR_5XX'
    );
    assert(
      classifyResilienceError({ message: 'The model is overloaded. Please try again later.' }, false, false, false) ===
        'NETWORK_OR_SDK_ERROR',
      'T5.4: Generic overload without 503 status classified as NETWORK_OR_SDK_ERROR'
    );
    assert(
      classifyResilienceError(new Error('SyntaxError: Unexpected token in JSON'), false, false, false) === 'INVALID_RESPONSE',
      'T5.5: JSON SyntaxError classified as INVALID_RESPONSE'
    );
    assert(
      classifyResilienceError(new Error('AbortError'), false, false, true) === 'CLIENT_ABORT',
      'T5.6: Client cancellation classified as CLIENT_ABORT'
    );
    assert(
      classifyResilienceError(new Error('AbortError'), false, true, false) === 'CLIENT_DISCONNECTED',
      'T5.7: Disconnect classified as CLIENT_DISCONNECTED'
    );
  }

  // -------------------------------------------------------------------------
  // TEST 6: Başarılı model yanıtı yanlışlıkla fallback olarak etiketlenmez
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 6: Successful model response never labeled as fallback ---${RESET}`);
  {
    const realResponseAi = {
      models: {
        generateContent: async () => ({
          text: JSON.stringify({ visualPlatform: 'FortiWeb WAF Console', status: 'OK' }),
        }),
      },
    };

    const res = await executeModelWithResilience({
      ai: realResponseAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 2000,
      contents: 'image-data',
      parseResponse: (t) => JSON.parse(t),
      fallbackGenerator: () => ({
        visualPlatform: 'Görsel Telemetri Fallback',
        fallbackLimitation: { modelCallFailed: true },
      }),
    });

    assert(res.fallbackActive === false, 'T6.1: fallbackActive is strictly false');
    assert(res.source === 'gemini-3.1-flash-lite', 'T6.2: Source is the model name');
    assert((res.result as any).visualPlatform === 'FortiWeb WAF Console', 'T6.3: Model result retained unmodified');
  }

  // -------------------------------------------------------------------------
  // TEST 7: Aynı istekte fallback iki kez çalışmaz
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 7: Idempotent Single Fallback Execution ---${RESET}`);
  {
    let fallbackCalls = 0;
    const failingAi = {
      models: {
        generateContent: async () => {
          throw new Error('Immediate upstream error');
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: failingAi,
      models: ['gemini-3.1-flash-lite', 'gemini-flash-latest'],
      timeoutMs: 500,
      contents: 'prompt',
      fallbackGenerator: () => {
        fallbackCalls++;
        return { fallbackValue: true };
      },
    });

    assert(res.fallbackActive === true, 'T7.1: Fallback active');
    assert(fallbackCalls === 1, 'T7.2: fallbackGenerator invoked exactly once (count=1)');
    assert(res.fallbackExecutionCount === 1, 'T7.3: result confirms single fallback execution');
  }

  // -------------------------------------------------------------------------
  // TEST 8: Birbirinden bağımsız iki eşzamanlı istek birbirini iptal etmez
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 8: Concurrent Isolated Requests do not cross-abort ---${RESET}`);
  {
    const req1Controller = new AbortController();
    const req2Controller = new AbortController();

    const concurrentAi = {
      models: {
        generateContent: async ({ config }: any) => {
          const sig: AbortSignal = config.abortSignal;
          return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
              resolve({ text: JSON.stringify({ req: 'completed' }) });
            }, 120);

            sig.addEventListener('abort', () => {
              clearTimeout(timer);
              const e = new Error('Aborted');
              e.name = 'AbortError';
              reject(e);
            });
          });
        },
      },
    };

    // Start both concurrently
    const p1 = executeModelWithResilience({
      ai: concurrentAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 1000,
      contents: 'p1',
      reqSignal: req1Controller.signal,
      parseResponse: (t) => JSON.parse(t),
      fallbackGenerator: () => ({ req: 'p1-fallback' }),
    });

    const p2 = executeModelWithResilience({
      ai: concurrentAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 1000,
      contents: 'p2',
      reqSignal: req2Controller.signal,
      parseResponse: (t) => JSON.parse(t),
      fallbackGenerator: () => ({ req: 'p2-fallback' }),
    });

    // Abort request 1 only after 40ms
    setTimeout(() => {
      req1Controller.abort();
    }, 40);

    const [r1, r2] = await Promise.all([p1, p2]);

    assert(r1.fallbackActive === true, 'T8.1: Request 1 aborted -> fallback active');
    assert(r1.errorType === 'CLIENT_DISCONNECTED', 'T8.2: Request 1 classified as CLIENT_DISCONNECTED');
    assert(r2.fallbackActive === false, 'T8.3: Request 2 unaffected -> success');
    assert(r2.result.req === 'completed', 'T8.4: Request 2 resolved successfully without interference');
  }

  // -------------------------------------------------------------------------
  // TEST 9: İptal edilen isteğin geç gelen sonucu kullanıcıya sunulan fallback'i ezmez
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 9: Late response from timed out promise does not override fallback ---${RESET}`);
  {
    let resolveLatePromise: (val: any) => void = () => {};
    const lateAi = {
      models: {
        generateContent: async () => {
          return new Promise((resolve) => {
            resolveLatePromise = resolve;
          });
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: lateAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 80,
      contents: 'test',
      parseResponse: (t) => JSON.parse(t),
      fallbackGenerator: () => ({ source: 'deterministic-truth' }),
    });

    assert(res.fallbackActive === true, 'T9.1: Fallback chosen immediately at timeout');
    assert(res.result.source === 'deterministic-truth', 'T9.2: Result is deterministic fallback');

    // Now resolve the hung promise late with "malicious / late" payload
    try {
      resolveLatePromise({ text: JSON.stringify({ source: 'late-hijack' }) });
    } catch {}

    // Verify original result object is completely untouched
    assert(res.result.source === 'deterministic-truth', 'T9.3: Fallback result cannot be overwritten late');
  }

  // -------------------------------------------------------------------------
  // TEST 10: Timeout ve retry birleşimi tanımlanan gecikme sınırlarını aşmaz
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 10: Strict Latency Bound (attempts=1 prevents multi-retry sprawl) ---${RESET}`);
  {
    const start = Date.now();
    const delayedAi = {
      models: {
        generateContent: async ({ config }: any) => {
          assert(config?.httpOptions?.retryOptions?.attempts === 1, 'T10.1: retry attempts strictly bounded to 1');
          return new Promise((_, reject) => {
            config.abortSignal.addEventListener('abort', () => {
              const e = new Error('Abort');
              e.name = 'AbortError';
              reject(e);
            });
          });
        },
      },
    };

    const timeoutLimit = 200;
    await executeModelWithResilience({
      ai: delayedAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: timeoutLimit,
      contents: 'prompt',
      fallbackGenerator: () => ({ status: 'safe' }),
    });

    const elapsed = Date.now() - start;
    // Must be close to 200ms, definitely not 2000ms+ (which would happen with 5 exponential retries)
    assert(elapsed < timeoutLimit + 100, `T10.2: Elapsed ${elapsed}ms respects strict timeout boundary`);
  }

  // -------------------------------------------------------------------------
  // TEST 11: Normal tamamlanmada timer ve listener kaynakları temizlenir
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 11: Timer & Listener Cleaned Up on Normal Finish ---${RESET}`);
  {
    const reqSignal = new AbortController().signal;
    const initialListenerCount = (reqSignal as any).listenerCount ? (reqSignal as any).listenerCount('abort') : 0;

    const normalAi = {
      models: {
        generateContent: async () => ({ text: 'ok' }),
      },
    };

    const res = await executeModelWithResilience({
      ai: normalAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 5000,
      contents: 'p',
      reqSignal,
      fallbackGenerator: () => 'fallback',
    });

    assert(res.activeTimersCleared === true, 'T11.1: Timers cleared indicator confirmed');
    const finalListenerCount = (reqSignal as any).listenerCount ? (reqSignal as any).listenerCount('abort') : 0;
    assert(finalListenerCount <= initialListenerCount, 'T11.2: Event listener cleanly detached from reqSignal');
  }

  // -------------------------------------------------------------------------
  // TEST 12: Gerçek Taşıma Katmanı (Node.js HTTP Server + Fetch Abort) Doğrulaması
  // -------------------------------------------------------------------------
  console.log(`\n${YELLOW}--- TEST 12: Real Transport-Layer Cancellation via Node HTTP & AbortSignal ---${RESET}`);
  {
    let serverSocketDestroyed = false;
    let requestReceivedOnServer = false;

    // Create an ephemeral local HTTP server to receive the transport request
    const server = http.createServer((req, res) => {
      requestReceivedOnServer = true;
      req.on('close', () => {
        // Socket closed by client
        serverSocketDestroyed = true;
      });
      // Deliberately hold request open for 5 seconds without responding
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        }
      }, 5000);
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as any).port;
    const testUrl = `http://127.0.0.1:${port}/mock-gemini-endpoint`;

    // AI client that performs real HTTP fetch using the passed config.abortSignal
    const realHttpTransportAi = {
      models: {
        generateContent: async ({ config }: any) => {
          const fetchResponse = await fetch(testUrl, {
            method: 'POST',
            body: JSON.stringify({ contents: 'test' }),
            signal: config.abortSignal, // Real transport level binding!
          });
          const text = await fetchResponse.text();
          return { text };
        },
      },
    };

    const res = await executeModelWithResilience({
      ai: realHttpTransportAi,
      models: ['gemini-3.1-flash-lite'],
      timeoutMs: 150, // Times out after 150ms while server holds for 5000ms
      contents: 'test',
      fallbackGenerator: () => ({ fallback: true }),
    });

    // Give 50ms for socket close event on local loopback
    await new Promise((r) => setTimeout(r, 60));
    server.close();

    assert(requestReceivedOnServer === true, 'T12.1: Real HTTP request arrived at transport listener');
    assert(res.fallbackActive === true, 'T12.2: Fallback activated due to transport timeout');
    assert(res.errorType === 'TIMEOUT', 'T12.3: Error type classified as TIMEOUT');
    assert(res.transportAborted === true, 'T12.4: Transport abort flag confirmed');
    assert(serverSocketDestroyed === true, 'T12.5: Server confirmed client aborted socket at transport layer!');
    assert(res.serverBillingStoppageGuaranteed === false, 'T12.6: Server billing stoppage accurately flagged as NOT guaranteed');
  }

  // -------------------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------------------
  console.log(`\n${CYAN}================================================================${RESET}`);
  console.log(`TOTAL AUDIT CHECKS: ${passCount + failCount}`);
  console.log(`PASSED: ${GREEN}${passCount}${RESET}`);
  console.log(`FAILED: ${failCount > 0 ? RED : GREEN}${failCount}${RESET}`);
  console.log(`${CYAN}================================================================${RESET}\n`);

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((e) => {
  console.error('Test execution error:', e);
  process.exit(1);
});
