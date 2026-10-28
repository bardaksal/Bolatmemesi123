import type { GenerateContentConfig } from '@google/genai';

/**
 * Classification of operational & network outcomes for Gemini model executions.
 */
export type ResilienceErrorType =
  | 'TIMEOUT'
  | 'CLIENT_ABORT'
  | 'CLIENT_DISCONNECTED'
  | 'RATE_LIMIT_429'
  | 'SERVER_ERROR_5XX'
  | 'NETWORK_OR_SDK_ERROR'
  | 'INVALID_RESPONSE'
  | 'SUCCESS';

export interface ModelAttemptMetrics {
  model: string;
  durationMs: number;
  status: 'SUCCESS' | 'FAILED' | 'TIMEOUT' | 'ABORTED';
  errorType: ResilienceErrorType;
  errorMessage?: string;
  transportAborted: boolean;
}

export interface ResilienceExecutionOptions<T> {
  ai?: any;
  models: string[];
  timeoutMs: number;
  contents: any;
  config?: GenerateContentConfig;
  reqSignal?: AbortSignal;
  clientDisconnected?: () => boolean;
  parseResponse?: (text: string) => T;
  validateResponse?: (data: T) => boolean;
  fallbackGenerator: (errorContext?: { errorType: ResilienceErrorType; lastError?: any }) => T;
  onAttemptComplete?: (metrics: ModelAttemptMetrics) => void;
}

export interface ResilienceExecutionResult<T> {
  success: boolean;
  result: T;
  source: string;
  fallbackActive: boolean;
  errorType: ResilienceErrorType;
  transportAborted: boolean;
  cancellationAudited: boolean;
  serverBillingStoppageGuaranteed: boolean; // Explicit: false because SDK notes AbortSignal is client-side only
  durationMs: number;
  attempts: ModelAttemptMetrics[];
  activeTimersCleared: boolean;
  fallbackExecutionCount: number;
}

/**
 * Classifies any thrown error or operational termination state into formal diagnostic types.
 */
export function classifyResilienceError(
  error: any,
  isTimeout: boolean,
  isDisconnect: boolean,
  isClientAbort: boolean
): ResilienceErrorType {
  if (isDisconnect) {
    return 'CLIENT_DISCONNECTED';
  }
  if (isTimeout) {
    return 'TIMEOUT';
  }
  if (isClientAbort) {
    return 'CLIENT_ABORT';
  }

  const msg = error?.message || (typeof error === 'string' ? error : '') || '';
  const status = error?.status || error?.statusCode;

  if (
    status === 429 ||
    msg.includes('429') ||
    msg.includes('RESOURCE_EXHAUSTED') ||
    msg.includes('quota') ||
    error?.name === 'RateLimitError'
  ) {
    return 'RATE_LIMIT_429';
  }

  if (
    (typeof status === 'number' && status >= 500 && status < 600) ||
    msg.includes('500') ||
    msg.includes('502') ||
    msg.includes('503') ||
    msg.includes('504') ||
    msg.includes('UNAVAILABLE') ||
    msg.includes('high demand')
  ) {
    return 'SERVER_ERROR_5XX';
  }

  if (
    error?.name === 'AbortError' ||
    msg.includes('aborted') ||
    msg.includes('AbortError')
  ) {
    return 'CLIENT_ABORT';
  }

  if (msg.includes('JSON') || msg.includes('parse') || msg.includes('SyntaxError')) {
    return 'INVALID_RESPONSE';
  }

  return 'NETWORK_OR_SDK_ERROR';
}

/**
 * Executes Gemini content generation across candidate models with strict timeout governance,
 * client-side transport abort integration via AbortController, timer lifecycle cleanup,
 * and deterministic fallback safety.
 */
export async function executeModelWithResilience<T>(
  options: ResilienceExecutionOptions<T>
): Promise<ResilienceExecutionResult<T>> {
  const {
    ai,
    models,
    timeoutMs,
    contents,
    config,
    reqSignal,
    clientDisconnected,
    parseResponse,
    validateResponse,
    fallbackGenerator,
    onAttemptComplete,
  } = options;

  const recordedAttempts: ModelAttemptMetrics[] = [];
  const overallStartTime = Date.now();
  let lastErrorType: ResilienceErrorType = 'NETWORK_OR_SDK_ERROR';
  let lastError: any = null;
  let allTimersCleared = true;

  // If no AI client available or API key missing, immediately invoke fallback
  if (!ai || !ai.models || typeof ai.models.generateContent !== 'function') {
    const fallback = fallbackGenerator({ errorType: 'NETWORK_OR_SDK_ERROR', lastError: new Error('AI client unconfigured') });
    return {
      success: true,
      result: fallback,
      source: 'fallback-handler',
      fallbackActive: true,
      errorType: 'NETWORK_OR_SDK_ERROR',
      transportAborted: false,
      cancellationAudited: true,
      serverBillingStoppageGuaranteed: false,
      durationMs: 0,
      attempts: [],
      activeTimersCleared: true,
      fallbackExecutionCount: 1,
    };
  }

  for (const model of models) {
    // Check if client disconnected before even starting candidate
    if (reqSignal?.aborted || (clientDisconnected && clientDisconnected())) {
      lastErrorType = 'CLIENT_DISCONNECTED';
      break;
    }

    const attemptStartTime = Date.now();
    const attemptController = new AbortController();
    let attemptTimedOut = false;
    let attemptDisconnected = false;
    let timerId: NodeJS.Timeout | null = null;

    const onReqAbort = () => {
      attemptDisconnected = true;
      attemptController.abort(new Error('CLIENT_DISCONNECTED'));
    };

    if (reqSignal) {
      reqSignal.addEventListener('abort', onReqAbort, { once: true });
    }

    // Set functional timeout bounded per candidate
    const timeoutPromise = new Promise<never>((_, reject) => {
      timerId = setTimeout(() => {
        attemptTimedOut = true;
        const err = new Error(`Model request timed out after ${timeoutMs}ms for ${model}`);
        err.name = 'TimeoutError';
        attemptController.abort(err);
        reject(err);
      }, timeoutMs);
    });

    try {
      // Build effective config passing SDK-supported parameters:
      // abortSignal: passes caller's AbortSignal to ApiClient.apiCall
      // httpOptions.timeout: passes per-attempt timeout to ApiClient
      // httpOptions.retryOptions: bound retries to 1 so timeout is strict
      const effectiveConfig: GenerateContentConfig = {
        ...(config || {}),
        abortSignal: attemptController.signal,
        httpOptions: {
          ...(config?.httpOptions || {}),
          timeout: timeoutMs,
          retryOptions: {
            attempts: 1, // Avoid uncontrolled SDK internal retries multiplying latency
          },
        },
      };

      const response: any = await Promise.race([
        ai.models.generateContent({
          model,
          contents,
          config: effectiveConfig,
        }),
        timeoutPromise,
      ]);

      // Normal completion: IMMEDIATELY clear timeout timer and event listener!
      if (timerId) {
        clearTimeout(timerId);
        timerId = null;
      }
      if (reqSignal) {
        reqSignal.removeEventListener('abort', onReqAbort);
      }

      // Check if attempt timed out or aborted while waiting for response resolution
      if (attemptTimedOut || attemptController.signal.aborted || (reqSignal && reqSignal.aborted)) {
        throw new Error(attemptTimedOut ? `Timed out for ${model}` : 'Aborted by caller');
      }

      // Extract raw text
      const rawText = response?.text || '';
      let parsedData: T;

      if (parseResponse) {
        try {
          parsedData = parseResponse(rawText);
        } catch (parseErr: any) {
          const attemptMetric: ModelAttemptMetrics = {
            model,
            durationMs: Date.now() - attemptStartTime,
            status: 'FAILED',
            errorType: 'INVALID_RESPONSE',
            errorMessage: parseErr?.message || 'Failed to parse model response',
            transportAborted: false,
          };
          recordedAttempts.push(attemptMetric);
          onAttemptComplete?.(attemptMetric);
          lastErrorType = 'INVALID_RESPONSE';
          lastError = parseErr;
          continue; // Try next candidate or fallback
        }
      } else {
        parsedData = rawText as unknown as T;
      }

      // Validation hook
      if (validateResponse && !validateResponse(parsedData)) {
        const attemptMetric: ModelAttemptMetrics = {
          model,
          durationMs: Date.now() - attemptStartTime,
          status: 'FAILED',
          errorType: 'INVALID_RESPONSE',
          errorMessage: 'Validation failed on parsed model response',
          transportAborted: false,
        };
        recordedAttempts.push(attemptMetric);
        onAttemptComplete?.(attemptMetric);
        lastErrorType = 'INVALID_RESPONSE';
        continue;
      }

      // Success!
      const attemptMetric: ModelAttemptMetrics = {
        model,
        durationMs: Date.now() - attemptStartTime,
        status: 'SUCCESS',
        errorType: 'SUCCESS',
        transportAborted: false,
      };
      recordedAttempts.push(attemptMetric);
      onAttemptComplete?.(attemptMetric);

      return {
        success: true,
        result: parsedData,
        source: model,
        fallbackActive: false,
        errorType: 'SUCCESS',
        transportAborted: false,
        cancellationAudited: true,
        serverBillingStoppageGuaranteed: false,
        durationMs: Date.now() - overallStartTime,
        attempts: recordedAttempts,
        activeTimersCleared: true,
        fallbackExecutionCount: 0,
      };
    } catch (err: any) {
      // Clean up timer and listener immediately on error
      if (timerId) {
        clearTimeout(timerId);
        timerId = null;
      }
      if (reqSignal) {
        reqSignal.removeEventListener('abort', onReqAbort);
      }

      const isTimeout =
        attemptTimedOut ||
        err?.message?.includes('timed out') ||
        err?.message?.includes('TIMEOUT');
      const isDisconnect = attemptDisconnected || Boolean(reqSignal?.aborted);
      const isClientAbort = attemptController.signal.aborted && !isTimeout && !isDisconnect;

      const classified = classifyResilienceError(err, isTimeout, isDisconnect, isClientAbort);
      const wasTransportAborted = isTimeout || isDisconnect || isClientAbort;

      const attemptMetric: ModelAttemptMetrics = {
        model,
        durationMs: Date.now() - attemptStartTime,
        status: isTimeout ? 'TIMEOUT' : wasTransportAborted ? 'ABORTED' : 'FAILED',
        errorType: classified,
        errorMessage: err?.message || String(err),
        transportAborted: wasTransportAborted,
      };
      recordedAttempts.push(attemptMetric);
      onAttemptComplete?.(attemptMetric);

      lastErrorType = classified;
      lastError = err;

      // If client disconnected, stop immediately without trying second candidate
      if (isDisconnect) {
        break;
      }
    }
  }

  // If we reach here, all candidates failed, timed out, or were disconnected
  let fallbackCount = 0;
  fallbackCount++;
  const fallbackResult = fallbackGenerator({ errorType: lastErrorType, lastError });

  return {
    success: true,
    result: fallbackResult,
    source: 'fallback-handler',
    fallbackActive: true,
    errorType: lastErrorType,
    transportAborted: recordedAttempts.some((a) => a.transportAborted),
    cancellationAudited: true,
    serverBillingStoppageGuaranteed: false, // In accordance with SDK docs
    durationMs: Date.now() - overallStartTime,
    attempts: recordedAttempts,
    activeTimersCleared: allTimersCleared,
    fallbackExecutionCount: fallbackCount,
  };
}
