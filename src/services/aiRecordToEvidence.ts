import {
  UniversalEvidence,
  FieldObservation,
  SourceType,
} from '../types/investigationEvidence';
import { RecordValidationResult, FieldValidationResult } from '../types/aiLogUnderstanding';
import { assessInputAdmissibility } from './universalEvidenceExtractor';
import { WINDOWS_EVENT_NAMES, WINDOWS_SUBSTATUS_MAP, WINDOWS_LOGON_TYPE_MAP } from './quickTriageHelper';

function createObservation<T = string | number | null>(
  val: T,
  rawVal: string | null | undefined,
  status: FieldObservation['status'],
  sourceSpanStr?: string,
  method: any = 'VISUAL_READING'
): FieldObservation<T> {
  return {
    value: val,
    rawValue: rawVal !== undefined ? rawVal : (val !== null ? String(val) : null),
    status,
    sourceType: 'TEXT_LOG',
    extractionMethod: method,
    sourceReference: sourceSpanStr,
  };
}

const notPresentObs = <T>(ref?: string): FieldObservation<T> =>
  createObservation<T>(null as any, null, 'NOT_PRESENT', ref, 'DIRECT_KEY_VALUE');

const notAssessedObs = <T>(ref?: string): FieldObservation<T> =>
  createObservation<T>(null as any, null, 'NOT_ASSESSED', ref, 'DIRECT_KEY_VALUE');

/**
 * Transforms a validated AI record into a canonical UniversalEvidence instance.
 * Strictly preserves field statuses (OBSERVED, DERIVED, UNCERTAIN, NOT_PRESENT, NOT_ASSESSED)
 * and attaches precise raw-span provenance.
 */
export function convertAiRecordToUniversalEvidence(
  rec: RecordValidationResult,
  formatHint: string = 'UNKNOWN'
): UniversalEvidence {
  const rawText = rec.rawText || '';
  const admissibility = assessInputAdmissibility(rawText);

  // Map fields by name (case-insensitive)
  const fieldsMap = new Map<string, FieldValidationResult>();
  (rec.fields || []).forEach((f) => {
    fieldsMap.set(f.fieldName.toLowerCase(), f);
  });

  const getF = (...names: string[]): FieldValidationResult | undefined => {
    for (const n of names) {
      const match = fieldsMap.get(n.toLowerCase());
      if (match) return match;
    }
    return undefined;
  };

  const toObs = <T = string | null>(
    field: FieldValidationResult | undefined,
    converter?: (v: string) => T
  ): FieldObservation<T> => {
    if (!field || field.validatedStatus === 'NOT_PRESENT') {
      return notPresentObs<T>();
    }
    if (field.validatedStatus === 'NOT_ASSESSED') {
      return notAssessedObs<T>();
    }
    if (field.decision === 'REJECTED') {
      return createObservation<T>(
        null as any,
        field.value,
        'UNCERTAIN',
        field.rejectionReason,
        'HEURISTIC'
      );
    }

    const spanStr = field.resolvedSourceSpan
      ? `[span ${field.resolvedSourceSpan.start}..${field.resolvedSourceSpan.end}]`
      : undefined;

    const typedVal: T = converter ? converter(field.value) : (field.value as any);

    return createObservation<T>(
      typedVal,
      field.value,
      field.validatedStatus,
      spanStr,
      field.validatedStatus === 'OBSERVED' ? 'DIRECT_KEY_VALUE' : 'DERIVED_TRANSLATION'
    );
  };

  // 1. ACTOR & USER
  const userField = getF('user', 'username', 'account', 'actor', 'targetusername', 'subjectusername', 'targetuser', 'kullanici');
  const subjectUserField = getF('subjectuser', 'subjectusername', 'caller', 'creator');

  const actorObs = toObs<string | null>(userField);
  const subjectUserObs = toObs<string | null>(subjectUserField);

  // 2. ENDPOINTS
  const srcIpField = getF('sourceip', 'srcip', 'src', 'clientip', 'client_ip', 'c-ip', 'ip', 'source');
  const srcPortField = getF('sourceport', 'srcport', 'sport');
  const dstIpField = getF('destinationip', 'dstip', 'dst', 'serverip', 'destination');
  const dstPortField = getF('destinationport', 'dstport', 'dport', 'port');
  const hostField = getF('host', 'hostname', 'computer', 'workstation', 'server');

  const srcIpObs = toObs<string | null>(srcIpField);
  const srcPortObs = toObs<number | null>(srcPortField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const dstIpObs = toObs<string | null>(dstIpField);
  const dstPortObs = toObs<number | null>(dstPortField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const hostObs = toObs<string | null>(hostField);

  // 3. ACTION & OUTCOME
  const secDevActionField = getF('securitydeviceaction', 'device_action', 'waf_action');
  const actionField = getF('action', 'act', 'policy_action', 'disposition');
  const outcomeField = getF('outcome', 'result', 'status');
  const authOutcomeField = getF('authenticationoutcome', 'auth_outcome');

  const actionObs = toObs<string | null>(actionField);

  // Security Device Action is strictly preserved ONLY for actual security enforcement telemetry
  const isSecurityDeviceFormat = /Fortinet|WAF|Firewall|CEF|LEEF/i.test(formatHint) && !/Linux|OpenSSH|sshd|nginx|apache|postfix|sudo/i.test(formatHint);
  const explicitSecDevAction = secDevActionField || (isSecurityDeviceFormat ? actionField : undefined);
  const wafActionObs = toObs<string | null>(explicitSecDevAction);

  let outcomeVal: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN' = 'UNKNOWN';
  let outcomeStatus: FieldObservation['status'] = 'NOT_ASSESSED';

  // True Security Device Block verification
  const isExplicitSecDevBlock = Boolean(
    explicitSecDevAction &&
    explicitSecDevAction.decision === 'ACCEPTED' &&
    /^(?:drop|deny|block|reject|reset|prevent|blocked)$/i.test(explicitSecDevAction.value.trim())
  );

  if (isExplicitSecDevBlock) {
    outcomeVal = 'BLOCKED';
    outcomeStatus = 'OBSERVED';
  } else if (authOutcomeField && authOutcomeField.decision === 'ACCEPTED') {
    outcomeVal = authOutcomeField.value.toUpperCase().includes('FAIL') ? 'FAILURE' : 'SUCCESS';
    outcomeStatus = 'DERIVED';
  } else if (outcomeField && outcomeField.decision === 'ACCEPTED') {
    const v = outcomeField.value.toUpperCase();
    if (isSecurityDeviceFormat && (v.includes('BLOCK') || v.includes('DENY') || v.includes('DROP') || v.includes('RESET'))) {
      outcomeVal = 'BLOCKED';
      outcomeStatus = 'OBSERVED';
    } else if (v.includes('FAIL') || v.includes('REJECT') || v.includes('DENIED') || v.includes('401') || v.includes('403') || v.includes('500')) {
      outcomeVal = 'FAILURE';
      outcomeStatus = 'DERIVED';
    } else if (v.includes('SUCCESS') || v.includes('ALLOW') || v.includes('ACCEPT') || v.includes('200')) {
      outcomeVal = 'SUCCESS';
      outcomeStatus = 'DERIVED';
    }
  } else if (actionField && actionField.decision === 'ACCEPTED') {
    const act = actionField.value.toUpperCase();
    if (isSecurityDeviceFormat && (act.includes('BLOCK') || act.includes('DENY') || act.includes('DROP') || act.includes('RESET'))) {
      outcomeVal = 'BLOCKED';
      outcomeStatus = 'OBSERVED';
    } else if (act.includes('ALLOW') || act.includes('ACCEPT') || act.includes('PASS')) {
      outcomeVal = 'SUCCESS';
      outcomeStatus = 'DERIVED';
    } else if (act.includes('DISCONNECT') || act.includes('DENY') || act.includes('FAIL')) {
      outcomeVal = 'FAILURE';
      outcomeStatus = 'DERIVED';
    }
  }

  const outcomeObs: FieldObservation<'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'UNKNOWN'> = {
    value: outcomeVal,
    rawValue: outcomeField?.value || actionField?.value || null,
    status: outcomeStatus,
    sourceType: 'TEXT_LOG',
    extractionMethod: 'DERIVED_TRANSLATION',
  };

  // 4. TIMESTAMP
  const timeField = getF('timestamp', 'time', 'date', 'datetime', '@timestamp');
  const timestampObs = toObs<string | null>(timeField);

  // 5. PROCESS & HTTP DISAMBIGUATION (HTTP Request ≠ CommandLine)
  const httpMethodField = getF('httpmethod', 'method', 'cs-method');
  const httpUriField = getF('httprequesturi', 'uri', 'rawpayload', 'url', 'cs-uri-stem');
  const isHttpTelemetry = Boolean(httpMethodField || httpUriField || /Apache|Nginx|IIS/i.test(formatHint));

  const procField = getF('process', 'image', 'processname', 'binary');
  const pidField = getF('pid', 'processid');
  const cmdField = isHttpTelemetry ? undefined : getF('commandline', 'command', 'cmd', 'processcommandline', 'args');
  const parentField = getF('parentprocess', 'parentimage', 'parentcommandline');

  const procNameObs = toObs<string | null>(procField);
  const pidObs = toObs<number | null>(pidField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const cmdLineObs = isHttpTelemetry ? notPresentObs<string | null>() : toObs<string | null>(cmdField);
  const parentProcObs = toObs<string | null>(parentField);

  // 6. TELEMETRY
  const eventIdField = getF('eventid', 'event_id', 'eventcode');
  const subStatusField = getF('substatus', 'sub_status');
  const logonTypeField = getF('logontype', 'logon_type');
  const httpStatusField = getF('httpstatus', 'status_code', 'http_status');
  const rawPayloadField = httpUriField || getF('rawpayload', 'payload', 'request');
  const serviceNameField = getF('servicename', 'service_name');
  const protoField = httpMethodField || getF('protocol', 'proto');

  const eventIdObs = toObs<number | null>(eventIdField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const subStatusObs = toObs<string | null>(subStatusField);
  const logonTypeObs = toObs<number | null>(logonTypeField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const httpStatusObs = toObs<number | null>(httpStatusField, (v) => (!isNaN(parseInt(v, 10)) ? parseInt(v, 10) : (null as any)));
  const rawPayloadObs = toObs<string | null>(rawPayloadField);
  const serviceNameObs = toObs<string | null>(serviceNameField);
  const protoObs = toObs<string | null>(protoField);

  const eventNameObs = eventIdObs.value && WINDOWS_EVENT_NAMES[eventIdObs.value]
    ? createObservation(WINDOWS_EVENT_NAMES[eventIdObs.value].name, null, 'DERIVED', 'WINDOWS_EVENT_NAMES')
    : notPresentObs<string | null>();

  const subStatusDesc = subStatusObs.value && WINDOWS_SUBSTATUS_MAP[subStatusObs.value.toUpperCase()]
    ? createObservation(WINDOWS_SUBSTATUS_MAP[subStatusObs.value.toUpperCase()], null, 'DERIVED', 'WINDOWS_SUBSTATUS_MAP')
    : notPresentObs<string | null>();

  // Collect unparsed fields
  const unparsedFields: Record<string, string> = {};
  (rec.fields || []).forEach((f) => {
    unparsedFields[f.fieldName] = f.value;
  });

  return {
    admissibility,
    rawContent: rawText,
    actor: actorObs,
    subjectUser: subjectUserObs,
    sourceEndpoint: {
      ip: srcIpObs,
      port: srcPortObs,
      host: notPresentObs(),
    },
    destinationEndpoint: {
      ip: dstIpObs,
      port: dstPortObs,
      host: hostObs,
    },
    action: actionObs,
    outcome: outcomeObs,
    timestamp: timestampObs,
    process: {
      name: procNameObs,
      pid: pidObs,
      commandLine: cmdLineObs,
      parentProcess: parentProcObs,
    },
    telemetry: {
      protocol: protoObs,
      httpStatus: httpStatusObs,
      wafAction: wafActionObs,
      errorCode: notPresentObs(),
      errorDescription: subStatusDesc,
      rawPayload: rawPayloadObs,
      eventId: eventIdObs,
      eventName: eventNameObs,
      logonType: logonTypeObs,
      subStatus: subStatusObs,
      serviceName: serviceNameObs,
    },
    unparsedFields,
  };
}
