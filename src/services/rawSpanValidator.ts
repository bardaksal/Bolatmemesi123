import {
  AiLogStructureResponse,
  AiRecord,
  AiField,
  LogUnderstandingValidationReport,
  RecordValidationResult,
  FieldValidationResult,
  SourceSpan,
} from '../types/aiLogUnderstanding';

/**
 * PHASE 4 — DETERMINISTIC RAW-SPAN VALIDATOR
 *
 * Enforces strict provenance and zero-hallucination rules:
 * 1. Verifies raw input span boundaries [rawStart, rawEnd]
 * 2. Checks exact substring provenance between raw input and rawText
 * 3. Detects illegal record overlap across logical events
 * 4. Verifies every claimed field value actually exists inside the record's raw span
 * 5. Identifies and REJECTS hallucinated fields
 * 6. Identifies and REJECTS cross-event data contamination
 * 7. Enforces that missing fields are explicitly NOT_PRESENT / NOT_ASSESSED
 */
export function validateAiLogStructure(
  rawInput: string,
  aiResponse: AiLogStructureResponse
): LogUnderstandingValidationReport {
  const inputLen = rawInput.length;
  const records = aiResponse.records || [];
  const validatedRecords: RecordValidationResult[] = [];

  let hallucinationsDetected = 0;
  let crossEventContaminationsDetected = 0;
  let acceptedRecordsCount = 0;
  let rejectedRecordsCount = 0;
  let uncertainRecordsCount = 0;
  let hasOverlappingRecords = false;

  // Build an index of all distinct field values per record for cross-contamination checking
  const recordValuesMap = new Map<number, Set<string>>();
  records.forEach((rec) => {
    const valSet = new Set<string>();
    (rec.fields || []).forEach((f) => {
      if (f.value && f.status === 'OBSERVED') {
        const v = String(f.value).trim().toLowerCase();
        if (v.length > 2 && v !== 'true' && v !== 'false' && v !== 'null') {
          valSet.add(v);
        }
      }
    });
    recordValuesMap.set(rec.recordIndex, valSet);
  });

  // Sort records by rawStart for linear overlap checking
  const sortedRecords = [...records].sort((a, b) => a.rawStart - b.rawStart);

  for (let i = 0; i < sortedRecords.length; i++) {
    const rec = sortedRecords[i];
    const reasons: string[] = [];
    let spanIntegrity: RecordValidationResult['spanIntegrity'] = 'VALID';
    let recordStatus: RecordValidationResult['recordStatus'] = 'ACCEPTED';

    // 1. Boundary sanity check
    if (
      typeof rec.rawStart !== 'number' ||
      typeof rec.rawEnd !== 'number' ||
      isNaN(rec.rawStart) ||
      isNaN(rec.rawEnd) ||
      rec.rawStart < 0 ||
      rec.rawEnd > inputLen ||
      rec.rawStart >= rec.rawEnd
    ) {
      spanIntegrity = 'OUT_OF_BOUNDS';
      recordStatus = 'REJECTED';
      reasons.push(
        `Geçersiz aralık sınırları: [start=${rec.rawStart}, end=${rec.rawEnd}], toplam girdi uzunluğu: ${inputLen}.`
      );
    }

    // 2. Exact or normalized text match with rawInput span
    let expectedSlice = '';
    if (spanIntegrity === 'VALID') {
      expectedSlice = rawInput.slice(rec.rawStart, rec.rawEnd);
      const cleanExpected = expectedSlice.replace(/\r\n/g, '\n').trim();
      const cleanActual = (rec.rawText || '').replace(/\r\n/g, '\n').trim();

      if (cleanExpected !== cleanActual) {
        // Check if substring exists close by or is a complete mismatch
        const exactIdx = rawInput.indexOf(cleanActual);
        if (exactIdx !== -1 && Math.abs(exactIdx - rec.rawStart) < 20) {
          // Micro-drift in index: auto-correct boundaries
          rec.rawStart = exactIdx;
          rec.rawEnd = exactIdx + cleanActual.length;
          expectedSlice = rawInput.slice(rec.rawStart, rec.rawEnd);
        } else {
          spanIntegrity = 'TEXT_MISMATCH';
          recordStatus = 'UNCERTAIN';
          reasons.push('Span içindeki ham girdi metni ile record.rawText birebir uyuşmuyor.');
        }
      }
    }

    // 3. Overlap check with previous record
    if (i > 0) {
      const prevRec = sortedRecords[i - 1];
      if (rec.rawStart < prevRec.rawEnd) {
        hasOverlappingRecords = true;
        spanIntegrity = 'OVERLAPPING';
        recordStatus = 'UNCERTAIN';
        reasons.push(
          `Olaylar arasında örtüşme (overlap) saptandı: Olay #${rec.recordIndex} (start=${rec.rawStart}), Olay #${prevRec.recordIndex} (end=${prevRec.rawEnd}) sınırından önce başlıyor.`
        );
      }
    }

    // 4. Validate each field within the record's raw span
    const recordSpanText = rec.rawText || expectedSlice || '';
    const fieldResults: FieldValidationResult[] = [];
    let acceptedFieldsCount = 0;
    let rejectedFieldsCount = 0;
    let recHallucinations = 0;
    let recCrossContaminations = 0;

    const fields = rec.fields || [];

    for (const f of fields) {
      const rawVal = f.value !== null && f.value !== undefined ? String(f.value).trim() : '';
      const claimedStatus = f.status || 'OBSERVED';

      // Case A: Field is claimed NOT_PRESENT or NOT_ASSESSED
      if (claimedStatus === 'NOT_PRESENT' || claimedStatus === 'NOT_ASSESSED') {
        fieldResults.push({
          fieldName: f.name,
          value: rawVal,
          claimedStatus,
          validatedStatus: claimedStatus,
          decision: 'ACCEPTED',
          sourceSpanValid: true,
          foundInRawSpan: false,
          isCrossEventContaminated: false,
          isHallucinated: false,
        });
        acceptedFieldsCount++;
        continue;
      }

      // Case B: Field is claimed OBSERVED or DERIVED
      // Substring check: Does rawVal exist in this record's raw text?
      const posInSpan = recordSpanText.indexOf(rawVal);
      const foundInRaw = rawVal.length > 0 && posInSpan !== -1;

      // Check sourceSpan if provided
      let sourceSpanValid = false;
      let resolvedSpan: SourceSpan | undefined = undefined;

      if (f.sourceSpan && typeof f.sourceSpan.start === 'number' && typeof f.sourceSpan.end === 'number') {
        // Can be relative to rawText or absolute to rawInput
        const relSlice = recordSpanText.slice(f.sourceSpan.start, f.sourceSpan.end);
        const absSlice = rawInput.slice(f.sourceSpan.start, f.sourceSpan.end);

        if (relSlice === rawVal) {
          sourceSpanValid = true;
          resolvedSpan = {
            start: rec.rawStart + f.sourceSpan.start,
            end: rec.rawStart + f.sourceSpan.end,
          };
        } else if (absSlice === rawVal && f.sourceSpan.start >= rec.rawStart && f.sourceSpan.end <= rec.rawEnd) {
          sourceSpanValid = true;
          resolvedSpan = f.sourceSpan;
        }
      } else if (foundInRaw) {
        sourceSpanValid = true;
        resolvedSpan = {
          start: rec.rawStart + posInSpan,
          end: rec.rawStart + posInSpan + rawVal.length,
        };
      }

      // Check cross-event contamination:
      // Does this value belong to another record, while being absent from current span?
      let isCrossEventContaminated = false;
      if (!foundInRaw && rawVal.length > 2) {
        const valLower = rawVal.toLowerCase();
        for (const [otherIdx, otherSet] of recordValuesMap.entries()) {
          if (otherIdx !== rec.recordIndex && otherSet.has(valLower)) {
            isCrossEventContaminated = true;
            break;
          }
        }
      }

      let decision: FieldValidationResult['decision'] = 'ACCEPTED';
      let validatedStatus = claimedStatus;
      let rejectionReason: string | undefined = undefined;
      let isHallucinated = false;

      if (!foundInRaw) {
        if (claimedStatus === 'DERIVED') {
          // Derived fields (e.g. status code 200 -> SUCCESS, Event ID 4625 -> FAILURE) can be derived without literal string
          validatedStatus = 'DERIVED';
          decision = 'ACCEPTED';
          acceptedFieldsCount++;
        } else {
          // OBSERVED but not present in raw span -> MUST BE REJECTED!
          decision = 'REJECTED';
          validatedStatus = 'UNCERTAIN';
          isHallucinated = !isCrossEventContaminated;
          if (isCrossEventContaminated) {
            recCrossContaminations++;
            rejectionReason = `Çapraz olay kontaminasyonu: "${rawVal}" değeri geçerli olay span'ında bulunamadı; başka bir olayın verisi taşınmış.`;
          } else {
            recHallucinations++;
            rejectionReason = `Halüsinasyon / Doğrulanamayan alan: "${rawVal}" değeri ilgili olayın raw span'ında mevcut değil.`;
          }
          rejectedFieldsCount++;
        }
      } else {
        acceptedFieldsCount++;
      }

      fieldResults.push({
        fieldName: f.name,
        value: rawVal,
        claimedStatus,
        validatedStatus,
        decision,
        sourceSpanValid,
        foundInRawSpan: foundInRaw,
        claimedSourceSpan: f.sourceSpan,
        resolvedSourceSpan: resolvedSpan,
        rejectionReason,
        isCrossEventContaminated,
        isHallucinated,
      });
    }

    hallucinationsDetected += recHallucinations;
    crossEventContaminationsDetected += recCrossContaminations;

    if (recCrossContaminations > 0) {
      reasons.push(`${recCrossContaminations} adet çapraz olay veri sızıntısı reddedildi.`);
    }
    if (recHallucinations > 0) {
      reasons.push(`${recHallucinations} adet ham span'da bulunmayan halüsinasyon alan reddedildi.`);
    }

    // Determine record status
    if (spanIntegrity !== 'VALID') {
      recordStatus = spanIntegrity === 'OUT_OF_BOUNDS' ? 'REJECTED' : 'UNCERTAIN';
    } else if (recCrossContaminations > 0 || recHallucinations > 0) {
      recordStatus = 'UNCERTAIN';
    } else {
      recordStatus = 'ACCEPTED';
    }

    if (recordStatus === 'ACCEPTED') acceptedRecordsCount++;
    else if (recordStatus === 'REJECTED') rejectedRecordsCount++;
    else uncertainRecordsCount++;

    validatedRecords.push({
      recordIndex: rec.recordIndex,
      rawStart: rec.rawStart,
      rawEnd: rec.rawEnd,
      rawText: rec.rawText,
      spanIntegrity,
      recordStatus,
      fields: fieldResults,
      acceptedFieldsCount,
      rejectedFieldsCount,
      hallucinatedFieldsCount: recHallucinations,
      crossContaminatedFieldsCount: recCrossContaminations,
      reasons,
    });
  }

  const totalCandidateRecords = records.length;
  const totalFields = validatedRecords.reduce((acc, r) => acc + r.fields.length, 0);
  const totalAcceptedFields = validatedRecords.reduce((acc, r) => acc + r.acceptedFieldsCount, 0);
  const provenanceAdherenceRate =
    totalFields > 0 ? Math.round((totalAcceptedFields / totalFields) * 100) : 100;

  const overallValidationStatus: LogUnderstandingValidationReport['overallValidationStatus'] =
    hallucinationsDetected === 0 &&
    crossEventContaminationsDetected === 0 &&
    !hasOverlappingRecords &&
    rejectedRecordsCount === 0
      ? 'PASS'
      : acceptedRecordsCount > 0
      ? 'PARTIAL'
      : 'FAIL';

  const summaryMarkdown = `### 🛡️ Deterministik Raw-Span Doğrulama Özeti (Phase 4):
* **Toplam Mantıksal Kayıt:** ${totalCandidateRecords}
* **Doğrulanan (Kabul Edilen) Kayıt:** ${acceptedRecordsCount}
* **Belirsiz / Uyuşmazlık Kayıt:** ${uncertainRecordsCount}
* **Reddedilen Kayıt:** ${rejectedRecordsCount}
* **Raw-Span Kanıt Sadakat Oranı:** %${provenanceAdherenceRate}
* **Örtüşen Olay (Overlap):** ${hasOverlappingRecords ? '⚠️ Tespit Edildi' : '✅ Sıfır (0)'}
* **Çapraz Olay Veri Bulaşması (Cross-Event Contamination):** ${crossEventContaminationsDetected > 0 ? `⚠️ ${crossEventContaminationsDetected} adet reddedildi` : '✅ Sıfır (0)'}
* **Halüsinasyon / Uydurma Alan (Hallucinated Fields):** ${hallucinationsDetected > 0 ? `⚠️ ${hallucinationsDetected} adet reddedildi` : '✅ Sıfır (0)'}
* **Genel Doğrulama Kararı:** **${overallValidationStatus}**`;

  return {
    inputLength: inputLen,
    totalCandidateRecords,
    acceptedRecordsCount,
    rejectedRecordsCount,
    uncertainRecordsCount,
    validatedRecords,
    hasOverlappingRecords,
    hallucinationsDetected,
    crossEventContaminationsDetected,
    overallValidationStatus,
    provenanceAdherenceRate,
    summaryMarkdown,
  };
}
