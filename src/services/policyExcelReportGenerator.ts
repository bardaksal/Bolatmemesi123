import * as XLSX from 'xlsx';
import { PolicyComparisonResult } from '../types';

/**
 * Generates a comprehensive, audit-grade 14-sheet XLSX workbook
 * matching customer requirements for WAF & Firewall policy comparison.
 */
export function generatePolicyComparisonExcelWorkbook(res: PolicyComparisonResult): XLSX.WorkBook {
  const wb = XLSX.utils.book_new();

  // Helper to format percentage
  const fmtPct = (val: number | null | undefined): string => {
    if (val === null || val === undefined) return 'N/A';
    return `${val >= 0 ? '+' : ''}${val.toFixed(2)}%`;
  };

  // Helper for safe number or N/A
  const numOrNA = (val: number | 'N/A' | undefined | null): string | number => {
    if (val === 'N/A' || val === null || val === undefined) return 'N/A';
    return val;
  };

  // --------------------------------------------------------------------------
  // SHEET 1: 01_Executive_Summary
  // --------------------------------------------------------------------------
  const sheet1Data: (string | number)[][] = [
    ['WAF & GÜVENLİK POLİTİKASI DEĞİŞİKLİĞİ ETKİ ANALİZİ — YÖNETİCİ ÖZETİ'],
    ['Rapor Oluşturma Tarihi', res.analyzedAt],
    ['Veri Modu', res.isDemo ? 'DEMO / SİMÜLASYON VERİSİ' : 'GERÇEK MÜŞTERİ VERİSİ'],
    ['WAF Aksiyon Verisi Durumu', res.actionDataAvailable ? 'MEVCUT (Action Kolonu Tespit Edildi)' : 'YOK (Yalnızca HTTP Response / Count Mevcut)'],
    [],
    ['METRİK', 'DÖNEM A (ÖNCESİ / REFERANS)', 'DÖNEM B (SONRASI / GÜNCEL)', 'DEĞİŞİM (DELTA)', 'YÜZDE DEĞİŞİM'],
    ['Dönem Etiketi', res.periodALabel, res.periodBLabel, '-', '-'],
    ['Toplam Gözlem / İstek Sayısı (SUM Count)', res.totalObservationsA, res.totalObservationsB, res.totalObservationsB - res.totalObservationsA, fmtPct(res.totalObservationsA > 0 ? ((res.totalObservationsB - res.totalObservationsA) / res.totalObservationsA) * 100 : null)],
    ['ALERT Aksiyonu Olay Sayısı', res.actionDataAvailable ? (res.periodA.alertedRequests ?? 0) : 'N/A', res.actionDataAvailable ? (res.periodB.alertedRequests ?? 0) : 'N/A', res.actionDataAvailable ? (res.periodB.alertedRequests ?? 0) - (res.periodA.alertedRequests ?? 0) : 'N/A', '-'],
    ['BLOCK Aksiyonu Olay Sayısı', res.actionDataAvailable ? res.periodA.blockedRequests : 'N/A', res.actionDataAvailable ? res.periodB.blockedRequests : 'N/A', res.actionDataAvailable ? res.periodB.blockedRequests - res.periodA.blockedRequests : 'N/A', '-'],
    ['Genel WAF BLOCK Oranı', res.actionDataAvailable ? `%${res.periodA.blockRate.toFixed(2)}` : 'N/A', res.actionDataAvailable ? `%${res.periodB.blockRate.toFixed(2)}` : 'N/A', res.actionDataAvailable ? `${res.blockRateDelta >= 0 ? '+' : ''}${res.blockRateDelta.toFixed(2)} yp` : 'N/A', res.actionDataAvailable ? fmtPct(res.blockRateRelativeChangePct) : 'N/A'],
    ['Gerçek Trafik Hacmi (MB)', res.periodA.hasByteData ? `${(res.periodA.totalBytes / (1024 * 1024)).toFixed(2)} MB` : 'N/A (Byte Yok)', res.periodB.hasByteData ? `${(res.periodB.totalBytes / (1024 * 1024)).toFixed(2)} MB` : 'N/A (Byte Yok)', res.preventedTrafficMb !== null ? `${res.preventedTrafficMb} MB (Engellenen)` : 'N/A', '-'],
    ['Farklı Policy Sayısı', res.policyComparison.length, res.policyComparison.length, '-', '-'],
    ['İncelenen Kural / Event Sayısı', res.signatureImpacts.length, res.signatureImpacts.length, '-', '-'],
    ['Sonraki Dönemde BLOCK Gözlenen Kayıtlar', res.continuingSignatures.blockObserved.length, '-', '-', '-'],
    ['Sonraki Dönemde ALERT Devam Eden Kayıtlar', res.continuingSignatures.alertContinuing.length, '-', '-', '-'],
    ['Sonraki Dönemde Kaybolan Kayıtlar (Loglarda Yok)', res.notObservedSignatures.length, '-', '-', '-'],
    ['After Döneminde İlk Kez Gözlenen Kayıtlar', res.newObservedSignatures.length, '-', '-', '-'],
    [],
    ['YÖNETİCİ BRİFİNGİ'],
    [res.executiveSummary],
    [],
    ['TEMEL ADLİ BULGULAR'],
    ...res.keyFindings.map((f, i) => [`${i + 1}.`, f]),
    [],
    ['ÖNEMLİ METODOLOJİK DİPNOTLAR'],
    ...res.footnotes.map((fn, i) => [`[${i + 1}]`, fn]),
  ];

  const ws1 = XLSX.utils.aoa_to_sheet(sheet1Data);
  ws1['!cols'] = [{ wch: 36 }, { wch: 32 }, { wch: 32 }, { wch: 22 }, { wch: 20 }];
  XLSX.utils.book_append_sheet(wb, ws1, '01_Executive_Summary');

  // --------------------------------------------------------------------------
  // SHEET 2: 02_Before_After
  // --------------------------------------------------------------------------
  const sheet2Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Log Source',
    'Before Count',
    'After Count',
    'Before ALERT',
    'Before BLOCK',
    'After ALERT',
    'After BLOCK',
    'Before Response Dağılımı',
    'After Response Dağılımı',
    'Aksiyon Değişimi',
    'Teknik Durum',
    'Delta (Fark)',
    'Değişim %',
    'Adli Değerlendirme',
  ];

  const sheet2Rows = res.signatureImpacts.map((sig) => {
    const respA = sig.beforeResponses
      ? Object.entries(sig.beforeResponses).map(([k, v]) => `${k}:${v}`).join('; ')
      : '-';
    const respB = sig.afterResponses
      ? Object.entries(sig.afterResponses).map(([k, v]) => `${k}:${v}`).join('; ')
      : '-';

    return [
      sig.policyId,
      sig.eventName || sig.name,
      sig.threatType || sig.category,
      sig.logSource || '-',
      sig.beforeCount ?? sig.periodA_total,
      sig.afterCount ?? sig.periodB_total,
      res.actionDataAvailable ? numOrNA(sig.periodA_alerted) : 'N/A',
      res.actionDataAvailable ? numOrNA(sig.periodA_blocked) : 'N/A',
      res.actionDataAvailable ? numOrNA(sig.periodB_alerted) : 'N/A',
      res.actionDataAvailable ? numOrNA(sig.periodB_blocked) : 'N/A',
      respA,
      respB,
      res.actionDataAvailable ? sig.actionChangeLabel : 'N/A (Action Yok)',
      sig.technicalStatus,
      (sig.afterCount ?? sig.periodB_total) - (sig.beforeCount ?? sig.periodA_total),
      fmtPct(sig.changePct),
      sig.forensicInterpretation,
    ];
  });

  const ws2 = XLSX.utils.aoa_to_sheet([sheet2Headers, ...sheet2Rows]);
  ws2['!cols'] = [
    { wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 18 },
    { wch: 14 }, { wch: 14 }, { wch: 14 }, { wch: 14 },
    { wch: 14 }, { wch: 14 }, { wch: 28 }, { wch: 28 },
    { wch: 20 }, { wch: 22 }, { wch: 14 }, { wch: 14 },
    { wch: 45 },
  ];
  XLSX.utils.book_append_sheet(wb, ws2, '02_Before_After');

  // --------------------------------------------------------------------------
  // SHEET 3: 03_Policy_Analysis
  // --------------------------------------------------------------------------
  const sheet3Headers = [
    'Policy Adı',
    'Before Toplam Gözlem',
    'After Toplam Gözlem',
    'Delta (Fark)',
    'Değişim %',
    'Before BLOCK Oranı',
    'After BLOCK Oranı',
    'Farklı Event Sayısı',
    'Devam Eden Eventler',
    'Kaybolan Eventler',
    'Yeni Görülen Eventler',
  ];

  const sheet3Rows = res.policyComparison.map((p) => [
    p.policy,
    p.beforeCount,
    p.afterCount,
    p.delta,
    fmtPct(p.changePct),
    p.beforeBlockRate !== null && p.beforeBlockRate !== undefined ? `%${p.beforeBlockRate.toFixed(1)}` : 'N/A',
    p.afterBlockRate !== null && p.afterBlockRate !== undefined ? `%${p.afterBlockRate.toFixed(1)}` : 'N/A',
    p.eventsCount,
    p.continuingEventsCount,
    p.disappearedEventsCount,
    p.newEventsCount,
  ]);

  const ws3 = XLSX.utils.aoa_to_sheet([sheet3Headers, ...sheet3Rows]);
  ws3['!cols'] = [
    { wch: 38 }, { wch: 20 }, { wch: 20 }, { wch: 16 },
    { wch: 16 }, { wch: 18 }, { wch: 18 }, { wch: 18 },
    { wch: 18 }, { wch: 18 }, { wch: 20 },
  ];
  XLSX.utils.book_append_sheet(wb, ws3, '03_Policy_Analysis');

  // --------------------------------------------------------------------------
  // SHEET 4: 04_Rule_Event_Analysis
  // --------------------------------------------------------------------------
  const sheet4Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Before Gözlem',
    'After Gözlem',
    'Delta',
    'Değişim %',
    'Durum',
    'Gözlenen Aksiyon (Before)',
    'Gözlenen Aksiyon (After)',
  ];

  const sheet4Rows = res.signatureImpacts.map((s) => [
    s.policyId,
    s.eventName || s.name,
    s.threatType || s.category,
    s.beforeCount ?? s.periodA_total,
    s.afterCount ?? s.periodB_total,
    (s.afterCount ?? s.periodB_total) - (s.beforeCount ?? s.periodA_total),
    fmtPct(s.changePct),
    s.technicalStatus,
    res.actionDataAvailable ? (s.periodA_blocked > 0 ? 'BLOCK' : s.periodA_alerted > 0 ? 'ALERT' : 'DİĞER') : 'N/A',
    res.actionDataAvailable ? (s.periodB_blocked > 0 ? 'BLOCK' : s.periodB_alerted > 0 ? 'ALERT' : 'DİĞER') : 'N/A',
  ]);

  const ws4 = XLSX.utils.aoa_to_sheet([sheet4Headers, ...sheet4Rows]);
  ws4['!cols'] = [
    { wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 16 },
    { wch: 16 }, { wch: 14 }, { wch: 14 }, { wch: 22 },
    { wch: 24 }, { wch: 24 },
  ];
  XLSX.utils.book_append_sheet(wb, ws4, '04_Rule_Event_Analysis');

  // --------------------------------------------------------------------------
  // SHEET 5: 05_Action_Analysis
  // --------------------------------------------------------------------------
  const sheet5Data: (string | number)[][] = [
    ['AKSİYON BAZLI KARŞILAŞTIRMA ANALİZİ'],
  ];

  if (res.actionDataAvailable) {
    sheet5Data.push(
      ['Aksiyon (Action)', 'Dönem A Olay Sayısı', 'Dönem B Olay Sayısı', 'Delta (Fark)', 'Açıklama'],
      ['ALERT', res.periodA.alertedRequests ?? 0, res.periodB.alertedRequests ?? 0, (res.periodB.alertedRequests ?? 0) - (res.periodA.alertedRequests ?? 0), 'Yalnızca loglama / alarm aksiyonu'],
      ['BLOCK / DENY', res.periodA.blockedRequests, res.periodB.blockedRequests, res.periodB.blockedRequests - res.periodA.blockedRequests, 'WAF sınırında engellenen istekler'],
      ['ALLOW / DİĞER', res.periodA.allowedRequests, res.periodB.allowedRequests, res.periodB.allowedRequests - res.periodA.allowedRequests, 'İzin verilen veya diğer kararlar'],
      ['TOPLAM', res.totalObservationsA, res.totalObservationsB, res.totalObservationsB - res.totalObservationsA, 'Toplam değerlendirilen trafik / kayıt']
    );
  } else {
    sheet5Data.push(
      ['Bilgilendirme:'],
      ['Yüklenen Excel veri setinde ayrı bir "Action" kolonu bulunmamaktadır.'],
      ['Response alanı HTTP yanıt kodlarını (500, 200, 403 vb.) temsil ettiği için adli doğruluk gereği sahte aksiyon üretilmemiştir.'],
      ['Aksiyon analizi yalnızca loglarda veya Excelde doğrudan Action/Disposition alanı sağlandığında aktif olur.']
    );
  }

  const ws5 = XLSX.utils.aoa_to_sheet(sheet5Data);
  ws5['!cols'] = [{ wch: 25 }, { wch: 22 }, { wch: 22 }, { wch: 18 }, { wch: 40 }];
  XLSX.utils.book_append_sheet(wb, ws5, '05_Action_Analysis');

  // --------------------------------------------------------------------------
  // SHEET 6: 06_Response_Analysis
  // --------------------------------------------------------------------------
  const allCodes = Array.from(
    new Set([
      ...Object.keys(res.responseDistribution.periodA),
      ...Object.keys(res.responseDistribution.periodB),
    ])
  ).sort((a, b) => parseInt(a, 10) - parseInt(b, 10));

  const sheet6Headers = [
    'HTTP Response Kodu',
    'Dönem A Gözlem Sayısı',
    'Dönem A Payı (%)',
    'Dönem B Gözlem Sayısı',
    'Dönem B Payı (%)',
    'Delta (Fark)',
    'Durum Değerlendirmesi',
  ];

  const sheet6Rows = allCodes.map((code) => {
    const cntA = res.responseDistribution.periodA[code] || 0;
    const cntB = res.responseDistribution.periodB[code] || 0;
    const pctA = res.totalObservationsA > 0 ? (cntA / res.totalObservationsA) * 100 : 0;
    const pctB = res.totalObservationsB > 0 ? (cntB / res.totalObservationsB) * 100 : 0;
    const delta = cntB - cntA;

    let evalText = 'Stabil';
    if (code.startsWith('5')) evalText = delta < 0 ? 'Backend 5xx hatalarında azalma' : 'Backend 5xx hatalarında artış';
    else if (code.startsWith('4')) evalText = delta > 0 ? '4xx istemci/engelleme yanıtlarında artış' : '4xx yanıtlarında azalma';
    else if (code.startsWith('2')) evalText = delta > 0 ? '2xx başarılı yanıtlarda artış' : '2xx başarılı yanıtlarda azalma';

    return [code, cntA, `%${pctA.toFixed(1)}`, cntB, `%${pctB.toFixed(1)}`, delta, evalText];
  });

  const ws6 = XLSX.utils.aoa_to_sheet([sheet6Headers, ...sheet6Rows]);
  ws6['!cols'] = [{ wch: 20 }, { wch: 22 }, { wch: 18 }, { wch: 22 }, { wch: 18 }, { wch: 16 }, { wch: 36 }];
  XLSX.utils.book_append_sheet(wb, ws6, '06_Response_Analysis');

  // --------------------------------------------------------------------------
  // SHEET 7: 07_Continuing_Alerts
  // --------------------------------------------------------------------------
  const sheet7Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Before ALERT Sayısı',
    'After ALERT Sayısı',
    'After BLOCK Sayısı',
    'After Toplam Gözlem',
    'Durum',
    'Adli Açıklama',
  ];

  const sheet7Rows = res.continuingSignatures.alertContinuing.map((s) => [
    s.policyId,
    s.eventName || s.name,
    s.threatType || s.category,
    res.actionDataAvailable ? numOrNA(s.periodA_alerted) : s.beforeCount ?? s.periodA_total,
    res.actionDataAvailable ? numOrNA(s.periodB_alerted) : s.afterCount ?? s.periodB_total,
    res.actionDataAvailable ? numOrNA(s.periodB_blocked) : 'N/A',
    s.afterCount ?? s.periodB_total,
    s.technicalStatus,
    'İlgili imza/kural sonraki dönemde de gözlenmekte ve ALERT aksiyonu devam etmektedir.',
  ]);

  const ws7 = XLSX.utils.aoa_to_sheet([sheet7Headers, ...sheet7Rows]);
  ws7['!cols'] = [{ wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 18 }, { wch: 18 }, { wch: 18 }, { wch: 18 }, { wch: 22 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, ws7, '07_Continuing_Alerts');

  // --------------------------------------------------------------------------
  // SHEET 8: 08_Block_Observed
  // --------------------------------------------------------------------------
  const sheet8Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Before Aksiyon Dağılımı',
    'After Aksiyon Dağılımı',
    'Before Toplam',
    'After BLOCK Sayısı',
    'Değişim',
    'Durum',
  ];

  const sheet8Rows = res.continuingSignatures.blockObserved.map((s) => [
    s.policyId,
    s.eventName || s.name,
    s.threatType || s.category,
    `ALERT: ${s.periodA_alerted} | BLOCK: ${s.periodA_blocked}`,
    `ALERT: ${s.periodB_alerted} | BLOCK: ${s.periodB_blocked}`,
    s.beforeCount ?? s.periodA_total,
    s.periodB_blocked,
    s.actionChangeLabel,
    s.technicalStatus,
  ]);

  const ws8 = XLSX.utils.aoa_to_sheet([sheet8Headers, ...sheet8Rows]);
  ws8['!cols'] = [{ wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 25 }, { wch: 25 }, { wch: 16 }, { wch: 18 }, { wch: 20 }, { wch: 22 }];
  XLSX.utils.book_append_sheet(wb, ws8, '08_Block_Observed');

  // --------------------------------------------------------------------------
  // SHEET 9: 09_Disappeared
  // --------------------------------------------------------------------------
  const sheet9Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Before Gözlem Sayısı',
    'After Gözlem Sayısı',
    'Durum',
    'Adli Açıklama',
  ];

  const sheet9Rows = res.notObservedSignatures.map((s) => [
    s.policyId,
    s.eventName || s.name,
    s.threatType || s.category,
    s.beforeCount ?? s.periodA_total,
    0,
    'LOGLARDA_GOZLENMEDI',
    'İlgili kayıt sonraki karşılaştırma döneminde kaynak loglarda gözlenmemiştir.',
  ]);

  const ws9 = XLSX.utils.aoa_to_sheet([sheet9Headers, ...sheet9Rows]);
  ws9['!cols'] = [{ wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 20 }, { wch: 20 }, { wch: 24 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, ws9, '09_Disappeared');

  // --------------------------------------------------------------------------
  // SHEET 10: 10_New_Events
  // --------------------------------------------------------------------------
  const sheet10Headers = [
    'Policy',
    'Event Name',
    'Threat Type',
    'Before Gözlem Sayısı',
    'After Gözlem Sayısı',
    'Durum',
    'Adli Açıklama',
  ];

  const sheet10Rows = res.newObservedSignatures.map((s) => [
    s.policyId,
    s.eventName || s.name,
    s.threatType || s.category,
    0,
    s.afterCount ?? s.periodB_total,
    'YENI_GORULEN_EVENT',
    'Önceki dönemde bulunmayıp politika sonrası dönemde ilk kez loglanan kayıt.',
  ]);

  const ws10 = XLSX.utils.aoa_to_sheet([sheet10Headers, ...sheet10Rows]);
  ws10['!cols'] = [{ wch: 30 }, { wch: 32 }, { wch: 22 }, { wch: 20 }, { wch: 20 }, { wch: 24 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, ws10, '10_New_Events');

  // --------------------------------------------------------------------------
  // SHEET 11: 11_Daily_Trends
  // --------------------------------------------------------------------------
  const sheet11Headers = [
    'Dönem',
    'Başlangıç Tarihi',
    'Bitiş Tarihi',
    'Toplam Gün',
    'Toplam İstek/Gözlem',
    'Günlük Ortalama İstek',
    'Günlük Ortalama BLOCK',
    'Normalizasyon Değerlendirmesi',
  ];

  const sheet11Rows = [
    [
      res.periodALabel,
      res.periodA.startDate || 'Belirtilmedi',
      res.periodA.endDate || 'Belirtilmedi',
      res.periodA.totalDays || 1,
      res.totalObservationsA,
      res.periodA.dailyAverageRequests,
      res.actionDataAvailable ? res.periodA.dailyAverageBlocks : 'N/A',
      'Referans Dönem',
    ],
    [
      res.periodBLabel,
      res.periodB.startDate || 'Belirtilmedi',
      res.periodB.endDate || 'Belirtilmedi',
      res.periodB.totalDays || 1,
      res.totalObservationsB,
      res.periodB.dailyAverageRequests,
      res.actionDataAvailable ? res.periodB.dailyAverageBlocks : 'N/A',
      'Güncel Dönem',
    ],
  ];

  const ws11 = XLSX.utils.aoa_to_sheet([sheet11Headers, ...sheet11Rows]);
  ws11['!cols'] = [{ wch: 28 }, { wch: 20 }, { wch: 20 }, { wch: 14 }, { wch: 20 }, { wch: 22 }, { wch: 22 }, { wch: 28 }];
  XLSX.utils.book_append_sheet(wb, ws11, '11_Daily_Trends');

  // --------------------------------------------------------------------------
  // SHEET 12: 12_Target_Hosts
  // --------------------------------------------------------------------------
  const sheet12Headers = [
    'Hedef Sunucu / Host',
    'Before İzin Verilen/Gözlenen',
    'After BLOCK Sayısı',
    'Kombine Koruma Oranı',
    'İlgili Kural ve İmzalar (Alt Kırılım)',
  ];

  const sheet12Rows = res.protectedServers.map((srv) => [
    srv.server,
    srv.periodA_attacksAllowed,
    srv.periodB_attacksBlocked,
    'N/A (Birleşik oran uygulanamaz)',
    srv.threats.map((t) => `${t.ruleOrAttack}: ${t.periodB_attacksBlocked} BLOCK`).join('; '),
  ]);

  const ws12 = XLSX.utils.aoa_to_sheet([sheet12Headers, ...sheet12Rows]);
  ws12['!cols'] = [{ wch: 28 }, { wch: 26 }, { wch: 20 }, { wch: 45 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, ws12, '12_Target_Hosts');

  // --------------------------------------------------------------------------
  // SHEET 13: 13_Data_Quality
  // --------------------------------------------------------------------------
  const dqA = res.dataQuality.periodA;
  const dqB = res.dataQuality.periodB;

  const sheet13Data: (string | number)[][] = [
    ['VERİ KALİTESİ VE ŞEMA UYUMLULUK DENETİMİ (DATA QUALITY AUDIT)'],
    [],
    ['METRİK', 'DÖNEM A (REFERANS DOSYASI)', 'DÖNEM B (GÜNCEL DOSYA)', 'DEĞERLENDİRME'],
    ['Toplam Okunan Satır', dqA.totalRows, dqB.totalRows, 'Okunan ham satır sayısı'],
    ['Başarıyla Parse Edilen Satır', dqA.parsedRows, dqB.parsedRows, 'Şemaya uygun ayrıştırılan satırlar'],
    ['Reddedilen Satır (Rejected)', dqA.rejectedRows, dqB.rejectedRows, dqA.rejectedRows + dqB.rejectedRows === 0 ? 'Mükemmel (Kayıp yok)' : 'İnceleme gerekli'],
    ['Toplam Kümülatif Gözlem (SUM Count)', dqA.aggregateCount, dqB.aggregateCount, 'Tüm Count değerlerinin matematiksel toplamı'],
    ['Eksik Policy Alanı Olan Satır', dqA.missingPolicy, dqB.missingPolicy, dqA.missingPolicy + dqB.missingPolicy === 0 ? 'Tam' : 'Eksik alan mevcut'],
    ['Eksik Event Name Olan Satır', dqA.missingEvent, dqB.missingEvent, dqA.missingEvent + dqB.missingEvent === 0 ? 'Tam' : 'Eksik alan mevcut'],
    ['Eksik Action Alanı', dqA.missingAction, dqB.missingAction, res.actionDataAvailable ? 'Mevcut' : 'Excelde Action kolonu yok (Response mevcut)'],
    ['Eksik Response Alanı', dqA.missingResponse, dqB.missingResponse, dqA.missingResponse + dqB.missingResponse === 0 ? 'Tam' : 'Eksik alan mevcut'],
    ['Geçersiz / Okunamayan Count', dqA.invalidCount, dqB.invalidCount, dqA.invalidCount + dqB.invalidCount === 0 ? 'Tam' : 'Hatalı numerik değer'],
    [],
    ['DÖNEM A VERİ UYARILARI'],
    ...(dqA.warnings.length > 0 ? dqA.warnings.map((w, i) => [`${i + 1}.`, w]) : [['1.', 'Herhangi bir veri kalitesi anomalisi tespit edilmedi.']]),
    [],
    ['DÖNEM B VERİ UYARILARI'],
    ...(dqB.warnings.length > 0 ? dqB.warnings.map((w, i) => [`${i + 1}.`, w]) : [['1.', 'Herhangi bir veri kalitesi anomalisi tespit edilmedi.']]),
  ];

  const ws13 = XLSX.utils.aoa_to_sheet(sheet13Data);
  ws13['!cols'] = [{ wch: 35 }, { wch: 28 }, { wch: 28 }, { wch: 35 }];
  XLSX.utils.book_append_sheet(wb, ws13, '13_Data_Quality');

  // --------------------------------------------------------------------------
  // SHEET 14: 14_Methodology
  // --------------------------------------------------------------------------
  const sheet14Data: (string | number)[][] = [
    ['WAF & GÜVENLİK POLİTİKASI DEĞİŞİKLİĞİ KARŞILAŞTIRMA METODOLOJİSİ'],
    [],
    ['1. Nedensellik ve Saldırı Eşleştirme Sınırı:'],
    ['İki farklı zaman dilimindeki (Dönem A ve Dönem B) olaylar otomatik olarak birebir "aynı saldırılar" veya "aynı saldırganlar" olarak kabul edilemez. Bir imzanın sonraki dönemde görünmemesi "saldırı kesinlikle engellendi" anlamına gelmez; yalnızca "ilgili imza sonraki dönemde loglarda gözlenmemiştir" olarak ifade edilir.'],
    [],
    ['2. Karşılaştırma Anahtarı:'],
    ['Karşılaştırmanın ana ekseni POLICY + EVENT NAME / RULE / SIGNATURE olarak belirlenmiştir. Tek başına hedef IP/Host bir karşılaştırma anahtarı değildir; host yalnızca alt kırılım olarak incelenir. Aynı sunucu üzerindeki farklı saldırı tipleri kombine tek bir yüzdeye indirgenemez.'],
    [],
    ['3. Aksiyon (Action) ve HTTP Response Ayrımı:'],
    ['Response kolonu (500, 200, 403 vb.) ile WAF Aksiyonu (Blocked, Alarmed, Drop vb.) iki tamamen bağımsız veri alanıdır. 403 kodu otomatik olarak WAF BLOCK kabul edilemez, 500 kodu otomatik olarak engelleme sayılamaz. Gerçek Excelde ayrı bir Action alanı yoksa BLOCK oranı kesinlikle uydurulmaz.'],
    [],
    ['4. Kümülatif İstek (Count) Ağırlıklandırması:'],
    ['F5 WAF özet Excel raporlarında her satır tek bir istek değil, Count kolonu kadar istek hacmini temsil eder. Toplam gözlem SUM(Count) ile hesaplanır.'],
    [],
    ['5. Trafik Hacmi ve Backend Rahatlaması:'],
    ['Log kaynağında gerçek aktarılan byte bilgisi bulunmuyorsa trafik hacmi (MB) N/A olarak bırakılır; sentetik varsayım yapılmaz. Backend uygulama logları olmadan WAF loglarından backend rahatlaması kesin olarak iddia edilemez.'],
  ];

  const ws14 = XLSX.utils.aoa_to_sheet(sheet14Data);
  ws14['!cols'] = [{ wch: 100 }];
  XLSX.utils.book_append_sheet(wb, ws14, '14_Methodology');

  return wb;
}
