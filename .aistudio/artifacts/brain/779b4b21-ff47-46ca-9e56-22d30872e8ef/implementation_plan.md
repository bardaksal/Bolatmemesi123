# Uygulama Planı: Ana Ekranda Doğrudan Gemini Log Analizi

Kullanıcı tercihleri doğrultusunda, ana ekrandaki "Ham Log Yapıştır ve Avlan" akışında Gemini modelinin (`gemini-3.8-flash`) doğrudan analiz yapması ve herhangi bir görsel durum rozeti/telemetri göstergesi olmadan arka planda çalışması sağlanacaktır.

---

## 1. Mimari ve İş Akışı Tasarımı

1. **Mevcut Durum**:
   - Ana ekranda (`ThreatHuntingTab` ve `App.tsx`) log yapıştırıldığında `handlePasteAndHunt` fonksiyonu yalnızca yerel regex ve Web Worker triyajını çalıştırıyordu.
   - Gemini API çağrıları yalnızca ayrı modal pencerelerinde (`AiLogUnderstandingModal`, `AiSocAssistantModal`) mevcuttu.

2. **Hedef Akış**:
   - Kullanıcı ana ekranda log yapıştırıp "Analiz Et / Avlan" butonuna bastığında:
     1. Girdi doğrudan arka planda `/api/ai/semantic-log-analysis` (Gemini API) hattına gönderilir.
     2. Gemini `gemini-3.8-flash` modeli ham metindeki olay sınırlarını, semantik alanları (Source IP, URI, Event ID, vb.) ve güvenlik hipotezlerini çıkarır.
     3. Ham-span validator ile Gemini çıktısı doğrulanır (halüsinasyon koruması).
     4. Çıkan semantik olaylar `HuntingReport`, `RiskQueue` ve `RawLogTriage` yapılarına dönüştürülerek doğrudan ana arayüze beslenir.
     5. Ağ kesintisi veya API kotası durumunda yerel deterministik motor sessiz bir güvenlik yedeği olarak devreye girer.

3. **Görsel Tasarım Disiplini**:
   - Kullanıcı talebi ("Görsel gösterge olmadan arka planda çalışsın") ve platform kuralları uyarınca ek bir API rozeti, telemetri kutusu veya durum etiketi eklenmeyecektir.
   - Mevcut standart analiz süreci çubuğu işleyişi gösterecektir.

---

## 2. Değişiklik Yapılacak Dosyalar

1. **`src/services/geminiDirectHunter.ts`**:
   - Ana log yapıştırma akışını Gemini semantik analiz uç noktasına (`/api/ai/semantic-log-analysis`) bağlayan ve sonuçları `HuntingReport` ile `RiskQueueItem` formatına dönüştüren servis.

2. **`src/App.tsx`**:
   - `handlePasteAndHunt` fonksiyonunun doğrudan Gemini analiz hattını tetikleyecek şekilde asenkron olarak güncellenmesi.

3. **`server.ts`**:
   - `/api/ai/semantic-log-analysis` uç noktasının ana ekrandan gelen doğrudan istekleri optimum model parametreleriyle ve kesintisiz yanıt verecek şekilde hazır tutulması.

4. **`src/tests/geminiDirectHuntIntegration.test.ts`**:
   - Ana ekran log yapıştırma akışında Gemini semantik verilerinin rapor nesnesine başarıyla işlendiğini doğrulayan entegrasyon testleri.

---

## 3. Doğrulama ve Test Adımları

- [x] Ana ekranda log yapıştırıldığında Gemini semantik çıkarımının doğrudan çalışması.
- [x] SSH, Web, Sysmon ve Firewall loglarının doğru alan ve risk etiketleriyle sonuç tablosuna yansıması.
- [x] Görsel arayüzün gereksiz rozet veya telemetri içermediğinin denetlenmesi.
- [x] `npm test` ve `compile_applet` ile tüm suiti başarıyla doğrulamak.
