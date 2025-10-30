

# Web Güvenlik Tarayıcısı Chrome Uzantısı

Bu Chrome uzantısı, web sayfalarındaki potansiyel güvenlik açıklarını tespit etmek için tasarlanmıştır. XSS, güvensiz cookie kullanımı, şifre alanı güvenliği, CSP eksikliği ve daha fazlası gibi yaygın güvenlik sorunlarını kontrol eder. Eğitim ve test amaçlıdır.

## Özellikler
- XSS, CSRF, Cookie, Storage, Şifre alanı ve CSP kontrolleri
- **Fuzzy Logic Executor**: Trapezoidal üyelik fonksiyonları ve IF-THEN kuralları ile açıklık derecelendirmesi
- **Çok-LLM Hybrid Değerlendirme**: GPT, Gemini, DeepSeek modelleri ile karşılaştırmalı scoring
- **Standartlaştırılmış Score Methodları**: Açıklık tipi, lokasyon, eşleşme sayısı ve context faktörlerine dayalı scoring
- **Benchmark Loglama**: Sentry.io (opsiyonel) ve Chrome Storage ile kullanıcı tercihleri ve model performansı izleme
- Aktif sekmede tarama başlatma
- Tespit edilen açıkları JSON/CSV olarak dışa aktarma
- Filtreleme ve detaylı raporlama
- Ayarlar sayfası ile tarama ve filtre seçenekleri
- Model seçimi ile kişiselleştirilmiş değerlendirme
- Modern ve kullanıcı dostu arayüz

## Dosya Yapısı
- `manifest.json`: Uzantı yapılandırması ve izinler, web_accessible_resources tanımı
- `background.js`: Arka planda konfigürasyon yönetimi (Fuzzy Logic ve Score Methods yükleme), localStorage caching, message routing
- `content.js`: Sayfa üzerinde güvenlik açıklarını tarayan script, XSS, cookie, storage, şifre alanı, CSP ve ağ izleme kontrolleri, standardize edilmiş output formatı
- `popup.html`, `popup.js`: Sonuçların ve kontrollerin gösterildiği arayüz, tarama başlatma, filtreleme, dışa aktarma, **Fuzzy Logic executor, score calculator, hybrid result rendering, model seçimi**
- `settings.html`, `settings.js`: Ayarlar arayüzü ve işlemleri, filtre ve tarama seçenekleri
- `styles.css`: Tüm arayüz için modern stil dosyası, **hybrid results grid, model selector styling**
- `fuzzyLogic.json`: **Fuzzy Logic modellerinin tanımı (GPT, Gemini), üyelik fonksiyonları, kurallar, output eşlemeleri**
- `scoreMethods.json`: **Score hesaplama metodları (GPT, Gemini, DeepSeek), tip/lokasyon ağırlıkları, normalizasyon kuralları**
- `images/`: Uzantı ikonları (`icon16.png`, `icon48.png`, `icon128.png`)

## Kurulum
1. Bu dizini bilgisayarınıza indirin.
2. Chrome'da `chrome://extensions` adresine gidin.
3. "Geliştirici Modu"nu açın.
4. "Paketlenmemiş uzantı yükle" butonuna tıklayın ve `chrome-vuln-scanner-main` klasörünü seçin.

## Kullanım
- "Sayfayı Tara" butonuna tıklayarak aktif sekmedeki web sayfasını tarayın.
- Tespit edilen açıklar listelenir, filtrelenebilir ve JSON/CSV olarak dışa aktarılabilir.
- Ayarlar sekmesinden tarama ve filtreleme seçeneklerini düzenleyebilirsiniz.

## Tespit Edilen Açıklar
- **XSS (Cross-Site Scripting)**: DOM yazma, document.write, eval, inline event handler, javascript: URL, dinamik script ekleme, URL parametreleri
- **Cookie Güvenliği**: Hassas anahtarlar, HTTPS kontrolü
- **Storage Güvenliği**: localStorage/sessionStorage'da hassas veri
- **Şifre Alanı Güvenliği**: HTTP/HTTPS, autocomplete, form method/action, CSRF token
- **CSP (Content Security Policy)**: CSP eksikliği, unsafe-inline/eval
- **Ağ İzleme**: HTTP üzerinden istek, hassas veri içeren URL/gövde

## Mimarı

### Client-Side Fuzzy Logic ve Hybrid Scoring
Uzantı, açıklık derecelendirmesi için karma bir yaklaşım kullanır:

1. **Detection Layer (content.js)**: Statik regex ve DOM tabanlı açıklık tespiti
2. **Scoring Layer (popup.js)**: LLM-generated weight matrices kullanılarak açıklar normalize edilir (0-1 skalası)
3. **Evaluation Layer (popup.js)**: Fuzzy Logic executor, trapezoidal üyelik fonksiyonları ve IF-THEN kuralları ile derecelendirme
4. **Benchmarking**: Tüm LLM × Fuzzy Logic kombinasyonlarının sonuçları Sentry.io ve Chrome Storage'a kaydedilir

### Configuration Management (background.js)
- `fuzzyLogic.json` ve `scoreMethods.json` dosyaları chrome.runtime.getURL() ile yüklenir
- localStorage'da 24 saatlik cache ile saklanır
- chrome.alarms ile otomatik güncelleme
- Popup ve Content scriptlerine message API üzerinden dağıtılır

### Model Selection
Kullanıcılar popup'ta model seçim dropdown'larıyla tercih edebilir:
- **Score Method**: GPT, Gemini, DeepSeek
- **Fuzzy Logic**: GPT, Gemini

## Teknoloji Stack
- **Frontend**: Vanilla JavaScript, HTML5, CSS3 (Manifest V3 uyumlu)
- **Fuzzy Logic**: Trapezoidal üyelik fonksiyonları, rule-based inference, defuzzification
- **Data Format**: Standardize JSON (fuzzyLogic.json, scoreMethods.json)
- **Analytics** (Opsiyonel): Sentry.io SDK, Chrome Storage API
- **Package Format**: Chrome Extension Manifest V3

## Benchmark Data
Extension, kullanıcı seçimlerini ve model performansını takip eder:
- `benchmarkData` localStorage array'inde maksimum 1000 event kayıt tutulur
- Sentry.io aktivse, tüm benchmark etkinlikleri gönderilir
- Timestamp, eventName ve ilgili data ile kaydedilir

## Katkı
Eğitim ve test amaçlıdır. Geliştirmeye açıktır.

## Lisans
MIT