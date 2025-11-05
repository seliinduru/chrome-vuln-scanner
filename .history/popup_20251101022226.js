// popup.js
// popup ile background / content arasında haberleşme, UI render
// Fuzzy Logic executor ve score hesaplama
// Sentry.io entegrasyonu ve benchmark logging

// ===== GLOBAL DEĞİŞKENLER =====
let currentVulns = []; // Aktif sekmeye ait zafiyetler
let filterSettings = {}; // Ayarlar sayfasından gelen filtreler
let fuzzyLogicConfig = {}; // Background'tan gelen Fuzzy Logic konfigürasyonu
let scoreMethods = {}; // Background'tan gelen Score Method konfigürasyonu
let selectedScoreModel = 'gpt'; // Varsayılan LLM Score modeli
let selectedFuzzyModel = 'gpt'; // Varsayılan Fuzzy Logic modeli

// DOM Elementleri
const statusText = document.getElementById('statusText');
const vulnListDiv = document.getElementById('vulnList');
const scanBtn = document.getElementById('scanBtn');
const backToResultsBtn = document.getElementById('backToResultsBtn');

// ===== SENTRY ENTEGRASYONU (Devre dışı) =====
const SENTRY_DSN = '';
let sentryActive = false;
async function initSentry() {
  sentryActive = false;
  console.log('Sentry integration disabled (CSP restriction)');
}

// Benchmark loglama
function logBenchmark(eventName, data) {
  try {
    if (sentryActive && window.Sentry) {
      window.Sentry.captureEvent({
        message: eventName,
        level: 'info',
        tags: { type: 'benchmark' },
        contexts: { benchmark: data }
      });
    }
    
    chrome.storage.local.get('benchmarkData', (result) => {
      let benchmarks = result.benchmarkData || [];
      benchmarks.push({
        timestamp: new Date().toISOString(),
        eventName,
        ...data
      });
      // Sadece son 1000 kaydı tut
      if (benchmarks.length > 1000) {
        benchmarks = benchmarks.slice(benchmarks.length - 1000);
      }
      chrome.storage.local.set({ benchmarkData: benchmarks });
    });
  } catch (e) {
    console.error('Benchmark logging error:', e);
  }
}

// ===== CORE LOGIC (Fuzzy Logic & Scoring) - BURAYA KODUNUZ GELİR =====

// ... (Burada mevcut `calculateScore`, `executeFuzzyLogic`, `generateHybridResults`, `calculateTrapezoidMembership` gibi fonksiyonlarınız olmalıdır.)

// Şimdilik sadece render için placeholder fonksiyonlar
function calculateScore(vuln, scoreMethodConfig) {
    // LLM tabanlı skor hesaplama mantığı
    return Math.floor(Math.random() * 100); 
}

function executeFuzzyLogic(vuln, fuzzyConfig) {
    // Fuzzy Logic hesaplama mantığı
    const score = Math.random();
    return score > 0.7 ? 'High' : (score > 0.4 ? 'Medium' : 'Low');
}

function generateHybridResults() {
    currentVulns = currentVulns.map(vuln => {
        const scoreMethodConfig = scoreMethods.llmModels[selectedScoreModel] || scoreMethods.llmModels['gpt'];
        const fuzzyConfig = fuzzyLogicConfig.llmModels[selectedFuzzyModel] || fuzzyLogicConfig.llmModels['gpt'];

        // 1. LLM Score (0-100)
        vuln.llmScore = calculateScore(vuln, scoreMethodConfig);
        
        // 2. Fuzzy Logic Score (High/Medium/Low)
        vuln.fuzzySeverity = executeFuzzyLogic(vuln, fuzzyConfig);
        
        // 3. Final Severity (Filtreleme için)
        vuln.severity = vuln.fuzzySeverity.toLowerCase(); // High, Medium, Low
        
        return vuln;
    });
}

// ===== UI RENDER (Zafiyetleri Ekrana Basma) =====

function renderVulns() {
  // Filtreleme
  const filteredVulns = currentVulns.filter(vuln => {
    const severityMatch = filterSettings.severity.includes(vuln.severity);
    const typeMatch = filterSettings.vulnTypes.includes(vuln.type);
    return severityMatch && typeMatch;
  });

  vulnListDiv.innerHTML = ''; // Temizle
  
  if (filteredVulns.length === 0) {
    vulnListDiv.classList.add('empty');
    vulnListDiv.innerHTML = `
      <div class="empty-state">
        <p>${currentVulns.length === 0 ? 'Henüz tarama yapılmadı.' : 'Filtrelere uygun açık bulunamadı.'}</p>
      </div>
    `;
    return;
  }
  
  vulnListDiv.classList.remove('empty');
  filteredVulns.forEach(vuln => {
    const item = document.createElement('div');
    item.className = `vuln-item severity-${vuln.severity}`;
    item.innerHTML = `
      <div class="vuln-header">
        <span class="vuln-severity">${vuln.fuzzySeverity}</span>
        <h4>${vuln.title} (${vuln.type.toUpperCase()})</h4>
      </div>
      <p class="vuln-details">${vuln.details}</p>
      <button class="details-btn">Detaylar</button>
    `;
    
    // Detay butonu olay dinleyicisi
    item.querySelector('.details-btn').addEventListener('click', () => {
        showVulnDetails(vuln);
    });

    vulnListDiv.appendChild(item);
  });
}

// Detay sayfasını göster
function showVulnDetails(vuln) {
    document.getElementById('results').classList.remove('active');
    
    let detailSection = document.getElementById('vulnDetailSection');
    if (!detailSection) {
        detailSection = document.createElement('section');
        detailSection.id = 'vulnDetailSection';
        detailSection.className = 'tab-content';
        // Detay sayfasına geri butonu eklemek için global değişkene ata
        const modal = document.querySelector('.modal');
        modal.insertBefore(detailSection, modal.querySelector('footer'));
    }
    
    // Detay sayfası içeriği
    detailSection.innerHTML = `
        <header class="modal-header">
            <h1 class="detail-title">${vuln.title}</h1>
            <button id="backToResultsBtn" class="back-button">← Sonuçlara Geri Dön</button>
        </header>
        <div class="card detail-card">
            <div class="detail-row">
                <strong>Şiddet (Fuzzy):</strong> <span class="vuln-severity severity-${vuln.severity}">${vuln.fuzzySeverity}</span>
            </div>
            <div class="detail-row">
                <strong>LLM Skoru (0-100):</strong> ${vuln.llmScore}
            </div>
            <div class="detail-row">
                <strong>Açık Tipi:</strong> ${vuln.type.toUpperCase()}
            </div>
            <div class="detail-row">
                <strong>Detaylar:</strong> ${vuln.details}
            </div>
            ${vuln.evidence ? `<div class="detail-row">
                <strong>Kanıt/Kod:</strong> <pre>${vuln.evidence}</pre>
            </div>` : ''}
            
            <div class="detail-row detail-factors">
                <strong>Faktörler:</strong> 
                <ul>
                    <li>Konum: ${vuln.location}</li>
                    <li>Eşleşme Sayısı: ${vuln.matchCount}</li>
                    <li>Context: ${vuln.contextFactors ? 'Etkili' : 'Etkisiz'}</li>
                    <li>Kullanıcı Etkileşimi: ${vuln.userInteractionRequired ? 'Gerekli' : 'Gereksiz'}</li>
                    <li>Harici Faktörler (Malicious URL): ${vuln.isMaliciousURL ? 'Evet' : 'Hayır'}</li>
                </ul>
            </div>
            
        </div>
    `;
    detailSection.classList.add('active');

    // Geri butonu olay dinleyicisi
    detailSection.querySelector('#backToResultsBtn').addEventListener('click', () => {
        detailSection.classList.remove('active');
        document.getElementById('results').classList.add('active');
    });
}

// ===== API MESSAGING (Content Script ve Background) =====

// Background'tan zafiyetleri çek ve render et
function getVulnsFromBackground() {
  chrome.runtime.sendMessage({ action: 'getVulns' }, (response) => {
    if (response && Array.isArray(response.vulnerabilities)) {
      currentVulns = response.vulnerabilities;
      generateHybridResults();
      renderVulns();
      
      const count = currentVulns.length;
      setStatus(count === 0 ? 'Tarandı — Açık bulunamadı' : `Tarandı — ${count} açık bulundu`);
    } else {
      currentVulns = [];
      renderVulns();
      setStatus('Tarandı — Açık bulunamadı');
    }
  });
}

// Durum yazısı
function setStatus(s) {
  // statusText'in DOM'da tanımlı olduğundan emin ol
  const st = document.getElementById('statusText'); 
  if (st) st.textContent = s;
}

// ===== EXPORT (Dışa Aktarma) =====
function exportData(data, filename, mime) {
  // ... (Mevcut dışa aktarma kodunuz buraya gelecektir)
}

// ===== INITIALIZATION / EVENT LISTENERS =====

document.addEventListener('DOMContentLoaded', () => {
  // Konfigürasyonları yükle
  chrome.runtime.sendMessage({ action: 'getFuzzyLogic' }, (resp) => {
    if (resp && resp.fuzzyLogic) {
      fuzzyLogicConfig = resp.fuzzyLogic;
    }
  });

  chrome.runtime.sendMessage({ action: 'getScoreMethods' }, (resp) => {
    if (resp && resp.scoreMethods) {
      scoreMethods = resp.scoreMethods;
    }
  });

  chrome.storage.local.get('scannerSettings', (result) => {
    filterSettings = result.scannerSettings || getDefaultSettings();
  });

  // Background'tan mevcut zafiyetleri çek (popup açıldığında)
  getVulnsFromBackground(); 
  
  // Tab geçişleri
  document.querySelectorAll('.tab').forEach(button => {
    button.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
      
      const targetTab = e.target.getAttribute('data-tab');
      document.getElementById(targetTab).classList.add('active');
      e.target.classList.add('active');
      
      // Ayarlar tabına basılırsa settings.html'e yönlendir
      if (targetTab === 'settings') {
        window.location.href = 'settings.html';
      }
    });
  });
  
  // Model seçimi (GPT/Gemini/DeepSeek)
  const scoreSelect = document.getElementById('scoreModelSelect');
  const fuzzySelect = document.getElementById('fuzzyLogicSelect');
  
  if (scoreSelect) {
    scoreSelect.addEventListener('change', (e) => {
      selectedScoreModel = e.target.value;
      if (currentVulns.length > 0) {
        generateHybridResults();
        renderVulns();
      }
    });
  }
  
  if (fuzzySelect) {
    fuzzySelect.addEventListener('change', (e) => {
      selectedFuzzyModel = e.target.value;
      if (currentVulns.length > 0) {
        generateHybridResults();
        renderVulns();
      }
    });
  }

  // Filtre butonları
  document.querySelectorAll('.filter').forEach(button => {
    button.addEventListener('click', (e) => {
      document.querySelectorAll('.filter').forEach(btn => btn.classList.remove('active'));
      e.target.classList.add('active');
      
      const severity = e.target.getAttribute('data-sev');
      filterSettings.severity = severity === 'all' ? ['high', 'medium', 'low'] : [severity];
      renderVulns();
    });
  });
  
  // Export butonları
  document.getElementById('exportJson').addEventListener('click', () => {
    // Sadece filtrelenmiş veriyi al
    const filteredVulns = currentVulns.filter(vuln => filterSettings.severity.includes(vuln.severity) && filterSettings.vulnTypes.includes(vuln.type));
    exportData(JSON.stringify(filteredVulns, null, 2), 'vulnerabilities.json', 'application/json');
  });

  document.getElementById('exportCsv').addEventListener('click', () => {
    // ... CSV Export kodu
  });
  
  function getDefaultSettings() {
    return {
      severity: ['high', 'medium', 'low'],
      vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
      scanOptions: ['passive']
    };
  }
  
  // ===== TARAMA BAŞLATMA (HATA ÇÖZÜMÜ BURADA) =====
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      setStatus('Taranıyor...');
      const scanStartTime = Date.now();
      
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.id) {
          setStatus('Aktif sekme bulunamadı');
          logBenchmark('scan_error', { reason: 'no_active_tab' });
          return;
        }

        // Yardımcı mesaj gönderme fonksiyonu
        const sendMessageAndHandleError = () => {
          
          // ZAMAN AŞIMI MEKANİZMASI (8 saniye) - Takılı kalma sorununu çözer
          const timeoutId = setTimeout(() => {
              const currentStatus = document.getElementById('statusText')?.textContent;
              if (currentStatus === 'Taranıyor...') {
                  console.warn('Tarama zaman aşımı.');
                  setStatus('Tarama zaman aşımına uğradı (content script yanıt vermiyor).');
                  getVulnsFromBackground(); // Sonuçları sıfırla/Yenile
              }
          }, 8000); // 8 saniye zaman aşımı

          chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
              clearTimeout(timeoutId); // Yanıt gelince zaman aşımını temizle

              if (chrome.runtime.lastError) {
                  // Hata: Content script hiç yanıt vermezse
                  console.warn('sendMessage error:', chrome.runtime.lastError.message);
                  setStatus('Tarama başarısız: Sekmeye erişilemiyor veya content.js hatası.');
                  getVulnsFromBackground();
                  return;
              }

              // ELSE YAZAN YERİN DÜZELTİLMİŞ HALİ
              if (response && Array.isArray(response.vulnerabilities)) {
                  // Başarılı durum
                  currentVulns = response.vulnerabilities;
                  chrome.runtime.sendMessage({ action: 'vulnerabilitiesDetected', vulnerabilities: currentVulns });
                  
                  generateHybridResults(); // Skorları hesapla
                  
                  renderVulns();
                  const scanDuration = Date.now() - scanStartTime;
                  setStatus(`Tarandı — ${currentVulns.length} açık bulundu (${scanDuration}ms)`);
                  
                  logBenchmark('scan_completed', {
                      vulnCount: currentVulns.length,
                      duration: scanDuration,
                      url: tab.url
                  });
              } else {
                  // Yanıt geldi ama veri boş veya geçersiz
                  console.warn('Tarama yanıtı boş veya geçersiz.');
                  setStatus('Tarandı — 0 açık (Yanıt alındı, sonuç boş)');
                  currentVulns = [];
                  renderVulns();
                  logBenchmark('scan_error', { reason: 'empty_vulnerabilities_response' });
              }
          });
        }; // sendMessageAndHandleError END

        // 1. Durum Kontrolü (Content script zaten yüklenmiş mi?)
        chrome.tabs.sendMessage(tab.id, { action: 'checkStatus' }, async (response) => {
          if (chrome.runtime.lastError || !response || !response.status) {
            // 2. Hazır değilse, content.js'i enjekte et
            console.log("Content script yok, programlı enjeksiyon yapılıyor...");
            try {
              await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js']
              });
              // 3. Enjeksiyondan sonra tarama komutunu gönder
              sendMessageAndHandleError();

            } catch (e) {
              console.error('Script enjeksiyon hatası:', e);
              setStatus('Script enjeksiyonu başarısız. İzinleri (scripting) kontrol edin.');
              logBenchmark('scan_error', { reason: 'scripting_error' });
            }
          } else {
            // 4. Content script zaten çalışıyorsa, doğrudan tarama komutunu gönder
            sendMessageAndHandleError();
          }
        });
      });
    });
  } // scanBtn END
});