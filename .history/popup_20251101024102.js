// popup.js
// popup ile background / content arasında haberleşme, UI render
// Fuzzy executor ve score hesaplama

// ===== GLOBAL DEĞİŞKENLER =====
let currentVulns = []; 
let filterSettings = {};
let fuzzyLogicConfig = {}; 
let scoreMethods = {}; 
let selectedScoreModel = 'gpt';
let selectedFuzzyModel = 'gpt';

// DOM Elementleri
const statusText = document.getElementById('statusText'); // Global olarak tanımlandı
const vulnListDiv = document.getElementById('vulnList');
const scanBtn = document.getElementById('scanBtn');

// Benchmark loglama (Kendi orijinal kodunuzdaki benchmark logging fonksiyonu)
function logBenchmark(eventName, data) {
  try {
    chrome.storage.local.get('benchmarkData', (result) => {
        let benchmarks = result.benchmarkData || [];
        benchmarks.push({
          timestamp: new Date().toISOString(),
          eventName,
          ...data
        });
        if (benchmarks.length > 1000) {
          benchmarks = benchmarks.slice(benchmarks.length - 1000);
        }
        chrome.storage.local.set({ benchmarkData: benchmarks });
      });
  } catch (e) {
    console.error('Benchmark logging error:', e);
  }
}

// Durum yazısı (Hata Çözümü: Global referansı kontrol ederek kullan)
function setStatus(s) {
  if (statusText) statusText.textContent = s;
}

// Varsayılan ayarları getir
function getDefaultSettings() {
    return {
      severity: ['high', 'medium', 'low'],
      vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
      scanOptions: ['passive']
    };
}

// Placeholder: Kendi gerçek implementasyonunuzla değiştirin
function calculateScore(vuln, scoreMethodConfig) {
    // ScoreMethods'daki formül ve ağırlıklar burada uygulanmalı
    // Basit Random Score
    return Math.floor(Math.random() * 100); 
}

// Placeholder: Kendi gerçek implementasyonunuzla değiştirin
function executeFuzzyLogic(vuln, fuzzyConfig) {
    // FuzzyLogic'teki üyelik fonksiyonları ve kurallar burada uygulanmalı
    const score = Math.random();
    return score > 0.7 ? 'High' : (score > 0.4 ? 'Medium' : 'Low');
}

// LLM Score ve Fuzzy Logic hesaplama (Hata Çözümü: Config varlığını kontrol et)
function generateHybridResults() {
    // Config nesnelerinin varlığını ve llmModels içini kontrol et
    if (!fuzzyLogicConfig.llmModels || !scoreMethods.llmModels) {
        currentVulns = currentVulns.map(vuln => {
            vuln.llmScore = vuln.llmScore || 50; 
            vuln.fuzzySeverity = vuln.severity ? vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1) : 'Medium';
            vuln.severity = vuln.severity || 'medium';
            return vuln;
        });
        console.warn('Fuzzy/Score config henüz yüklenmedi. Varsayılan skorlar kullanılıyor.');
        return;
    }

    currentVulns = currentVulns.map(vuln => {
        // Seçili model bulunamazsa GPT varsayılana dön
        const scoreMethodConfig = scoreMethods.llmModels[selectedScoreModel] || scoreMethods.llmModels['gpt'];
        const fuzzyConfig = fuzzyLogicConfig.llmModels[selectedFuzzyModel] || fuzzyLogicConfig.llmModels['gpt'];

        // 1. LLM Score (0-100)
        vuln.llmScore = calculateScore(vuln, scoreMethodConfig);
        
        // 2. Fuzzy Logic Score (High/Medium/Low)
        vuln.fuzzySeverity = executeFuzzyLogic(vuln, fuzzyConfig);
        
        // 3. Final Severity (Filtreleme için)
        vuln.severity = vuln.fuzzySeverity.toLowerCase();
        
        return vuln;
    });
}

function renderVulns() {
  // Filtreleme
  const filteredVulns = currentVulns.filter(vuln => {
    // Null/undefined kontrolü ekle
    const severityMatch = filterSettings.severity && filterSettings.severity.includes(vuln.severity);
    const typeMatch = filterSettings.vulnTypes && filterSettings.vulnTypes.includes(vuln.type);
    return severityMatch && typeMatch;
  });

  if (!vulnListDiv) return; // DOM'da yoksa çık

  vulnListDiv.innerHTML = '';
  
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
        <span class="vuln-severity">${vuln.fuzzySeverity || 'N/A'}</span>
        <h4>${vuln.title || 'Bilinmeyen Açık'} (${vuln.type ? vuln.type.toUpperCase() : 'N/A'})</h4>
      </div>
      <p class="vuln-details">${vuln.details || 'Detay yok.'}</p>
      <button class="details-btn">Detaylar</button>
    `;
    
    item.querySelector('.details-btn').addEventListener('click', () => {
        showVulnDetails(vuln);
    });

    vulnListDiv.appendChild(item);
  });
}

function showVulnDetails(vuln) {
    document.getElementById('results')?.classList.remove('active');
    
    let detailSection = document.getElementById('vulnDetailSection');
    // Eğer detailSection yoksa dinamik olarak oluştur
    if (!detailSection) {
        detailSection = document.createElement('section');
        detailSection.id = 'vulnDetailSection';
        detailSection.className = 'tab-content';
        document.querySelector('.modal').appendChild(detailSection);
    }

    detailSection.innerHTML = `
        <header class="modal-header">
            <h1 class="detail-title">${vuln.title || 'Detaylar'}</h1>
            <button id="backToResultsBtn" class="back-button">← Sonuçlara Geri Dön</button>
        </header>
        <div class="card detail-card">
            <div class="detail-row">
                <strong>Şiddet (Fuzzy):</strong> <span class="vuln-severity severity-${vuln.severity}">${vuln.fuzzySeverity || 'N/A'}</span>
            </div>
            <div class="detail-row">
                <strong>LLM Skoru (0-100):</strong> ${vuln.llmScore || 'N/A'}
            </div>
            <div class="detail-row">
                <strong>Açık Tipi:</strong> ${vuln.type ? vuln.type.toUpperCase() : 'N/A'}
            </div>
            <div class="detail-row">
                <strong>Detaylar:</strong> ${vuln.details || 'Yok'}
            </div>
            ${vuln.evidence ? `<div class="detail-row">
                <strong>Kanıt/Kod:</strong> <pre>${vuln.evidence}</pre>
            </div>` : ''}
            
            <div class="detail-row detail-factors">
                <strong>Faktörler:</strong> 
                <ul>
                    <li>Konum: ${vuln.location || 'N/A'}</li>
                    <li>Eşleşme Sayısı: ${vuln.matchCount || 0}</li>
                    <li>Context: ${vuln.contextFactors ? 'Etkili' : 'Etkisiz'}</li>
                    <li>Kullanıcı Etkileşimi: ${vuln.userInteractionRequired ? 'Gerekli' : 'Gereksiz'}</li>
                    <li>Harici Faktörler (Malicious URL): ${vuln.isMaliciousURL ? 'Evet' : 'Hayır'}</li>
                </ul>
            </div>
        </div>
    `;
    detailSection.classList.add('active');

    detailSection.querySelector('#backToResultsBtn')?.addEventListener('click', () => {
        detailSection.classList.remove('active');
        document.getElementById('results')?.classList.add('active');
    });
}

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

// Dışa aktarma helper'ı 
function exportData(data, filename, mime) {
    const blob = new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    if (chrome.downloads) {
        chrome.downloads.download({ url, filename }, () => URL.revokeObjectURL(url));
    } else {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }
}


// ===== INITIALIZATION / EVENT LISTENERS =====

document.addEventListener('DOMContentLoaded', () => {
  // Konfigürasyonları yükle (Asenkron)
  chrome.runtime.sendMessage({ action: 'getFuzzyLogic' }, (resp) => {
    if (resp && resp.fuzzyLogic) {
      fuzzyLogicConfig = resp.fuzzyLogic;
      generateHybridResults();
      renderVulns();
    }
  });

  chrome.runtime.sendMessage({ action: 'getScoreMethods' }, (resp) => {
    if (resp && resp.scoreMethods) {
      scoreMethods = resp.scoreMethods;
      generateHybridResults();
      renderVulns();
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
      document.getElementById(targetTab)?.classList.add('active');
      e.target.classList.add('active');
      
      // Ayarlar sekmesine tıklandığında settings.html'e yönlendir
      if (targetTab === 'settings') {
        window.location.href = 'settings.html';
      }
      
      // Detay sekmesini kontrol et
      document.getElementById('vulnDetailSection')?.classList.remove('active');
      if (targetTab === 'results') {
          document.getElementById('results').classList.add('active');
      }
    });
  });
  
  // Model seçimi listener'ları
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
      // Tüm filtre butonlarını pasif yap, sadece tıklananı aktif yap
      document.querySelectorAll('.filter').forEach(btn => btn.classList.remove('active'));
      e.target.classList.add('active');
      
      const severity = e.target.getAttribute('data-sev');
      // Tümü seçiliyse tüm seviyeleri ekle, değilse sadece seçileni
      filterSettings.severity = severity === 'all' ? ['high', 'medium', 'low'] : [severity];
      renderVulns();
    });
  });
  
  // Export butonları
  document.getElementById('exportJson')?.addEventListener('click', () => {
    const filteredVulns = currentVulns.filter(vuln => filterSettings.severity.includes(vuln.severity) && filterSettings.vulnTypes.includes(vuln.type));
    exportData(JSON.stringify(filteredVulns, null, 2), 'vulnerabilities.json', 'application/json');
    setStatus('JSON olarak dışa aktarıldı');
  });

  document.getElementById('exportCsv')?.addEventListener('click', () => {
    setStatus('CSV Dışa Aktarma Hazırlanıyor...');
    // CSV Export mantığı buraya eklenebilir
    // Örneğin: const csvData = convertToCsv(filteredVulns); exportData(csvData, 'vulnerabilities.csv', 'text/csv');
  });
  
  // ===== TARAMA BAŞLATMA (HATA ÇÖZÜMÜ) =====
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      setStatus('Taranıyor...');
      const scanStartTime = Date.now();
      
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.id) {
          setStatus('Aktif sekme bulunamadı');
          return;
        }

        const sendMessageAndHandleError = () => {
          
          // ZAMAN AŞIMI MEKANİZMASI (8 saniye)
          const timeoutId = setTimeout(() => {
              if (document.getElementById('statusText')?.textContent === 'Taranıyor...') {
                  setStatus('Tarama zaman aşımına uğradı (content script yanıt vermiyor).');
                  getVulnsFromBackground();
              }
          }, 8000);

          chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
              clearTimeout(timeoutId);

              if (chrome.runtime.lastError) {
                  console.error('sendMessage error:', chrome.runtime.lastError.message);
                  setStatus('Tarama başarısız: Sekmeye erişilemiyor veya content.js hatası.');
                  getVulnsFromBackground();
                  return;
              }

              if (response && Array.isArray(response.vulnerabilities)) {
                  currentVulns = response.vulnerabilities;
                  // Sonuçları background'a kaydet (popup kapandığında kaybolmasın diye)
                  chrome.runtime.sendMessage({ action: 'vulnerabilitiesDetected', vulnerabilities: currentVulns });
                  
                  generateHybridResults();
                  
                  renderVulns();
                  const scanDuration = Date.now() - scanStartTime;
                  setStatus(`Tarandı — ${currentVulns.length} açık bulundu (${scanDuration}ms)`);
              } else {
                  setStatus('Tarandı — 0 açık (Yanıt alındı, sonuç boş)');
                  currentVulns = [];
                  renderVulns();
              }
          });
        };

        // Content script enjeksiyon kontrolü
        chrome.tabs.sendMessage(tab.id, { action: 'checkStatus' }, async (response) => {
          if (chrome.runtime.lastError || !response || !response.status) {
            try {
              // Content script yoksa, programlı enjekte et
              await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js']
              });
              sendMessageAndHandleError();

            } catch (e) {
              console.error('Script enjeksiyon hatası:', e);
              setStatus('Script enjeksiyonu başarısız. Manifest izinlerini kontrol edin.');
            }
          } else {
            // Content script zaten çalışıyorsa