// popup.js
// popup ile background / content arasında haberleşme, UI render
// Fuzzy Logic executor ve score hesaplama
// Sentry.io entegrasyonu ve benchmark logging

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
        data
      });
      // Limit to 1000 logs
      if (benchmarks.length > 1000) benchmarks = benchmarks.slice(-1000); 
      chrome.storage.local.set({ benchmarkData: benchmarks });
    });
  } catch (e) {
    console.error('Benchmark logging error', e);
  }
}

initSentry();

// ===== DOM ELEMENTS (DOMContentLoaded içinde erişilecek) =====
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions;

// ===== STATE VARIABLES =====
let currentVulns = [];
let currentFilter = 'all';
let filterSettings = null;
let fuzzyLogicConfig = {};
let scoreMethods = {};
let hybridResults = {}; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };

// ===== FUZZY LOGIC UTILS =====

function trapezoidalMembership(value, params) {
  const [a, b, c, d] = params;
  if (value <= a || value >= d) return 0;
  if (value >= b && value <= c) return 1;
  if (value > a && value < b) return (value - a) / (b - a);
  if (value > c && value < d) return (d - value) / (d - c);
  return 0;
}

function executeFuzzyLogic(vulnData, llmModel = 'gpt') {
  if (!fuzzyLogicConfig.llmModels || !fuzzyLogicConfig.llmModels[llmModel]) {
    console.warn(`Fuzzy Logic model '${llmModel}' bulunamadı`);
    return { label: 'Bilinmiyor', score: 0, numericLevel: 0 };
  }

  const model = fuzzyLogicConfig.llmModels[llmModel];
  
  // Basit bir örnek için, ağırlık değerlerini doğrudan kullan.
  const typeScore = vulnData.typeWeight || 0.5;
  const locationScore = vulnData.locationWeight || 0.5;
  const matchCountNorm = Math.min(vulnData.matchCount / 10, 1);
  const avgScore = (typeScore * 0.4) + (locationScore * 0.3) + (matchCountNorm * 0.3);

  let bestOutput = 'dusuk';
  if (avgScore > 0.8) bestOutput = 'kritik';
  else if (avgScore > 0.6) bestOutput = 'yuksek';
  else if (avgScore > 0.4) bestOutput = 'orta';
  else bestOutput = 'dusuk';

  // Rule-based mantığı simüle et (Gerçek fuzzy logic burada olur)
  const output = model.outputs ? model.outputs[bestOutput] : { 
      label: bestOutput.charAt(0).toUpperCase() + bestOutput.slice(1), 
      score: Math.round(avgScore * 100) / 10, // 10 üzerinden yuvarla
      numericLevel: avgScore 
  };
  return output;
}

// ===== SCORE HESAPLAMA =====

function calculateScoreForVuln(vuln, llmModel = 'gpt') {
  if (!scoreMethods.llmModels || !scoreMethods.llmModels[llmModel]) {
    console.warn(`Score Method model '${llmModel}' bulunamadı`);
    return 0.5;
  }

  const method = scoreMethods.llmModels[llmModel];
  
  const typeWeight = method.typeWeights[vuln.type] || 0.5;
  const locationWeight = method.locationWeights[vuln.location] || 0.5;
  const matchCountNorm = Math.min((vuln.matchCount || 1) / 10, 1);
  
  let contextWeight = 0.5;
  // HTTPS kontrolü (client side'da sadece sayfa protokolünü kontrol edebiliriz)
  if (window.location.protocol === 'https:') {
    contextWeight = 0.3;
  } else {
    contextWeight = 0.8;
  }

  if (vuln.userInteractionRequired) {
    contextWeight -= 0.2; // Kullanıcı etkileşimi gerektirenler daha düşüktür
  }
  if (vuln.isMaliciousURL) {
    contextWeight += 0.4; // Kötü niyetli URL daha yüksektir
  }
  contextWeight = Math.min(Math.max(contextWeight, 0), 1);

  // Formül: score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2)
  let score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2);
  
  return Math.min(Math.max(score, 0), 1); 
}

// ===== HIBRIT SONUÇLAR =====

function generateHybridResults() {
  hybridResults = {};
  
  currentVulns.forEach((vuln, idx) => {
    hybridResults[idx] = {};
    
    // Score Method'ları dene
    Object.keys(scoreMethods.llmModels || {}).forEach(scoreLLM => {
      hybridResults[idx][scoreLLM] = {};
      
      const score = calculateScoreForVuln(vuln, scoreLLM);
      
      // Fuzzy Logic Method'ları dene
      Object.keys(fuzzyLogicConfig.llmModels || {}).forEach(fuzzyLLM => {
        // Gerekli ağırlıklar Score Method'dan alınır
        hybridResults[idx][scoreLLM][fuzzyLLM] = executeFuzzyLogic(
          {
            type: vuln.type,
            typeWeight: (scoreMethods.llmModels[scoreLLM]?.typeWeights[vuln.type] || 0.5),
            location: vuln.location,
            locationWeight: (scoreMethods.llmModels[scoreLLM]?.locationWeights[vuln.location] || 0.5),
            matchCount: vuln.matchCount || 1,
            // Bu parametreler vuln nesnesinde yoktur, sadece hesaplama için simüle edilir
            userInteractionRequired: vuln.userInteractionRequired,
            isMaliciousURL: vuln.isMaliciousURL
          },
          fuzzyLLM
        );
      });
    });
  });
  
  logBenchmark('hybrid_results_generated', {
    vulnCount: currentVulns.length,
    scoreMethodCount: Object.keys(scoreMethods.llmModels || {}).length,
    fuzzyLogicCount: Object.keys(fuzzyLogicConfig.llmModels || {}).length
  });
}

// ===== UI RENDER (VULNERABILITIES) =====

// Tek bir zafiyet için HTML oluşturma
function createVulnHTML(vuln, hybridResult) {
    const defaultModel = selectedModels.fuzzyLogic;
    const scoreModel = selectedModels.scoreMethod;

    const modelResult = hybridResult[scoreModel]?.[defaultModel] || { label: 'Bilinmiyor', score: 'N/A' };
    
    // Severity sınıfını Türkçe etiketlerden CSS'e uygun formata çevir
    const sevClass = modelResult.label.toLowerCase().replace('kritik', 'high').replace('yuksek', 'high').replace('orta', 'medium').replace('dusuk', 'low').replace('bilinmiyor', 'low');

    // Kanıt (evidence) için snippet'ı kullan
    const evidenceContent = vuln.evidence ? 
        (typeof vuln.evidence === 'object' ? JSON.stringify(vuln.evidence, null, 2) : String(vuln.evidence)) : 
        'Kanıt yok.';
        
    const evidenceHtml = vuln.evidence 
        ? `<button class="evidence-btn">Kanıtı Göster</button><pre class="evidence-panel">${evidenceContent}</pre>`
        : '';
        
    // String birleştirme
    return (
        `<div class="vuln-item" data-index="${currentVulns.indexOf(vuln)}" data-severity="${sevClass}">` +
            `<span class="sev ${sevClass}">${modelResult.label}</span>` +
            `<div class="vuln-title">${vuln.title} (${modelResult.score} / 10)</div>` +
            `<div class="vuln-details">${vuln.details}</div>` +
            `<div class="vuln-meta">Tür: ${vuln.type} | Lokasyon: ${vuln.location}</div>` +
            evidenceHtml +
        `</div>`
    );
}

const emptyStateHTML = `
    <div class="empty-state">
      <p>Tebrikler! Belirtilen kriterlere uyan güvenlik açığı bulunamadı.</p>
    </div>
`;

function renderVulns() {
  const defaultModel = selectedModels.fuzzyLogic;
  const scoreModel = selectedModels.scoreMethod;

  // Filtreleme
  const filteredVulns = currentVulns.filter((vuln, idx) => {
    const result = hybridResults[idx]?.[scoreModel]?.[defaultModel];
    const sevClass = result?.label?.toLowerCase() || 'dusuk';
    
    if (currentFilter === 'all') return true;
    
    // Filtreleme mantığı: Etiketi karşılaştır
    if (currentFilter === 'high' && (sevClass === 'yuksek' || sevClass === 'kritik')) return true;
    if (currentFilter === 'medium' && sevClass === 'orta') return true;
    if (currentFilter === 'low' && sevClass === 'dusuk') return true;
    
    return false;
  });

  vulnList.innerHTML = ''; // Önce listeyi temizle

  if (filteredVulns.length === 0) {
    vulnList.innerHTML = emptyStateHTML;
    vulnList.classList.add('empty');
  } else {
    vulnList.classList.remove('empty');
    const itemsContainer = document.createElement('div');
    itemsContainer.className = 'vuln-items';

    filteredVulns.forEach((vuln) => {
        const originalIndex = currentVulns.indexOf(vuln);
        const hybridResult = hybridResults[originalIndex];
        const vulnHtml = createVulnHTML(vuln, hybridResult);
        itemsContainer.innerHTML += vulnHtml;
    });

    vulnList.appendChild(itemsContainer);

    // Event Listener'ları ekle (renderVulns içinde kalması uygundur)
    document.querySelectorAll('.evidence-btn').forEach(btn => { 
        btn.addEventListener('click', (e) => {
            const panel = e.target.closest('.vuln-item')?.querySelector('.evidence-panel');
            if (panel) { 
                panel.classList.toggle('visible');
                e.target.textContent = panel.classList.contains('visible') ? 'Kanıtı Gizle' : 'Kanıtı Göster';
            }
        });
    });
  }
}

// ===== DATA DOWNLOAD (EXPORT) UTILS =====

function downloadData(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  if (chrome.downloads) {
    // Chrome API'si kullanarak indir
    chrome.downloads.download({ url, filename }, () => URL.revokeObjectURL(url));
  } else {
    // Normal tarayıcı indir
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
}

function exportToJSON() {
  const data = JSON.stringify({
    timestamp: new Date().toISOString(),
    filter: currentFilter,
    scoreModel: selectedModels.scoreMethod,
    fuzzyModel: selectedModels.fuzzyLogic,
    results: currentVulns.map((vuln, index) => ({
      ...vuln,
      hybridScore: hybridResults[index]?.[selectedModels.scoreMethod]?.[selectedModels.fuzzyLogic]
    }))
  }, null, 2);
  downloadData(data, `scan-results-${Date.now()}.json`, 'application/json');
  setStatus('JSON olarak aktarıldı.');
  logBenchmark('export_json', { count: currentVulns.length });
}

function exportToCSV() {
  const header = "Severity,Type,Location,Title,Details,HybridScore,HybridLabel\n";
  const rows = currentVulns.map((vuln, index) => {
    const score = hybridResults[index]?.[selectedModels.scoreMethod]?.[selectedModels.fuzzyLogic];
    // CSV içeriğinde tırnak işareti varsa kaçış karakteri (escape) ekle
    const safeTitle = vuln.title.replace(/"/g, '""');
    const safeDetails = vuln.details.replace(/"/g, '""');
    return `${score?.label || vuln.severity},${vuln.type},${vuln.location},"${safeTitle}","${safeDetails}",${score?.score || 'N/A'},${score?.label || 'N/A'}`;
  });
  downloadData(header + rows.join('\n'), `scan-results-${Date.now()}.csv`, 'text/csv');
  setStatus('CSV olarak aktarıldı.');
  logBenchmark('export_csv', { count: currentVulns.length });
}

// Export butonları için listener'ları kuran fonksiyon
function setupExportButtons() {
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', exportToJSON);
    }
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportToCSV);
    }
}

// Durum yazısı
function setStatus(s) {
  if (statusText) statusText.textContent = s;
}

// ===== BACKGROUND COMMUNICATION & INITIALIZATION LOGIC =====

function getVulnsFromBackground() {
  chrome.runtime.sendMessage({ action: 'getVulns' }, (response) => {
    if (response && response.vulnerabilities) {
      currentVulns = response.vulnerabilities;
      generateHybridResults();
      renderVulns();
      setStatus(currentVulns.length === 0 ? 'Tarama tamamlandı: Açık bulunamadı.' : `${currentVulns.length} açık bulundu.`);
    } else {
      setStatus('Tarama bekleniyor...');
    }
  });
}

function fillModelSelects() {
    // Model seçim kutularını doldur
    if (scoreMethodSelect) {
        scoreMethodSelect.innerHTML = ''; 
        Object.keys(scoreMethods.llmModels || { gpt: {} }).forEach(model => {
            const option = document.createElement('option');
            option.value = model;
            option.textContent = model.toUpperCase();
            scoreMethodSelect.appendChild(option);
        });
        scoreMethodSelect.value = selectedModels.scoreMethod || 'gpt';
    }

    if (fuzzyLogicSelect) {
        fuzzyLogicSelect.innerHTML = '';
        Object.keys(fuzzyLogicConfig.llmModels || { gpt: {} }).forEach(model => {
            const option = document.createElement('option');
            option.value = model;
            option.textContent = model.toUpperCase();
            fuzzyLogicSelect.appendChild(option);
        });
        fuzzyLogicSelect.value = selectedModels.fuzzyLogic || 'gpt';
    }
}

function checkAndRender() {
    // Fuzzy logic ve Score Method config'leri yüklendiğinde çalışır
    fillModelSelects();
    getVulnsFromBackground();
}


// ===== INITIALIZATION (Tüm DOM işlemleri buraya taşınmıştır) =====

// Sayfa açıldığında
document.addEventListener('DOMContentLoaded', () => {
  // DOM öğelerine erişim (Burada tanımlanmaları ve atanmaları kritik)
  scanBtn = document.getElementById('scanBtn');
  exportJsonBtn = document.getElementById('exportJson');
  exportCsvBtn = document.getElementById('exportCsv');
  vulnList = document.getElementById('vulnList');
  statusText = document.getElementById('statusText');
  scoreMethodSelect = document.getElementById('scoreMethodSelect');
  fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
  aiSuggestions = document.getElementById('aiSuggestions');

  if (!scanBtn || !exportJsonBtn || !exportCsvBtn || !vulnList) {
    console.error('Kritik DOM elementleri eksik. popup.html dosyasını kontrol edin.');
    setStatus('Hata: UI bileşenleri eksik.');
    return;
  }
  
  // UI SEKMELER VE KONTROLLER
  document.querySelectorAll('.tab').forEach(t =>
    t.addEventListener('click', (e) => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      e.target.classList.add('active');
      const tab = e.target.dataset.tab;

      if (tab === 'settings') {
        window.location.href = 'settings.html';
        return;
      }

      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById(tab).classList.add('active');
    })
  );

  document.querySelectorAll('.filter').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.filter').forEach(x => x.classList.remove('active'));
      e.target.classList.add('active');
      currentFilter = e.target.dataset.sev;
      renderVulns();
    });
  });

  // Export buton listener'ları
  setupExportButtons();

  // Model Seçimi Listener'ları
  if (scoreMethodSelect) {
    scoreMethodSelect.addEventListener('change', (e) => {
      selectedModels.scoreMethod = e.target.value;
      logBenchmark('score_method_selected', { model: e.target.value });
      // Yeni model seçildiğinde sonuçları tekrar render et
      generateHybridResults();
      renderVulns(); 
    });
  }

  if (fuzzyLogicSelect) {
    fuzzyLogicSelect.addEventListener('change', (e) => {
      selectedModels.fuzzyLogic = e.target.value;
      logBenchmark('fuzzy_logic_selected', { model: e.target.value });
      // Yeni model seçildiğinde sonuçları tekrar render et
      generateHybridResults();
      renderVulns(); 
    });
  }

  // Tarama başlatma listener'ı
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

        // 1. Content script'i enjekte et
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
          });
        } catch (e) {
          // CSP veya zaten yüklü olması durumunda hata verebilir, sadece uyar
          console.warn('Content script injection warning:', e.message);
        }

        // 2. Tarama komutunu content.js'e gönder
        chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
          if (chrome.runtime.lastError) {
              console.warn('sendMessage error after injection attempt', chrome.runtime.lastError.message);
              setStatus('Tarama başarısız: content.js yanıt vermedi (Sekme engellenmiş olabilir).');
              getVulnsFromBackground(); // Background'dan yine de mevcut veriyi dene
              return;
          }

          if (response && response.vulnerabilities) {
              currentVulns = response.vulnerabilities || [];
              
              // content.js zaten background'a kaydetti, bu sadece UI'ı güncellemek için
              
              generateHybridResults();
              renderVulns();
              
              const scanDuration = Date.now() - scanStartTime;
              setStatus(`Tarama tamamlandı: ${currentVulns.length} açık bulundu. (${scanDuration}ms)`);
              logBenchmark('scan_success', { duration: scanDuration, vuln_count: currentVulns.length });

          } else {
              setStatus('Tarama sonuçları alınamadı (content.js yanıt vermedi).');
              getVulnsFromBackground();
          }
        });
      });
    });
  }
  
  // Konfigürasyonları yükle (Fuzzy Logic ve Score Methods)
  // İki farklı mesaj beklemesi, yüklemenin tamamlandığından emin olmak için gereklidir.
  let fuzzyLoaded = false;
  let scoreLoaded = false;

  chrome.runtime.sendMessage({ action: 'getFuzzyLogic' }, (resp) => {
    if (resp && resp.fuzzyLogic) {
      fuzzyLogicConfig = resp.fuzzyLogic;
      fuzzyLoaded = true;
      if (scoreLoaded) checkAndRender(); 
    }
  });

  chrome.runtime.sendMessage({ action: 'getScoreMethods' }, (resp) => {
    if (resp && resp.scoreMethods) {
      scoreMethods = resp.scoreMethods;
      scoreLoaded = true;
      if (fuzzyLoaded) checkAndRender();
    }
  });

  // Ayarları yükle (Filtreleme)
  chrome.storage.local.get('scannerSettings', (result) => {
    filterSettings = result.scannerSettings || {
      severity: ['high', 'medium', 'low'],
      vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
      scanOptions: ['passive']
    };
  });
});