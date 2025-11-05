// popup.js
// popup ile background / content arasında haberleşme, UI render
// Fuzzy Logic executor ve score hesaplama
// Sentry.io entegrasyonu ve benchmark logging

// ===== SENTRY ENTEGRASYONU =====
// Sentry SDK'yı (Opsiyonel) başlat
// NOT: Chrome Extension CSP kısıtlamaları nedeniyle, Sentry CDN kullanımı devre dışı bırakıldı.
// Benchmark logging sadece Chrome Storage'a yapılır.
const SENTRY_DSN = ''; // Devre dışı (CSP güvenlik kısıtlaması)
let sentryActive = false;

// Async Sentry başlatma (Şu an devre dışı)
async function initSentry() {
  // Sentry CDN, Chrome Extension CSP'si tarafından engelleniyor.
  // Remote monitoring için, kendiniz bir backend oluşturabilirsiniz.
  sentryActive = false;
  console.log('Sentry integration disabled (CSP restriction)');
}

// Benchmark loglama
function logBenchmark(eventName, data) {
  try {
    // Sentry'ye gönder (şu an devre dışı - CSP kısıtlaması)
    if (sentryActive && window.Sentry) {
      window.Sentry.captureEvent({
        message: eventName,
        level: 'info',
        tags: { type: 'benchmark' },
        contexts: {
          benchmark: data
        }
      });
    }
    
    // Chrome Storage'a yerel olarak da kaydet (Analytics)
    chrome.storage.local.get('benchmarkData', (result) => {
      let benchmarks = result.benchmarkData || [];
      benchmarks.push({
        timestamp: new Date().toISOString(),
        eventName,
        data
      });
      // Son 1000 event'i tut
      if (benchmarks.length > 1000) benchmarks = benchmarks.slice(-1000);
      chrome.storage.local.set({ benchmarkData: benchmarks });
    });
  } catch (e) {
    console.error('Benchmark logging error', e);
  }
}

// Sentry'yi başlat
initSentry();

// ===== DOM ELEMENTS =====
const scanBtn = document.getElementById('scanBtn');
const exportJsonBtn = document.getElementById('exportJson');
const exportCsvBtn = document.getElementById('exportCsv');
const vulnList = document.getElementById('vulnList');
const statusText = document.getElementById('statusText');
const scoreMethodSelect = document.getElementById('scoreMethodSelect');
const fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
const aiSuggestions = document.getElementById('aiSuggestions');

// Safety check for DOM elements
if (!scanBtn || !exportJsonBtn || !exportCsvBtn) {
  console.error('Critical DOM elements missing. Check popup.html');
}

// ===== STATE VARIABLES =====
let currentVulns = [];
let currentFilter = 'all';
let filterSettings = null;
let fuzzyLogicConfig = {};
let scoreMethods = {};
let hybridResults = {}; // Hibrit sonuçlar için
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' }; // Kullanıcı seçimi

// ===== FUZZY LOGIC EXECUTOR =====

// Trapezoidal üyelik fonksiyonu
function trapezoidalMembership(value, params) {
  const [a, b, c, d] = params;
  if (value <= a || value >= d) return 0;
  if (value >= b && value <= c) return 1;
  if (value > a && value < b) return (value - a) / (b - a);
  if (value > c && value < d) return (d - value) / (d - c);
  return 0;
}

// Fuzzy Logic executor - Belirli bir LLM modeli için
function executeFuzzyLogic(vulnData, llmModel = 'gpt') {
  if (!fuzzyLogicConfig.llmModels || !fuzzyLogicConfig.llmModels[llmModel]) {
    console.warn(`Fuzzy Logic model '${llmModel}' bulunamadı`);
    return { label: 'Bilinmiyor', score: 0, numericLevel: 0 };
  }

  const model = fuzzyLogicConfig.llmModels[llmModel];
  
  // Girdileri encode et (string -> numeric)
  const typeScore = model.memberships.type[vulnData.type] ? 
    trapezoidalMembership(vulnData.typeWeight || 0.5, model.memberships.type[vulnData.type]) : 0.5;
  
  const locationScore = model.memberships.location[vulnData.location] ?
    trapezoidalMembership(vulnData.locationWeight || 0.5, model.memberships.location[vulnData.location]) : 0.5;
  
  const matchCountNorm = Math.min(vulnData.matchCount / 10, 1);
  const matchCountScore = model.memberships.matchCount[
    matchCountNorm > 0.6 ? 'high' : matchCountNorm > 0.2 ? 'medium' : 'low'
  ] ? trapezoidalMembership(matchCountNorm, model.memberships.matchCount[
    matchCountNorm > 0.6 ? 'high' : matchCountNorm > 0.2 ? 'medium' : 'low'
  ]) : 0.5;

  const contextScore = model.memberships.contextFactors[vulnData.httpsPresent ? 'httpsPresent' : 'httpsAbsent'] ?
    trapezoidalMembership(0.5, model.memberships.contextFactors[vulnData.httpsPresent ? 'httpsPresent' : 'httpsAbsent']) : 0.5;

  // Kuralları uygula
  let ruleOutputs = {};
  if (model.rules && Array.isArray(model.rules)) {
    model.rules.forEach(rule => {
      let activation = 1;
      if (rule.if && Array.isArray(rule.if)) {
        rule.if.forEach(condition => {
          // Basit AND mantığı
          activation = Math.min(activation, 0.7); // Örnek aktivasyon
        });
      }
      activation *= rule.weight || 1;
      ruleOutputs[rule.then] = Math.max(ruleOutputs[rule.then] || 0, activation);
    });
  }

  // En yüksek aktivasyonlu output'u seç (Defuzzification)
  let bestOutput = 'dusuk';
  let bestScore = 0;
  for (const [key, score] of Object.entries(ruleOutputs)) {
    if (score > bestScore) {
      bestScore = score;
      bestOutput = key;
    }
  }

  // Eğer kurallar sonuç vermezse, doğrudan skordan karar ver
  if (bestScore === 0) {
    const avgScore = (typeScore + locationScore + matchCountScore + contextScore) / 4;
    if (avgScore > 0.75) bestOutput = 'kritik';
    else if (avgScore > 0.5) bestOutput = 'yuksek';
    else if (avgScore > 0.25) bestOutput = 'orta';
    else bestOutput = 'dusuk';
  }

  const output = model.outputs[bestOutput] || { label: 'Orta', score: 5, numericLevel: 0.5 };
  return output;
}

// ===== SCORE HESAPLAMA =====

// Tespit edilen açıklık için score hesapla
function calculateScoreForVuln(vuln, llmModel = 'gpt') {
  if (!scoreMethods.llmModels || !scoreMethods.llmModels[llmModel]) {
    console.warn(`Score Method model '${llmModel}' bulunamadı`);
    return 0.5;
  }

  const method = scoreMethods.llmModels[llmModel];
  
  // Ağırlıkları al
  const typeWeight = method.typeWeights[vuln.type] || 0.5;
  const locationWeight = method.locationWeights[vuln.location] || 0.5;
  const matchCountNorm = Math.min((vuln.matchCount || 1) / 10, 1);
  
  // Context faktörü hesapla
  let contextWeight = 0.5;
  if (typeof vuln.httpsPresent === 'boolean') {
    contextWeight = vuln.httpsPresent ? 0.3 : 0.8;
  }
  if (vuln.userInteractionRequired) {
    contextWeight -= 0.2;
  }
  if (vuln.isMaliciousURL) {
    contextWeight += 0.4;
  }
  contextWeight = Math.min(Math.max(contextWeight, 0), 1);

  // Formülü uygula (GPT formülü örneği)
  let score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2);
  
  return Math.min(Math.max(score, 0), 1); // 0-1 arası normalize
}

// ===== HIBRIT SONUÇLAR =====

// Tüm LLM kombinasyonları için sonuçlar üret
function generateHybridResults() {
  hybridResults = {};
  
  // Her açıklık için
  currentVulns.forEach((vuln, idx) => {
    hybridResults[idx] = {};
    
    // Her LLM modeli için
    Object.keys(scoreMethods.llmModels || {}).forEach(scoreLLM => {
      hybridResults[idx][scoreLLM] = {};
      
      // Score hesapla
      const score = calculateScoreForVuln(vuln, scoreLLM);
      
      // Her fuzzy LLM'ye gönder
      Object.keys(fuzzyLogicConfig.llmModels || {}).forEach(fuzzyLLM => {
        const key = `${scoreLLM}_${fuzzyLLM}`;
        hybridResults[idx][scoreLLM][fuzzyLLM] = executeFuzzyLogic(
          {
            type: vuln.type,
            typeWeight: (scoreMethods.llmModels[scoreLLM]?.typeWeights[vuln.type] || 0.5),
            location: vuln.location,
            locationWeight: (scoreMethods.llmModels[scoreLLM]?.locationWeights[vuln.location] || 0.5),
            matchCount: vuln.matchCount || 1,
            httpsPresent: true, // Detection'dan alınacak
            userInteractionRequired: vuln.userInteractionRequired,
            isMaliciousURL: false // Detection'dan alınacak
          },
          fuzzyLLM
        );
      });
    });
  });
  
  // Benchmark loglama
  logBenchmark('hybrid_results_generated', {
    vulnCount: currentVulns.length,
    scoreMethodCount: Object.keys(scoreMethods.llmModels || {}).length,
    fuzzyLogicCount: Object.keys(fuzzyLogicConfig.llmModels || {}).length
  });
}

// ===== UI SEKMELER VE KONTROLLER =====

// Sekmeler arası geçiş
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

// Filtre butonları
document.querySelectorAll('.filter').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('.filter').forEach(x => x.classList.remove('active'));
    e.target.classList.add('active');
    currentFilter = e.target.dataset.sev;
    renderVulns();
  });
});

// Model seçim dropdown'ları event listeners
if (scoreMethodSelect) {
  scoreMethodSelect.addEventListener('change', (e) => {
    selectedModels.scoreMethod = e.target.value;
    logBenchmark('score_method_selected', { model: e.target.value });
    renderVulns(); // Sonuçları yeniden renderla
  });
}

if (fuzzyLogicSelect) {
  fuzzyLogicSelect.addEventListener('change', (e) => {
    selectedModels.fuzzyLogic = e.target.value;
    logBenchmark('fuzzy_logic_selected', { model: e.target.value });
    renderVulns(); // Sonuçları yeniden renderla
  });
}

// Tarama başlatma
if (scanBtn) {
  scanBtn.addEventListener('click', async () => {
    setStatus('Taranıyor...');
    const scanStartTime = Date.now();
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.id) {
        setStatus('Aktif sekme bulunamadı');
        logBenchmark('scan_error', { reason: 'no_active_tab' });
        return;
      }

      chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn('sendMessage error', chrome.runtime.lastError);
          setStatus('İçerik scripti yüklü değil');
          logBenchmark('scan_error', { reason: 'content_script_error' });
          getVulnsFromBackground();
          return;
        }

        if (response && response.vulnerabilities) {
          currentVulns = response.vulnerabilities || [];
          chrome.runtime.sendMessage({ action: 'vulnerabilitiesDetected', vulnerabilities: currentVulns });
          
          // Fuzzy logic ile derecelendirme yap
          generateHybridResults();
          
          renderVulns();
          const scanDuration = Date.now() - scanStartTime;
          setStatus(`Tarandı — ${currentVulns.length} açık bulundu`);
          
          // Benchmark loglama
          logBenchmark('scan_completed', {
            vulnCount: currentVulns.length,
            duration: scanDuration,
            url: tab.url
          });
        } else {
          logBenchmark('scan_error', { reason: 'no_vulnerabilities_response' });
          getVulnsFromBackground();
        }
      });
    });
  });
}

// JSON dışa aktar
if (exportJsonBtn) {
  exportJsonBtn.addEventListener('click', () => {
    if (!currentVulns.length) {
      alert('Dışa aktarmak için önce tarama yapın.');
      return;
    }
    const dataStr = JSON.stringify(currentVulns, null, 2);
    downloadBlob(dataStr, 'application/json', 'wg_vulnerabilities.json');
    logBenchmark('export_json', { vulnCount: currentVulns.length });
  });
}
// CSV dışa aktar
if (exportCsvBtn) {
  exportCsvBtn.addEventListener('click', () => {
    if (!currentVulns.length) {
      alert('Dışa aktarmak için önce tarama yapın.');
      return;
    }
    const csv = toCsv(currentVulns);
    downloadBlob(csv, 'text/csv', 'wg_vulnerabilities.csv');
    logBenchmark('export_csv', { vulnCount: currentVulns.length });
  });
}

// ===== HELPER FUNCTIONS =====

// Background'dan veri al
function getVulnsFromBackground() {
  chrome.runtime.sendMessage({ action: 'getVulns' }, (resp) => {
    if (resp && resp.vulnerabilities) {
      currentVulns = resp.vulnerabilities;
      generateHybridResults();
      renderVulns();
      setStatus(`Son kayıt yüklendi — ${currentVulns.length} açık`);
    } else {
      currentVulns = [];
      renderVulns();
      setStatus('Henüz tarama yapılmadı');
    }
  });
}

// **[YENİ EKLENDİ]** Detayları Göster/Gizle Tıklama Dinleyicisi
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('toggle-details')) {
        const detailsDiv = e.target.previousElementSibling; 
        if (detailsDiv && detailsDiv.classList.contains('result-details')) {
            const isVisible = detailsDiv.style.display === 'block';
            detailsDiv.style.display = isVisible ? 'none' : 'block';
            e.target.textContent = isVisible ? 'Detayları Göster' : 'Detayları Gizle';
        }
    }
});


// Render
function renderVulns() {
  chrome.storage.local.get('scannerSettings', (result) => {
    filterSettings = result.scannerSettings || {
      severity: ['high', 'medium', 'low'],
      vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
      scanOptions: ['passive']
    };

    let filtered = currentVulns.filter(v => {
      if (!v) return false;
      if (currentFilter === 'all') return true;
      return (v.severity || '').toLowerCase() === currentFilter;
    });

    if (filterSettings) {
      if (filterSettings.severity?.length)
        filtered = filtered.filter(v => filterSettings.severity.includes(v.severity));

      if (filterSettings.vulnTypes?.length)
        filtered = filtered.filter(v => {
          if (!v.type && filterSettings.vulnTypes.includes('other')) return true;
          return filterSettings.vulnTypes.includes(v.type);
        });
    }

    vulnList.innerHTML = '';
    if (!filtered.length) {
      vulnList.classList.add('empty');
      vulnList.innerHTML = `<div class="empty-state"><p>Bu filtreye uygun açık bulunamadı.</p></div>`;
      return;
    }

    vulnList.classList.remove('empty');
    const ul = document.createElement('div');
    ul.className = 'vuln-items';

    filtered.forEach((v, displayIdx) => {
      const origIdx = currentVulns.indexOf(v);
      const card = document.createElement('div');
      card.className = 'vuln-item';

      const sev = (v.severity || 'medium').toLowerCase();
      const sevBadge = document.createElement('span');
      sevBadge.className = `sev ${sev}`;
      sevBadge.textContent = sev === 'high' ? 'Yüksek' : sev === 'medium' ? 'Orta' : sev === 'low' ? 'Düşük' : sev;

      const title = document.createElement('div');
      title.className = 'vuln-title';
      title.textContent = v.title || '(başlık yok)';

      const details = document.createElement('div');
      details.className = 'vuln-details';
      details.textContent = v.details || '';

      const meta = document.createElement('div');
      meta.className = 'vuln-meta';
      meta.innerHTML = `<small>Tip: ${v.type || '-'} | ID: ${v.id || '-'}</small>`;

      card.append(sevBadge, title, details, meta);

      // Hibrit Sonuçlar Paneli
      const hybridPanel = document.createElement('div');
      hybridPanel.className = 'hybrid-results-panel';
      
      const panelTitle = document.createElement('div');
      panelTitle.className = 'hybrid-panel-title';
      panelTitle.innerHTML = '<strong>📊 Seçili Model Değerlendirmesi:</strong>';
      
      const resultsContainer = document.createElement('div');
      resultsContainer.className = 'hybrid-results-container';
      
      let finalScore = 'N/A';
      let fuzzyLabel = 'Bilinmiyor';

      // Seçili modellerin sonucunu göster
      if (hybridResults[origIdx] && 
          hybridResults[origIdx][selectedModels.scoreMethod] && 
          hybridResults[origIdx][selectedModels.scoreMethod][selectedModels.fuzzyLogic]) {
        
        const result = hybridResults[origIdx][selectedModels.scoreMethod][selectedModels.fuzzyLogic];
        fuzzyLabel = result.label;
        finalScore = (result.score * 10).toFixed(1);

        const resultCard = document.createElement('div');
        resultCard.className = `hybrid-result-card ${result.numericLevel >= 0.7 ? 'critical' : result.numericLevel >= 0.4 ? 'high' : 'medium'}`;
        resultCard.innerHTML = `
          <div class="result-main">
            <div class="result-model">${selectedModels.scoreMethod.toUpperCase()} + ${selectedModels.fuzzyLogic.toUpperCase()}</div>
            <div class="result-label">${result.label}</div>
            <div class="result-score">${finalScore}/10</div>
          </div>
        `;
        resultsContainer.appendChild(resultCard);
      } else {
        resultsContainer.innerHTML = '<p style="color: var(--muted); font-size: 12px;">Henüz model seçimi yapılmadı veya sonuç bulunamadı.</p>';
      }
      
      hybridPanel.append(panelTitle, resultsContainer);
      card.appendChild(hybridPanel);


      // **[YENİ EKLENDİ]** Puan Detayı ve Çözüm Önerisi oluşturma
      
      const scoreWeight = scoreMethods.llmModels[selectedModels.scoreMethod];
      const typeWeight = scoreWeight ? scoreWeight.typeWeights[v.type] || 0.5 : 0.5;
      const locationWeight = scoreWeight ? scoreWeight.locationWeights[v.location] || 0.5 : 0.5;

      const tempScoreDetail = `LLM (${selectedModels.scoreMethod.toUpperCase()}): Tip Ağırlığı: ${typeWeight.toFixed(2)}, Konum Ağırlığı: ${locationWeight.toFixed(2)}, Son Fuzzy Çıktı: ${fuzzyLabel} (${finalScore}/10)`;

      let tempFixSuggestion = 'Genel Çözüm Önerisi: Tüm kullanıcı girişlerini sunucu tarafında temizleyin (sanitize) ve modern güvenlik başlıklarını kullanın.';
      if (v.type === 'xss') {
          tempFixSuggestion = 'XSS Önleme: DOM manipülasyonları yaparken **.textContent** kullanın ve kullanıcıdan gelen veriyi asla **.innerHTML** ile basmayın. Inputları uygun şekilde kodlayın (output encoding).';
      } else if (v.type === 'csp') {
          tempFixSuggestion = 'CSP Ekleme: Güçlü bir **Content-Security-Policy** başlığı tanımlayın. Özellikle tarayıcınızın engellemediği **unsafe-inline** ve **unsafe-eval** gibi direktiflerden kaçının.';
      } else if (v.type === 'cookie') {
           tempFixSuggestion = 'Cookie Güvenliği: Hassas veriler için **Secure** ve **HttpOnly** bayraklarını kullanın. Hassas olmayan veriler için **SameSite=Strict** veya **Lax** uygulayın.';
      }
      // **[YENİ EKLENDİ]** Detaylar ve Öneri alanı
      const detailsContainer = document.createElement('div');
      detailsContainer.className = 'result-details';
      detailsContainer.style.display = 'none'; // Varsayılan olarak gizli
      detailsContainer.innerHTML = `
          <h4>Puan Detayı:</h4>
          <p class="score-breakdown">${tempScoreDetail}</p>
          <h4>Önerilen Çözüm:</h4>
          <p class="fix-suggestion-content">${tempFixSuggestion}</p>
      `;
      
      const toggleButton = document.createElement('button');
      toggleButton.className = 'toggle-details';
      toggleButton.textContent = 'Detayları Göster';
      
      // Kanıt (Evidence) paneli varsa, eklemeleri Kanıt panelinden önce yap
      if (v.evidence) {
        const evidBtn = document.createElement('button');
        evidBtn.className = 'evidence-btn';
        evidBtn.textContent = 'Kanıtı Göster';
        const evidPanel = document.createElement('pre');
        evidPanel.className = 'evidence-panel';
        evidPanel.textContent = typeof v.evidence === 'string'
          ? v.evidence
          : JSON.stringify(v.evidence, null, 2);

        evidBtn.addEventListener('click', () => {
          evidPanel.classList.toggle('visible');
        });
        
        // Yeni elementleri Kanıt butonundan önce ekle
        card.append(detailsContainer, toggleButton, evidBtn, evidPanel);
      } else {
        // Kanıt yoksa, yeni elementleri en sona ekle
        card.append(detailsContainer, toggleButton);
      }


      ul.appendChild(card);
    });

    vulnList.appendChild(ul);
  });
}

// CSV dönüştürücü
function toCsv(arr) {
  if (!arr?.length) return '';
  const headers = ['id', 'title', 'details', 'type', 'severity', 'evidence'];
  const lines = [headers.join(',')];

  arr.forEach(item => {
    const row = headers.map(h => {
      let v = item[h];
      if (v == null) return '""';
      if (typeof v === 'object') v = JSON.stringify(v);
      v = String(v).replace(/"/g, '""');
      return `"${v}"`;
    });
    lines.push(row.join(','));
  });

  return lines.join('\n');
}

// Dosya indirme
function downloadBlob(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
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

// Durum yazısı
function setStatus(s) {
  if (statusText) statusText.textContent = s;
}

// ===== INITIALIZATION =====

// Sayfa açıldığında
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
    filterSettings = result.scannerSettings || {
      severity: ['high', 'medium', 'low'],
      vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
      scanOptions: ['passive']
    };
  });

  getVulnsFromBackground();

  const scanOnLoad = document.getElementById('scanOnLoad');
  if (scanOnLoad) {
    scanOnLoad.addEventListener('change', (e) => {
      chrome.storage.local.set({ scanOnPageLoad: e.target.checked });
      logBenchmark('scan_on_load_changed', { value: e.target.checked });
    });
  }
  
  logBenchmark('popup_loaded', { timestamp: new Date().toISOString() });
});