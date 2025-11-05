// popup.js

// Global State
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'GPT', fuzzyLogic: 'GPT' }; 
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null;
let tabData = null; 
let isScanning = false;
let filterSettings = getDefaultSettings(); 

// DOM Elements - Must be initialized in DOMContentLoaded
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions, footerStatus;


// Helper: Log for performance/debugging (Simplified)
function logBenchmark(eventName, data = {}) {
    console.log(`[BENCHMARK] ${eventName}`, { timestamp: new Date().toISOString(), ...data });
}

// Helper: Set Status Text
function setStatus(message) {
    statusText.textContent = message;
    if (footerStatus) {
        footerStatus.textContent = message;
    }
}

// Helper: Get Default Settings 
function getDefaultSettings() {
  return {
    severity: ['high', 'medium', 'low'],
    vulnTypes: ['xss', 'sqli', 'csrf', 'other', 'transport', 'cookie', 'storage', 'csp', 'network'],
    scanOptions: ['passive']
  };
}

// Helper: Vulnerability Filtering
function filterVulns(vulns) {
    let filtered = vulns;
    
    if (currentFilter !== 'all') {
        filtered = filtered.filter(v => {
            const sev = v.severity ? v.severity.toLowerCase() : (v.severity || 'medium').toLowerCase();
            return sev === currentFilter;
        });
    }

    if (typeof filterSettings !== 'undefined') {
        filtered = filtered.filter(v => {
            const sev = v.severity ? v.severity.toLowerCase() : (v.severity || 'medium').toLowerCase();
            const type = v.type ? v.type.toLowerCase() : 'other';
            
            const sevMatch = filterSettings.severity.includes(sev);
            const typeMatch = filterSettings.vulnTypes.includes(type);
            
            return sevMatch && typeMatch;
        });
    }

    return filtered;
}


// --- SCORE & FUZZY LOGIC ---
function calculateScoreForVuln(vuln) {
    let score = vuln.llmScore || 50; 
    
    let label = 'Orta';
    if (score >= 90) label = 'Kritik';
    else if (score >= 70) label = 'Yüksek';
    else if (score < 40) label = 'Düşük';
    
    return { score: Math.min(100, Math.max(0, score)), label };
}

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) {
        console.warn('Fuzzy/Score config henüz yüklenmedi. Varsayılan skorlar kullanılıyor.');
        currentVulns = currentVulns.map(vuln => {
            vuln.llmScore = vuln.llmScore || 50; 
            vuln.fuzzySeverity = vuln.severity ? 
                vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1) : 
                'Orta';
            vuln.severity = vuln.severity || 'medium';
            return vuln;
        });
        return; 
    }
    
    currentVulns = currentVulns.map(vuln => {
        let hybridResult = {};
        
        Object.keys(scoreMethods).forEach(scoreKey => {
            let scoreMethodResult = {};
            
            Object.keys(fuzzyLogicConfig).forEach(fuzzyKey => {
                const { score, label } = calculateScoreForVuln(vuln);
                
                scoreMethodResult[fuzzyKey] = {
                    score: score,
                    label: label,
                };
            });
            hybridResult[scoreKey] = scoreMethodResult;
        });
        
        vuln.hybridResult = hybridResult;
        const selectedScore = hybridResult[selectedModels.scoreMethod]?.[selectedModels.fuzzyLogic];
        if (selectedScore) {
            vuln.llmScore = selectedScore.score;
            vuln.fuzzySeverity = selectedScore.label;
            vuln.severity = selectedScore.label.toLowerCase().replace('kritik', 'high').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        }
        
        return vuln;
    });
}

// --- UI RENDERING ---

function createVulnHTML(vuln, hybridResult) {
    const scoreModelKey = selectedModels.scoreMethod;
    const fuzzyModelKey = selectedModels.fuzzyLogic;

    const modelResult = hybridResult[scoreModelKey]?.[fuzzyModelKey] || { label: 'Orta', score: 'N/A' };
    const sevClass = (vuln.severity || 'medium').toLowerCase().replace('kritik', 'high').replace('yüksek', 'high');
    
    const evidenceContent = vuln.evidence ? 
        (typeof vuln.evidence === 'object' ? JSON.stringify(vuln.evidence, null, 2) : String(vuln.evidence)) : 
        'Kanıt yok.';
    
    const evidencePanel = vuln.evidence 
        ? `<div class="evidence-panel" style="display:none;"><pre>${evidenceContent}</pre></div>`
        : '';

    const modelScoreLabel = vuln.llmScore || modelResult.score;
    const modelLabel = vuln.fuzzySeverity || modelResult.label;
    
    return (
        `<div class="vuln-item severity-${sevClass}" data-severity="${sevClass}" data-type="${vuln.type.toLowerCase()}" data-index="${currentVulns.indexOf(vuln)}">` +
            `<div class="vuln-header">` +
                `<span class="vuln-severity ${sevClass}">${modelLabel} (${modelScoreLabel}/100)</span>` +
                `<h4>${vuln.title || 'Bilinmeyen Açık'} (${vuln.type.toUpperCase()})</h4>` +
            `</div>` +
            `<p class="vuln-details">${vuln.details || 'Detay yok.'}</p>` +
            `<div class="vuln-actions">` +
                `<button class="details-btn" data-index="${currentVulns.indexOf(vuln)}">Detaylar</button>` +
                (vuln.evidence ? `<button class="evidence-btn" data-index="${currentVulns.indexOf(vuln)}">Kanıtı Göster</button>` : '') +
            `</div>` +
            evidencePanel +
        `</div>`
    );
}


function renderVulns() {
    if (!vulnList) return; 
    
    const filteredVulns = filterVulns(currentVulns);
    vulnList.innerHTML = ''; 

    if (filteredVulns.length === 0) {
        vulnList.innerHTML = '<p class="no-results">Filtrelere uygun açık bulunamadı.</p>';
        setStatus(`Tarandı — 0 açık bulundu`);
        aiSuggestions.innerHTML = '';
        return;
    }

    filteredVulns.forEach(vuln => {
        const item = document.createElement('div');
        item.innerHTML = createVulnHTML(vuln, vuln.hybridResult || {});
        vulnList.appendChild(item.firstChild);
    });
    
    const scanTimeInfo = lastScanTimestamp ? `(${(Date.now() - lastScanTimestamp)}ms)` : '';
    setStatus(`Web Güvenlik Tarayıcısı — Tarandı — ${filteredVulns.length} açık bulundu ${scanTimeInfo}`);
    
    // Olay dinleyicilerini dinamik olarak ekle
    document.querySelectorAll('.evidence-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const vulnItem = e.target.closest('.vuln-item');
            const panel = vulnItem.querySelector('.evidence-panel');
            if (panel) {
                const isHidden = panel.style.display === 'none' || panel.style.display === '';
                panel.style.display = isHidden ? 'block' : 'none';
                e.target.textContent = isHidden ? 'Kanıtı Gizle' : 'Kanıtı Göster';
            }
        });
    });

    document.querySelectorAll('.details-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.target.dataset.index;
            const vuln = currentVulns.find(v => currentVulns.indexOf(v) == index); 
            showVulnDetails(vuln);
        });
    });
    
    renderAiSuggestions(filteredVulns);
}

function showVulnDetails(vuln) {
    if (!vuln) return;
    
    const detailsContainer = document.getElementById('detailsContainer');
    const listContainer = document.getElementById('vulnListContainer');
    
    if (!detailsContainer || !listContainer) return;
    
    listContainer.style.display = 'none';
    detailsContainer.style.display = 'block';
    
    const modelResult = vuln.hybridResult?.[selectedModels.scoreMethod]?.[selectedModels.fuzzyLogic] || { label: 'Orta', score: 'N/A' };
    const sevClass = (vuln.severity || 'medium').toLowerCase().replace('kritik', 'high').replace('yüksek', 'high');
    const evidenceContent = vuln.evidence ? (typeof vuln.evidence === 'object' ? JSON.stringify(vuln.evidence, null, 2) : String(vuln.evidence)) : 'Kanıt yok.';
    
    detailsContainer.innerHTML = `
        <button id="backToResults" class="back-button">← Sonuçlara Geri Dön</button>
        <div class="vuln-details-card">
            <span class="sev ${sevClass}">${modelResult.label}</span>
            <h2>${vuln.title} (${vuln.type.toUpperCase()})</h2>
            <p><strong>Şiddet (Fuzzy):</strong> ${modelResult.label}</p>
            <p><strong>LLM Skoru (0-100):</strong> ${vuln.llmScore || 'N/A'}</p>
            <p><strong>Açık Tipi:</strong> ${vuln.type.toUpperCase()}</p>
            <p><strong>Detaylar:</strong> ${vuln.details}</p>
            <p><strong>Kanıt/Kod:</strong></p>
            <pre>${evidenceContent}</pre>
            <p><strong>Faktörler:</strong></p>
            <ul>
                <li>Konum: ${vuln.location}</li>
                <li>Eşleşme Sayısı: ${vuln.matchCount}</li>
                <li>Context: ${vuln.contextFactors ? 'Etkili' : 'Etkisiz'}</li>
                <li>Kullanıcı Etkileşimi: ${vuln.userInteractionRequired ? 'Gerekli' : 'Gereksiz'}</li>
                <li>Harici Faktörler (Malicious URL): ${vuln.isMaliciousURL ? 'Evet' : 'Hayır'}</li>
            </ul>
        </div>
    `;

    document.getElementById('backToResults')?.addEventListener('click', () => {
        detailsContainer.style.display = 'none';
        listContainer.style.display = 'block';
    });
}


function renderAiSuggestions(vulns) {
    if (!aiSuggestions) return; 
    
    aiSuggestions.innerHTML = '';
    
    if (vulns.length === 0) {
        aiSuggestions.innerHTML = '<p>Filtrelere uygun açık bulunamadı.</p>';
        return;
    }
    
    const highVulns = vulns.filter(v => (v.severity || 'medium').toLowerCase() === 'high' || (v.fuzzySeverity || '').toLowerCase() === 'kritik' || (v.fuzzySeverity || '').toLowerCase() === 'yüksek');
    
    let advice = [];
    
    if (highVulns.length > 0) {
        advice.push(`<strong>${highVulns.length} Yüksek Riskli/Kritik Açık Bulundu.</strong> Bu açıkları öncelikli olarak ele alın.`);
    }

    if (vulns.some(v => v.type === 'xss' || v.type === 'storage')) {
        advice.push("XSS Önleme: DOM manipülasyonları yaparken **textContent** kullanın ve kullanıcıdan gelen veriyi asla **innerHTML** ile basmayın. Inputları uygun şekilde kodlayın (output encoding).");
    }
    if (vulns.some(v => v.type === 'csrf' || v.type === 'cookie')) {
        advice.push("CSRF/Session Güvenliği: Tüm hassas cookie'ler için **HttpOnly** ve **Secure** bayraklarını ayarlayın. **SameSite=Lax/Strict** kullanın.");
    }
    if (vulns.some(v => v.type === 'transport' || v.type === 'csp')) {
        advice.push("Ulaşım/CSP: Tüm site trafiğini **HTTPS** üzerinden zorunlu kılın. Zafiyet etkilerini azaltmak için güçlü bir **Content Security Policy (CSP)** uygulayın.");
    }

    if (advice.length === 0) {
        aiSuggestions.innerHTML = '<p>Harika! Yüksek riskli açıklar bulunamadı. Detaylı tarama sonuçlarını incelemeye devam edin.</p>';
    } else {
        aiSuggestions.innerHTML = '<h2>Önerilen Çözümler:</h2>' + advice.map(a => `<p class="ai-advice">${a}</p>`).join('');
    }
}


function setupExportButtons() {
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            downloadData(currentVulns, 'vulnerabilities', 'json');
            logBenchmark('export_json');
        });
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            downloadData(currentVulns, 'vulnerabilities', 'csv');
            logBenchmark('export_csv');
        });
    }
}

function downloadData(data, filename, format) {
    if (data.length === 0) {
        alert("Dışa aktarılacak veri bulunamadı.");
        return;
    }

    let output;
    let mimeType;

    if (format === 'json') {
        output = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
    } else if (format === 'csv') {
        const header = ['Title', 'Severity', 'Type', 'Details'].join(',');
        const rows = data.map(v => 
            [
                `"${(v.title || '').replace(/"/g, '""')}"`,
                v.fuzzySeverity || v.severity,
                v.type,
                `"${(v.details || '').replace(/"/g, '""')}"`
            ].join(',')
        );
        output = [header].concat(rows).join('\n');
        mimeType = 'text/csv';
    } else {
        return;
    }

    const blob = new Blob([output], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// --- SCANNING & COMMUNICATION ---

function getVulnsFromBackground() {
    chrome.runtime.sendMessage({ action: "getVulnerabilities" }, (response) => {
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            lastScanTimestamp = response.timestamp || Date.now();
            generateHybridResults();
            renderVulns();
            setStatus(`Web Güvenlik Tarayıcısı — Tarandı — ${currentVulns.length} açık bulundu (${(Date.now() - lastScanTimestamp)}ms)`);
            logBenchmark('initial_render_success', { vulnCount: currentVulns.length });
        } else {
            setStatus("Tarama yapılmadı veya sonuç bulunamadı.");
            logBenchmark('initial_render_no_data');
        }
    });
}

async function startScan() {
    if (isScanning) return;
    
    isScanning = true;
    scanBtn.textContent = 'Taranıyor...';
    setStatus('Tarama Başlatılıyor...');
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        tabData = tab;

        // 1. content.js'yi enjekte et. (IIFE sayesinde sadece bir kez çalışır)
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
        });
        
        // ZAMANLAMA HATASI DÜZELTMESİ: content.js'nin mesaj dinleyicisini kurması için 100ms bekleme.
        await new Promise(r => setTimeout(r, 100)); 

        // 2. Tarama komutunu gönder
        const scanStart = Date.now();
        // Bu çağrı, content.js'den yanıt gelene kadar bekler (popup'ı açık tutar).
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        
        const scanDuration = Date.now() - scanStart;
        lastScanTimestamp = Date.now();
        
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            logBenchmark('scan_success', { vulnCount: currentVulns.length, duration: scanDuration, url: tab.url });
        } else {
            // Yanıt boşsa veya hata varsa (port kapalıysa) background'dan çekmeyi dene (fallback)
            logBenchmark('scan_error', { reason: 'no_vulnerabilities_response_fallback' });
            getVulnsFromBackground(); 
            return;
        }

    } catch (error) {
        // Port kapalıysa veya uzantı izinleri yoksa bu hata fırlatılır.
        console.error('Tarama hatası (Kritik):', error);
        setStatus('Tarama hatası oluştu: Uzantı ile sayfa arasında iletişim kesildi. Lütfen sayfayı yenilemeyi deneyin veya uzantı izinlerini kontrol edin.');
        logBenchmark('scan_fatal_error', { message: error.message });
        return;
    } finally {
        isScanning = false;
        if (scanBtn) scanBtn.textContent = 'Sayfayı Tara';
    }
    
    // Sonuçları işle ve göster
    generateHybridResults();
    renderVulns();
}

// --- MAIN INITIALIZATION ---

document.addEventListener('DOMContentLoaded', () => {
    // 1. DOM Elementlerini ATAMA
    scanBtn = document.getElementById('scanBtn');
    exportJsonBtn = document.getElementById('exportJson');
    exportCsvBtn = document.getElementById('exportCsv');
    vulnList = document.getElementById('vulnList');
    statusText = document.getElementById('statusText');
    scoreMethodSelect = document.getElementById('scoreMethodSelect');
    fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
    aiSuggestions = document.getElementById('aiSuggestions');
    footerStatus = document.getElementById('footerStatus'); 
    
    // settings.js'den gelen ayarları yükle
    chrome.storage.local.get('scannerSettings', (result) => {
        filterSettings = result.scannerSettings || getDefaultSettings();
    });

    if (!scanBtn || !vulnList || !statusText) {
      console.error('Kritik DOM elementleri eksik. popup.html dosyasını kontrol edin.');
      return; 
    }
    
    // 2. UI SEKMELER VE FİLTRE KONTROLLERİ 
    document.querySelectorAll('.tab').forEach(t =>
        t.addEventListener('click', (e) => {
            const targetTab = e.target.closest('.tab');
            if (!targetTab) return; 

            document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
            targetTab.classList.add('active');
            const tabName = targetTab.dataset.tab;

            if (tabName === 'settings') {
                window.location.href = 'settings.html';
                return;
            }

            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tabName)?.classList.add('active'); 
        })
    );

    document.querySelectorAll('.filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetFilter = e.target.closest('.filter');
            if (!targetFilter) return;

            document.querySelectorAll('.filter').forEach(x => x.classList.remove('active'));
            targetFilter.classList.add('active');
            currentFilter = targetFilter.dataset.sev;
            renderVulns();
        });
    });

    // 3. MODEL SEÇİM LISTENER'LARI
    if (scoreMethodSelect) {
        scoreMethodSelect.addEventListener('change', (e) => {
            selectedModels.scoreMethod = e.target.value;
            generateHybridResults();
            renderVulns(); 
        });
    }

    if (fuzzyLogicSelect) {
        fuzzyLogicSelect.addEventListener('change', (e) => {
            selectedModels.fuzzyLogic = e.target.value;
            generateHybridResults();
            renderVulns(); 
        });
    }

    // 4. TARAMA VE EXPORT LİSTENER'LARI
    setupExportButtons(); 
    if (scanBtn) {
        scanBtn.addEventListener('click', startScan);
    }
    
    // 5. KONFİGÜRASYON VE VERİ YÜKLEME 
    let fuzzyLoaded = false;
    let scoreLoaded = false;
    
    const checkAndRender = () => {
        if (fuzzyLoaded && scoreLoaded) {
            getVulnsFromBackground();
        }
    };
    
    // Konfigürasyonları background'tan çek (Simülasyon)
    const mockFuzzy = { 'GPT': {}, 'Local': {} };
    const mockScore = { 'GPT': {}, 'Default': {} };

    // Fuzzy Logic
    if (fuzzyLogicSelect) {
        Object.keys(mockFuzzy).forEach(key => {
            const option = new Option(key, key);
            fuzzyLogicSelect.add(option);
        });
        fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
    }
    fuzzyLogicConfig = mockFuzzy;
    fuzzyLoaded = true;

    // Score Methods
    if (scoreMethodSelect) {
        Object.keys(mockScore).forEach(key => {
            const option = new Option(key, key);
            scoreMethodSelect.add(option);
        });
        scoreMethodSelect.value = selectedModels.scoreMethod;
    }
    scoreMethods = mockScore;
    scoreLoaded = true;
    
    checkAndRender();
});