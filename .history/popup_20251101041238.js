// popup.js

// Global State
let currentVulns = [];
let currentFilter = 'all'; 
// Varsayılan modeller: scoreMethod küçük harf (scoreMethods.json'daki anahtar), fuzzyLogic büyük harf (fuzzyLogic.json'daki anahtar)
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'GPT' }; 
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null; 
let tabData = null; 
let isScanning = false;
let filterSettings = getDefaultSettings(); 

// DOM Elements - Must be initialized in DOMContentLoaded
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions, footerStatus;


// Helper: Set Status Text
function setStatus(message) {
    if (!statusText) return; // DOM atamaları yapılmamışsa
    statusText.textContent = message;
    if (footerStatus) {
        footerStatus.textContent = message;
    }
}

// Helper: Get Default Settings 
function getDefaultSettings() {
  // Bu ayarlar, settings.js'den yüklenene kadar varsayılan olarak kullanılır
  return {
    severity: ['high', 'medium', 'low'],
    vulnTypes: ['xss', 'sqli', 'csrf', 'other', 'transport', 'cookie', 'storage', 'csp', 'network'],
    scanOptions: ['passive']
  };
}

// Helper: Safely evaluate a math expression string
function safeEvaluate(expression, inputs) {
    let code = expression;
    let finalInputs = {};

    // 1. Girdileri formüle yerleştirmek için bir nesne hazırla (stringler küçük harfe çevrildi)
    for (const key in inputs) {
        let value = inputs[key];
        
        if (typeof value === 'string') {
            finalInputs[key] = value.toLowerCase(); 
        } else if (typeof value === 'boolean' || typeof value === 'number') {
            finalInputs[key] = value;
        } else {
             finalInputs[key] = 0;
        }
    }
    
    // 2. Formülü güvenli ortamda (Function constructor) çalıştır
    const keys = Object.keys(finalInputs);
    const values = Object.values(finalInputs);
    
    try {
        // Formülün içindeki 'score = ' kısmını kaldır
        if (code.startsWith('score =')) {
            code = code.substring(7).trim();
        }
        
        // Dinamik olarak bir fonksiyon oluştur ve çalıştır
        const func = new Function(...keys, `return ${code};`);
        return func(...values);
    } catch (e) {
        console.error('Formula evaluation error:', e, 'Expression:', expression, 'Inputs:', finalInputs);
        return 0.5; // Hata durumunda %50 normalized skor
    }
}

// --- SCORE & FUZZY LOGIC (Dinamik Skor Hesaplama) ---
function calculateScoreForVuln(vuln) {
    const modelKey = selectedModels.scoreMethod;
    const config = scoreMethods?.llmModels?.[modelKey];

    if (!config) {
        let score = vuln.llmScore || 50; 
        let label = (score >= 90) ? 'Kritik' : (score >= 70) ? 'Yüksek' : (score < 40) ? 'Düşük' : 'Orta';
        return { score: Math.min(100, Math.max(0, score)), label };
    }

    // 1. Gerekli Input Verilerini Topla
    const httpsPresent = tabData?.url?.startsWith('https:') || false;
    
    const inputs = {
        type: vuln.type.toLowerCase(),
        location: (vuln.location || 'body').toLowerCase(),
        matchCount: vuln.matchCount || 1,
        evidenceLength: vuln.evidenceLength || 0,
        httpsPresent: httpsPresent,
        userInteractionRequired: vuln.userInteractionRequired || false,
        isMaliciousURL: vuln.isMaliciousURL || false,
    };

    // 2. Ağırlık Değerlerini Al
    const typeWeight = config.typeWeights?.[inputs.type] || 0.5;
    const locationWeight = config.locationWeights?.[inputs.location] || 0.5;

    // 3. Normalizasyon ve Context Hesaplamaları (Geçici formül değişkenleri için)
    const context = {
        typeWeight,
        locationWeight,
        ...inputs, 
    };

    const normResults = {};
    const { normalize } = config;
    if (normalize) {
        for (const normKey in normalize) {
            const normExpression = normalize[normKey];
            // Normalizasyon formüllerini çalıştır
            const result = safeEvaluate(normExpression, context); 
            normResults[normKey + 'Norm'] = result; 
            if (normKey.includes('context')) {
                 context[normKey] = result;
            }
        }
    }
    
    // 4. Final Formül Inputları (Ana formülün çalışması için gerekenler)
    const finalInputs = {
        typeWeight,
        locationWeight,
        ...inputs,
        ...normResults, 
        contextWeight: context.contextWeight || 0, 
        contextFactor: context.contextFactor || 0, 
    };

    // 5. Final Formülünü Çalıştır
    let scoreNormalized = safeEvaluate(config.formula, finalInputs);
    
    // Skor 0-1 aralığında, 0-100'e dönüştür
    let finalScore = Math.round(scoreNormalized * 100); 

    // Final Severity Labeling (Fuzzy Logic'i taklit eden basit mantık)
    let label = 'Orta';
    if (finalScore >= 90) label = 'Kritik';
    else if (finalScore >= 70) label = 'Yüksek';
    else if (finalScore < 40) label = 'Düşük';
    
    // NOT: Gerçek Fuzzy Logic uygulamasını burada kullanmak için, fuzzyLogicConfig'ten 
    // seçili modelin kurallarını çekip uygulamak gerekir. Basitçe label'ı döndürüyoruz.
    
    return { score: Math.min(100, Math.max(0, finalScore)), label };
}

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) {
        // Yapılandırma yoksa, varsayılan değerleri koru
        currentVulns = currentVulns.map(vuln => {
            vuln.llmScore = vuln.llmScore || 50; 
            vuln.fuzzySeverity = vuln.severity ? vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1) : 'Orta';
            vuln.severity = vuln.severity || 'medium';
            return vuln;
        });
        return; 
    }
    
    currentVulns = currentVulns.map(vuln => {
        let hybridResult = {};
        const scoreKey = selectedModels.scoreMethod;
        let scoreMethodResult = {};
            
        Object.keys(fuzzyLogicConfig).forEach(fuzzyKey => {
            const { score, label } = calculateScoreForVuln(vuln);
            
            scoreMethodResult[fuzzyKey] = {
                score: score,
                label: label,
            };
        });
        
        hybridResult[scoreKey] = scoreMethodResult;
        
        vuln.hybridResult = hybridResult;
        const selectedScore = hybridResult[selectedModels.scoreMethod]?.[selectedModels.fuzzyLogic];
        
        if (selectedScore) {
            vuln.llmScore = selectedScore.score;
            vuln.fuzzySeverity = selectedScore.label;
            // Filtreleme için uygun küçük harfli değere dönüştür
            vuln.severity = selectedScore.label.toLowerCase().replace('kritik', 'high').replace('yüksek/orta', 'medium').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        }
        
        return vuln;
    });
}


// --- UI / Rendering / Export Functions ---

function filterVulns() {
    // Seçili filtre ayarlarına göre currentVulns listesini filtreler
    const { severity, vulnTypes } = filterSettings;
    return currentVulns.filter(vuln => 
        severity.includes(vuln.severity) && vulnTypes.includes(vuln.type)
    );
}

function createVulnHTML(vuln) {
    // Tek bir güvenlik açığı için HTML yapısını oluşturur
    const severityClass = vuln.severity || 'medium';
    const scoreText = vuln.llmScore ? `${vuln.llmScore} - ${vuln.fuzzySeverity}` : 'N/A';
    
    let html = `
        <li class="vuln-item ${severityClass}" data-vuln-id="${vuln.id}">
            <div class="vuln-header">
                <span class="vuln-title">${vuln.title} (${vuln.type.toUpperCase()})</span>
                <span class="vuln-score score-${severityClass}">${scoreText}</span>
            </div>
            <div class="vuln-details-toggle">
                <button class="toggle-btn" data-vuln-id="${vuln.id}">Detaylar</button>
            </div>
            <div class="vuln-details" id="details-${vuln.id}">
                <p><strong>Açıklama:</strong> ${vuln.details}</p>
                <p><strong>Konum/Etki:</strong> ${vuln.location || 'Bilinmiyor'}</p>
                ${vuln.evidence ? `<pre><strong>Kanıt:</strong> ${vuln.evidence}</pre>` : ''}
                <div id="ai-suggestion-${vuln.id}" class="ai-suggestion-box"></div>
            </div>
        </li>
    `;
    return html;
}

function renderVulns() {
    // Filtrelenmiş sonuçları listeler ve DOM'a ekler
    if (!vulnList) return;
    
    const filtered = filterVulns();
    vulnList.innerHTML = '';
    
    if (filtered.length === 0) {
        vulnList.innerHTML = '<li class="no-results">Seçilen filtrelerle eşleşen açık bulunamadı.</li>';
        return;
    }
    
    filtered.forEach(vuln => {
        vulnList.innerHTML += createVulnHTML(vuln);
    });
    
    // Detay butonu listener'larını ekle
    document.querySelectorAll('.toggle-btn').forEach(button => {
        button.onclick = (e) => showVulnDetails(e.target.dataset.vulnId);
    });
}

function showVulnDetails(vulnId) {
    // Detay panelini açar/kapatır ve yapay zeka önerilerini render eder
    const detailsPanel = document.getElementById(`details-${vulnId}`);
    const vuln = currentVulns.find(v => v.id === vulnId);
    
    if (!detailsPanel) return;
    
    if (detailsPanel.style.display === 'block') {
        detailsPanel.style.display = 'none';
        detailsPanel.parentNode.querySelector('.toggle-btn').textContent = 'Detaylar';
    } else {
        detailsPanel.style.display = 'block';
        detailsPanel.parentNode.querySelector('.toggle-btn').textContent = 'Kapat';
        renderAiSuggestions(vuln);
    }
}

function renderAiSuggestions(vuln) {
    // Yapay zeka önerileri (şimdilik placeholder)
    const aiBox = document.getElementById(`ai-suggestion-${vuln.id}`);
    if (!aiBox) return;

    aiBox.innerHTML = `
        <h4>LLM Çözüm Önerileri:</h4>
        <p><strong>Risk:</strong> ${vuln.llmScore} / 100 (${vuln.fuzzySeverity})</p>
        <p><strong>Öneri:</strong> Bu, tarayıcı tabanlı bir XSS açığıdır. Tüm kullanıcı girdilerini (özellikle URL parametreleri) sunucu tarafında temizleyin ve çıktı kodlamasını (HTML entity encoding) uygulayın.</p>
        <p><strong>Açık Tipi:</strong> ${vuln.type.toUpperCase()}</p>
    `;
}

function setupExportButtons() {
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            const data = JSON.stringify(currentVulns, null, 2);
            downloadData(data, 'scan_results.json', 'application/json');
        });
    }
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            // Basit CSV dönüştürme (geliştirilebilir)
            const headers = ["ID", "Başlık", "Tip", "Skor", "Konum", "Detaylar"];
            const rows = currentVulns.map(v => [
                v.id, v.title, v.type, v.llmScore, v.location, v.details.replace(/"/g, '""')
            ]);
            
            const csv = [
                headers.join(','),
                ...rows.map(row => row.join(','))
            ].join('\n');
            
            downloadData(csv, 'scan_results.csv', 'text/csv');
        });
    }
}

function downloadData(data, filename, type) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}


// --- SCANNING & COMMUNICATION ---

function getVulnsFromBackground() {
    chrome.runtime.sendMessage({ action: "getVulns" }, (response) => {
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            lastScanTimestamp = response.timestamp || Date.now();
            
            if (fuzzyLogicConfig && scoreMethods) {
                generateHybridResults();
                renderVulns();
                setStatus(`Son tarama: ${new Date(lastScanTimestamp).toLocaleTimeString()}`);
            } else {
                 setStatus("Yapılandırmalar yükleniyor, lütfen bekleyin...");
            }
        } else {
            setStatus("Tarama yapılmadı veya sonuç bulunamadı.");
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

        // 1. content.js'yi enjekte et.
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
        });
        
        // 2. Tarama komutunu gönder
        let response = null;
        try {
            // content.js'nin hazırlanması için kısa bekleme
            await new Promise(r => setTimeout(r, 150)); 
            response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        } catch (e) {
            console.warn("Mesaj yanıtı alınamadı, arka plandan çekiliyor:", e);
            getVulnsFromBackground(); 
            return;
        }
        
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            lastScanTimestamp = Date.now();
        } else {
            getVulnsFromBackground(); 
            return;
        }

    } catch (error) {
        console.error('Tarama hatası (Kritik):', error);
        setStatus('Tarama hatası oluştu: Uzantı izinlerini veya Chrome sürümünüzü kontrol edin.');
        return;
    } finally {
        isScanning = false;
        if (scanBtn) scanBtn.textContent = 'Sayfayı Tara';
    }
    
    generateHybridResults();
    renderVulns();
    setStatus(`Son tarama: ${new Date(lastScanTimestamp).toLocaleTimeString()}`);
}


// --- MAIN INITIALIZATION ---

document.addEventListener('DOMContentLoaded', async () => {
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
    
    // Model seçimleri için listener
    if (scoreMethodSelect) scoreMethodSelect.addEventListener('change', (e) => {
        selectedModels.scoreMethod = e.target.value;
        generateHybridResults();
        renderVulns();
    });
    
    if (fuzzyLogicSelect) fuzzyLogicSelect.addEventListener('change', (e) => {
        selectedModels.fuzzyLogic = e.target.value;
        generateHybridResults();
        renderVulns();
    });
    
    // Ayarlar butonu listener
    document.getElementById('settingsBtn')?.addEventListener('click', () => {
        window.location.href = 'settings.html';
    });
    

    // settings.js'den gelen ayarları yükle
    chrome.storage.local.get('scannerSettings', (result) => {
        filterSettings = result.scannerSettings || getDefaultSettings();
    });
    
    setupExportButtons(); 
    if (scanBtn) {
        scanBtn.addEventListener('click', startScan);
    }
    
    // Mevcut aktif sekmenin bilgisini al
    try {
        [tabData] = await chrome.tabs.query({ active: true, currentWindow: true });
    } catch (e) {
        console.error("Aktif sekme bilgisi alınamadı:", e);
    }
    
    // KONFİGÜRASYON VE VERİ YÜKLEME
    const loadConfigsAndData = () => {
        setStatus("Yapılandırmalar arka plandan yükleniyor...");
        
        // 1. Fuzzy Logic'i çek
        chrome.runtime.sendMessage({ action: "getFuzzyLogic" }, (response) => {
            if (response && response.fuzzyLogic) {
                fuzzyLogicConfig = response.fuzzyLogic;
                if (fuzzyLogicSelect) {
                    fuzzyLogicSelect.innerHTML = '';
                    Object.keys(fuzzyLogicConfig).forEach(key => {
                        const option = new Option(key, key);
                        fuzzyLogicSelect.add(option);
                    });
                    fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
                }
            }
            
            // 2. Score Methods'u çek
            chrome.runtime.sendMessage({ action: "getScoreMethods" }, (response) => {
                if (response && response.scoreMethods && response.scoreMethods.llmModels) {
                    scoreMethods = response.scoreMethods;
                    if (scoreMethodSelect) {
                        scoreMethodSelect.innerHTML = '';
                         // llmModels altındaki anahtarları UI'a ekle
                        Object.keys(scoreMethods.llmModels).forEach(key => {
                            const option = new Option(key.toUpperCase(), key);
                            scoreMethodSelect.add(option);
                        });
                        // Seçili modeli kontrol et ve ayarla
                        const firstModel = Object.keys(scoreMethods.llmModels)[0];
                        if (!scoreMethods.llmModels[selectedModels.scoreMethod] && firstModel) {
                             selectedModels.scoreMethod = firstModel;
                        }
                        scoreMethodSelect.value = selectedModels.scoreMethod;
                    }
                }
                
                // 3. Verileri ve render'ı başlat
                setStatus("Yapılandırmalar yüklendi. Veriler çekiliyor...");
                getVulnsFromBackground();
            });
        });
    };
    
    loadConfigsAndData(); 
});