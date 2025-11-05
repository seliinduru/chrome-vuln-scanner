// popup.js

// Global State
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'GPT' }; 
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null; 
let tabData = null; 
let isScanning = false;
let filterSettings = getDefaultSettings(); 

// DOM Elements
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions, footerStatus;


// Helper: Set Status Text
function setStatus(message) {
    if (!statusText) return; 
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

// --- SCORE & FUZZY LOGIC (CSP Uyumlu Statik Skor Hesaplama) ---
function calculateScoreForVuln(vuln) {
    const modelKey = selectedModels.scoreMethod;
    const config = scoreMethods?.llmModels?.[modelKey];

    if (!config) {
        // Fallback: Konfigürasyon yoksa veya hata varsa
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
    
    // Normalizasyon formüllerinden katsayıları çek (matchCount / X)
    const matchDivisor = parseFloat(config.normalize?.matchCount?.match(/\/ (\d+)/)?.[1] || 10);
    const evidenceDivisor = parseFloat(config.normalize?.evidenceLength?.match(/\/ (\d+)/)?.[1] || 500);

    // 3. STATİK HESAPLAMALAR
    let matchCountNorm = 0;
    let contextValue = 0; // contextWeight veya contextFactor

    // 3.1. Normalizasyon Hesaplamaları (Math.min(A/B, 1))
    matchCountNorm = Math.min(inputs.matchCount / matchDivisor, 1);
    // evidenceLengthNorm şu an ana formüllerde kullanılmıyor, atlanabilir.

    // 3.2. Context/Ağırlık Hesaplamaları (Ternary operatörler)
    // scoreMethods.json dosyasındaki formülleri birebir statik olarak uyguluyoruz.

    if (modelKey === 'gpt') {
        // ContextWeight Formülü: (httpsPresent ? 0.3 : 0.8) + (userInteractionRequired ? -0.2 : 0.1) + (isMaliciousURL ? 0.4 : 0)
        contextValue = (inputs.httpsPresent ? 0.3 : 0.8) + 
                       (inputs.userInteractionRequired ? -0.2 : 0.1) + 
                       (inputs.isMaliciousURL ? 0.4 : 0);
    
    } else if (modelKey === 'gemini') {
        // ContextFactor Formülü: (httpsPresent ? 0.25 : 0.75) + (userInteractionRequired ? -0.15 : 0.15) + (isMaliciousURL ? 0.35 : 0)
        contextValue = (inputs.httpsPresent ? 0.25 : 0.75) + 
                       (inputs.userInteractionRequired ? -0.15 : 0.15) + 
                       (inputs.isMaliciousURL ? 0.35 : 0);

    } else if (modelKey === 'deepseek') {
        // ContextWeight Formülü: (httpsPresent ? 0.35 : 0.85) + (userInteractionRequired ? -0.25 : 0.2) + (isMaliciousURL ? 0.45 : 0)
        contextValue = (inputs.httpsPresent ? 0.35 : 0.85) + 
                       (inputs.userInteractionRequired ? -0.25 : 0.2) + 
                       (inputs.isMaliciousURL ? 0.45 : 0);
    }
    
    // 3.3. Ana Skor Formülü Hesaplamaları
    let scoreNormalized = 0;

    if (modelKey === 'gpt') {
         // score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2)
         scoreNormalized = (typeWeight * 0.4) + 
                           (locationWeight * 0.2) + 
                           (matchCountNorm * 0.2) + 
                           (contextValue * 0.2); 
    } else if (modelKey === 'gemini') {
         // score = ((typeWeight + locationWeight) / 2) * 0.6 + (matchCountNorm * 0.25) + (contextFactor * 0.15)
         scoreNormalized = (((typeWeight + locationWeight) / 2) * 0.6) +
                           (matchCountNorm * 0.25) +
                           (contextValue * 0.15); 
    } else if (modelKey === 'deepseek') {
         // score = (typeWeight * 0.35) + (locationWeight * 0.25) + (matchCountNorm * 0.25) + (contextWeight * 0.15)
         scoreNormalized = (typeWeight * 0.35) + 
                           (locationWeight * 0.25) + 
                           (matchCountNorm * 0.25) + 
                           (contextValue * 0.15); 
    } else {
        return { score: 50, label: 'Orta' }; 
    }
    
    // 4. Final Sonuç
    let finalScore = Math.round(scoreNormalized * 100); 

    // Final Severity Labeling
    let label = 'Orta';
    if (finalScore >= 90) label = 'Kritik';
    else if (finalScore >= 70) label = 'Yüksek';
    else if (finalScore < 40) label = 'Düşük';
    
    return { score: Math.min(100, Math.max(0, finalScore)), label };
}

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) {
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
            // Severity'i filtreleme için uygun küçük harfli değere dönüştür
            vuln.severity = selectedScore.label.toLowerCase().replace('kritik', 'high').replace('yüksek/orta', 'medium').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        }
        
        return vuln;
    });
}


// --- UI / Rendering / Export Functions (Değişmedi) ---

function filterVulns() { /* ... */ return currentVulns.filter(vuln => filterSettings.severity.includes(vuln.severity) && filterSettings.vulnTypes.includes(vuln.type)); }
function createVulnHTML(vuln) { /* ... */ }
function renderVulns() { /* ... */ 
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
    
    document.querySelectorAll('.toggle-btn').forEach(button => {
        button.onclick = (e) => showVulnDetails(e.target.dataset.vulnId);
    });
}
function showVulnDetails(vulnId) { /* ... */ }
function renderAiSuggestions(vuln) { /* ... */ }
function setupExportButtons() { /* ... */ }
function downloadData(data, filename, type) { /* ... */ }


// --- SCANNING & COMMUNICATION (Değişmedi) ---

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

        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
        });
        
        let response = null;
        try {
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


// --- MAIN INITIALIZATION (Değişmedi) ---

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
                        Object.keys(scoreMethods.llmModels).forEach(key => {
                            const option = new Option(key.toUpperCase(), key);
                            scoreMethodSelect.add(option);
                        });
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