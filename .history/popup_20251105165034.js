// popup.js

// Global State
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' }; // Değerleri küçük harfe çevirdim
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
    statusText.textContent = message;
    if (footerStatus) {
        footerStatus.textContent = message;
    }
}

// Helper: Log for performance/debugging (Simplified)
function logBenchmark(eventName, data = {}) {
    console.log(`[BENCHMARK] ${eventName}`, { timestamp: new Date().toISOString(), ...data });
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
    
    // UI butonları ile filtreleme
    if (currentFilter !== 'all') {
        filtered = filtered.filter(v => {
            const sev = v.severity ? v.severity.toLowerCase() : 'medium';
            return sev === currentFilter;
        });
    }

    // Settings filtresi
    if (typeof filterSettings !== 'undefined') {
        filtered = filtered.filter(v => {
            const sev = v.severity ? v.severity.toLowerCase() : 'medium';
            const type = v.type ? v.type.toLowerCase() : 'other';
            
            const sevMatch = filterSettings.severity.includes(sev);
            const typeMatch = filterSettings.vulnTypes.includes(type);
            
            return sevMatch && typeMatch;
        });
    }

    return filtered;
}

// =================================================================================
// FUZZY LOGIC ENGINE
// =================================================================================

const FuzzyLogicEngine = {
    /**
     * Trapezoidal üyelik fonksiyonu.
     * Bir değerin belirli bir aralıktaki üyelik derecesini (0-1) hesaplar.
     * @param {number} x - Değerlendirilecek kesin değer.
     * @param {number[]} p - Trapezoidin 4 köşe noktası [a, b, c, d].
     * @returns {number} Üyelik derecesi (0 ile 1 arasında).
     */
    getTrapezoidMembership: (x, p) => {
        const [a, b, c, d] = p;
        if (x <= a || x >= d) return 0;
        if (x >= b && x <= c) return 1;
        if (x > a && x < b) return (x - a) / (b - a);
        if (x > c && x < d) return (d - x) / (d - c);
        return 0;
    },

    /**
     * Zafiyet girdilerini bulanıklaştırır.
     * @param {object} vuln - Değerlendirilecek zafiyet nesnesi.
     * @param {object} memberships - fuzzyLogic.json'dan gelen üyelik fonksiyonları.
     * @returns {object} Her bir bulanık değişken için üyelik derecelerini içeren nesne.
     */
    fuzzify: (vuln, memberships) => {
        const fuzzyInputs = {};

        const categories = {
            'type': vuln.type,
            'location': vuln.location,
            'contextFactors': vuln.contextFactors ? 'httpsAbsent' : 'httpsPresent',
            'userInteraction': vuln.userInteractionRequired ? 'withInteraction' : 'noInteraction',
            'externalFactors': vuln.isMaliciousURL ? 'malicious' : 'trusted'
        };

        for (const category in memberships) {
            if (categories[category]) {
                fuzzyInputs[category] = {};
                const vulnKey = categories[category];
                for (const term in memberships[category]) {
                    fuzzyInputs[category][term] = (term.toLowerCase() === vulnKey.toLowerCase()) ? 1.0 : 0.0;
                }
            }
        }

        fuzzyInputs.matchCount = {};
        const normalizedMatchCount = Math.min(vuln.matchCount || 1, 10) / 10.0;
        for (const term in memberships.matchCount) {
             fuzzyInputs.matchCount[term] = FuzzyLogicEngine.getTrapezoidMembership(
                normalizedMatchCount,
                memberships.matchCount[term]
            );
        }

        return fuzzyInputs;
    },
    
    /**
     * Bulanık mantık motorunu çalıştırır.
     * @param {object} vuln - Değerlendirilecek zafiyet.
     * @param {object} config - Seçili modelin fuzzy logic yapılandırması.
     * @returns {{score: number, label: string}} Hesaplanan skor ve etiket.
     */
    evaluate: (vuln, config) => {
        if (!config || !config.rules || !config.outputs) {
            console.error("Fuzzy logic yapılandırması eksik veya hatalı.");
            return { score: 50, label: "Orta" };
        }

        const fuzzyInputs = FuzzyLogicEngine.fuzzify(vuln, config.memberships);
        const outputStrengths = {};

        config.rules.forEach(rule => {
            let ruleStrength = 1.0;
            
            rule.if.forEach(condition => {
                const [category, term] = condition.split('.');
                const membershipValue = fuzzyInputs[category]?.[term] || 0.0;
                ruleStrength = Math.min(ruleStrength, membershipValue);
            });
            
            ruleStrength *= (rule.weight || 1.0);
            const outputTerm = rule.then;
            outputStrengths[outputTerm] = Math.max(outputStrengths[outputTerm] || 0.0, ruleStrength);
        });

        let totalWeightedScore = 0;
        let totalWeight = 0;

        for (const term in outputStrengths) {
            const strength = outputStrengths[term];
            if (strength > 0 && config.outputs[term]) {
                totalWeightedScore += strength * config.outputs[term].score;
                totalWeight += strength;
            }
        }

        if (totalWeight === 0) {
            return { score: 20, label: "Düşük" };
        }

        const finalScore = (totalWeightedScore / totalWeight) * 10;

        let finalLabel = "Düşük";
        let maxStrength = 0;
        for (const term in outputStrengths) {
            if (outputStrengths[term] > maxStrength && config.outputs[term]) {
                maxStrength = outputStrengths[term];
                finalLabel = config.outputs[term].label;
            }
        }

        return { score: Math.round(finalScore), label: finalLabel };
    }
};

// =================================================================================
// END OF FUZZY LOGIC ENGINE
// =================================================================================


// --- SCORE & FUZZY LOGIC ---
function calculateScoreForVuln(vuln) {
    if (!fuzzyLogicConfig || !selectedModels || !fuzzyLogicConfig[selectedModels.fuzzyLogic]) {
        const severityMap = { 'high': 85, 'critical': 95, 'medium': 50, 'low': 20 };
        return {
            score: severityMap[vuln.severity] || 50,
            label: vuln.severity ? (vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)) : 'Orta'
        };
    }
    
    const currentFuzzyModelConfig = fuzzyLogicConfig[selectedModels.fuzzyLogic];
    return FuzzyLogicEngine.evaluate(vuln, currentFuzzyModelConfig);
}

function generateHybridResults() {
    if (!fuzzyLogicConfig) {
        console.warn("Fuzzy logic yapılandırması henüz yüklenmedi.");
        return; 
    }
    
    currentVulns = currentVulns.map(vuln => {
        const result = calculateScoreForVuln(vuln);
        
        vuln.llmScore = result.score;
        vuln.fuzzySeverity = result.label;
        vuln.severity = result.label.toLowerCase().replace('kritik', 'high').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        
        vuln.hybridResult = {
            [selectedModels.scoreMethod]: {
                [selectedModels.fuzzyLogic]: {
                    score: result.score,
                    label: result.label,
                }
            }
        };
        
        return vuln;
    });
}


// --- UI RENDERING ---

function createVulnHTML(vuln, hybridResult) {
    const scoreModelKey = selectedModels.scoreMethod;
    const fuzzyModelKey = selectedModels.fuzzyLogic;

    // hybridResult'ın varlığını kontrol et
    const modelResult = hybridResult && hybridResult[scoreModelKey] && hybridResult[scoreModelKey][fuzzyModelKey] 
        ? hybridResult[scoreModelKey][fuzzyModelKey] 
        : { label: 'Orta', score: 'N/A' };

    const sevClass = (vuln.severity || 'medium').toLowerCase().replace('kritik', 'high').replace('yüksek', 'high');
    
    const evidenceContent = vuln.evidence ? 
        (typeof vuln.evidence === 'object' ? JSON.stringify(vuln.evidence, null, 2) : String(vuln.evidence)) : 
        'Kanıt yok.';
    
    const evidencePanel = vuln.evidence 
        ? `<div class="evidence-panel" style="display:none;"><pre>${evidenceContent}</pre></div>`
        : '';

    const modelScoreLabel = vuln.llmScore !== undefined ? vuln.llmScore : modelResult.score;
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
    
    generateHybridResults(); // Her render öncesi skorları yeniden hesapla
    const filteredVulns = filterVulns(currentVulns);
    vulnList.innerHTML = ''; 

    if (filteredVulns.length === 0) {
        vulnList.innerHTML = '<p class="no-results">Filtrelere uygun açık bulunamadı veya henüz tarama yapılmadı.</p>';
        setStatus(`Tarama bekleniyor...`);
        aiSuggestions.innerHTML = '<p>Tarama sonuçları geldikten sonra burada öneriler görünecek.</p>';
        return;
    }

    filteredVulns.forEach(vuln => {
        const item = document.createElement('div');
        item.innerHTML = createVulnHTML(vuln, vuln.hybridResult || {});
        vulnList.appendChild(item.firstChild);
    });
    
    const scanTimeInfo = lastScanTimestamp ? `(${new Date(lastScanTimestamp).toLocaleTimeString()})` : '';
    setStatus(`Tarama tamamlandı — ${filteredVulns.length} açık bulundu ${scanTimeInfo}`);
    
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
            const vuln = currentVulns[parseInt(index, 10)]; 
            showVulnDetails(vuln);
        });
    });
    
    renderAiSuggestions(filteredVulns);
}

function showVulnDetails(vuln) {
    // Bu fonksiyon şimdilik aynı kalabilir.
    // ... (Mevcut kodunuzu burada tutun)
}

function renderAiSuggestions(vulns) {
    // Bu fonksiyon şimdilik aynı kalabilir.
    // ... (Mevcut kodunuzu burada tutun)
}

function setupExportButtons() {
    // Bu fonksiyon şimdilik aynı kalabilir.
    // ... (Mevcut kodunuzu burada tutun)
}

function downloadData(data, filename, format) {
    // Bu fonksiyon şimdilik aynı kalabilir.
    // ... (Mevcut kodunuzu burada tutun)
}

// --- SCANNING & COMMUNICATION ---

function getVulnsFromBackground() {
    chrome.runtime.sendMessage({ action: "getVulns" }, (response) => { // 'getVulnerabilities' -> 'getVulns' olarak düzeltildi.
        if (chrome.runtime.lastError) {
            console.error("Arka plandan veri alınamadı:", chrome.runtime.lastError.message);
            setStatus("Hata: Arka plan betiğiyle iletişim kurulamadı.");
            return;
        }
        
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            lastScanTimestamp = response.timestamp || null;
            renderVulns();
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
    scanBtn.disabled = true;
    scanBtn.textContent = 'Taranıyor...';
    setStatus('Tarama Başlatılıyor...');
    vulnList.innerHTML = '<p>Tarama işlemi sürüyor, lütfen bekleyin...</p>';
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
            throw new Error("Aktif sekme bulunamadı.");
        }
        tabData = tab;

        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
        });
        
        await new Promise(r => setTimeout(r, 150)); 

        const scanStart = Date.now();
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        
        const scanDuration = Date.now() - scanStart;
        lastScanTimestamp = Date.now();
        
        if (response && response.vulnerabilities) {
            currentVulns = response.vulnerabilities;
            logBenchmark('scan_success', { vulnCount: currentVulns.length, duration: scanDuration, url: tab.url });
        } else {
            getVulnsFromBackground(); 
            return;
        }

    } catch (error) {
        console.error('Tarama hatası (Kritik):', error);
        setStatus(`Tarama hatası: ${error.message}`);
        // Hata durumunda, belki arka planda kalmış eski bir sonuç vardır.
        getVulnsFromBackground();
        return;
    } finally {
        isScanning = false;
        if(scanBtn) {
            scanBtn.disabled = false;
            scanBtn.textContent = 'Sayfayı Tara';
        }
    }
    
    renderVulns();
}

async function loadConfigurationsAndInitialData() {
    try {
        const [fuzzyResponse, scoreResponse] = await Promise.all([
            new Promise((resolve, reject) => chrome.runtime.sendMessage({ action: "getFuzzyLogic" }, res => {
                if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
                resolve(res);
            })),
            new Promise((resolve, reject) => chrome.runtime.sendMessage({ action: "getScoreMethods" }, res => {
                if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
                resolve(res);
            }))
        ]);

        // Fuzzy Logic yapılandırmasını yükle ve dropdown'ı doldur
        if (fuzzyResponse && fuzzyResponse.fuzzyLogic) {
            fuzzyLogicConfig = fuzzyResponse.fuzzyLogic.llmModels; // JSON'daki iç içe yapıyı düzelt
            if (fuzzyLogicSelect) {
                fuzzyLogicSelect.innerHTML = ''; // Temizle
                Object.keys(fuzzyLogicConfig).forEach(key => {
                    const option = new Option(key.toUpperCase(), key);
                    fuzzyLogicSelect.add(option);
                });
                fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
            }
        }

        // Score Methods yapılandırmasını yükle ve dropdown'ı doldur
        if (scoreResponse && scoreResponse.scoreMethods) {
            scoreMethods = scoreResponse.scoreMethods;
            if (scoreMethodSelect) {
                scoreMethodSelect.innerHTML = ''; // Temizle
                Object.keys(scoreMethods).forEach(key => {
                    const option = new Option(key.toUpperCase(), key);
                    scoreMethodSelect.add(option);
                });
                scoreMethodSelect.value = selectedModels.scoreMethod;
            }
        }

    } catch (error) {
        console.error("Yapılandırma dosyaları yüklenemedi:", error);
        setStatus("Hata: Yapılandırmalar yüklenemedi.");
    } finally {
        // Yapılandırmalar yüklendikten sonra (veya hata olsa bile) arka plandaki mevcut veriyi çek
        getVulnsFromBackground();
    }
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
    // footerStatus = document.getElementById('footerStatus'); // HTML'de bu ID yok, hata almamak için kapattım
    
    chrome.storage.local.get('scannerSettings', (result) => {
        filterSettings = result.scannerSettings || getDefaultSettings();
    });
    
    // 2. UI SEKMELER VE FİLTRE KONTROLLERİ 
    // ... (Mevcut Event Listener kodlarınız burada kalabilir)

    // 3. MODEL SEÇİM LISTENER'LARI
    if (scoreMethodSelect) {
        scoreMethodSelect.addEventListener('change', (e) => {
            selectedModels.scoreMethod = e.target.value;
            renderVulns();
        });
    }

    if (fuzzyLogicSelect) {
        fuzzyLogicSelect.addEventListener('change', (e) => {
            selectedModels.fuzzyLogic = e.target.value;
            renderVulns();
        });
    }

    // 4. TARAMA VE EXPORT LİSTENER'LARI
    setupExportButtons(); 
    if (scanBtn) {
        scanBtn.addEventListener('click', startScan);
    }
    
    // 5. KONFİGÜRASYON VE VERİ YÜKLEME
    loadConfigurationsAndInitialData();
});