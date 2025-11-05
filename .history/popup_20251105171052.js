// popup.js - TAM VE DÜZELTİLMİŞ VERSİYON

// =================================================================================
// GLOBAL STATE & DOM ELEMENTS
// =================================================================================
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null; 
let isScanning = false;
let filterSettings = {}; 

// DOM Elements
let scanBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions;

// =================================================================================
// HELPER FUNCTIONS
// =================================================================================

function setStatus(message) {
    if (statusText) statusText.textContent = message;
}

function getDefaultSettings() {
  return {
    severity: ['high', 'medium', 'low'],
    vulnTypes: ['xss', 'sqli', 'csrf', 'other', 'transport', 'cookie', 'storage', 'csp', 'network']
  };
}

function filterVulns(vulns) {
    if (currentFilter === 'all') return vulns;
    return vulns.filter(v => (v.severity ? v.severity.toLowerCase() : 'medium') === currentFilter);
}

// =================================================================================
// SCORE & FUZZY LOGIC ENGINES
// =================================================================================

const ScoreCalculator = {
    /**
     * CSP-UYUMLU SKOR HESAPLAYICI. 'new Function' VEYA 'eval' KULLANMAZ.
     */
    calculateScore: (vuln, config, modelName) => {
        if (!config) return 50;
        
        const typeWeight = config.typeWeights[vuln.type] || 0.5;
        const locationWeight = config.locationWeights[vuln.location] || 0.5;
        const matchCount = vuln.matchCount || 1;
        const httpsPresent = !vuln.contextFactors;
        const userInteractionRequired = vuln.userInteractionRequired;
        const isMaliciousURL = vuln.isMaliciousURL;

        // Normalizasyonları manuel olarak hesapla
        const matchCountNorm = Math.min(matchCount / (modelName === 'deepseek' ? 12 : (modelName === 'gemini' ? 8 : 10)), 1);
        
        let contextWeight = 0;
        if (modelName === 'gpt') {
            contextWeight = (httpsPresent ? 0.3 : 0.8) + (userInteractionRequired ? -0.2 : 0.1) + (isMaliciousURL ? 0.4 : 0);
        } else if (modelName === 'gemini') {
            contextWeight = (httpsPresent ? 0.25 : 0.75) + (userInteractionRequired ? -0.15 : 0.15) + (isMaliciousURL ? 0.35 : 0);
        } else if (modelName === 'deepseek') {
            contextWeight = (httpsPresent ? 0.35 : 0.85) + (userInteractionRequired ? -0.25 : 0.2) + (isMaliciousURL ? 0.45 : 0);
        }
        
        let score = 0;
        // Formülleri manuel olarak uygula
        switch(modelName) {
            case 'gemini':
                score = ((typeWeight + locationWeight) / 2) * 0.6 + (matchCountNorm * 0.25) + (contextWeight * 0.15);
                break;
            case 'deepseek':
                score = (typeWeight * 0.35) + (locationWeight * 0.25) + (matchCountNorm * 0.25) + (contextWeight * 0.15);
                break;
            case 'gpt':
            default:
                score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2);
                break;
        }

        return Math.round(Math.max(0, Math.min(1, score)) * 100);
    }
};

const FuzzyLogicEngine = {
    evaluate: (vuln, config) => {
        if (!config || !config.rules) return { score: 50, label: "Orta" };
        const memberships = config.memberships;
        const fuzzyInputs = {};
        
        // Fuzzify inputs
        const categories = { 'type': vuln.type, 'location': vuln.location, 'contextFactors': vuln.contextFactors ? 'absent' : 'present', 'userInteraction': vuln.userInteractionRequired ? 'with' : 'no', 'externalFactors': vuln.isMaliciousURL ? 'malicious' : 'trusted' };
        for (const cat in categories) {
            fuzzyInputs[cat] = {};
            for (const term in memberships[cat]) {
                 fuzzyInputs[cat][term] = term.includes(categories[cat]) ? 1.0 : 0.0;
            }
        }
        fuzzyInputs.matchCount = {};
        const normalizedMatchCount = Math.min(vuln.matchCount || 1, 10) / 10.0;
        for (const term in memberships.matchCount) {
             const p = memberships.matchCount[term];
             const [a, b, c, d] = p;
             if (normalizedMatchCount <= a || normalizedMatchCount >= d) fuzzyInputs.matchCount[term] = 0;
             else if (normalizedMatchCount >= b && normalizedMatchCount <= c) fuzzyInputs.matchCount[term] = 1;
             else if (normalizedMatchCount > a && normalizedMatchCount < b) fuzzyInputs.matchCount[term] = (normalizedMatchCount - a) / (b - a);
             else fuzzyInputs.matchCount[term] = (d - normalizedMatchCount) / (d - c);
        }
        
        // Evaluate rules
        const outputStrengths = {};
        config.rules.forEach(rule => {
            let ruleStrength = rule.if.reduce((min, cond) => {
                const [cat, term] = cond.split('.');
                return Math.min(min, fuzzyInputs[cat]?.[term] || 0.0);
            }, 1.0);
            ruleStrength *= (rule.weight || 1.0);
            outputStrengths[rule.then] = Math.max(outputStrengths[rule.then] || 0.0, ruleStrength);
        });
        
        // Defuzzify
        let totalWeightedScore = 0, totalWeight = 0, finalLabel = "Düşük", maxStrength = 0;
        for (const term in outputStrengths) {
            const strength = outputStrengths[term];
            if (strength > 0 && config.outputs[term]) {
                totalWeightedScore += strength * config.outputs[term].score;
                totalWeight += strength;
                if (strength > maxStrength) {
                    maxStrength = strength;
                    finalLabel = config.outputs[term].label;
                }
            }
        }
        
        if (totalWeight === 0) return { score: 20, label: "Düşük" };
        const finalScore = (totalWeightedScore / totalWeight) * 10;
        return { score: Math.round(finalScore), label: finalLabel };
    }
};

// =================================================================================
// CORE LOGIC & RENDERING
// =================================================================================

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) return;
    const scoreConfig = scoreMethods.llmModels[selectedModels.scoreMethod];
    const fuzzyConfig = fuzzyLogicConfig.llmModels[selectedModels.fuzzyLogic];
    if (!scoreConfig || !fuzzyConfig) return;
    
    currentVulns = currentVulns.map(vuln => {
        const scoreResult = ScoreCalculator.calculateScore(vuln, scoreConfig, selectedModels.scoreMethod);
        const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, fuzzyConfig);
        
        const finalScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
        const finalLabel = fuzzyResult.score > scoreResult ? fuzzyResult.label : (scoreResult > 85 ? 'Kritik' : (scoreResult > 70 ? 'Yüksek' : (scoreResult > 40 ? 'Orta' : 'Düşük')));

        vuln.llmScore = finalScore;
        vuln.fuzzySeverity = finalLabel;
        vuln.severity = finalLabel.toLowerCase().replace('kritik', 'high');
        return vuln;
    });
}

function renderVulns() {
    if (!vulnList) return; 
    generateHybridResults();
    const filteredVulns = filterVulns(currentVulns);
    
    if (filteredVulns.length === 0) {
        vulnList.innerHTML = '<div class="empty-state"><p>Filtreye uygun açık bulunamadı veya tarama yapılmadı.</p></div>';
        setStatus(`Tarama bekleniyor...`);
        return;
    }

    vulnList.innerHTML = filteredVulns.map(vuln => {
        const sevClass = (vuln.severity || 'medium').toLowerCase();
        return `
            <div class="vuln-item severity-${sevClass}">
                <div class="vuln-header">
                    <span class="vuln-severity ${sevClass}">${vuln.fuzzySeverity} (${vuln.llmScore}/100)</span>
                    <h4>${vuln.title} (${vuln.type.toUpperCase()})</h4>
                </div>
                <p class="vuln-details">${vuln.details}</p>
            </div>`;
    }).join('');
    
    setStatus(`Tarama tamamlandı — ${filteredVulns.length} açık bulundu`);
}

// =================================================================================
// COMMUNICATION & INITIALIZATION
// =================================================================================

async function startScan() {
    if (isScanning) return;
    isScanning = true;
    scanBtn.disabled = true;
    scanBtn.textContent = 'Taranıyor...';
    setStatus('Tarama Başlatılıyor...');
    vulnList.innerHTML = '<div class="empty-state"><p>Tarama işlemi sürüyor...</p></div>';
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) throw new Error("Aktif sekme bulunamadı.");
        
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        
        lastScanTimestamp = Date.now();
        currentVulns = response?.vulnerabilities || [];
    } catch (error) {
        console.error('Tarama hatası:', error);
        setStatus(`Tarama hatası: ${error.message}`);
        currentVulns = [];
    } finally {
        isScanning = false;
        scanBtn.disabled = false;
        scanBtn.textContent = 'Sayfayı Tara';
        renderVulns();
    }
}

async function loadInitialData() {
    try {
        const [fuzzyRes, scoreRes, vulnsRes] = await Promise.all([
            chrome.runtime.sendMessage({ action: "getFuzzyLogic" }),
            chrome.runtime.sendMessage({ action: "getScoreMethods" }),
            chrome.runtime.sendMessage({ action: "getVulns" })
        ]);

        if (fuzzyRes?.fuzzyLogic) {
            fuzzyLogicConfig = fuzzyRes.fuzzyLogic;
            Object.keys(fuzzyLogicConfig.llmModels).forEach(key => fuzzyLogicSelect.add(new Option(key.toUpperCase(), key)));
            fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
        }

        if (scoreRes?.scoreMethods) {
            scoreMethods = scoreRes.scoreMethods;
            Object.keys(scoreMethods.llmModels).forEach(key => scoreMethodSelect.add(new Option(key.toUpperCase(), key)));
            scoreMethodSelect.value = selectedModels.scoreMethod;
        }

        if (vulnsRes?.vulnerabilities) {
            currentVulns = vulnsRes.vulnerabilities;
            lastScanTimestamp = vulnsRes.timestamp;
        }

    } catch (error) {
        console.error("Başlangıç verileri yüklenemedi:", error);
        setStatus("Hata: Yapılandırmalar yüklenemedi.");
    } finally {
        renderVulns();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elementlerini ata
    scanBtn = document.getElementById('scanBtn');
    vulnList = document.getElementById('vulnList');
    statusText = document.getElementById('statusText');
    scoreMethodSelect = document.getElementById('scoreMethodSelect');
    fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
    aiSuggestions = document.getElementById('aiSuggestions');
    
    // Ayarları yükle
    filterSettings = getDefaultSettings(); 

    // Event Listener'ları kur
    scanBtn.addEventListener('click', startScan);
    scoreMethodSelect.addEventListener('change', () => { selectedModels.scoreMethod = scoreMethodSelect.value; renderVulns(); });
    fuzzyLogicSelect.addEventListener('change', () => { selectedModels.fuzzyLogic = fuzzyLogicSelect.value; renderVulns(); });

    document.querySelectorAll('.filter').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelector('.filter.active').classList.remove('active');
            btn.classList.add('active');
            currentFilter = btn.dataset.sev;
            renderVulns();
        });
    });
    
    // Başlangıç verilerini yükle
    loadInitialData();
});