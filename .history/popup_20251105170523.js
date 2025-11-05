// popup.js

// =================================================================================
// GLOBAL STATE & DOM ELEMENTS
// =================================================================================
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null; 
let tabData = null; 
let isScanning = false;
let filterSettings = {}; 

// DOM Elements - Must be initialized in DOMContentLoaded
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions, footerStatus;

// =================================================================================
// SCORE & FUZZY LOGIC ENGINES
// =================================================================================

const ScoreCalculator = {
    calculateScore: (vuln, config) => {
        if (!config || !config.formula) {
            console.error("Score method yapılandırması eksik veya hatalı.");
            return 50;
        }
        try {
            const { typeWeights, locationWeights, normalize, formula } = config;
            const typeWeight = typeWeights[vuln.type] || 0.5;
            const locationWeight = locationWeights[vuln.location] || 0.5;
            const matchCount = vuln.matchCount || 1;
            const httpsPresent = !vuln.contextFactors;
            const userInteractionRequired = vuln.userInteractionRequired;
            const isMaliciousURL = vuln.isMaliciousURL;
            
            const matchCountNorm = new Function('matchCount', `return ${normalize.matchCount}`)(matchCount);
            
            let contextWeight = 0;
            const contextFormula = normalize.contextWeight || normalize.contextFactor;
            if (contextFormula) {
                 contextWeight = new Function('httpsPresent', 'userInteractionRequired', 'isMaliciousURL', `return ${contextFormula}`)(httpsPresent, userInteractionRequired, isMaliciousURL);
            }

            const formulaParams = { typeWeight, locationWeight, matchCountNorm, contextWeight, contextFactor: contextWeight };
            let finalFormula = formula.replace('score = ', '');
            for (const key in formulaParams) {
                finalFormula = finalFormula.replace(new RegExp(key, 'g'), formulaParams[key]);
            }

            const calculatedScore = new Function(`return ${finalFormula}`)();
            return Math.round(Math.max(0, Math.min(1, calculatedScore)) * 100);
        } catch (e) {
            console.error("Skor formülü hesaplama hatası:", e);
            return 50;
        }
    }
};

const FuzzyLogicEngine = {
    getTrapezoidMembership: (x, p) => {
        const [a, b, c, d] = p;
        if (x <= a || x >= d) return 0;
        if (x >= b && x <= c) return 1;
        if (x > a && x < b) return (x - a) / (b - a);
        if (x > c && x < d) return (d - x) / (d - c);
        return 0;
    },
    fuzzify: (vuln, memberships) => {
        const fuzzyInputs = {};
        const categories = { 'type': vuln.type, 'location': vuln.location, 'contextFactors': vuln.contextFactors ? 'httpsAbsent' : 'httpsPresent', 'userInteraction': vuln.userInteractionRequired ? 'withInteraction' : 'noInteraction', 'externalFactors': vuln.isMaliciousURL ? 'malicious' : 'trusted' };
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
             fuzzyInputs.matchCount[term] = FuzzyLogicEngine.getTrapezoidMembership(normalizedMatchCount, memberships.matchCount[term]);
        }
        return fuzzyInputs;
    },
    evaluate: (vuln, config) => {
        if (!config || !config.rules || !config.outputs) return { score: 50, label: "Orta" };
        const fuzzyInputs = FuzzyLogicEngine.fuzzify(vuln, config.memberships);
        const outputStrengths = {};
        config.rules.forEach(rule => {
            let ruleStrength = 1.0;
            rule.if.forEach(condition => {
                const [category, term] = condition.split('.');
                ruleStrength = Math.min(ruleStrength, fuzzyInputs[category]?.[term] || 0.0);
            });
            ruleStrength *= (rule.weight || 1.0);
            const outputTerm = rule.then;
            outputStrengths[outputTerm] = Math.max(outputStrengths[outputTerm] || 0.0, ruleStrength);
        });
        let totalWeightedScore = 0, totalWeight = 0;
        for (const term in outputStrengths) {
            const strength = outputStrengths[term];
            if (strength > 0 && config.outputs[term]) {
                totalWeightedScore += strength * config.outputs[term].score;
                totalWeight += strength;
            }
        }
        if (totalWeight === 0) return { score: 20, label: "Düşük" };
        const finalScore = (totalWeightedScore / totalWeight) * 10;
        let finalLabel = "Düşük", maxStrength = 0;
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
// HELPER FUNCTIONS
// =================================================================================
function setStatus(message) {
    if (statusText) statusText.textContent = message;
}

function getDefaultSettings() {
  return {
    severity: ['high', 'medium', 'low'],
    vulnTypes: ['xss', 'sqli', 'csrf', 'other', 'transport', 'cookie', 'storage', 'csp', 'network'],
    scanOptions: ['passive']
  };
}

function filterVulns(vulns) {
    if (currentFilter !== 'all') {
        return vulns.filter(v => (v.severity ? v.severity.toLowerCase() : 'medium') === currentFilter);
    }
    return vulns;
}

// =================================================================================
// CORE LOGIC (SCORE CALCULATION & RENDERING)
// =================================================================================

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) return;
    const currentScoreModelConfig = scoreMethods.llmModels[selectedModels.scoreMethod];
    const currentFuzzyModelConfig = fuzzyLogicConfig.llmModels[selectedModels.fuzzyLogic];
    if (!currentScoreModelConfig || !currentFuzzyModelConfig) return;
    
    currentVulns = currentVulns.map(vuln => {
        const scoreResult = ScoreCalculator.calculateScore(vuln, currentScoreModelConfig);
        const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, currentFuzzyModelConfig);
        const finalScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
        const finalLabel = fuzzyResult.score > scoreResult ? fuzzyResult.label : (scoreResult > 85 ? 'Kritik' : (scoreResult > 70 ? 'Yüksek' : (scoreResult > 40 ? 'Orta' : 'Düşük')));

        vuln.llmScore = finalScore;
        vuln.fuzzySeverity = finalLabel;
        vuln.severity = finalLabel.toLowerCase().replace('kritik', 'high').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        vuln.hybridResult = { [selectedModels.scoreMethod]: { [selectedModels.fuzzyLogic]: { score: finalScore, label: finalLabel }}};
        return vuln;
    });
}

function renderVulns() {
    if (!vulnList) return; 
    generateHybridResults();
    const filteredVulns = filterVulns(currentVulns);
    vulnList.innerHTML = ''; 

    if (filteredVulns.length === 0) {
        vulnList.innerHTML = '<div class="empty-state"><p>Filtreye uygun açık bulunamadı veya tarama yapılmadı.</p></div>';
        setStatus(`Tarama bekleniyor...`);
        if (aiSuggestions) aiSuggestions.innerHTML = '<p class="muted">Tarama sonuçları geldikten sonra burada öneriler görünecek.</p>';
        return;
    }

    vulnList.innerHTML = filteredVulns.map(vuln => createVulnHTML(vuln)).join('');
    
    const scanTimeInfo = lastScanTimestamp ? `(${new Date(lastScanTimestamp).toLocaleTimeString()})` : '';
    setStatus(`Tarama tamamlandı — ${filteredVulns.length} açık bulundu ${scanTimeInfo}`);
    
    addVulnEventListeners();
    renderAiSuggestions(filteredVulns);
}

function createVulnHTML(vuln) {
    const sevClass = (vuln.severity || 'medium').toLowerCase();
    const modelScoreLabel = vuln.llmScore !== undefined ? vuln.llmScore : 'N/A';
    const modelLabel = vuln.fuzzySeverity || 'Orta';
    
    return `
        <div class="vuln-item severity-${sevClass}" data-index="${currentVulns.indexOf(vuln)}">
            <div class="vuln-header">
                <span class="vuln-severity ${sevClass}">${modelLabel} (${modelScoreLabel}/100)</span>
                <h4>${vuln.title || 'Bilinmeyen Açık'} (${vuln.type.toUpperCase()})</h4>
            </div>
            <p class="vuln-details">${vuln.details || 'Detay yok.'}</p>
            <div class="vuln-actions">
                ${vuln.evidence ? `<button class="evidence-btn">Kanıtı Göster</button>` : ''}
            </div>
            ${vuln.evidence ? `<div class="evidence-panel" style="display:none;"><pre>${JSON.stringify(vuln.evidence, null, 2)}</pre></div>` : ''}
        </div>`;
}

function renderAiSuggestions(vulns) {
    // Bu fonksiyonu şimdilik basit tutabiliriz.
    if (!aiSuggestions) return;
    const highVulns = vulns.filter(v => v.severity === 'high');
    if (highVulns.length > 0) {
        aiSuggestions.innerHTML = `<p class="ai-advice"><strong>${highVulns.length} adet Yüksek/Kritik açık bulundu.</strong> Bu açıklara öncelik vermeniz önerilir.</p>`;
    } else {
        aiSuggestions.innerHTML = '<p>Harika! Yüksek riskli açıklar bulunamadı.</p>';
    }
}


// =================================================================================
// EVENT LISTENERS & COMMUNICATION
// =================================================================================

function addVulnEventListeners() {
    document.querySelectorAll('.vuln-item .evidence-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const panel = e.target.closest('.vuln-item').querySelector('.evidence-panel');
            if (panel) {
                const isHidden = panel.style.display === 'none';
                panel.style.display = isHidden ? 'block' : 'none';
                e.target.textContent = isHidden ? 'Kanıtı Gizle' : 'Kanıtı Göster';
            }
        });
    });
}

async function startScan() {
    if (isScanning) return;
    isScanning = true;
    scanBtn.disabled = true;
    scanBtn.textContent = 'Taranıyor...';
    setStatus('Tarama Başlatılıyor...');
    vulnList.innerHTML = '<div class="empty-state"><p>Tarama işlemi sürüyor, lütfen bekleyin...</p></div>';
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab.id) throw new Error("Aktif sekme bulunamadı.");
        
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
        await new Promise(r => setTimeout(r, 150)); 
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        
        lastScanTimestamp = Date.now();
        currentVulns = (response && response.vulnerabilities) ? response.vulnerabilities : [];
    } catch (error) {
        console.error('Tarama hatası (Kritik):', error);
        setStatus(`Tarama hatası: ${error.message}`);
        currentVulns = [];
    } finally {
        isScanning = false;
        if(scanBtn) {
            scanBtn.disabled = false;
            scanBtn.textContent = 'Sayfayı Tara';
        }
        renderVulns();
    }
}

async function loadConfigurationsAndInitialData() {
    try {
        const [fuzzyResponse, scoreResponse, vulnsResponse] = await Promise.all([
            chrome.runtime.sendMessage({ action: "getFuzzyLogic" }),
            chrome.runtime.sendMessage({ action: "getScoreMethods" }),
            chrome.runtime.sendMessage({ action: "getVulns" })
        ]);

        if (fuzzyResponse && fuzzyResponse.fuzzyLogic) {
            fuzzyLogicConfig = fuzzyResponse.fuzzyLogic;
            Object.keys(fuzzyLogicConfig.llmModels).forEach(key => fuzzyLogicSelect.add(new Option(key.toUpperCase(), key)));
            fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
        }

        if (scoreResponse && scoreResponse.scoreMethods) {
            scoreMethods = scoreResponse.scoreMethods;
            Object.keys(scoreMethods.llmModels).forEach(key => scoreMethodSelect.add(new Option(key.toUpperCase(), key)));
            scoreMethodSelect.value = selectedModels.scoreMethod;
        }

        if (vulnsResponse && vulnsResponse.vulnerabilities) {
            currentVulns = vulnsResponse.vulnerabilities;
            lastScanTimestamp = vulnsResponse.timestamp;
        }

    } catch (error) {
        console.error("Başlangıç verileri yüklenemedi:", error);
        setStatus("Hata: Yapılandırmalar yüklenemedi.");
    } finally {
        renderVulns();
    }
}

// =================================================================================
// MAIN INITIALIZATION
// =================================================================================

document.addEventListener('DOMContentLoaded', () => {
    // 1. DOM Elementlerini ATAMA
    scanBtn = document.getElementById('scanBtn');
    vulnList = document.getElementById('vulnList');
    statusText = document.getElementById('statusText');
    scoreMethodSelect = document.getElementById('scoreMethodSelect');
    fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
    aiSuggestions = document.getElementById('aiSuggestions');
    
    // 2. Event Listener'ları Kurma
    scanBtn.addEventListener('click', startScan);

    scoreMethodSelect.addEventListener('change', (e) => {
        selectedModels.scoreMethod = e.target.value;
        renderVulns();
    });

    fuzzyLogicSelect.addEventListener('change', (e) => {
        selectedModels.fuzzyLogic = e.target.value;
        renderVulns();
    });

    document.querySelectorAll('.filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelector('.filter.active').classList.remove('active');
            e.target.classList.add('active');
            currentFilter = e.target.dataset.sev;
            renderVulns();
        });
    });

    // Sekme yönetimi
    document.querySelectorAll('.tab').forEach(t => {
        t.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            if (tabName === 'settings') {
                // Ayarlar sayfasına yönlendirme (eğer varsa)
                // chrome.runtime.openOptionsPage(); veya window.location.href = 'settings.html';
                return;
            }
            document.querySelectorAll('.tab.active, .tab-content.active').forEach(el => el.classList.remove('active'));
            e.target.classList.add('active');
            document.getElementById(tabName)?.classList.add('active');
        });
    });
    
    // 3. Başlangıç Verilerini Yükleme
    filterSettings = getDefaultSettings(); // Tanımlamayı buraya taşıdım.
    loadConfigurationsAndInitialData();
});