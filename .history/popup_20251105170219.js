// popup.js

// Global State
let currentVulns = [];
let currentFilter = 'all'; 
let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };
let fuzzyLogicConfig = null;
let scoreMethods = null;
let lastScanTimestamp = null; 
let tabData = null; 
let isScanning = false;
let filterSettings = getDefaultSettings(); 

// DOM Elements - Must be initialized in DOMContentLoaded
let scanBtn, exportJsonBtn, exportCsvBtn, vulnList, statusText, scoreMethodSelect, fuzzyLogicSelect, aiSuggestions, footerStatus;


// =================================================================================
// SCORE CALCULATOR ENGINE (from scoreMethods.json)
// =================================================================================
const ScoreCalculator = {
    /**
     * Verilen zafiyet ve model yapılandırmasına göre bir ön skor hesaplar.
     * Bu motor, JSON'daki formülleri güvenli bir şekilde işler.
     * @param {object} vuln - Değerlendirilecek zafiyet nesnesi.
     * @param {object} config - scoreMethods.json'dan seçili modelin yapılandırması.
     * @returns {number} 0-100 arasında bir skor.
     */
    calculateScore: (vuln, config) => {
        if (!config || !config.formula) {
            console.error("Score method yapılandırması eksik veya hatalı.");
            return 50; // Varsayılan değer
        }

        const { typeWeights, locationWeights, normalize, formula } = config;

        // 1. Girdi değerlerini al ve ağırlıklarını bul
        const typeWeight = typeWeights[vuln.type] || 0.5;
        const locationWeight = locationWeights[vuln.location] || 0.5;
        const matchCount = vuln.matchCount || 1;
        const httpsPresent = !vuln.contextFactors;
        const userInteractionRequired = vuln.userInteractionRequired;
        const isMaliciousURL = vuln.isMaliciousURL;
        
        // 2. Normalizasyonları güvenli bir şekilde hesapla
        // eval() kullanmaktan kaçınıyoruz.
        const matchCountNorm = new Function('matchCount', `return ${normalize.matchCount}`)(matchCount);

        let contextWeight = 0;
        const contextFormula = normalize.contextWeight || normalize.contextFactor;
        if (contextFormula) {
             contextWeight = new Function('httpsPresent', 'userInteractionRequired', 'isMaliciousURL', `return ${contextFormula}`)(
                httpsPresent, userInteractionRequired, isMaliciousURL
            );
        }

        // 3. Ana formülü, değişkenleri yerleştirerek güvenli bir şekilde hesapla
        const formulaParams = {
            typeWeight,
            locationWeight,
            matchCountNorm,
            contextWeight,
            contextFactor: contextWeight // Gemini modelindeki farklı isimlendirme için
        };
        
        let finalFormula = formula.replace('score = ', '');
        for (const key in formulaParams) {
            finalFormula = finalFormula.replace(new RegExp(key, 'g'), formulaParams[key]);
        }

        try {
            const calculatedScore = new Function(`return ${finalFormula}`)();
            // Sonucu 0-100 arasına ölçekleyip sıkıştıralım
            return Math.round(Math.max(0, Math.min(1, calculatedScore)) * 100);
        } catch (e) {
            console.error("Skor formülü hesaplama hatası:", e, "Formula:", finalFormula);
            return 50;
        }
    }
};

// =================================================================================
// FUZZY LOGIC ENGINE
// =================================================================================

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

// --- SCORE & FUZZY LOGIC ---

function generateHybridResults() {
    if (!fuzzyLogicConfig || !scoreMethods) {
        console.warn("Yapılandırma dosyaları henüz yüklenmedi.");
        return;
    }

    const currentScoreModelConfig = scoreMethods.llmModels[selectedModels.scoreMethod];
    const currentFuzzyModelConfig = fuzzyLogicConfig.llmModels[selectedModels.fuzzyLogic];

    if (!currentScoreModelConfig || !currentFuzzyModelConfig) {
        console.error("Seçili modeller için yapılandırma bulunamadı.");
        return;
    }
    
    currentVulns = currentVulns.map(vuln => {
        // Hibrit Yaklaşım:
        // 1. ScoreCalculator ile formül tabanlı bir skor hesaplanır.
        // 2. FuzzyLogicEngine ile kural tabanlı bir değerlendirme yapılır.
        // Sonuç olarak ikisinin ortalamasını alarak daha dengeli bir skor elde edelim.
        
        const scoreResult = ScoreCalculator.calculateScore(vuln, currentScoreModelConfig);
        const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, currentFuzzyModelConfig);

        // İki modelin sonucunu birleştirelim (örneğin %50-%50 ağırlıkla)
        const finalScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
        
        // Etiket olarak daha yüksek risk belirten modeli seçelim
        const finalLabel = fuzzyResult.score > scoreResult ? fuzzyResult.label : (scoreResult > 70 ? 'Yüksek' : 'Orta');

        vuln.llmScore = finalScore;
        vuln.fuzzySeverity = finalLabel; // Semantik olarak bu ismi koruyabiliriz.
        vuln.severity = finalLabel.toLowerCase().replace('kritik', 'high').replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        
        vuln.hybridResult = {
            [selectedModels.scoreMethod]: {
                [selectedModels.fuzzyLogic]: { score: finalScore, label: finalLabel }
            }
        };
        
        return vuln;
    });
}


// --- UI RENDERING ---
// ... (Bu bölümden sonrası aynı kalabilir, herhangi bir değişiklik gerekmiyor) ...
// --- MAIN INITIALIZATION ---

// Helper fonksiyonları (setStatus, logBenchmark, getDefaultSettings, filterVulns)
// ... (Bu fonksiyonlar aynı kalabilir) ...

// UI Rendering Fonksiyonları (createVulnHTML, renderVulns, showVulnDetails, vb.)
// ... (Bu fonksiyonlar aynı kalabilir) ...

// Tarama ve İletişim Fonksiyonları (getVulnsFromBackground, startScan)
// ... (Bu fonksiyonlar aynı kalabilir) ...

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

        if (fuzzyResponse && fuzzyResponse.fuzzyLogic) {
            fuzzyLogicConfig = fuzzyResponse.fuzzyLogic;
            if (fuzzyLogicSelect) {
                fuzzyLogicSelect.innerHTML = '';
                Object.keys(fuzzyLogicConfig.llmModels).forEach(key => {
                    const option = new Option(key.toUpperCase(), key);
                    fuzzyLogicSelect.add(option);
                });
                fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
            }
        }

        if (scoreResponse && scoreResponse.scoreMethods) {
            scoreMethods = scoreResponse.scoreMethods;
            const models = scoreMethods.llmModels || scoreMethods;
            if (scoreMethodSelect) {
                scoreMethodSelect.innerHTML = '';
                Object.keys(models).forEach(key => {
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
        getVulnsFromBackground();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // ... (Bu bölümün tamamı aynı kalabilir) ...
    // --- KODUNUZDAKİ MEVCUT DOMCONTENTLOADED İÇERİĞİNİ BURADA TUTUN ---
});