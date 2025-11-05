
// popup.js - CSP UYUMLU, TAM VE SEKME GEÇİŞİ EKLENMİŞ VERSİYON

document.addEventListener('DOMContentLoaded', () => {

    // =========================================================================
    // GLOBAL STATE & DOM ELEMENTS
    // =========================================================================
    let currentVulns = [];
    let currentFilter = 'all';
    let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };
    let fuzzyLogicConfig = null;
    let scoreMethods = null;
    let isScanning = false;

    const scanBtn = document.getElementById('scanBtn');
    const vulnList = document.getElementById('vulnList');
    const statusText = document.getElementById('statusText');
    const scoreMethodSelect = document.getElementById('scoreMethodSelect');
    const fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================
    const setStatus = (message) => {
        if (statusText) statusText.textContent = message;
    };

    const filterVulns = (vulns) => {
        if (currentFilter === 'all') return vulns;
        return vulns.filter(v => (v.severity || 'medium').toLowerCase() === currentFilter);
    };

    // =========================================================================
    // SCORE & FUZZY LOGIC ENGINES (GÜVENLİ VERSİYON)
    // =========================================================================
    const ScoreCalculator = {
        calculateScore: (vuln, config, modelName) => {
            if (!config) return 50;
            const { typeWeights, locationWeights } = config;
            const typeWeight = typeWeights[vuln.type] || 0.5;
            const locationWeight = locationWeights[vuln.location] || 0.5;
            const matchCount = vuln.matchCount || 1;
            const httpsPresent = !vuln.contextFactors;
            const userInteractionRequired = vuln.userInteractionRequired;
            const isMaliciousURL = vuln.isMaliciousURL;
            
            let matchCountNorm = 0, contextWeight = 0, score = 0;
            
            if (modelName === 'gemini') {
                matchCountNorm = Math.min(matchCount / 8, 1);
                contextWeight = (httpsPresent ? 0.25 : 0.75) + (userInteractionRequired ? -0.15 : 0.15) + (isMaliciousURL ? 0.35 : 0);
                score = ((typeWeight + locationWeight) / 2) * 0.6 + (matchCountNorm * 0.25) + (contextWeight * 0.15);
            } else if (modelName === 'deepseek') {
                matchCountNorm = Math.min(matchCount / 12, 1);
                contextWeight = (httpsPresent ? 0.35 : 0.85) + (userInteractionRequired ? -0.25 : 0.2) + (isMaliciousURL ? 0.45 : 0);
                score = (typeWeight * 0.35) + (locationWeight * 0.25) + (matchCountNorm * 0.25) + (contextWeight * 0.15);
            } else { // 'gpt' ve varsayılan
                matchCountNorm = Math.min(matchCount / 10, 1);
                contextWeight = (httpsPresent ? 0.3 : 0.8) + (userInteractionRequired ? -0.2 : 0.1) + (isMaliciousURL ? 0.4 : 0);
                score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2);
            }
            return Math.round(Math.max(0, Math.min(1, score)) * 100);
        }
    };
    
    const FuzzyLogicEngine = {
        evaluate: (vuln, config) => {
             if (!config || !config.rules) return { score: 50, label: "Orta" };
            const { memberships, rules, outputs } = config;
            const fuzzyInputs = {};
            const categories = { type: vuln.type, location: vuln.location };
            for(const cat in categories){ fuzzyInputs[cat] = {}; for(const term in memberships[cat]){ fuzzyInputs[cat][term] = (term === categories[cat]) ? 1.0 : 0.0; } }

            let totalWeightedScore = 0, totalWeight = 0, finalLabel = "Düşük";
            rules.forEach(rule => {
                const score = outputs[rule.then]?.score || 5;
                totalWeightedScore += score;
                totalWeight += 1;
                finalLabel = outputs[rule.then]?.label || "Orta";
            });

            if (totalWeight === 0) return { score: 20, label: "Düşük" };
            return { score: Math.round((totalWeightedScore / totalWeight) * 10), label: finalLabel };
        }
    };

    // =========================================================================
    // CORE LOGIC & RENDERING
    // =========================================================================
    const generateHybridResults = () => {
        if (!fuzzyLogicConfig || !scoreMethods) return;
        const scoreConfig = scoreMethods.llmModels[selectedModels.scoreMethod];
        const fuzzyConfig = fuzzyLogicConfig.llmModels[selectedModels.fuzzyLogic];
        if (!scoreConfig || !fuzzyConfig) return;
        
        currentVulns = currentVulns.map(vuln => {
            const scoreResult = ScoreCalculator.calculateScore(vuln, scoreConfig, selectedModels.scoreMethod);
            const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, fuzzyConfig);
            
            vuln.llmScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
            vuln.fuzzySeverity = fuzzyResult.score > scoreResult ? fuzzyResult.label : (scoreResult > 70 ? 'Yüksek' : 'Orta');
            vuln.severity = vuln.fuzzySeverity.toLowerCase().replace('kritik', 'high');
            return vuln;
        });
    };

    const renderVulns = () => {
        if (!vulnList) return;
        generateHybridResults();
        const filteredVulns = filterVulns(currentVulns);
        
        vulnList.innerHTML = '';
        if (filteredVulns.length === 0) {
            vulnList.innerHTML = '<div class="empty-state"><p>Tarama sonucu bulunamadı.</p></div>';
            setStatus(`Kullanıma hazır.`);
            return;
        }

        filteredVulns.forEach(vuln => {
            const item = document.createElement('div');
            const sevClass = (vuln.severity || 'medium').toLowerCase();
            item.className = `vuln-item severity-${sevClass}`;
            item.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-severity ${sevClass}">${vuln.fuzzySeverity} (${vuln.llmScore}/100)</span>
                    <h4>${vuln.title} (${vuln.type.toUpperCase()})</h4>
                </div>
                <p class="vuln-details">${vuln.details}</p>`;
            vulnList.appendChild(item);
        });
        
        setStatus(`Tarama tamamlandı — ${filteredVulns.length} açık bulundu`);
    };

    // =========================================================================
    // COMMUNICATION & INITIALIZATION
    // =========================================================================
    const startScan = async () => {
        if (isScanning) return;
        isScanning = true;
        scanBtn.disabled = true;
        scanBtn.textContent = 'Taranıyor...';
        setStatus('Tarama başlıyor...');
        
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.id) throw new Error("Aktif sekme bulunamadı.");
            
            await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
            const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
            currentVulns = response?.vulnerabilities || [];
        } catch (error) {
            console.error('Tarama hatası:', error.message);
            setStatus(`Tarama hatası. Sayfayı yenileyin.`);
            currentVulns = [];
        } finally {
            isScanning = false;
            scanBtn.disabled = false;
            scanBtn.textContent = 'Sayfayı Tara';
            renderVulns();
        }
    };

    const loadInitialData = async () => {
        try {
            const responses = await Promise.all([
                chrome.runtime.sendMessage({ action: "getFuzzyLogic" }),
                chrome.runtime.sendMessage({ action: "getScoreMethods" }),
                chrome.runtime.sendMessage({ action: "getVulns" })
            ]);

            const [fuzzyRes, scoreRes, vulnsRes] = responses;

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
            }
        } catch (error) {
            console.error("Başlangıç verileri yüklenemedi:", error.message);
            setStatus("Hata: Arka plan betiğiyle iletişim kurulamadı.");
        } finally {
            renderVulns();
        }
    };

    // =========================================================================
    // EVENT LISTENERS
    // =========================================================================
    scanBtn.addEventListener('click', startScan);
    scoreMethodSelect.addEventListener('change', () => { selectedModels.scoreMethod = scoreMethodSelect.value; renderVulns(); });
    fuzzyLogicSelect.addEventListener('change', () => { selectedModels.fuzzyLogic = fuzzyLogicSelect.value; renderVulns(); });

    document.querySelectorAll('.filter').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelector('.filter.active')?.classList.remove('active');
            btn.classList.add('active');
            currentFilter = btn.dataset.sev;
            renderVulns();
        });
    });

    // --- YENİ EKLENEN SEKME GEÇİŞ KODU ---
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const targetTabId = e.target.dataset.tab;

            // Ayarlar sekmesi özel durumu
            if (targetTabId === 'settings') {
                alert('Ayarlar sayfası henüz oluşturulmadı.');
                return; 
            }

            // Aktif olan sekmelerden 'active' class'ını kaldır
            document.querySelector('.tab.active')?.classList.remove('active');
            document.querySelector('.tab-content.active')?.classList.remove('active');

            // Tıklanan sekmeyi ve ilgili içerik alanını aktif yap
            e.target.classList.add('active');
            document.getElementById(targetTabId)?.classList.add('active');
        });
    });
    
    // =========================================================================
    // INITIAL LOAD
    // =========================================================================
    loadInitialData();
});