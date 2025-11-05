// popup.js - DIŞA AKTARMA ÖZELLİĞİ EKLENMİŞ NİHAİ VE TEMİZ VERSİYON

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
    const aiSuggestions = document.getElementById('aiSuggestions');
    const exportJsonBtn = document.getElementById('exportJson');
    const exportCsvBtn = document.getElementById('exportCsv');

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================
    const setStatus = (message) => { if (statusText) statusText.textContent = message; };

    const filterVulns = (vulns) => { 
        if (currentFilter === 'all') return vulns; 
        return vulns.filter(v => (v.severity || 'medium').toLowerCase() === currentFilter); 
    };
    
    const downloadFile = (content, fileName, contentType) => {
        const a = document.createElement("a");
        const file = new Blob([content], { type: contentType });
        a.href = URL.createObjectURL(file);
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(a.href);
    };

    // =========================================================================
    // SCORE & FUZZY LOGIC ENGINES
    // =========================================================================
    const ScoreCalculator = {
        calculateScore: (vuln, config, modelName) => {
            if (!config || !config.typeWeights) return 50;
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
            } else {
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
            const { rules, outputs } = config;
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
        currentVulns.forEach(vuln => {
            const scoreResult = ScoreCalculator.calculateScore(vuln, scoreConfig, selectedModels.scoreMethod);
            const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, fuzzyConfig);
            vuln.llmScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
            vuln.fuzzySeverity = fuzzyResult.score > scoreResult ? fuzzyResult.label : (scoreResult > 70 ? 'Yüksek' : 'Orta');
            vuln.severity = vuln.fuzzySeverity.toLowerCase().replace('kritik', 'high');
        });
    };

    const renderAiSuggestions = (vulns) => {
        if (!aiSuggestions) return;
        if (!vulns || vulns.length === 0) {
            aiSuggestions.innerHTML = '<p class="muted">Öneri gösterecek bir açık bulunamadı.</p>';
            return;
        }
        let suggestionsHTML = '<h3>Önerilen Çözümler</h3>';
        const suggestionMap = {};
        vulns.forEach(vuln => {
            if (suggestionMap[vuln.type]) return;
            switch (vuln.type) {
                case 'xss':
                    suggestionsHTML += `<div class="ai-advice"><h4>XSS Zafiyetleri İçin</h4><p>Kullanıcıdan gelen verileri DOM'a yazdırırken <strong>textContent</strong> kullanın...</p></div>`;
                    suggestionMap.xss = true;
                    break;
                case 'csp':
                    suggestionsHTML += `<div class="ai-advice"><h4>CSP Eksikliği İçin</h4><p>HTTP başlıklarına katı bir <strong>Content-Security-Policy</strong> ekleyin...</p></div>`;
                    suggestionMap.csp = true;
                    break;
                case 'csrf': case 'cookie':
                    suggestionsHTML += `<div class="ai-advice"><h4>Cookie & CSRF Güvenliği</h4><p>Tüm oturum cookielerinin <strong>HttpOnly</strong>, <strong>Secure</strong> ve <strong>SameSite=Lax/Strict</strong> bayraklarına sahip olduğundan emin olun...</p></div>`;
                    suggestionMap.csrf = true; suggestionMap.cookie = true;
                    break;
            }
        });
        aiSuggestions.innerHTML = Object.keys(suggestionMap).length > 0 ? suggestionsHTML : '<p class="muted">Bu açık türleri için henüz bir öneri tanımlanmadı.</p>';
    };

    const renderVulns = () => {
        if (!vulnList) return;
        if (!fuzzyLogicConfig || !scoreMethods) {
            setStatus("Hata: Değerlendirme modelleri yüklenemedi.");
            vulnList.innerHTML = `<div class="empty-state"><p>Arka plan betiğinde hata oluştu. Service Worker konsolunu kontrol edin.</p></div>`;
            return;
        }
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
                    <span class="vuln-severity ${sevClass}">${vuln.fuzzySeverity || 'Orta'} (${vuln.llmScore || 'N/A'}/100)</span>
                    <h4>${vuln.title || 'Bilinmeyen Açık'} (${vuln.type.toUpperCase()})</h4>
                </div>
                <p class="vuln-details">${vuln.details}</p>`;
            vulnList.appendChild(item);
        });
        setStatus(`Tarama tamamlandı — ${filteredVulns.length} açık bulundu`);
    };

    // =========================================================================
    // COMMUNICATION & INITIALIZATION
    // =========================================================================
    const startScan = async () => { /* ... öncekiyle aynı ... */ };
    const loadInitialData = async () => { /* ... öncekiyle aynı ... */ };
    
    // (Fonksiyon içeriklerini tekrar ekliyorum)
    const startScanFn = async () => {
        if (isScanning || !fuzzyLogicConfig) return;
        isScanning = true;
        scanBtn.disabled = true;
        scanBtn.textContent = 'Taranıyor...';
        setStatus('Tarama başlıyor...');
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.id) throw new Error("Aktif sekme bulunamadı.");
            await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
            await new Promise(resolve => setTimeout(resolve, 100));
            const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
            currentVulns = response?.vulnerabilities || [];
            chrome.runtime.sendMessage({ action: 'vulnerabilitiesDetected', vulnerabilities: currentVulns });
        } catch (error) {
            console.error('Tarama hatası:', error.message);
            setStatus(`Tarama hatası.`);
            currentVulns = [];
        } finally {
            isScanning = false;
            scanBtn.disabled = false;
            scanBtn.textContent = 'Sayfayı Tara';
            renderVulns();
        }
    };
    const loadInitialDataFn = async () => {
        try {
            const [fuzzyRes, scoreRes, vulnsRes] = await Promise.all([
                chrome.runtime.sendMessage({ action: "getFuzzyLogic" }),
                chrome.runtime.sendMessage({ action: "getScoreMethods" }),
                chrome.runtime.sendMessage({ action: "getVulns" })
            ]);
            if (fuzzyRes?.error) throw new Error(fuzzyRes.error);
            if (scoreRes?.error) throw new Error(scoreRes.error);
            fuzzyLogicConfig = fuzzyRes?.fuzzyLogic;
            scoreMethods = scoreRes?.scoreMethods;
            currentVulns = vulnsRes?.vulnerabilities || [];
            if (fuzzyLogicConfig && scoreMethods) {
                Object.keys(fuzzyLogicConfig.llmModels).forEach(key => scoreMethodSelect.add(new Option(key.toUpperCase(), key)));
                scoreMethodSelect.value = selectedModels.scoreMethod;
                Object.keys(scoreMethods.llmModels).forEach(key => fuzzyLogicSelect.add(new Option(key.toUpperCase(), key)));
                fuzzyLogicSelect.value = selectedModels.fuzzyLogic;
                scanBtn.disabled = false;
            } else {
                throw new Error("Yapılandırma dosyaları boş veya hatalı geldi.");
            }
        } catch (error) {
            console.error("Başlangıç verileri yüklenemedi:", error.message);
            setStatus(`Hata: ${error.message}`);
            scanBtn.disabled = true;
        } finally {
            renderVulns();
        }
    };

    // =========================================================================
    // EVENT LISTENERS & INITIAL LOAD
    // =========================================================================
    scanBtn.disabled = true;
    scanBtn.addEventListener('click', startScanFn);
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

    document.querySelectorAll('.tab').forEach(tabButton => {
        tabButton.addEventListener('click', (event) => {
            const clickedTabId = event.currentTarget.dataset.tab;
            if (clickedTabId === 'settings') {
                window.location.href = 'settings.html';
                return; 
            }
            document.querySelectorAll('.tab.active, .tab-content.active').forEach(el => el.classList.remove('active'));
            event.currentTarget.classList.add('active');
            document.getElementById(clickedTabId)?.classList.add('active');
            if (clickedTabId === 'ai') {
                renderAiSuggestions(currentVulns);
            }
        });
    });
    
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            if (currentVulns.length === 0) {
                alert("Dışa aktarılacak bir zafiyet bulunamadı.");
                return;
            }
            const jsonData = JSON.stringify(currentVulns, null, 2);
            downloadFile(jsonData, 'vulnerabilities.json', 'application/json');
        });
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            if (currentVulns.length === 0) {
                alert("Dışa aktarılacak bir zafiyet bulunamadı.");
                return;
            }
            const headers = ['severity', 'score', 'title', 'type', 'details'];
            let csvContent = headers.join(',') + '\r\n';
            currentVulns.forEach(vuln => {
                const row = [
                    vuln.fuzzySeverity || 'N/A',
                    vuln.llmScore || 'N/A',
                    `"${(vuln.title || '').replace(/"/g, '""')}"`,
                    vuln.type || 'N/A',
                    `"${(vuln.details || '').replace(/"/g, '""')}"`
                ];
                csvContent += row.join(',') + '\r\n';
            });
            downloadFile(csvContent, 'vulnerabilities.csv', 'text/csv;charset=utf-8;');
        });
    }

    loadInitialDataFn();
});