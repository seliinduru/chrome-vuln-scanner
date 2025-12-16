// popup.js - AGENTIC SCANNER VERSION

document.addEventListener('DOMContentLoaded', () => {

    // --- YASAL ONAY KONTROLÜ ---
    const consentModal = document.getElementById('consentModal');
    const acceptBtn = document.getElementById('acceptConsent');
    const declineBtn = document.getElementById('declineConsent');

    if (consentModal) {
        chrome.storage.local.get('consentAccepted', (data) => {
            if (!data.consentAccepted) {
                consentModal.style.display = 'flex';
            } else {
                consentModal.style.display = 'none';
            }
        });

        acceptBtn.addEventListener('click', () => {
            chrome.storage.local.set({ consentAccepted: true }, () => {
                consentModal.style.display = 'none';
            });
        });

        declineBtn.addEventListener('click', () => {
            window.close();
        });
    }

    // --- GLOBAL VARIABLES ---
    let currentVulns = [];
    let currentScanIndex = -1;
    let currentFilter = 'all';
    let selectedModels = { scoreMethod: 'gpt', fuzzyLogic: 'gpt' };
    let fuzzyLogicConfig = null;
    let scoreMethods = null;
    let isScanning = false;
    let pendingRequests = {}; // Tracks active requests per model: { 'modelId': true/false }

    const DEFAULT_SETTINGS = {
        autoScan: false,
        networkMonitor: true,
        domMonitor: true,
        severity: ['high', 'medium', 'low']
    };

    // --- DOM ELEMENTS ---
    // Views
    const viewHome = document.getElementById('view-home');
    const viewProgress = document.getElementById('view-progress');
    const viewDashboard = document.getElementById('view-dashboard');
    const viewSettings = document.getElementById('view-settings');

    // Buttons
    const startAgentScanBtn = document.getElementById('startAgentScanBtn');
    const newScanBtn = document.getElementById('newScanBtn');
    
    // Dashboard Elements
    const vulnList = document.getElementById('vulnList');
    const vulnDetails = document.getElementById('vulnDetails');
    const statusText = document.getElementById('statusText');
    const scoreMethodSelect = document.getElementById('scoreMethodSelect');
    const fuzzyLogicSelect = document.getElementById('fuzzyLogicSelect');
    const aiVulnList = document.getElementById('aiVulnList');
    const aiModelSelect = document.getElementById('aiModelSelect');
    const exportJsonBtn = document.getElementById('exportJson');
    const exportCsvBtn = document.getElementById('exportCsv');
    const historyList = document.getElementById('historyList');

    // --- HELPER FUNCTIONS ---
    const setStatus = (message) => { if (statusText) statusText.textContent = message; };
    
    const switchView = (viewId) => {
        [viewHome, viewProgress, viewDashboard, viewSettings].forEach(el => {
            if(el) el.classList.remove('active');
        });
        document.getElementById(viewId).classList.add('active');

        // Header Visibility Logic
        const mainHeader = document.getElementById('main-header');
        if (mainHeader) {
            if (viewId === 'view-dashboard') {
                mainHeader.style.display = 'flex';
            } else {
                mainHeader.style.display = 'none';
            }
        }
    };

    const downloadFile = (content, fileName, contentType) => { 
        const a = document.createElement("a"); 
        const file = new Blob([content], { type: contentType }); 
        a.href = URL.createObjectURL(file); 
        a.download = fileName; 
        a.click(); 
        URL.revokeObjectURL(a.href); 
    };

    // --- SCORING & FUZZY LOGIC ---
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
            
            matchCountNorm = Math.min(matchCount / 10, 1);
            contextWeight = (httpsPresent ? 0.3 : 0.8) + (userInteractionRequired ? -0.2 : 0.1) + (isMaliciousURL ? 0.4 : 0);
            score = (typeWeight * 0.4) + (locationWeight * 0.2) + (matchCountNorm * 0.2) + (contextWeight * 0.2);
            
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

    const processResults = () => {
        if (!fuzzyLogicConfig || !scoreMethods) return;
        const scoreConfig = scoreMethods.llmModels[selectedModels.scoreMethod];
        const fuzzyConfig = fuzzyLogicConfig.llmModels[selectedModels.fuzzyLogic];
        
        currentVulns.forEach(vuln => {
            const scoreResult = ScoreCalculator.calculateScore(vuln, scoreConfig, selectedModels.scoreMethod);
            const fuzzyResult = FuzzyLogicEngine.evaluate(vuln, fuzzyConfig);
            
            // Hybrid Score
            vuln.llmScore = Math.round((scoreResult * 0.5) + (fuzzyResult.score * 0.5));
            
            // Determine Severity Label based on Score
            if (vuln.llmScore >= 80) vuln.fuzzySeverity = 'Yüksek';
            else if (vuln.llmScore >= 50) vuln.fuzzySeverity = 'Orta';
            else vuln.fuzzySeverity = 'Düşük';
            
            vuln.severity = vuln.fuzzySeverity.toLowerCase().replace('yüksek', 'high').replace('orta', 'medium').replace('düşük', 'low');
        });
    };

    // --- UI RENDERING ---
    const showNotification = (message) => {
        const notification = document.createElement('div');
        notification.className = 'notification-toast';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #334155;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
            font-size: 0.9em;
        `;
        document.body.appendChild(notification);
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    };

    const getAiSuggestion = async (vuln, index) => {
        const modelId = aiModelSelect ? aiModelSelect.value : 'gpt';
        
        // Check Global Lock for this model
        if (pendingRequests[modelId]) {
            alert(`"${modelId.toUpperCase()}" modeli şu anda başka bir işlem yapıyor. Lütfen bekleyin.`);
            return;
        }

        // Set Locks
        pendingRequests[modelId] = true;
        if (!vuln.isProcessing) vuln.isProcessing = {};
        vuln.isProcessing[modelId] = true;
        
        renderAiSuggestions(); // Re-render to update UI state

        try {
            let suggestion = "";
            if (window.llmService) {
                suggestion = await window.llmService.analyzeVuln(vuln, modelId);
            } else {
                // Fallback simulation
                await new Promise(r => setTimeout(r, 3000));
                suggestion = `[${modelId.toUpperCase()}] Önerisi: Bu ${vuln.type} zafiyeti için girdileri sanitize edin ve CSP politikalarını sıkılaştırın.`;
            }
            
            // Initialize aiSuggestions if not exists
            if (!vuln.aiSuggestions) vuln.aiSuggestions = {};
            
            // Store suggestion
            vuln.aiSuggestions[modelId] = suggestion;
            
            // Update storage
            if (currentScanIndex !== -1) {
                const data = await chrome.storage.local.get('scanHistory');
                const history = data.scanHistory || [];
                if (history[currentScanIndex]) {
                    history[currentScanIndex].vulns = currentVulns;
                    await chrome.storage.local.set({ scanHistory: history });
                }
            }

            // Notify if user is looking at another model or just generally
            if (aiModelSelect && aiModelSelect.value !== modelId) {
                showNotification(`${modelId.toUpperCase()} modelinden yeni bir öneri geldi!`);
            } else {
                showNotification("AI Önerisi başarıyla alındı.");
            }

        } catch (error) {
            console.error(error);
            alert("Hata: " + error.message);
        } finally {
            // Release Locks
            pendingRequests[modelId] = false;
            if (vuln.isProcessing) vuln.isProcessing[modelId] = false;
            renderAiSuggestions();
        }
    };

    const renderAiSuggestions = () => {
        if (!aiVulnList) return;
        aiVulnList.innerHTML = '';
        
        const filtered = currentVulns.filter(v => currentFilter === 'all' || (v.severity || 'medium') === currentFilter);
        const selectedModel = aiModelSelect ? aiModelSelect.value : 'gpt';
        
        if (filtered.length === 0) {
            aiVulnList.innerHTML = '<div class="empty-state"><p>Öneri bulunacak açık yok.</p></div>';
            return;
        }

        filtered.forEach((vuln, index) => {
            const item = document.createElement('div');
            item.className = 'vuln-item';
            
            let contentHtml = `
                <div class="vuln-header">
                    <h4>${vuln.title || 'Bilinmeyen Açık'}</h4>
                    <span class="vuln-severity ${vuln.severity || 'medium'}">${vuln.fuzzySeverity || 'Orta'}</span>
                </div>
                <p class="vuln-details" style="margin-top: 5px; font-size: 0.9em; color: #64748b;">${vuln.details || ''}</p>
            `;

            // Check if we have a suggestion for the SELECTED model
            const suggestion = vuln.aiSuggestions ? vuln.aiSuggestions[selectedModel] : null;
            const isProcessing = vuln.isProcessing && vuln.isProcessing[selectedModel];
            const isModelBusy = pendingRequests[selectedModel];

            if (suggestion) {
                contentHtml += `
                <div class="ai-suggestion-box" style="margin-top:10px; padding:10px; background:#f8fafc; border-radius:6px; font-size:0.9em;">
                    <strong>🤖 AI Önerisi (${selectedModel.toUpperCase()}):</strong>
                    <p style="margin-top:5px; white-space: pre-wrap;">${suggestion}</p>
                </div>`;
            } else if (isProcessing) {
                // Currently processing THIS item
                contentHtml += `
                <div class="ai-actions" style="margin-top:10px;">
                    <button disabled class="secondary-btn-theme" style="width:100%; justify-content:center; opacity: 0.7; cursor: not-allowed;">
                        . . .
                    </button>
                </div>`;
            } else if (isModelBusy) {
                // Model is busy with ANOTHER item
                contentHtml += `
                <div class="ai-actions" style="margin-top:10px;">
                    <button disabled class="secondary-btn-theme" style="width:100%; justify-content:center; opacity: 0.5; cursor: not-allowed;" title="Model şu an başka bir işlem yapıyor">
                        🔒 Bekleniyor...
                    </button>
                </div>`;
            } else {
                // Ready to request
                contentHtml += `
                <div class="ai-actions" style="margin-top:10px;">
                    <button id="btn-ai-${index}" class="secondary-btn-theme" style="width:100%; justify-content:center;">
                        🤖 AI Çözüm Önerisi Al
                    </button>
                    <div id="ai-output-${index}" style="color:red; font-size:0.8em; margin-top:5px;"></div>
                </div>`;
            }
            
            item.innerHTML = contentHtml;
            aiVulnList.appendChild(item);

            // Attach event listener if button exists
            const btn = document.getElementById(`btn-ai-${index}`);
            if (btn) {
                btn.addEventListener('click', () => getAiSuggestion(vuln, index));
            }
        });
    };

    const renderVulns = () => {
        if (!vulnList) return;
        vulnList.innerHTML = '';
        vulnDetails.style.display = 'none';
        vulnList.style.display = 'block';

        processResults();
        renderAiSuggestions();
        
        const filtered = currentVulns.filter(v => currentFilter === 'all' || (v.severity || 'medium') === currentFilter);
        
        if (filtered.length === 0) {
            vulnList.innerHTML = '<div class="empty-state"><p>Kriterlere uygun açık bulunamadı.</p></div>';
            return;
        }

        filtered.forEach((vuln, index) => {
            const item = document.createElement('div');
            const sevClass = (vuln.severity || 'medium');
            item.className = `vuln-item severity-${sevClass} clickable`;
            item.innerHTML = `
                <div class="vuln-header">
                    <h4>${vuln.title || 'Bilinmeyen Açık'}</h4>
                    <span class="vuln-severity ${sevClass}">${vuln.fuzzySeverity} (${vuln.llmScore})</span>
                </div>
                <p class="vuln-details">${vuln.details}</p>
            `;
            item.addEventListener('click', () => showVulnDetails(vuln));
            vulnList.appendChild(item);
        });
        
        setStatus(`${filtered.length} açık listeleniyor.`);
    };

    const showVulnDetails = (vuln) => {
        const evidenceContent = vuln.evidence ? JSON.stringify(vuln.evidence, null, 2) : 'Kanıt yok.';
        vulnDetails.innerHTML = `
            <div class="card detail-card">
                <button id="backToListBtn" class="back-button"> Listeye Dön</button>
                <div class="vuln-header">
                    <span class="vuln-severity severity-${vuln.severity}">${vuln.fuzzySeverity} (${vuln.llmScore})</span>
                    <h4>${vuln.title}</h4>
                </div>
                <p class="detail-description">${vuln.details}</p>
                <h5>Risk Faktörleri</h5>
                <ul class="detail-factors">
                    <li><strong>Tür:</strong> ${vuln.type.toUpperCase()}</li>
                    <li><strong>Konum:</strong> ${vuln.location}</li>
                    <li><strong>Eşleşme:</strong> ${vuln.matchCount}</li>
                </ul>
                <h5>Teknik Kanıt</h5>
                <pre class="detail-evidence">${evidenceContent}</pre>
            </div>
        `;
        document.getElementById('backToListBtn').addEventListener('click', () => {
            vulnDetails.style.display = 'none';
            vulnList.style.display = 'block';
        });
        vulnList.style.display = 'none';
        vulnDetails.style.display = 'block';
    };

    const renderHistory = async () => {
        const data = await chrome.storage.local.get('scanHistory');
        const history = data.scanHistory || [];
        historyList.innerHTML = '';
        
        setStatus("Geçmiş taramalar listeleniyor.");

        if (history.length === 0) {
            historyList.innerHTML = '<div class="empty-state" style="padding:20px;">Geçmiş tarama yok.</div>';
            setStatus("Hazır");
            return;
        }

        // Show last 5 scans
        history.slice().reverse().slice(0, 5).forEach((scan, idx) => {
            const item = document.createElement('div');
            item.className = 'history-item';
            const date = new Date(scan.date).toLocaleString('tr-TR');
            
            // Count severities
            const high = scan.vulns.filter(v => v.severity === 'high').length;
            const med = scan.vulns.filter(v => v.severity === 'medium').length;
            const low = scan.vulns.filter(v => v.severity === 'low').length;

            item.innerHTML = `
                <div class="history-info">
                    <div class="history-url">${scan.url}</div>
                    <div class="history-date">${date}</div>
                </div>
                <div class="history-stats">
                    ${high > 0 ? `<span class="badge high">${high} Yüksek</span>` : ''}
                    ${med > 0 ? `<span class="badge medium">${med} Orta</span>` : ''}
                    ${low > 0 ? `<span class="badge low">${low} Düşük</span>` : ''}
                </div>
            `;
            item.addEventListener('click', () => {
                currentVulns = scan.vulns;
                currentScanIndex = history.length - 1 - idx;
                switchView('view-dashboard');
                renderVulns();
            });
            historyList.appendChild(item);
        });
    };

    const saveToHistory = async (vulns) => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const url = tab ? new URL(tab.url).hostname : 'Unknown';
        const scanRecord = {
            date: new Date().toISOString(),
            url: url,
            vulns: vulns
        };
        
        const data = await chrome.storage.local.get('scanHistory');
        const history = data.scanHistory || [];
        history.push(scanRecord);
        // Keep last 20
        if (history.length > 20) history.shift();
        
        await chrome.storage.local.set({ scanHistory: history });
        currentScanIndex = history.length - 1;
    };

    // --- AGENT SCAN LOGIC ---
    const runAgentScan = async () => {
        if (isScanning) return;
        isScanning = true;
        
        // 1. Switch to Progress View IMMEDIATELY
        switchView('view-progress');
        
        // Reset steps
        document.querySelectorAll('.step-item').forEach(el => {
            el.classList.remove('active', 'completed');
        });

        // Start Step 1 Animation
        const steps = ['step-network', 'step-dom', 'step-cookies', 'step-analysis'];
        document.getElementById(steps[0]).classList.add('active');

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab) throw new Error("Tab bulunamadı");

            // Send Start Command to Background (Reload & Scan)
            // Note: This will reload the page, which might close the popup.
            // If the popup stays open (e.g. devtools open), the animation continues.
            chrome.runtime.sendMessage({ action: 'start_full_scan', tabId: tab.id });
            
            // Simulate Progress Steps (Visual only, if popup stays open)
            setTimeout(() => { 
                document.getElementById(steps[0]).classList.remove('active');
                document.getElementById(steps[0]).classList.add('completed');
                document.getElementById(steps[1]).classList.add('active');
            }, 1500);

            setTimeout(() => { 
                document.getElementById(steps[1]).classList.remove('active');
                document.getElementById(steps[1]).classList.add('completed');
                document.getElementById(steps[2]).classList.add('active');
            }, 3000);

            setTimeout(() => { 
                document.getElementById(steps[2]).classList.remove('active');
                document.getElementById(steps[2]).classList.add('completed');
                document.getElementById(steps[3]).classList.add('active');
            }, 4500);
            
        } catch (error) {
            console.error(error);
            alert("Tarama başlatılamadı: " + error.message);
            switchView('view-home');
            isScanning = false;
        }
    };

    // --- INITIALIZATION ---
    const init = async () => {
        // Load Configs
        try {
            const [fuzzyRes, scoreRes] = await Promise.all([ 
                chrome.runtime.sendMessage({ action: "getFuzzyLogic" }), 
                chrome.runtime.sendMessage({ action: "getScoreMethods" }) 
            ]);
            fuzzyLogicConfig = fuzzyRes?.fuzzyLogic; 
            scoreMethods = scoreRes?.scoreMethods;

            // Populate Selects
            if (scoreMethods) {
                Object.keys(scoreMethods.llmModels).forEach(key => scoreMethodSelect.add(new Option(key.toUpperCase(), key)));
                
                // Add listener for Score Method
                scoreMethodSelect.addEventListener('change', (e) => {
                    selectedModels.scoreMethod = e.target.value;
                    renderVulns();
                });
            }
            if (fuzzyLogicConfig) {
                Object.keys(fuzzyLogicConfig.llmModels).forEach(key => fuzzyLogicSelect.add(new Option(key.toUpperCase(), key)));
                
                // Add listener for Fuzzy Logic
                fuzzyLogicSelect.addEventListener('change', (e) => {
                    selectedModels.fuzzyLogic = e.target.value;
                    renderVulns();
                });
            }
        } catch (e) { console.error("Config load error", e); }

        // Check Scan State
        try {
            const data = await chrome.storage.local.get('scanState');
            const scanState = data.scanState;
            
            if (scanState) {
                if (scanState.isScanning) {
                    switchView('view-progress');
                    // Optionally animate steps here
                } else if (scanState.results && scanState.results.length > 0) {
                    // If we have results from a recent scan, show them
                    currentVulns = scanState.results;
                    switchView('view-dashboard');
                    renderVulns();
                }
            }
        } catch (e) { console.error("State check error", e); }

        renderHistory();
    };

    // --- SETTINGS LOGIC ---
    const loadSettings = () => {
        chrome.storage.local.get('scannerSettings', (result) => {
            const settings = { ...DEFAULT_SETTINGS, ...result.scannerSettings };
            
            const autoScan = document.getElementById('setting-autoScan');
            if(autoScan) autoScan.checked = settings.autoScan;
            
            const networkMonitor = document.getElementById('setting-networkMonitor');
            if(networkMonitor) networkMonitor.checked = settings.networkMonitor;
            
            const domMonitor = document.getElementById('setting-domMonitor');
            if(domMonitor) domMonitor.checked = settings.domMonitor;

            document.querySelectorAll('input[name="setting-severity"]').forEach(cb => {
                cb.checked = settings.severity.includes(cb.value);
            });
        });
    };

    const saveSettings = () => {
        const settings = {
            autoScan: document.getElementById('setting-autoScan').checked,
            networkMonitor: document.getElementById('setting-networkMonitor').checked,
            domMonitor: document.getElementById('setting-domMonitor').checked,
            severity: Array.from(document.querySelectorAll('input[name="setting-severity"]:checked')).map(cb => cb.value)
        };
        
        chrome.storage.local.set({ scannerSettings: settings }, () => {
            const btn = document.getElementById('saveSettingsBtn');
            const originalText = btn.textContent;
            btn.textContent = 'Kaydedildi!';
            setTimeout(() => btn.textContent = originalText, 1500);
        });
    };

    const resetSettings = () => {
        chrome.storage.local.set({ scannerSettings: DEFAULT_SETTINGS }, () => {
            loadSettings();
        });
    };

    // --- EVENT LISTENERS ---
    startAgentScanBtn.addEventListener('click', runAgentScan);

    const openSettingsBtn = document.getElementById('openSettingsBtn');
    if (openSettingsBtn) {
        openSettingsBtn.addEventListener('click', () => {
            loadSettings();
            switchView('view-settings');
        });
    }

    const backFromSettingsBtn = document.getElementById('backFromSettingsBtn');
    if (backFromSettingsBtn) {
        backFromSettingsBtn.addEventListener('click', () => {
            switchView('view-home');
        });
    }

    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    if (saveSettingsBtn) saveSettingsBtn.addEventListener('click', saveSettings);

    const resetSettingsBtn = document.getElementById('resetSettingsBtn');
    if (resetSettingsBtn) resetSettingsBtn.addEventListener('click', resetSettings);

    newScanBtn.addEventListener('click', () => {
        switchView('view-home');
        renderHistory(); // Refresh history
    });

    // Listen for Scan Completion (if popup is open)
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'scan_complete') {
            // Final Step Completion
            const steps = ['step-network', 'step-dom', 'step-cookies', 'step-analysis'];
            document.getElementById(steps[3]).classList.remove('active');
            document.getElementById(steps[3]).classList.add('completed');

            setTimeout(() => {
                isScanning = false;
                currentVulns = message.vulnerabilities || [];
                saveToHistory(currentVulns);
                
                // Update UI
                switchView('view-dashboard');
                renderVulns();
                
                // Activate Results Tab
                document.querySelector('.tab[data-tab="results"]').click();
            }, 800); // Small delay to show "Analysis Complete" state
        }
    });

    // Filters
    document.querySelectorAll('.filter').forEach(btn => {
        btn.addEventListener('click', () => { 
            document.querySelector('.filter.active')?.classList.remove('active'); 
            btn.classList.add('active'); 
            currentFilter = btn.dataset.sev; 
            renderVulns(); 
        });
    });

    // Tabs
    document.querySelectorAll('.tab').forEach(tabButton => {
        tabButton.addEventListener('click', (event) => {
            const clickedTabId = event.currentTarget.dataset.tab;
            
            if (clickedTabId === 'settings') { 
                loadSettings();
                switchView('view-settings');
                return; 
            }

            // Switch to Dashboard View if not active
            if (!viewDashboard.classList.contains('active')) {
                switchView('view-dashboard');
            }

            document.querySelectorAll('.tab.active').forEach(el => el.classList.remove('active'));
            event.currentTarget.classList.add('active');
            
            document.querySelectorAll('.tab-content.active').forEach(el => el.classList.remove('active'));
            document.getElementById(clickedTabId)?.classList.add('active');
        });
    });

    // AI Model Select
    if (window.llmService && aiModelSelect) {
        const models = window.llmService.getAvailableModels();
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.id;
            option.textContent = model.name;
            aiModelSelect.appendChild(option);
        });

        // Add change listener to re-render suggestions when model changes
        aiModelSelect.addEventListener('change', () => {
            renderAiSuggestions();
        });
    }

    // Export Buttons
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            if (!currentVulns || currentVulns.length === 0) {
                alert("Dışa aktarılacak veri yok.");
                return;
            }
            const dataStr = JSON.stringify(currentVulns, null, 2);
            downloadFile(dataStr, `scan_results_${new Date().toISOString().slice(0,10)}.json`, 'application/json');
        });
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            if (!currentVulns || currentVulns.length === 0) {
                alert("Dışa aktarılacak veri yok.");
                return;
            }
            
            // CSV Header
            const headers = ["Title", "Type", "Severity", "Score", "Location", "Details", "AI Suggestions"];
            const rows = currentVulns.map(v => [
                `"${(v.title || '').replace(/"/g, '""')}"`,
                `"${(v.type || '').replace(/"/g, '""')}"`,
                `"${(v.fuzzySeverity || 'Orta')}"`,
                `"${(v.llmScore || 0)}"`,
                `"${(v.location || '').replace(/"/g, '""')}"`,
                `"${(v.details || '').replace(/"/g, '""')}"`,
                `"${(JSON.stringify(v.aiSuggestions || {})).replace(/"/g, '""')}"`
            ]);
            
            const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
            downloadFile(csvContent, `scan_results_${new Date().toISOString().slice(0,10)}.csv`, 'text/csv');
        });
    }

    init();
});
