// content.js - DYNAMIC ANALYSIS & VULNERABILITY SCANNER

(function() {
    if (window.CONTENT_SCRIPT_RUNNING) return;
    window.CONTENT_SCRIPT_RUNNING = true;

    let vulnerabilities = [];
    let networkMonitorInstalled = false;
    let observer = null;

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================
    function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
        // Prevent duplicates based on ID
        if (vulnerabilities.some(v => v.id === id)) return;
        
        vulnerabilities.push({ 
            id, title, details, type, severity, evidence,
            location: location || 'inline',
            matchCount: matchCount || 1,
            contextFactors: contextFactors || false,
            userInteractionRequired: userInteraction || false,
            isMaliciousURL: externalFactors || false
        });
    }

    function extractSnippet(src, terms) {
        if (!src) return '';
        for (const t of terms) {
            const idx = src.indexOf(t);
            if (idx >= 0) return src.slice(Math.max(0, idx-80), idx+200);
        }
        return src.slice(0, 200);
    }

    function truncate(s, n) { 
        return s && s.length > n ? s.slice(0,n)+'...' : s; 
    }

    // =========================================================================
    // SCANNING MODULES
    // =========================================================================

    // 1. URL & PARAMETER ANALYSIS (Static)
    function checkURLParameters() {
        try {
            const urlParams = new URLSearchParams(window.location.search);
            for (const [key, value] of urlParams) {
                // XSS
                if (/<|>|"|'|javascript:|onerror|onload|onclick/i.test(value)) {
                    addVuln('url_xss_' + key, `URL Parametresinde XSS`, `Parametre "${key}" HTML/JS karakterleri içeriyor.`, 'xss', 'high', { param: key, value: truncate(value, 50) }, 'url');
                }
                // SQLi
                if (/'|"|--|;|or\s+1|union|select|insert|delete|drop/i.test(value)) {
                    addVuln('url_sqli_' + key, `URL Parametresinde SQL Injection`, `Parametre "${key}" SQL karakterleri içeriyor.`, 'sqli', 'high', { param: key, value: truncate(value, 50) }, 'url');
                }
                // Path Traversal
                if (/\.\.|\/\/|%2e%2e|\.\.\//i.test(value)) {
                    addVuln('url_path_' + key, `URL Parametresinde Path Traversal`, `Parametre "${key}" dizin geçiş karakterleri içeriyor.`, 'path-traversal', 'high', { param: key, value: truncate(value, 50) }, 'url');
                }
                // LFI
                if (/(\/etc\/passwd|boot\.ini|win\.ini)/i.test(value)) {
                    addVuln('url_lfi_' + key, `URL Parametresinde LFI`, `Parametre "${key}" sistem dosyası okuma girişimi içeriyor.`, 'lfi', 'critical', { param: key, value: truncate(value, 50) }, 'url');
                }
                // RCE
                if (/(cmd|sh|bash|powershell|curl|wget|netcat|nc)\s+/i.test(value)) {
                    addVuln('url_rce_' + key, `URL Parametresinde RCE`, `Parametre "${key}" komut çalıştırma ifadesi içeriyor.`, 'rce', 'critical', { param: key, value: truncate(value, 50) }, 'url');
                }
            }
            
            // Hash Params
            const hashParams = new URLSearchParams(window.location.hash.slice(1));
            for (const [key, value] of hashParams) {
                if (/<|>|"|'|javascript:/i.test(value)) {
                    addVuln('hash_xss_' + key, `Hash Parametresinde XSS`, `Hash parametresi "${key}" riskli karakterler içeriyor.`, 'xss', 'medium', { param: key, value: truncate(value, 50) }, 'url');
                }
            }
        } catch (e) { console.error('URL Check Error:', e); }
    }

    // 2. DOM ANALYSIS (Static & Dynamic)
    function scanDOM(rootElement = document) {
        try {
            // Scripts & Event Handlers
            const scripts = rootElement.getElementsByTagName('script');
            const domPatterns = [/document\.write\(/, /innerHTML\s*=/, /outerHTML\s*=/, /document\.location\s*=/, /location\.href\s*=/];
            
            for (let script of scripts) {
                const content = script.textContent || script.innerText;
                if (!content) continue;
                domPatterns.forEach(pattern => {
                    if (pattern.test(content)) {
                        addVuln('dom_sink_' + Math.random().toString(36).substr(2, 5), 'Tehlikeli DOM Sink', 'Script içinde tehlikeli DOM manipülasyonu (sink) tespit edildi.', 'xss', 'medium', { snippet: extractSnippet(content, [pattern.source]) }, 'script');
                    }
                });
            }

            // Inline Handlers
            const all = rootElement.getElementsByTagName('*');
            for (let el of all) {
                for (let i = 0; i < el.attributes.length; i++) {
                    const attr = el.attributes[i];
                    if (/^on/i.test(attr.name) && attr.value) {
                        addVuln('inline_handler_' + Math.random().toString(36).substr(2, 5), 'Inline Event Handler', `Element <${el.tagName}> üzerinde inline handler (${attr.name}) bulundu.`, 'xss', 'low', { attr: attr.name, value: truncate(attr.value, 50) }, 'html');
                    }
                }
            }

            // Forms
            const forms = rootElement.getElementsByTagName('form');
            for (let i = 0; i < forms.length; i++) {
                const action = forms[i].getAttribute('action');
                const method = forms[i].getAttribute('method');
                
                if (action && (action.includes(window.location.pathname) || action === '#')) {
                    addVuln('form_reflected_' + i, 'Reflected XSS Riski (Form)', 'Form action mevcut sayfayı işaret ediyor.', 'xss', 'low', { formIndex: i }, 'form');
                }
                
                // Password over HTTP / GET
                const passInput = forms[i].querySelector('input[type="password"]');
                if (passInput) {
                    if (method && method.toLowerCase() === 'get') {
                        addVuln('pass_get_' + i, 'Şifre GET ile Gönderiliyor', 'Şifre alanı içeren form GET metodu kullanıyor.', 'transport', 'high', null, 'form');
                    }
                    if (window.location.protocol === 'http:') {
                        addVuln('pass_http_' + i, 'Şifre HTTP Üzerinden Gönderiliyor', 'Şifre alanı şifrelenmemiş bağlantıda.', 'transport', 'critical', null, 'form');
                    }
                }
            }
        } catch (e) { console.error('DOM Scan Error:', e); }
    }

    // 3. DYNAMIC DOM MONITORING (MutationObserver)
    function startDynamicAnalysis() {
        if (observer) return;
        observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1) { // ELEMENT_NODE
                            scanDOM(node); // Scan only the new node and its children
                        }
                    });
                }
            });
        });
        observer.observe(document.body, { childList: true, subtree: true });
        console.log('[Scanner] Dynamic DOM observer started.');
    }

    // 4. LIBRARY VULNERABILITY SCANNER
    function checkLibraries() {
        try {
            // jQuery
            if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
                const ver = window.jQuery.fn.jquery;
                if (ver.startsWith('1.') || ver.startsWith('2.')) {
                    addVuln('lib_jquery_old', `Eski jQuery Sürümü (${ver})`, 'Eski jQuery sürümleri bilinen XSS açıklarına sahip olabilir.', 'library', 'medium', { version: ver }, 'script');
                }
            }
            // Angular
            if (window.angular && window.angular.version) {
                addVuln('lib_angular', `AngularJS Tespit Edildi (${window.angular.version.full})`, 'Eski AngularJS sürümleri template injection açıklarına sahip olabilir.', 'library', 'info', { version: window.angular.version.full }, 'script');
            }
        } catch (e) { console.error('Lib Check Error:', e); }
    }

    // 5. STORAGE & COOKIE SECURITY
    function checkStorageAndCookies() {
        // Cookies
        if (document.cookie) {
            const cookies = document.cookie.split(';');
            cookies.forEach(c => {
                const [k, v] = c.trim().split('=');
                // HttpOnly check (if accessible via JS, it's not HttpOnly)
                addVuln('cookie_httponly_' + k, `HttpOnly Eksik: ${k}`, `Cookie JS tarafından okunabiliyor.`, 'cookie', 'medium', { cookie: k }, 'header');
                
                if (window.location.protocol === 'https:' && !c.includes('Secure') && !document.cookie.includes('Secure')) {
                     // Note: document.cookie doesn't show flags, but if we are in HTTPS and can read it, we can't be sure about Secure flag just from JS. 
                }
                if (/token|session|auth|key/i.test(k)) {
                    addVuln('cookie_sensitive_' + k, `Hassas Cookie: ${k}`, `Cookie ismi hassas veri çağrıştırıyor.`, 'cookie', 'high', { cookie: k }, 'header');
                }
            });
        }

        // LocalStorage
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (/token|auth|password|secret|key/i.test(k)) {
                    addVuln('ls_sensitive_' + k, `LocalStorage Hassas Veri: ${k}`, `LocalStorage içinde hassas anahtar bulundu.`, 'storage', 'medium', { key: k }, 'storage');
                }
            }
        } catch(e) {}
    }

    // 6. NETWORK MONITOR (XHR/Fetch Hook)
    function installNetworkHooks() {
        if (networkMonitorInstalled) return;
        networkMonitorInstalled = true;

        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._url = url;
            return originalOpen.apply(this, arguments);
        };

        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (this._url && /token=|api_key=|password=/i.test(this._url)) {
                addVuln('xhr_url_sensitive', 'XHR URL Hassas Veri', `XHR isteği URL'inde hassas veri: ${truncate(this._url, 50)}`, 'network', 'medium', { url: this._url }, 'network');
            }
            if (body && typeof body === 'string' && /password|token/i.test(body)) {
                 addVuln('xhr_body_sensitive', 'XHR Body Hassas Veri', `XHR isteği gövdesinde hassas veri.`, 'network', 'high', null, 'network');
            }
            return originalSend.apply(this, arguments);
        };

        const originalFetch = window.fetch;
        window.fetch = async function(input, init) {
            const url = (typeof input === 'string') ? input : input.url;
            if (/token=|api_key=|password=/i.test(url)) {
                addVuln('fetch_url_sensitive', 'Fetch URL Hassas Veri', `Fetch isteği URL'inde hassas veri: ${truncate(url, 50)}`, 'network', 'medium', { url }, 'network');
            }
            return originalFetch.apply(this, arguments);
        };
        console.log('[Scanner] Network hooks installed.');
    }

    // 3. LIBRARY ANALYSIS
    function checkLibraries() {
        try {
            // jQuery
            if (window.jQuery) {
                const ver = window.jQuery.fn.jquery;
                if (ver < '3.5.0') {
                    addVuln('lib_jquery_old', 'Eski jQuery Sürümü', `jQuery ${ver} kullanılıyor. Bilinen XSS zafiyetleri olabilir.`, 'library', 'medium', { version: ver }, 'script');
                }
            }
            // React, Vue, Angular detection often requires checking specific properties or devtools hooks
            // This is a basic check
            if (document.querySelector('[data-reactroot], [data-reactid]')) {
                 // React detected
            }
        } catch (e) {}
    }

    function checkStorageAndCookies() {
        // Cookies
        if (document.cookie) {
            const cookies = document.cookie.split(';');
            cookies.forEach(c => {
                if (!c.toLowerCase().includes('secure') && !window.location.protocol.includes('https')) {
                     // Client side can't easily see 'Secure' flag but can infer from protocol
                }
            });
        }
        // LocalStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const val = localStorage.getItem(key);
            if (/token|auth|password|key/i.test(key) || /eyJ/i.test(val)) { // JWT pattern
                addVuln('storage_sensitive_' + key, 'LocalStorage Hassas Veri', `LocalStorage'da hassas veri olabilir: ${key}`, 'storage', 'medium', { key, value: truncate(val, 20) }, 'storage');
            }
        }
    }

    // =========================================================================
    // AGENT OVERLAY & ORCHESTRATION
    // =========================================================================
    
    function createAgentOverlay() {
        if (document.getElementById('agent-overlay-root')) return;
        
        const overlay = document.createElement('div');
        overlay.id = 'agent-overlay-root';
        overlay.innerHTML = `
            <div class="agent-card">
                <div class="agent-spinner"></div>
                <div class="agent-title">Güvenlik Ajanı Çalışıyor</div>
                <div class="agent-status" id="agent-status-text">Sistem analiz ediliyor...</div>
                <div class="agent-log" id="agent-log-container"></div>
            </div>
        `;
        document.body.appendChild(overlay);
    }

    function updateAgentLog(message) {
        const container = document.getElementById('agent-log-container');
        const status = document.getElementById('agent-status-text');
        if (container && status) {
            const p = document.createElement('p');
            p.textContent = `> ${message}`;
            container.appendChild(p);
            container.scrollTop = container.scrollHeight;
            status.textContent = message;
        }
    }

    function removeAgentOverlay() {
        const overlay = document.getElementById('agent-overlay-root');
        if (overlay) overlay.remove();
    }

    async function runAgentScan(isAutoStart = false) {
        createAgentOverlay();
        vulnerabilities = []; // Reset
        
        try {
            if (isAutoStart) {
                updateAgentLog("Sayfa yeniden yüklendi. Ağ trafiği yakalandı.");
                await new Promise(r => setTimeout(r, 500));
            }

            // Step 1: Library Analysis
            updateAgentLog("Kütüphaneler ve Framework'ler taranıyor...");
            await new Promise(r => setTimeout(r, 800)); // Simulate work
            checkLibraries();
            updateAgentLog("Kütüphane analizi tamamlandı.");

            // Step 2: Network Analysis (Client-side hooks)
            updateAgentLog("İstemci tarafı ağ kancaları (Hooks) yerleştiriliyor...");
            installNetworkHooks(); 
            await new Promise(r => setTimeout(r, 500)); 

            // Step 3: DOM & Fuzzing
            updateAgentLog("DOM yapısı ve form girdileri analiz ediliyor...");
            checkURLParameters();
            scanDOM(document);
            checkStorageAndCookies();
            
            // CSP Check
            const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            if (cspMeta && (cspMeta.content.includes('unsafe-inline') || cspMeta.content.includes('unsafe-eval'))) {
                addVuln('csp_weak', 'Zayıf CSP (Meta)', 'CSP unsafe-inline/eval içeriyor.', 'csp', 'medium', { content: cspMeta.content }, 'header');
            }
            
            await new Promise(r => setTimeout(r, 1200)); // Simulate deep scan
            updateAgentLog("DOM analizi tamamlandı.");

            // Step 4: Finalizing
            updateAgentLog("Sonuçlar derleniyor ve Fuzzy Logic motoruna iletiliyor...");
            await new Promise(r => setTimeout(r, 1000));

            updateAgentLog("Tarama tamamlandı! Sonuçlar için eklentiyi açın.");
            await new Promise(r => setTimeout(r, 1500));

            removeAgentOverlay();
            
            // Send results to background
            chrome.runtime.sendMessage({ 
                action: 'scan_complete', 
                vulnerabilities: vulnerabilities 
            });

            return { vulnerabilities };

        } catch (e) {
            console.error(e);
            updateAgentLog("Hata oluştu: " + e.message);
            setTimeout(removeAgentOverlay, 2000);
            return { vulnerabilities, error: e.message };
        }
    }

    // Listen for messages
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'start_agent_scan') {
            runAgentScan().then(result => {
                sendResponse(result);
            });
            return true; // Async response
        }
        // Legacy support
        if (request.action === 'scanPage') {
            runAgentScan().then(result => {
                sendResponse(result);
            });
            return true;
        }
    });

    // Auto-Start Check (On Load)
    chrome.storage.local.get('scanState', (data) => {
        if (data.scanState && data.scanState.isScanning) {
            console.log("[Scanner] Auto-start detected from storage.");
            // Show overlay IMMEDIATELY before doing anything else
            createAgentOverlay();
            updateAgentLog("Tarama başlatılıyor...");
            updateAgentLog("Sayfa yeniden yüklendi, analiz devam ediyor.");
            
            // Small delay to ensure DOM is ready
            setTimeout(() => {
                runAgentScan(true);
            }, 500);
        }
    });

})();


