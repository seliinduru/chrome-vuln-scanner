// content.js - AYARLAR İLE ENTEGRE EDİLMİŞ, TAM VE NİHAİ VERSİYON

(function() {
    
    if (window.CONTENT_SCRIPT_RUNNING) {
        return; 
    }
    window.CONTENT_SCRIPT_RUNNING = true; 

    // =========================================================================
    // GLOBAL DEĞİŞKENLER VE VARSAYILAN AYARLAR
    // =========================================================================
    var vulnerabilities = []; 
    var networkMonitorInstalled = false;
    const defaultSettings = {
        vulnTypes: ['xss', 'sqli', 'csrf', 'cookie', 'storage', 'csp', 'network', 'transport', 'path-traversal']
    };

    // =========================================================================
    // YARDIMCI FONKSİYONLAR
    // =========================================================================
    function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
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
      for (const t of terms) {
        const idx = src.indexOf(t);
        if (idx >= 0) return src.slice(Math.max(0, idx-80), idx+200);
      }
      return src.slice(0,200);
    }

    function truncate(s, n) { 
      return s && s.length > n ? s.slice(0,n)+'...' : s; 
    }

    // =========================================================================
    // ANA TARAMA FONKSİYONU (AYARLARI OKUR)
    // =========================================================================
    async function scanPage() {
      vulnerabilities = [];

      try {
        const data = await chrome.storage.local.get('scannerSettings');
        const settings = data.scannerSettings || defaultSettings;
        const enabledChecks = settings.vulnTypes || [];

        console.log('Kullanılan tarama ayarları:', enabledChecks);

        if (enabledChecks.includes('xss') || enabledChecks.includes('sqli') || enabledChecks.includes('path-traversal')) {
            checkURLParameters(enabledChecks);
        }
        if (enabledChecks.includes('xss')) {
            checkForXSSVulnerabilities();
        }
        if (enabledChecks.includes('cookie') || enabledChecks.includes('csrf')) {
            checkCookieSecurity();
        }
        if (enabledChecks.includes('storage')) {
            checkStorageSecurity();
        }
        if (enabledChecks.includes('transport')) {
            checkPasswordFields();
        }
        if (enabledChecks.includes('csp')) {
            checkCSP();
        }
        if (enabledChecks.includes('network')) {
            installNetworkMonitor();
        }
        
      } catch (e) {
        console.error('scanPage hatası:', e);
      }
    }

    // =========================================================================
    // TÜM TARAMA FONKSİYONLARI
    // =========================================================================
    function checkURLParameters(enabledChecks) {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        for (const [key, value] of urlParams) {
          if (enabledChecks.includes('xss') && /<|>|"|'|javascript:|onerror|onload|onclick/i.test(value)) {
            addVuln('url_param_xss_' + key, `Potansiyel XSS riski: URL parametresi "${key}"`, `URL parametresi "${key}" HTML/JS karakterleri içeriyor.`, 'xss', 'high', { param: key, value: value.slice(0, 100) }, 'url');
          }
          if (enabledChecks.includes('sqli') && /'|"|--|;|or\s+1|union|select|insert|delete|drop/i.test(value)) {
            addVuln('url_param_sqli_' + key, `Potansiyel SQL Injection riski: URL parametresi "${key}"`, `URL parametresi "${key}" SQL karakterleri içeriyor.`, 'sqli', 'high', { param: key, value: value.slice(0, 100) }, 'url');
          }
          if (enabledChecks.includes('path-traversal') && /\.\.|\/\/|%2e%2e|\.\.\//i.test(value)) {
            addVuln('url_param_path_traversal_' + key, `Potansiyel Path Traversal riski: URL parametresi "${key}"`, `URL parametresi "${key}" path traversal karakterleri içeriyor.`, 'path-traversal', 'high', { param: key, value: value.slice(0, 100) }, 'url');
          }
        }
        const hashParams = new URLSearchParams(window.location.hash.slice(1));
        for (const [key, value] of hashParams) {
          if (enabledChecks.includes('xss') && /<|>|"|'|javascript:/i.test(value)) {
            addVuln('hash_param_xss_' + key, `Potansiyel XSS riski: Hash parametresi "${key}"`, `URL hash parametresi "${key}" HTML karakterleri içeriyor.`, 'xss', 'medium', { param: key, value: value.slice(0, 100) }, 'url');
          }
        }
      } catch (e) { console.error('checkURLParameters hatası:', e); }
    }

    function checkForXSSVulnerabilities() {
      const pageSource = document.documentElement.outerHTML || '';
      if (/\.\s*innerHTML\s*=?|innerHTML\s*=/.test(pageSource) || pageSource.includes('insertAdjacentHTML') || /outerHTML\s*=/.test(pageSource)) {
        const matches = (pageSource.match(/innerHTML|insertAdjacentHTML|outerHTML/g) || []).length;
        addVuln('xss_dom_write', 'Potansiyel XSS (DOM yazma kullanımı)', 'innerHTML/insertAdjacentHTML/outerHTML gibi DOM yazma çağrıları tespit edildi.', 'xss', 'high', { snippet: extractSnippet(pageSource, ['innerHTML','insertAdjacentHTML','outerHTML']) }, 'script', matches, true);
      }
      if (/document\.write\s*\(|document\.writeln\s*\(/.test(pageSource)) {
        const matches = (pageSource.match(/document\.write|document\.writeln/g) || []).length;
        addVuln('xss_document_write', 'Potansiyel XSS (document.write)', 'document.write veya document.writeln kullanımı bulundu.', 'xss', 'medium', null, 'script', matches, true);
      }
      if (/\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(pageSource)) {
        const matches = (pageSource.match(/eval|Function|setTimeout|setInterval/g) || []).length;
        addVuln('xss_eval_like', 'Riskli dinamik kod çalıştırma', 'eval/new Function veya setTimeout/setInterval(string) görünüyor.', 'xss', 'high', null, 'script', matches, true);
      }
      const all = document.getElementsByTagName('*');
      for (let el of all) {
        for (let i=0; i < el.attributes.length; i++) {
          const a = el.attributes[i];
          if (/^on/i.test(a.name) && a.value && a.value.trim() !== '') {
            addVuln('xss_inline_handler', 'Inline event handler tespit edildi', `Element ${el.tagName} üzerinde inline handler ${a.name} bulundu.`, 'xss', 'medium', { attr: a.name, value: a.value.slice(0,300) }, 'html', 1, false, true);
          }
        }
      }
      const anchors = document.querySelectorAll('a[href^="javascript:"]');
      if (anchors.length > 0) {
        addVuln('xss_js_url', 'javascript: URL tespit edildi', `${anchors.length} adet javascript: link bulundu.`, 'xss', 'low', null, 'html', anchors.length);
      }
    }

    function checkCookieSecurity() {
      try {
        if (window.location.protocol !== 'https:') {
          addVuln('page_insecure_transport', 'Sayfa HTTP (HTTPS değil)', 'Sayfa HTTPS üzerinden değil. Tüm veriler zayıf bir bağlantı üzerinden gidiyor olabilir.', 'transport', 'high', null, 'network');
        }
        const raw = document.cookie || '';
        if (raw) {
          const sensitiveKeys = ['token','session','auth','passwd','password','jwt','access','sid'];
          const pairs = raw.split(';').map(s=>s.trim());
          for (let p of pairs) {
            const [k,v] = p.split('=').map(x=>x && x.trim());
            if (!k) continue;
            const lower = k.toLowerCase();
            for (let s of sensitiveKeys) {
              if (lower.includes(s)) {
                addVuln('cookie_sensitive', 'Hassas bilgi içeren cookie', `document.cookie içinde "${k}" anahtarı bulundu.`, 'cookie', 'high', { cookie: k }, 'dom');
              }
            }
            if (!p.includes('Secure') && window.location.protocol === 'https:') {
              addVuln('cookie_no_secure', 'Cookie Secure bayrağı yok', `"${k}" cookie'si Secure bayrağına sahip değil.`, 'cookie', 'medium', { cookie: k }, 'dom');
            }
            if (!p.includes('SameSite')) {
              addVuln('cookie_no_samesite', 'Cookie SameSite bayrağı yok', `"${k}" cookie'si SameSite bayrağına sahip değil. CSRF riskini artırır.`, 'csrf', 'medium', { cookie: k }, 'dom');
            }
          }
        }
      } catch (e) { console.error('checkCookieSecurity hatası:', e); }
    }

    function checkStorageSecurity() {
      try {
        const sensitiveKeys = ['token', 'session', 'auth', 'passwd', 'password', 'jwt', 'access', 'sid'];
        const check = (storage, name) => {
          for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            const lowerKey = key.toLowerCase();
            for (let s of sensitiveKeys) {
              if (lowerKey.includes(s)) {
                addVuln(`storage_sensitive_${name}_${key}`, `Hassas veri ${name} Storage'da`, `${name} Storage içinde "${key}" anahtarında hassas veri bulundu.`, 'storage', 'high', { key, storage: name }, 'dom');
              }
            }
          }
        };
        check(localStorage, 'Local');
        check(sessionStorage, 'Session');
      } catch (e) { console.warn('Storage security check skipped', e); }
    }

    function checkPasswordFields() {
      try {
        const passwordFields = document.querySelectorAll('input[type="password"]');
        passwordFields.forEach((field, index) => {
          const form = field.closest('form');
          if (form) {
            const formAction = form.action;
            if (formAction && String(formAction).startsWith('http://')) {
              addVuln(`form_insecure_password_${index}`, `Şifre Formu Güvensiz Bağlantı`, `Şifre formu HTTP üzerinden gönderiliyor.`, 'transport', 'critical', { formAction }, 'form');
            } else if (window.location.protocol === 'http:') {
              addVuln(`form_insecure_password_${index}_page`, `Şifre Formu Güvensiz Sayfada`, `Şifre formu HTTP sayfasında kullanılıyor.`, 'transport', 'critical', { page: window.location.href }, 'form');
            }
          }
        });
      } catch (e) { console.error('checkPasswordFields hatası:', e); }
    }

    function checkCSP() {
      try {
        const policy = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content;
        if (!policy) {
          addVuln('csp_missing', 'Content Security Policy (CSP) eksik', 'Sayfa bir CSP başlığı içermiyor. Bu, XSS etkilerini artırabilir.', 'csp', 'high', null, 'header');
          return;
        }
        ['unsafe-inline', 'unsafe-eval', '*'].forEach(dir => {
          if (policy.includes(dir)) {
            addVuln(`csp_insecure_${dir.replace('*', 'wildcard')}`, `Zayıf CSP Direktifi: ${dir}`, `CSP politikası içerisinde "${dir}" kullanılıyor.`, 'csp', 'medium', { policy, directive: dir }, 'header');
          }
        });
      } catch (e) { console.error('checkCSP hatası:', e); }
    }

    function installNetworkMonitor() {
      if (networkMonitorInstalled) return;
      const originalFetch = window.fetch;
      window.fetch = function(...args) {
        const [resource, config] = args;
        inspectOutgoingRequest(String(resource), config);
        return originalFetch.apply(this, args);
      };
      networkMonitorInstalled = true;
    }

    function inspectOutgoingRequest(url, config) {
      try {
        if (/(password|token|jwt|session)/i.test(url)) {
          addVuln('outgoing_sensitive_url', 'Giden istek URL\'sinde hassas veri', `URL içinde hassas ifadeler bulundu: ${truncate(url, 120)}`, 'network', 'high');
        }
        const body = config?.body;
        if (body) {
            const s = typeof body === 'string' ? body : JSON.stringify(body) || '';
            if (/password=|passwd=|token|jwt|access_token/i.test(s)) {
              addVuln('outgoing_sensitive_body', 'Giden istek gövdesinde hassas veri', `İstek gövdesinde hassas ifadeler bulundu: ${truncate(s,300)}`, 'network', 'high');
            }
        }
      } catch (e) { console.error('inspectOutgoingRequest hatası:', e); }
    }

    // =========================================================================
    // MESAJ DİNLEYİCİSİ
    // =========================================================================
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'scanPage') {
        scanPage().then(() => {
            sendResponse({ vulnerabilities });
        });
        return true;
      }
      if (request.action === 'checkStatus') {
        sendResponse({ status: 'ready' });
        return true;
      }
    });

})();