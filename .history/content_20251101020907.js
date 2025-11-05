// content.js
// Bu dosya sayfa üzerinde koşar ve çok sayıda kontrol yapar.
// NOT: Riskli override/patch'ler minimum tutuldu, sadece request-monitoring için fetch/XHR patch yapılır.

let vulnerabilities = [];
let networkMonitorInstalled = false; // Ağ monitörünün kurulu olup olmadığını takip et

// Helper: push vulnerability with scoring inputs (benzersiz ID)
function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
  vulnerabilities.push({ 
    id, 
    title, 
    details, 
    type, 
    severity, 
    evidence,
    // Scoring inputs
    location: location || 'inline',
    matchCount: matchCount || 1,
    contextFactors: contextFactors || false,
    userInteractionRequired: userInteraction || false,
    isMaliciousURL: externalFactors || false
  });
}

// Helper: Kodu bul ve snippet al
function extractSnippet(src, terms) {
  for (const t of terms) {
    const idx = src.indexOf(t);
    if (idx >= 0) return src.slice(Math.max(0, idx-80), idx+200);
  }
  return src.slice(0,200);
}

// Helper: Stringi kısalt
function truncate(s, n) { 
  return s && s.length > n ? s.slice(0,n)+'...' : s; 
}

// Ana tarama fonksiyonu
function scanPage() {
  vulnerabilities = []; // temizle
  try {
    checkURLParameters(); // URL param'leri tara
    checkForXSSVulnerabilities();
    checkCookieSecurity();
    checkStorageSecurity();
    checkPasswordFields();
    checkCSP();
    installNetworkMonitor(); // outgoing istekleri izle
    // sonuçları background'a gönder
    chrome.runtime.sendMessage({ action: "vulnerabilitiesDetected", vulnerabilities });
  } catch (e) {
    console.error('scanPage error', e);
  }
}

// 1) URL Parametreleri Güvenlik Kontrolleri
function checkURLParameters() {
  try {
    const url = window.location.href;
    const urlParams = new URLSearchParams(window.location.search);
    
    for (const [key, value] of urlParams) {
      if (/<|>|"|'|javascript:|onerror|onload|onclick/i.test(value)) {
        addVuln(
          'url_param_xss_' + key,
          `Potansiyel XSS riski: URL parametresi "${key}"`,
          `URL parametresi "${key}=${value.slice(0, 50)}" HTML/JS karakterleri içeriyor. Eğer bu parametre DOM'a yazılırsa XSS riski vardır.`,
          'xss',
          'high',
          { paramName: key, paramValue: value.slice(0, 100) },
          'url',
          1,
          false,
          false,
          true
        );
      }
      
      if (/'|"|--|;|or\s+1|union|select|insert|delete|drop/i.test(value)) {
        addVuln(
          'url_param_sqli_' + key,
          `Potansiyel SQL Injection riski: URL parametresi "${key}"`,
          `URL parametresi "${key}=${value.slice(0, 50)}" SQL karakterleri içeriyor. Server-side query'lerde kullanılıyorsa SQLi riski vardır.`,
          'sql',
          'high',
          { paramName: key, paramValue: value.slice(0, 100) },
          'url',
          1,
          false,
          false,
          true
        );
      }
      
      if (/\.\.|\/\/|%2e%2e|\.\.\//i.test(value)) {
        addVuln(
          'url_param_path_traversal_' + key,
          `Potansiyel Path Traversal riski: URL parametresi "${key}"`,
          `URL parametresi "${key}=" path traversal karakterleri içeriyor (../ veya //). Dosya erişim kontrolünü atlamak için kullanılabilir.`,
          'path-traversal',
          'high',
          { paramName: key, paramValue: value.slice(0, 100) },
          'url',
          1,
          false,
          false,
          true
        );
      }
    }
    
    const hashParams = new URLSearchParams(window.location.hash.slice(1));
    for (const [key, value] of hashParams) {
      if (/<|>|"|'|javascript:/i.test(value)) {
        addVuln(
          'hash_param_xss_' + key,
          `Potansiyel XSS riski: Hash parametresi "${key}"`,
          `URL hash parametresi "${key}=${value.slice(0, 50)}" HTML karakterleri içeriyor.`,
          'xss',
          'medium',
          { paramName: key, paramValue: value.slice(0, 100) },
          'url',
          1,
          false,
          false,
          true
        );
      }
    }
  } catch (e) {
    console.error('checkURLParameters error', e);
  }
}

// 2) XSS kontrolleri (kod arama + DOM tarama)
function checkForXSSVulnerabilities() {
  const pageSource = document.documentElement.outerHTML || '';

  if (/\.\s*innerHTML\s*=?|innerHTML\s*=/.test(pageSource) || pageSource.includes('insertAdjacentHTML') || /outerHTML\s*=/.test(pageSource)) {
    const matches = (pageSource.match(/innerHTML|insertAdjacentHTML|outerHTML/g) || []).length;
    addVuln('xss_dom_write', 'Potansiyel XSS (DOM yazma kullanımı)', 'innerHTML/insertAdjacentHTML/outerHTML gibi DOM yazma çağrıları tespit edildi. Kullanıcı girdisiyle birlikte kullanılıyorsa XSS riski vardır.', 'xss', 'high', { snippet: extractSnippet(pageSource, ['innerHTML','insertAdjacentHTML','outerHTML']) }, 'script', matches, true);
  }

  if (/document\.write\s*\(|document\.writeln\s*\(/.test(pageSource)) {
    const matches = (pageSource.match(/document\.write|document\.writeln/g) || []).length;
    addVuln('xss_document_write', 'Potansiyel XSS (document.write)', 'document.write veya document.writeln kullanımı bulundu. Dinamik içerik yazarken dikkatli olun.', 'xss', 'medium', null, 'script', matches, true);
  }

  if (/\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(pageSource)) {
    const matches = (pageSource.match(/eval|Function|setTimeout|setInterval/g) || []).length;
    addVuln('xss_eval_like', 'Riskli dinamik kod çalıştırma', 'eval/new Function veya setTimeout/setInterval(string) görünüyor. Tüm kullanıcı girdileri kontrol edilmeli.', 'xss', 'high', null, 'script', matches, true);
  }

  const all = document.getElementsByTagName('*');
  let handlerCount = 0;
  for (let el of all) {
    for (let i=0;i<el.attributes.length;i++) {
      const a = el.attributes[i];
      if (/^on/i.test(a.name) && a.value && a.value.trim() !== '') {
        handlerCount++;
        addVuln('xss_inline_handler', 'Inline event handler tespit edildi', `Element ${el.tagName} üzerinde inline handler ${a.name}="${a.value.slice(0,120)}" bulundu.`, 'xss', 'medium', { attr: a.name, value: a.value.slice(0,300) }, 'html', 1, false, true);
      }
    }
  }

  const anchors = document.querySelectorAll('a[href^="javascript:"]');
  if (anchors.length > 0) {
    addVuln('xss_js_url', 'javascript: URL tespit edildi', `${anchors.length} adet javascript: link bulundu. Bunlar XSS için tehlikeli olabilir.`, 'xss', 'low', null, 'html', anchors.length);
  }

  const scripts = document.querySelectorAll('script');
  scripts.forEach(s => {
    const content = s.textContent || '';
    if (content && (/\beval\s*\(|new\s+Function\s*\(|document\.write|innerHTML|insertAdjacentHTML/.test(content))) {
      addVuln('xss_inline_script', 'Inline script içinde riskli kullanım', 'Bir <script> içinde eval/innerHTML/document.write/insertAdjacentHTML vb. kullanımı tespit edildi.', 'xss', 'high', { snippet: content.slice(0,300) }, 'script', 1, true);
    }
  });

  if (/\blocation\.search\b|\blocation\.hash\b/.test(pageSource)) {
    const matches = (pageSource.match(/location\.search|location\.hash/g) || []).length;
    addVuln('xss_source_param', 'URL parametreleri kullanımı', 'Kod içinde location.search veya location.hash referansı bulundu. Eğer bu veriler sanitasyon olmadan DOM\'a yazılıyorsa XSS riski vardır.', 'xss', 'medium', null, 'script', matches, true);
  }

  if (/createElement\s*\(\s*['"`]script['"`]\s*\)/.test(pageSource) && /\.textContent\s*=/.test(pageSource)) {
    addVuln('xss_dynamic_script', 'Dinamik script oluşturma tespit edildi', 'createElement("script") ile script oluşturulup textContent atanmışsa kötü niyetli kod eklenebilir.', 'xss', 'high');
  }
}

// 3) Cookie güvenliği (client-side kontroller)
function checkCookieSecurity() {
  try {
    if (window.location.protocol !== 'https:') {
      addVuln('page_insecure_transport', 'Sayfa HTTP (HTTPS değil)', 'Sayfa HTTPS üzerinden değil. Tüm veriler zayıf bir bağlantı üzerinden gidiyor olabilir.', 'transport', 'high', null, 'network', 1, false, false, true);
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
            addVuln('cookie_sensitive', 'Hassas bilgi içeren cookie', `document.cookie içinde "${k}" benzeri bir anahtar bulundu. Bu cookie client-side erişilebilir olabilir.`, 'cookie', 'high', { cookie: k }, 'dom', 1, true, false);
          }
        }

        // SameSite ve Secure kontrolü (sadece client-side görülebilenler için)
        if (!p.includes('Secure') && window.location.protocol === 'https:') {
          addVuln('cookie_no_secure', 'Cookie Secure bayrağı yok', `"${k}" cookie'si Secure bayrağına sahip değil. HTTP üzerinden de gönderilebilir (ancak şu an HTTPS'deyiz).`, 'cookie', 'medium', { cookie: k }, 'dom');
        }
        if (!p.includes('SameSite')) {
          addVuln('cookie_no_samesite', 'Cookie SameSite bayrağı yok', `"${k}" cookie'si SameSite bayrağına sahip değil. CSRF riskini artırır.`, 'csrf', 'medium', { cookie: k }, 'dom');
        }
      }
    }
    // HttpOnly kontrolü client-side yapılamaz. Bu bir sunucu tarafı testi olmalıdır.
  } catch (e) {
    console.error('checkCookieSecurity error', e);
  }
}

// 4) Local/Session Storage kontrolleri
function checkStorageSecurity() {
  try {
    const sensitiveKeys = ['token', 'session', 'auth', 'passwd', 'password', 'jwt', 'access', 'sid'];
    
    const checkStorage = (storage, name) => {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        const value = storage.getItem(key);
        
        const lowerKey = key.toLowerCase();
        
        for (let s of sensitiveKeys) {
          if (lowerKey.includes(s) || (value && typeof value === 'string' && value.length > 30 && lowerKey.includes('data'))) {
            addVuln(`storage_sensitive_${name}_${key}`, `Hassas veri ${name} Storage'da`, `${name} Storage içinde "${key}" anahtarında hassas veri bulunuyor. XSS durumunda çalınabilir.`, 'storage', 'high', { key, storage: name, value: truncate(value, 100) }, 'dom', 1, true);
          }
        }
      }
    };

    checkStorage(localStorage, 'Local');
    checkStorage(sessionStorage, 'Session');

  } catch (e) {
    // Storage'a erişim engellendiyse
    console.warn('Storage security check skipped (Access Denied)', e);
  }
}

// 5) Şifre alanı kontrolleri
function checkPasswordFields() {
  try {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach((field, index) => {
      const form = field.closest('form');
      if (form) {
        // Form HTTPS üzerinden gönderilmiyor
        if (form.action && form.action.startsWith('http://')) {
          addVuln(`form_insecure_password_${index}`, `Şifre Formu Güvensiz Bağlantı`, `Şifre formu HTTP üzerinden gönderiliyor: ${form.action.slice(0, 80)}`, 'transport', 'critical', { formAction: form.action }, 'form');
        }
      }
    });

  } catch (e) {
    console.error('checkPasswordFields error', e);
  }
}

// 6) Content Security Policy (CSP) kontrolü
function checkCSP() {
  try {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    const cspHeader = document.querySelector('meta[http-equiv="X-Content-Security-Policy" i]'); // Eski/Fallback

    const policy = cspMeta?.content || cspHeader?.content;

    if (!policy) {
      addVuln('csp_missing', 'Content Security Policy (CSP) eksik', 'Sayfa herhangi bir Content Security Policy (CSP) başlığı içermiyor. Bu, XSS etkilerini artırabilir.', 'csp', 'high', null, 'header');
      return;
    }

    // Güvenlik zafiyeti yaratan direktifleri kontrol et
    const insecureDirectives = [
      'unsafe-inline',
      'unsafe-eval',
      '*'
    ];
    
    insecureDirectives.forEach(directive => {
      const regex = new RegExp(directive, 'i');
      if (regex.test(policy) && !policy.includes('nonce') && !policy.includes('hash')) {
        addVuln(
          `csp_insecure_${directive.replace('*', 'wildcard')}`,
          `Zayıf CSP Direktifi: ${directive}`,
          `CSP politikası içerisinde "${directive}" kullanılıyor. Bu, XSS saldırılarının başarı şansını artırır.`,
          'csp',
          'medium',
          { policy, directive },
          'header'
        );
      }
    });

  } catch (e) {
    console.error('checkCSP error', e);
  }
}

// 7) Ağ Monitörü (Patching fetch ve XMLHttpRequest)
function installNetworkMonitor() {
  if (networkMonitorInstalled) return;

  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    const [resource, config] = args;
    inspectOutgoingRequest(resource, config);
    return originalFetch.apply(this, args);
  };
  
  // (XHR patching de eklenebilir, ancak fetch daha modern olduğu için şimdilik yeterli)

  networkMonitorInstalled = true;
}

function inspectOutgoingRequest(url, config) {
  try {
    // URL'de hassas veri kontrolü
    if (/(password|token|jwt|session)/i.test(url)) {
      addVuln('outgoing_sensitive_url', 'Outgoing istek URL\'sinde hassas veri', `URL içinde password/token gibi ifadeler bulundu: ${truncate(url, 120)}`, 'network', 'high');
    }

    // Config (Header/Body) kontrolü
    const headers = config?.headers;
    const body = config?.body;

    // Header'da hassas veri kontrolü
    if (headers) {
      const authHeader = (headers['Authorization'] || headers['authorization'] || '').toLowerCase();
      if (authHeader.includes('bearer') || authHeader.includes('token')) {
         addVuln('outgoing_auth_header', 'Authorization Headerı bulundu', `Authorization headerı tespit edildi. Bilgi ifşası riskini azaltmak için HttpOnly cookie kullanın.`, 'network', 'medium');
      }
    }

    // Body'de hassas veri kontrolü (Şifre/Token)
    if (body) {
      try {
        const s = typeof body === 'string' ? body : (JSON && JSON.stringify(body)) || '';
        if (/password=|passwd=|token|jwt|access_token/i.test(s)) {
          addVuln('outgoing_sensitive_body', 'Outgoing istek gövdesinde hassas veri', `İstek gövdesinde password/token gibi ifadeler bulundu: ${truncate(s,300)}`, 'network', 'high');
        }
      } catch (e) {}