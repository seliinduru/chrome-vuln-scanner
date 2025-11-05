// content.js
// Bu dosya sayfa üzerinde koşar ve çok sayıda kontrol yapar.
// NOT: Riskli override/patch'ler minimum tutuldu, sadece request-monitoring için fetch/XHR patch yapılır.

let vulnerabilities = [];

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
    // sonuçları background'a gönder (scanBtn'den başlatılırsa, popup'a da gönderilir)
    chrome.runtime.sendMessage({ action: "vulnerabilitiesDetected", vulnerabilities });
  } catch (e) {
    console.error('scanPage error', e);
  }
}

// 1) URL Parametreleri Güvenlik Kontrolleri
function checkURLParameters() {
  try {
    const url = new URL(window.location.href);
    url.searchParams.forEach((value, name) => {
      // Basit XSS kontrolü (Sadece eğitim amaçlı)
      if (/<script|<img|<svg/i.test(value) && name !== 'q') { 
        addVuln('url_xss_potential', `URL Parametresinde Potansiyel XSS`, `Parametre: ${name}, Değer: ${truncate(value, 150)}`, 'xss', 'high', value, 'url', 1, false, false, false);
      }
    });
  } catch (e) {}
}

// 2) XSS Kontrolleri (DOM tabanlı)
function checkForXSSVulnerabilities() {
  // Basit DOM-XSS sink kontrolü: innerHTML, document.write vb.
  // Bu, tarayıcının yerleşik XSS Auditor/Cleaner'larını atlatmak için daha derin analiz gerektirir.
  // Şimdilik sadece örnek bir XSS zafiyetini simüle edelim
  if (window.location.hash.includes('xss=true')) {
    addVuln('dom_xss_sim', 'Simüle Edilmiş DOM XSS', 'URL Hash içinde XSS kanıtı bulundu.', 'xss', 'high', window.location.hash, 'script', 1, false, false, false);
  }
}

// 3) Cookie Güvenliği Kontrolleri
function checkCookieSecurity() {
  document.cookie.split(';').forEach(cookie => {
    cookie = cookie.trim();
    if (!cookie) return;

    const [name, value] = cookie.split('=');
    
    // Güvenli (Secure) bayrağı eksik
    if (window.location.protocol === 'https:' && !cookie.includes('Secure')) {
      addVuln('cookie_insecure', `Güvenli Olmayan Çerez (Secure Flag Eksik)`, `Çerez adı: ${name}. HTTPS üzerinde Secure flag'ı yok.`, 'cookie', 'medium', cookie, 'header', 1, true, false, false);
    }
    
    // HttpOnly bayrağı eksik (XSS riskini artırır)
    if (!cookie.includes('HttpOnly')) {
      addVuln('cookie_httponly_missing', `HttpOnly Bayrağı Eksik`, `Çerez adı: ${name}. XSS saldırılarına karşı savunmasız.`, 'cookie', 'high', cookie, 'header', 1, true, false, false);
    }
    
    // Hassas veri içeren çerezler (Session ID vb.)
    if (/session|jwt|token/i.test(name)) {
      addVuln('cookie_sensitive', `Hassas Veri İçeren Çerez`, `Çerez adı: ${name}. Session/Token/JWT içeriyor.`, 'cookie', 'medium', cookie, 'header', 1, true, false, false);
    }
  });
}

// 4) HTML5 Depolama Güvenliği Kontrolleri
function checkStorageSecurity() {
  // localStorage Kontrolü
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);
    if (/token|jwt|session|password/i.test(key) || /token|jwt|password/i.test(value)) {
      addVuln('local_storage_sensitive', `localStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'medium', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }

  // sessionStorage Kontrolü (Aynı kontroller uygulanır)
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    const value = sessionStorage.getItem(key);
    if (/token|jwt|session|password/i.test(key) || /token|jwt|password/i.test(value)) {
      addVuln('session_storage_sensitive', `sessionStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'low', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }
}

// 5) Şifre Alanı Güvenliği Kontrolleri
function checkPasswordFields() {
  document.querySelectorAll('input[type="password"]').forEach(input => {
    // Autocomplete eksik (Tarayıcının şifre kaydetme uyarısını engeller)
    if (input.getAttribute('autocomplete') === 'off') {
      addVuln('password_autocomplete_off', 'Şifre Alanında Autocomplete Kapatılmış', 'Tarayıcının şifre yönetimi özelliğini devre dışı bırakıyor.', 'csrf', 'low', null, 'form', 1, false, false, false);
    }
  });
}

// 6) İçerik Güvenlik Politikası (CSP) Kontrolleri
function checkCSP() {
  // Content Security Policy (CSP) kontrolü, background.js'ten veya başlıklar üzerinden yapılmalıdır.
  // Content script bu bilgiye doğrudan erişemez. Bu sadece simülasyon.
  
  // Basit check: Eğer sayfa HTTPS değilse ve CSP yoksa
  if (window.location.protocol !== 'https:') {
    addVuln('page_not_https', 'Sayfa Güvenli Değil (HTTPS Eksik)', 'Sayfa HTTPS protokolü üzerinden yüklenmemiş.', 'network', 'high', null, 'header', 1, true, false, false);
  }

  // CSP başlığını kontrol etmenin content script'ten basit bir yolu yok, 
  // bu yüzden bunu background.js'in webRequest API'ı üzerinden yapmalısınız.
  // Burada sadece bir placeholder olarak ekliyoruz:
  addVuln('csp_sim', 'CSP Kontrolü Gerekiyor', 'Content Security Policy (CSP) varlığı kontrol edilmeli.', 'csp', 'medium');
}


// 7) Network Monitör Kurulumu (fetch/XHR override)
let networkMonitorInstalled = false;
function installNetworkMonitor() {
  if (networkMonitorInstalled) return;

  // XHR Override
  const originalXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new originalXHR(arguments);
    const originalSend = xhr.send;
    xhr.send = function(body) {
      inspectOutgoingRequest(xhr._method, xhr._url, xhr.getAllRequestHeaders(), body);
      return originalSend.apply(this, arguments);
    };
    const originalOpen = xhr.open;
    xhr.open = function(method, url) {
      xhr._method = method;
      xhr._url = url;
      return originalOpen.apply(this, arguments);
    };
    return xhr;
  };
  
  // Fetch Override
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const method = init && init.method || 'GET';
    const body = init && init.body || null;
    const headers = init && init.headers || {};
    // Fetch'te başlıkları yakalamak zor olduğundan, body'yi kontrol etmekle yetiniyoruz
    inspectOutgoingRequest(method, input, headers, body);
    return originalFetch.apply(this, arguments);
  };

  networkMonitorInstalled = true;
}

// Giden istekleri incele
function inspectOutgoingRequest(method, url, headers, body) {
  try {
    // Hassas verilerin gövdede gönderilmesini kontrol et (sadece password/token gibi)
    if (body) {
      try {
        const s = typeof body === 'string' ? body : (JSON && JSON.stringify(body)) || '';
        if (/password=|passwd=|token|jwt|access_token/i.test(s)) {
          addVuln('outgoing_sensitive_body', 'Outgoing istek gövdesinde hassas veri', `İstek gövdesinde password/token gibi ifadeler bulundu: ${truncate(s,300)}`, 'network', 'high', s.slice(0, 300), 'body', 1, true, false, false);
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('inspectOutgoingRequest error', e);
  }
}

// Utility helpers
function extractSnippet(src, terms) {
  for (const t of terms) {
    const idx = src.indexOf(t);
    if (idx >= 0) return src.slice(Math.max(0, idx-80), idx+200);
  }
  return src.slice(0,200);
}
function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+'...' : s; }

// Popup veya background'tan gelen komutları dinle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage') {
    scanPage();
    // async: sonuçları popup'a ilet
    sendResponse({ vulnerabilities });
    return true; 
  }

  // Eklendi: Content script'in yüklü olup olmadığını kontrol et (popup.js'teki yarış durumunu çözer)
  if (request.action === 'checkStatus') {
    sendResponse({ status: 'ready' });
    return true;
  }
});