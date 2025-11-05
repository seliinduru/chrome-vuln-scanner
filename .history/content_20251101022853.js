// content.js
// Bu dosya sayfa üzerinde koşar ve güvenlik kontrolleri yapar.

let vulnerabilities = []; // Global olarak tanımlandı

// Helper: push vulnerability with scoring inputs (benzersiz ID)
function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
  // HATA ÇÖZÜMÜ: vulnerabilities'in bir array olduğundan emin ol (tanımlama sorunu için önlem)
  if (!Array.isArray(vulnerabilities)) {
    vulnerabilities = []; 
  }
  
  vulnerabilities.push({ 
    id, 
    title: title || 'Bilinmeyen Açık', // Null kontrolü
    details: details || 'Detay yok.', // Null kontrolü
    type: type || 'other', // Null kontrolü
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
  vulnerabilities = []; // Her taramada sıfırla (HATA ÇÖZÜMÜ)
  try {
    checkURLParameters(); 
    checkForXSSVulnerabilities();
    checkCookieSecurity();
    checkStorageSecurity();
    checkPasswordFields();
    checkCSP();
    installNetworkMonitor(); 
    // sonuçları background'a gönder (scanBtn'den başlatılırsa, popup'a da gönderilir)
    chrome.runtime.sendMessage({ action: "vulnerabilitiesDetected", vulnerabilities });
  } catch (e) {
    console.error('scanPage error', e);
  }
}

// ... (Kalan tüm check fonksiyonları aynı kalır: checkURLParameters, checkForXSSVulnerabilities, checkCookieSecurity, vb.)

// 1) URL Parametreleri Güvenlik Kontrolleri (Örnekten kod: Parametreler eklendi)
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

// 2) XSS Kontrolleri (DOM tabanlı) (Örnekten kod)
function checkForXSSVulnerabilities() {
  if (window.location.hash.includes('xss=true')) {
    addVuln('dom_xss_sim', 'Simüle Edilmiş DOM XSS', 'URL Hash içinde XSS kanıtı bulundu.', 'xss', 'high', window.location.hash, 'script', 1, false, false, false);
  }
}

// 3) Cookie Güvenliği Kontrolleri (Örnekten kod)
function checkCookieSecurity() {
  document.cookie.split(';').forEach(cookie => {
    cookie = cookie.trim();
    if (!cookie) return;

    const [name, value] = cookie.split('=');
    
    if (window.location.protocol === 'https:' && !cookie.includes('Secure')) {
      addVuln('cookie_insecure', `Güvenli Olmayan Çerez (Secure Flag Eksik)`, `Çerez adı: ${name}. HTTPS üzerinde Secure flag'ı yok.`, 'cookie', 'medium', cookie, 'header', 1, true, false, false);
    }
    
    if (!cookie.includes('HttpOnly')) {
      addVuln('cookie_httponly_missing', `HttpOnly Bayrağı Eksik`, `Çerez adı: ${name}. XSS saldırılarına karşı savunmasız.`, 'cookie', 'high', cookie, 'header', 1, true, false, false);
    }
    
    if (/session|jwt|token/i.test(name)) {
      addVuln('cookie_sensitive', `Hassas Veri İçeren Çerez`, `Çerez adı: ${name}. Session/Token/JWT içeriyor.`, 'cookie', 'medium', cookie, 'header', 1, true, false, false);
    }
  });
}

// 4) HTML5 Depolama Güvenliği Kontrolleri (Örnekten kod)
function checkStorageSecurity() {
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);
    if (/token|jwt|session|password/i.test(key) || /token|jwt|password/i.test(value)) {
      addVuln('local_storage_sensitive', `localStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'medium', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }

  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    const value = sessionStorage.getItem(key);
    if (/token|jwt|session|password/i.test(key) || /token|jwt|password/i.test(value)) {
      addVuln('session_storage_sensitive', `sessionStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'low', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }
}

// 5) Şifre Alanı Güvenliği Kontrolleri (Örnekten kod)
function checkPasswordFields() {
  document.querySelectorAll('input[type="password"]').forEach(input => {
    if (input.getAttribute('autocomplete') === 'off') {
      addVuln('password_autocomplete_off', 'Şifre Alanında Autocomplete Kapatılmış', 'Tarayıcının şifre yönetimi özelliğini devre dışı bırakıyor.', 'csrf', 'low', null, 'form', 1, false, false, false);
    }
  });
}

// 6) İçerik Güvenlik Politikası (CSP) Kontrolleri (Örnekten kod)
function checkCSP() {
  if (window.location.protocol !== 'https:') {
    addVuln('page_not_https', 'Sayfa Güvenli Değil (HTTPS Eksik)', 'Sayfa HTTPS protokolü üzerinden yüklenmemiş.', 'network', 'high', null, 'header', 1, true, false, false);
  }

  addVuln('csp_sim', 'CSP Kontrolü Gerekiyor', 'Content Security Policy (CSP) varlığı kontrol edilmeli.', 'csp', 'medium');
}


// 7) Network Monitör Kurulumu (fetch/XHR override) (Örnekten kod)
let networkMonitorInstalled = false;
function installNetworkMonitor() {
  if (networkMonitorInstalled) return;

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
  
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const method = init && init.method || 'GET';
    const body = init && init.body || null;
    const headers = init && init.headers || {};
    inspectOutgoingRequest(method, input, headers, body);
    return originalFetch.apply(this, arguments);
  };

  networkMonitorInstalled = true;
}

// Giden istekleri incele (Örnekten kod)
function inspectOutgoingRequest(method, url, headers, body) {
  try {
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

// Utility helpers (Örnekten kod)
function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+'...' : s; }

// Popup veya background'tan gelen komutları dinle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage') {
    scanPage();
    sendResponse({ vulnerabilities });
    return true; 
  }

  // Content script'in yüklü olup olmadığını kontrol et (popup.js'teki yarış durumunu çözer)
  if (request.action === 'checkStatus') {
    sendResponse({ status: 'ready' });
    return true;
  }
});