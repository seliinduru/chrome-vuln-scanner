// content.js
// Bu dosya sayfa üzerinde koşar ve güvenlik kontrolleri yapar.

let vulnerabilities = []; // Global olarak tanımlandı

/**
 * Zafiyeti zafiyet listesine ekler.
 * @param {string} id - Benzersiz zafiyet ID'si.
 * @param {string} title - Zafiyetin kısa başlığı.
 * @param {string} details - Zafiyetin detaylı açıklaması.
 * @param {string} type - Zafiyetin türü (xss, csrf, cookie, csp, storage, network).
 * @param {string} [severity='medium'] - Başlangıç şiddeti (low, medium, high).
 * @param {string | null} [evidence=null] - Zafiyetin kanıtı (kod/değer).
 * @param {string} [location='inline'] - Zafiyetin konumu (url, header, body, script, form).
 * @param {number} [matchCount=1] - Eşleşme sayısı.
 * @param {boolean} [contextFactors=false] - Context faktörleri (HTTPS, vb.) etkili mi?
 * @param {boolean} [userInteraction=false] - Açığın tetiklenmesi için kullanıcı etkileşimi gerekli mi?
 * @param {boolean} [externalFactors=false] - Harici faktörler (malicious URL, vb.) etkili mi?
 */
function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
  // Hata Çözümü: vulnerabilities'in bir array olduğundan emin ol (tanımlama sorunu için önlem)
  if (!Array.isArray(vulnerabilities)) {
    vulnerabilities = []; 
  }
  
  vulnerabilities.push({ 
    id, 
    title: title || 'Bilinmeyen Açık', 
    details: details || 'Detay yok.', 
    type: type || 'other', 
    severity, 
    evidence,
    // Scoring inputs
    location: location,
    matchCount: matchCount,
    contextFactors: contextFactors,
    userInteractionRequired: userInteraction,
    isMaliciousURL: externalFactors
  });
}

// Ana tarama fonksiyonu
function scanPage() {
  vulnerabilities = []; // Her taramada sıfırla (Kritik: Array'in sıfırlandığından emin ol)
  try {
    checkURLParameters(); 
    checkForXSSVulnerabilities();
    checkCookieSecurity();
    checkStorageSecurity();
    checkPasswordFields();
    checkCSP();
    installNetworkMonitor(); 
    // sonuçları background'a gönder 
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
      if (/<script|<img|<svg/i.test(value) && name !== 'q') { 
        // 10 parametre çağrısı
        addVuln('url_xss_potential', `URL Parametresinde Potansiyel XSS`, `Parametre: ${name}, Değer: ${truncate(value, 150)}`, 'xss', 'high', value, 'url', 1, false, false, false);
      }
    });
  } catch (e) {}
}

// 2) XSS Kontrolleri (DOM tabanlı)
function checkForXSSVulnerabilities() {
  if (window.location.hash.includes('xss=true')) {
    // 10 parametre çağrısı
    addVuln('dom_xss_sim', 'Simüle Edilmiş DOM XSS', 'URL Hash içinde XSS kanıtı bulundu.', 'xss', 'high', window.location.hash, 'script', 1, false, false, false);
  }
}

// 3) Cookie Güvenliği Kontrolleri
function checkCookieSecurity() {
  document.cookie.split(';').forEach(cookie => {
    cookie = cookie.trim();
    if (!cookie) return;

    const [name] = cookie.split('=');
    
    // Güvenli (Secure) bayrağı eksik
    if (window.location.protocol === 'https:' && !cookie.includes('Secure')) {
      // 10 parametre çağrısı
      addVuln('cookie_insecure', `Güvenli Olmayan Çerez (Secure Flag Eksik)`, `Çerez adı: ${name}. HTTPS üzerinde Secure flag'ı yok.`, 'cookie', 'medium', cookie, 'header', 1, true, false, false);
    }
    
    // HttpOnly bayrağı eksik (XSS riskini artırır)
    if (!cookie.includes('HttpOnly')) {
      // 10 parametre çağrısı
      addVuln('cookie_httponly_missing', `HttpOnly Bayrağı Eksik`, `Çerez adı: ${name}. XSS saldırılarına karşı savunmasız.`, 'cookie', 'high', cookie, 'header', 1, true, false, false);
    }
    
    // Hassas veri içeren çerezler (Session ID vb.)
    if (/session|jwt|token/i.test(name)) {
      // 10 parametre çağrısı
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
      // 10 parametre çağrısı
      addVuln('local_storage_sensitive', `localStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'medium', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }

  // sessionStorage Kontrolü 
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    const value = sessionStorage.getItem(key);
    if (/token|jwt|session|password/i.test(key) || /token|jwt|password/i.test(value)) {
      // 10 parametre çağrısı
      addVuln('session_storage_sensitive', `sessionStorage'da Hassas Veri`, `Anahtar: ${key}. Token, şifre veya oturum verisi içeriyor olabilir.`, 'storage', 'low', `Key: ${key}, Value: ${truncate(value, 100)}`, 'storage', 1, false, false, false);
    }
  }
}

// 5) Şifre Alanı Güvenliği Kontrolleri
function checkPasswordFields() {
  document.querySelectorAll('input[type="password"]').forEach(input => {
    if (input.getAttribute('autocomplete') === 'off') {
      // 10 parametre çağrısı
      addVuln('password_autocomplete_off', 'Şifre Alanında Autocomplete Kapatılmış', 'Tarayıcının şifre yönetimi özelliğini devre dışı bırakıyor.', 'csrf', 'low', null, 'form', 1, false, false, false);
    }
  });
}

// 6) İçerik Güvenlik Politikası (CSP) Kontrolleri
function checkCSP() {
  const isHttps = window.location.protocol === 'https:';
  
  if (!isHttps) {
    // 10 parametre çağrısı
    addVuln('page_not_https', 'Sayfa Güvenli Değil (HTTPS Eksik)', 'Sayfa HTTPS protokolü üzerinden yüklenmemiş.', 'network', 'high', null, 'header', 1, true, false, false);
  }

  // 10 parametre çağrısı
  addVuln('csp_sim', 'CSP Kontrolü Gerekiyor', 'Content Security Policy (CSP) varlığı kontrol edilmeli.', 'csp', 'medium', null, 'header', 1, isHttps, false, false);
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
      // Hata Çözümü: URL'yi doğru çek
      inspectOutgoingRequest(xhr._method, xhr._url || xhr.responseURL, xhr.getAllRequestHeaders(), body);
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
    // Hata Çözümü: input string veya Request nesnesi olabilir
    const url = typeof input === 'string' ? input : (input.url || 'N/A');
    inspectOutgoingRequest(method, url, headers, body);
    return originalFetch.apply(this, arguments);
  };
  networkMonitorInstalled = true;
}

// Giden istekleri incele
function inspectOutgoingRequest(method, url, headers, body) {
  try {
    if (body) {
      try {
        const s = typeof body === 'string' ? body : (JSON && JSON.stringify(body)) || '';
        if (/password=|passwd=|token|jwt|access_token/i.test(s)) {
          // 10 parametre çağrısı
          addVuln('outgoing_sensitive_body', 'Outgoing istek gövdesinde hassas veri', `İstek gövdesinde password/token gibi ifadeler bulundu: ${truncate(s,300)}`, 'network', 'high', s.slice(0, 300), 'body', 1, true, false, false);
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('inspectOutgoingRequest error', e);
  }
}

// Utility helpers
function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+'...' : s; }


// Popup veya background'tan gelen komutları dinle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage') {
    scanPage();
    sendResponse({ vulnerabilities });
    return true; 
  }

  // Content script'in yüklü olup olmadığını kontrol et
  if (request.action === 'checkStatus') {
    sendResponse({ status: 'ready' });
    return true;
  }
});