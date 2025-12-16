// background.js - DETAYLI HATA AYIKLAMA MODU

let storedVulnerabilities = [];
let lastScanTimestamp = null;
let fuzzyLogicConfig = null;
let scoreMethods = null;
let configPromise = null;

const loadConfigurations = async () => {
  try {
    console.log('[BG] Yapılandırmaları yüklemeye başlanıyor...');

    // 1. fuzzyLogic.json dosyasını yükle
    const fuzzyResponse = await fetch(chrome.runtime.getURL('fuzzyLogic.json'));
    console.log('[BG] fuzzyLogic.json fetch durumu:', fuzzyResponse.status, fuzzyResponse.statusText);
    if (!fuzzyResponse.ok) {
      throw new Error('fuzzyLogic.json dosyası bulunamadı veya okunamadı. Lütfen dosya adını ve konumunu kontrol edin.');
    }
    fuzzyLogicConfig = await fuzzyResponse.json();
    console.log('[BG] fuzzyLogic.json başarıyla yüklendi ve ayrıştırıldı.');

    // 2. scoreMethods.json dosyasını yükle
    const scoreResponse = await fetch(chrome.runtime.getURL('scoreMethods.json'));
    console.log('[BG] scoreMethods.json fetch durumu:', scoreResponse.status, scoreResponse.statusText);
    if (!scoreResponse.ok) {
      throw new Error('scoreMethods.json dosyası bulunamadı veya okunamadı. Lütfen dosya adını ve konumunu kontrol edin.');
    }
    scoreMethods = await scoreResponse.json();
    console.log('[BG] scoreMethods.json başarıyla yüklendi ve ayrıştırıldı.');

  } catch (e) {
    // BU EN ÖNEMLİ KISIM! HATA OLURSA BURADA GÖRECEĞİZ.
    console.error('[BG] !!! YAPILANDIRMA YÜKLEME HATASI !!!', e);
    throw e; // Hatayı yukarıya fırlat ki popup da haberdar olsun
  }
};

configPromise = loadConfigurations();

// =============================================================================
// NETWORK MONITORING (Background)
// =============================================================================
let networkVulnerabilities = {}; // Map<tabId, Array>

function addNetworkVuln(tabId, vuln) {
    if (!networkVulnerabilities[tabId]) networkVulnerabilities[tabId] = [];
    // Avoid duplicates
    if (!networkVulnerabilities[tabId].some(v => v.id === vuln.id)) {
        networkVulnerabilities[tabId].push(vuln);
    }
}

// 1. Check Security Headers
chrome.webRequest.onHeadersReceived.addListener((details) => {
    if (details.type !== 'main_frame') return; // Only check main page headers for now
    
    const headers = details.responseHeaders || [];
    const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase());

    // HSTS
    if (!getHeader('Strict-Transport-Security') && details.url.startsWith('https')) {
        addNetworkVuln(details.tabId, {
            id: 'missing_hsts',
            title: 'HSTS Başlığı Eksik',
            details: 'Strict-Transport-Security başlığı sunucu yanıtında bulunamadı.',
            type: 'transport',
            severity: 'medium',
            location: 'header'
        });
    }

    // X-Frame-Options
    if (!getHeader('X-Frame-Options') && !getHeader('Content-Security-Policy')) {
        addNetworkVuln(details.tabId, {
            id: 'missing_clickjack_protection',
            title: 'Clickjacking Koruması Eksik',
            details: 'X-Frame-Options veya CSP frame-ancestors eksik.',
            type: 'csp',
            severity: 'medium',
            location: 'header'
        });
    }

    // X-Content-Type-Options
    if (!getHeader('X-Content-Type-Options')) {
        addNetworkVuln(details.tabId, {
            id: 'missing_nosniff',
            title: 'MIME Sniffing Koruması Eksik',
            details: 'X-Content-Type-Options: nosniff başlığı eksik.',
            type: 'csp',
            severity: 'low',
            location: 'header'
        });
    }

}, {urls: ["<all_urls>"]}, ["responseHeaders"]);

// 2. Check URL Sensitive Data (GET)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    const url = details.url;
    if (/token=|api_key=|password=|secret=/i.test(url)) {
        addNetworkVuln(details.tabId, {
            id: 'sensitive_url_bg_' + Math.random().toString(36).substr(2,5),
            title: 'URL\'de Hassas Veri (Network)',
            details: 'Ağ isteği URL parametrelerinde hassas veri tespit edildi.',
            type: 'network',
            severity: 'medium',
            evidence: { url: url.length > 100 ? url.substring(0,100) + '...' : url },
            location: 'network'
        });
    }
}, {urls: ["<all_urls>"]});

// Unified Message Listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getFuzzyLogic') {
    configPromise
      .then(() => sendResponse({ fuzzyLogic: fuzzyLogicConfig }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  if (message.action === 'getScoreMethods') {
    configPromise
      .then(() => sendResponse({ scoreMethods: scoreMethods }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  if (message.action === 'vulnerabilitiesDetected') {
    storedVulnerabilities = message.vulnerabilities || [];
    lastScanTimestamp = Date.now();
    sendResponse({ status: 'ok' });
    return false;
  }
  if (message.action === 'getVulns') {
    sendResponse({ vulnerabilities: storedVulnerabilities, timestamp: lastScanTimestamp });
    return false;
  }
  if (message.action === 'getNetworkVulns') {
      const tabId = message.tabId || sender.tab?.id;
      sendResponse({ vulnerabilities: networkVulnerabilities[tabId] || [] });
      return false;
  }
  
  // --- NEW: Full Scan Orchestration ---
  if (message.action === 'start_full_scan') {
      const tabId = message.tabId;
      if (!tabId) return;

      // 1. Clear previous network logs for this tab
      networkVulnerabilities[tabId] = [];

      // 2. Set Scanning State
      chrome.storage.local.set({ 
          scanState: { 
              isScanning: true, 
              tabId: tabId, 
              step: 'network_reload' 
          } 
      }, () => {
          // 3. Reload the tab to capture full network traffic
          chrome.tabs.reload(tabId);
      });
      
      sendResponse({ status: 'started' });
      return false;
  }

  if (message.action === 'scan_complete') {
      // Scan finished by content script
      const tabId = sender.tab?.id;
      if (tabId) {
          // Merge content vulns with network vulns
          const contentVulns = message.vulnerabilities || [];
          const netVulns = networkVulnerabilities[tabId] || [];
          const allVulns = [...contentVulns, ...netVulns];
          
          storedVulnerabilities = allVulns;
          lastScanTimestamp = Date.now();

          // Clear state
          chrome.storage.local.remove('scanState');
          
          // Notify Popup (if open) or save to storage
          chrome.storage.local.set({ scanResults: allVulns });
      }
  }

  return false;
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[BG] Uzantı kuruldu/güncellendi.');
  configPromise = loadConfigurations();
});

// Clear data on tab remove
chrome.tabs.onRemoved.addListener((tabId) => {
    delete networkVulnerabilities[tabId];
    // Also clear scan state if this tab was scanning
    chrome.storage.local.get('scanState', (data) => {
        if (data.scanState && data.scanState.tabId === tabId) {
            chrome.storage.local.remove('scanState');
        }
    });
});

// Inject Content Script on Reload if Scanning
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        chrome.storage.local.get('scanState', (data) => {
            if (data.scanState && data.scanState.isScanning && data.scanState.tabId === tabId) {
                console.log('[BG] Tarama durumu tespit edildi, content script enjekte ediliyor...', tabId);
                chrome.scripting.executeScript({
                    target: { tabId: tabId },
                    files: ['content.js']
                }).catch(err => console.error("[BG] Injection error:", err));
            }
        });
    }
});


