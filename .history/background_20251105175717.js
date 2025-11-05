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
  }
  if (message.action === 'getVulns') {
    sendResponse({ vulnerabilities: storedVulnerabilities, timestamp: lastScanTimestamp });
  }
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[BG] Uzantı kuruldu/güncellendi.');
  configPromise = loadConfigurations();
});