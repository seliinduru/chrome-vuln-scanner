// background.js - ZAMANLAMA HATALARINI ÖNLEYEN, GÜNCELLENMİŞ VERSİYON

let storedVulnerabilities = [];
let lastScanTimestamp = null;
let fuzzyLogicConfig = null;
let scoreMethods = null;
let configPromise = null; // Yapılandırmanın yüklendiğini belirten bir promise

// Yapılandırmaları yükleyen ve promise'i tamamlayan ana fonksiyon
const loadConfigurations = async () => {
  try {
    const [fuzzyResponse, scoreResponse] = await Promise.all([
      fetch(chrome.runtime.getURL('fuzzyLogic.json')),
      fetch(chrome.runtime.getURL('scoreMethods.json'))
    ]);

    if (!fuzzyResponse.ok || !scoreResponse.ok) {
      throw new Error(`Yapılandırma dosyası bulunamadı: ${!fuzzyResponse.ok ? 'fuzzyLogic.json' : 'scoreMethods.json'}`);
    }

    const [fuzzyData, scoreData] = await Promise.all([
      fuzzyResponse.json(),
      scoreResponse.json()
    ]);

    fuzzyLogicConfig = fuzzyData;
    scoreMethods = scoreData;

    await chrome.storage.local.set({
      cachedFuzzyLogic: fuzzyLogicConfig,
      cachedScoreMethods: scoreMethods,
      configLoadedAt: new Date().toISOString()
    });

    console.log('Fuzzy Logic ve Score Methods başarıyla yüklendi.');

  } catch (e) {
    console.error('Yapılandırma yükleme hatası (background.js):', e);
    // Hata durumunda promise'i reddet ki popup haberdar olsun
    throw e;
  }
};

// Uzantı ilk başladığında yapılandırma yüklemesini başlat
configPromise = loadConfigurations();

// Mesaj dinleyicisi
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  // Yapılandırma isteyen mesajlar, yüklemenin bitmesini beklemeli
  if (message.action === 'getFuzzyLogic') {
    configPromise
      .then(() => sendResponse({ fuzzyLogic: fuzzyLogicConfig }))
      .catch(error => sendResponse({ error: `Fuzzy Logic yüklenemedi: ${error.message}` }));
    return true; // Asenkron cevap verileceğini belirt
  }

  if (message.action === 'getScoreMethods') {
    configPromise
      .then(() => sendResponse({ scoreMethods: scoreMethods }))
      .catch(error => sendResponse({ error: `Score Methods yüklenemedi: ${error.message}` }));
    return true; // Asenkron cevap verileceğini belirt
  }
  
  // Diğer mesajlar anında cevaplanabilir
  if (message.action === 'vulnerabilitiesDetected') {
    storedVulnerabilities = Array.isArray(message.vulnerabilities) ? message.vulnerabilities : [];
    lastScanTimestamp = Date.now();
    sendResponse({ status: 'ok' });
  }

  if (message.action === 'getVulns') {
    sendResponse({
      vulnerabilities: storedVulnerabilities || [],
      timestamp: lastScanTimestamp
    });
  }
  
  return false;
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('Uzantı kuruldu/güncellendi. Yapılandırmalar yeniden yükleniyor.');
  // Yeniden yükleme durumunda promise'i güncelle
  configPromise = loadConfigurations();
});