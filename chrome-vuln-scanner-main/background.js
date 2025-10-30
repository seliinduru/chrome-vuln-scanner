// background.js
// İçerik scriptinden gelen zafiyetleri saklar ve popup'a sunar.
// Fuzzy Logic ve Score Methods yapılandırmalarını yönetir.

let storedVulnerabilities = []; // arka planda saklanan son sonuç
let fuzzyLogicConfig = {}; // Fuzzy logic yapılandırması
let scoreMethods = {}; // Score hesaplama methodları

// Yapılandırmaları yükle (local JSON dosyalarından veya API'den)
async function loadConfigurations() {
  try {
    // Local fuzzyLogic.json'u yükle
    const fuzzyResponse = await fetch(chrome.runtime.getURL('fuzzyLogic.json'));
    fuzzyLogicConfig = await fuzzyResponse.json();
    
    // Local scoreMethods.json'u yükle
    const scoreResponse = await fetch(chrome.runtime.getURL('scoreMethods.json'));
    scoreMethods = await scoreResponse.json();
    
    // localStorage'a cache et (Promise-based)
    await new Promise((resolve) => {
      chrome.storage.local.set({ 
        cachedFuzzyLogic: fuzzyLogicConfig,
        cachedScoreMethods: scoreMethods,
        configLoadedAt: new Date().toISOString()
      }, resolve);
    });
    
    console.log('Fuzzy Logic ve Score Methods yüklendi');
  } catch (e) {
    console.error('Yapılandırma yükleme hatası:', e);
    // Cache'den yükle
    await new Promise((resolve) => {
      chrome.storage.local.get(['cachedFuzzyLogic', 'cachedScoreMethods'], (result) => {
        fuzzyLogicConfig = result.cachedFuzzyLogic || {};
        scoreMethods = result.cachedScoreMethods || {};
        resolve();
      });
    });
  }
}

// Uzantı başlatıldığında yapılandırmaları yükle
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('Extension installed/updated');
  try {
    await loadConfigurations();
  } catch (e) {
    console.error('Initial config load error:', e);
  }
});

// Alarm'ı popup açıldığında veya lazım olduğunda oluştur (Service Worker'dan güvenli)
let alarmCreated = false;
const ensureAlarmCreated = async () => {
  if (alarmCreated) return;
  try {
    // Alarm zaten var mı kontrol et
    const alarms = await chrome.alarms.getAll();
    if (alarms.some(a => a.name === 'refreshConfigs')) {
      alarmCreated = true;
      return;
    }
    chrome.alarms.create('refreshConfigs', { periodInMinutes: 24 * 60 });
    alarmCreated = true;
    console.log('Alarm created successfully');
  } catch (e) {
    console.warn('Alarm creation warning:', e.message);
  }
};

// Alarm dinleyicisi
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'refreshConfigs') {
    console.log('Refreshing configs...');
    loadConfigurations().catch(e => console.error('Config refresh error:', e));
  }
});

// Sayfa açıldığında yapılandırmaları kontrol et
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  // Alarm'ı oluşturmayı dene (ilk sefer)
  await ensureAlarmCreated();
  
  if (Object.keys(fuzzyLogicConfig).length === 0) {
    try {
      await loadConfigurations();
    } catch (e) {
      console.error('On-demand config load error:', e);
    }
  }
});

// İçerik scriptinden gelirse kaydet
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (!message || !message.action) return;

    if (message.action === 'vulnerabilitiesDetected') {
      // içerik scripti doğrudan tarama sonuçlarını gönderiyor
      storedVulnerabilities = Array.isArray(message.vulnerabilities) ? message.vulnerabilities : [];
      sendResponse({ status: 'ok' });
      return true;
    }

    // popup'tan veya başka bir yerden "getVulns" isteği
    if (message.action === 'getVulns') {
      // Popup açıldığında alarm'ı oluştur
      ensureAlarmCreated();
      sendResponse({ vulnerabilities: storedVulnerabilities || [] });
      return true;
    }

    // Fuzzy Logic yapılandırmasını iste
    if (message.action === 'getFuzzyLogic') {
      sendResponse({ fuzzyLogic: fuzzyLogicConfig });
      return true;
    }

    // Score Methods yapılandırmasını iste
    if (message.action === 'getScoreMethods') {
      sendResponse({ scoreMethods: scoreMethods });
      return true;
    }

  } catch (e) {
    console.error('background onMessage error', e);
  }
});

// İlk yükleme - hata durumunda sessiz kalacak şekilde
loadConfigurations().catch(e => console.log('Initial load: using defaults or cache', e));
