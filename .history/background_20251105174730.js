// background.js
// İçerik scriptinden gelen zafiyetleri saklar ve popup'a sunar.
// Fuzzy Logic ve Score Methods yapılandırmalarını yönetir.

let storedVulnerabilities = []; 
let fuzzyLogicConfig = {}; 
let scoreMethods = {}; 
let lastScanTimestamp = null; 

async function loadConfigurations() {
  try {
    const fuzzyResponse = await fetch(chrome.runtime.getURL('fuzzyLogic.json'));
    fuzzyLogicConfig = await fuzzyResponse.json();
    
    const scoreResponse = await fetch(chrome.runtime.getURL('scoreMethods.json'));
    scoreMethods = await scoreResponse.json();
    
    // localStorage'a cache et
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
        console.log('Yapılandırmalar cache\'den yüklendi.');
        resolve();
      });
    });
  }
}

// Alarm yönetimi
let alarmCreated = false;
const ensureAlarmCreated = async () => {
  if (alarmCreated) return;
  try {
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

chrome.runtime.onInstalled.addListener(async () => {
  console.log('Extension installed/updated');
  await loadConfigurations();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'refreshConfigs') {
    console.log('Refreshing configs...');
    loadConfigurations().catch(e => console.error('Config refresh error:', e));
  }
});

chrome.tabs.onActivated.addListener(async () => {
  await ensureAlarmCreated();
  
  if (Object.keys(fuzzyLogicConfig).length === 0) {
    await loadConfigurations();
  }
});

// Mesaj dinleyicisi
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (!message || !message.action) return;

    if (message.action === 'vulnerabilitiesDetected') {
      storedVulnerabilities = Array.isArray(message.vulnerabilities) ? message.vulnerabilities : [];
      lastScanTimestamp = Date.now(); 
      sendResponse({ status: 'ok' });
      return true;
    }

    if (message.action === 'getVulns') {
      ensureAlarmCreated();
      sendResponse({ 
        vulnerabilities: storedVulnerabilities || [],
        timestamp: lastScanTimestamp 
      });
      return true;
    }

    if (message.action === 'getFuzzyLogic') {
      sendResponse({ fuzzyLogic: fuzzyLogicConfig });
      return true;
    }

    if (message.action === 'getScoreMethods') {
      sendResponse({ scoreMethods: scoreMethods });
      return true;
    }

  } catch (e) {
    console.error('background onMessage error', e);
  }
});

loadConfigurations().catch(e => console.log('Initial load: using defaults or cache', e));