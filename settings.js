// settings.js
// Ayarlar sayfası için JavaScript kodları

// Sayfa yüklendiğinde mevcut ayarları yükle
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  
  // Geri dönüş butonu
  document.getElementById('backBtn').addEventListener('click', () => {
    window.location.href = 'popup.html';
  });
  
  // Ayarları kaydet butonu
  document.getElementById('saveSettingsBtn').addEventListener('click', saveSettings);
  
  // Ayarları sıfırla butonu
  document.getElementById('resetSettingsBtn').addEventListener('click', resetSettings);
});

const DEFAULT_SETTINGS = {
    aiModel: 'gpt-4o',
    autoScan: false,
    networkMonitor: true,
    domMonitor: true,
    severity: ['high', 'medium', 'low']
};

function loadSettings() {
  chrome.storage.local.get('scannerSettings', (result) => {
    const settings = { ...DEFAULT_SETTINGS, ...result.scannerSettings };
    
    // AI Model
    const aiSelect = document.getElementById('defaultAiModel');
    if(aiSelect) aiSelect.value = settings.aiModel;

    // Toggles
    const autoScan = document.getElementById('autoScan');
    if(autoScan) autoScan.checked = settings.autoScan;
    
    const networkMonitor = document.getElementById('networkMonitor');
    if(networkMonitor) networkMonitor.checked = settings.networkMonitor;
    
    const domMonitor = document.getElementById('domMonitor');
    if(domMonitor) domMonitor.checked = settings.domMonitor;

    // Severity
    document.querySelectorAll('input[name="severity"]').forEach(cb => {
        cb.checked = settings.severity.includes(cb.value);
    });
  });
}

function saveSettings() {
  const settings = {
    aiModel: document.getElementById('defaultAiModel').value,
    autoScan: document.getElementById('autoScan').checked,
    networkMonitor: document.getElementById('networkMonitor').checked,
    domMonitor: document.getElementById('domMonitor').checked,
    severity: Array.from(document.querySelectorAll('input[name="severity"]:checked')).map(cb => cb.value)
  };
  
  chrome.storage.local.set({ scannerSettings: settings }, () => {
    const btn = document.getElementById('saveSettingsBtn');
    const originalText = btn.textContent;
    btn.textContent = 'Kaydedildi!';
    setTimeout(() => btn.textContent = originalText, 1500);
  });
}


// Ayarları sıfırla
function resetSettings() {
    chrome.storage.local.set({ scannerSettings: DEFAULT_SETTINGS }, () => {
        loadSettings();
    });
}