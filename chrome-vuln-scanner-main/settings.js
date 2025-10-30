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

// Mevcut ayarları yükle
function loadSettings() {
  chrome.storage.local.get('scannerSettings', (result) => {
    const settings = result.scannerSettings || getDefaultSettings();
    
    // Güvenlik açığı seviyesi
    document.querySelectorAll('input[name="severity"]').forEach(checkbox => {
      checkbox.checked = settings.severity.includes(checkbox.value);
    });
    
    // Açık türleri
    document.querySelectorAll('input[name="vulnType"]').forEach(checkbox => {
      checkbox.checked = settings.vulnTypes.includes(checkbox.value);
    });
    
    // Tarama seçenekleri
    document.querySelectorAll('input[name="scanOption"]').forEach(checkbox => {
      checkbox.checked = settings.scanOptions.includes(checkbox.value);
    });
  });
}

// Ayarları kaydet
function saveSettings() {
  const settings = {
    severity: [],
    vulnTypes: [],
    scanOptions: []
  };
  
  // Güvenlik açığı seviyesi
  document.querySelectorAll('input[name="severity"]:checked').forEach(checkbox => {
    settings.severity.push(checkbox.value);
  });
  
  // Açık türleri
  document.querySelectorAll('input[name="vulnType"]:checked').forEach(checkbox => {
    settings.vulnTypes.push(checkbox.value);
  });
  
  // Tarama seçenekleri
  document.querySelectorAll('input[name="scanOption"]:checked').forEach(checkbox => {
    settings.scanOptions.push(checkbox.value);
  });
  
  // Ayarları kaydet
  chrome.storage.local.set({ scannerSettings: settings }, () => {
    document.getElementById('statusText').textContent = 'Ayarlar kaydedildi';
    setTimeout(() => {
      document.getElementById('statusText').textContent = 'Ayarlar';
    }, 2000);
  });
}

// Varsayılan ayarları al
function getDefaultSettings() {
  return {
    severity: ['high', 'medium', 'low'],
    vulnTypes: ['xss', 'sqli', 'csrf', 'other'],
    scanOptions: ['passive']
  };
}

// Ayarları sıfırla
function resetSettings() {
  const defaultSettings = getDefaultSettings();
  
  // Güvenlik açığı seviyesi
  document.querySelectorAll('input[name="severity"]').forEach(checkbox => {
    checkbox.checked = defaultSettings.severity.includes(checkbox.value);
  });
  
  // Açık türleri
  document.querySelectorAll('input[name="vulnType"]').forEach(checkbox => {
    checkbox.checked = defaultSettings.vulnTypes.includes(checkbox.value);
  });
  
  // Tarama seçenekleri
  document.querySelectorAll('input[name="scanOption"]').forEach(checkbox => {
    checkbox.checked = defaultSettings.scanOptions.includes(checkbox.value);
  });
  
  // Ayarları kaydet
  chrome.storage.local.set({ scannerSettings: defaultSettings }, () => {
    document.getElementById('statusText').textContent = 'Ayarlar sıfırlandı';
    setTimeout(() => {
      document.getElementById('statusText').textContent = 'Ayarlar';
    }, 2000);
  });
}