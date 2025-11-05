// settings.js
// Ayarlar sayfası için JavaScript kodları

// DOM elementini global olarak al
const statusTextSpan = document.getElementById('statusText');

// Helper: Durum mesajını ayarla
function setStatus(text) {
  // Eğer element yüklendiyse (null değilse) metni değiştir.
  if (statusTextSpan) {
    statusTextSpan.textContent = text;
  }
}

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
  
  // İlk yükleme durumunu ayarla
  setStatus('Ayarlar');
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
    
    // Tarama seçenekleri (Eğer settings.html'de bu seçenekler varsa)
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
    // Hata çözümü için setStatus kullanıldı
    setStatus('Ayarlar kaydedildi');
    setTimeout(() => {
      setStatus('Ayarlar');
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
    // Hata çözümü için setStatus kullanıldı
    setStatus('Ayarlar sıfırlandı');
    setTimeout(() => {
      setStatus('Ayarlar');
    }, 2000);
  });
}