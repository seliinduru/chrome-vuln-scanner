// content.js (en altta)
// Popup veya background'tan gelen scanPage komutunu dinle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage') {
    scanPage();
    // async: sonuçları popup'a ilet
    sendResponse({ vulnerabilities });
    return true;
  }
  
  // YENİ: Popup'tan gelen durum kontrolü
  if (request.action === 'checkStatus') {
    sendResponse({ status: 'ready' });
    return true; // Asenkron yanıtı işaretler
  }
});