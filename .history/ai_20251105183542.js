// ai.js

document.addEventListener('DOMContentLoaded', () => {
    
    // Geri butonuna tıklama olayını ekle
    document.getElementById('backBtn').addEventListener('click', () => {
        window.location.href = 'popup.html';
    });

    // Sayfa yüklendiğinde en son tarama sonuçlarını iste ve önerileri göster
    chrome.runtime.sendMessage({ action: "getVulns" }, (response) => {
        if (response && response.vulnerabilities) {
            renderAiSuggestions(response.vulnerabilities);
        } else {
            console.error("Arka plandan zafiyet verisi alınamadı.");
        }
    });

});

const renderAiSuggestions = (vulns) => {
    const aiSuggestions = document.getElementById('aiSuggestions');
    if (!aiSuggestions) return;

    if (!vulns || vulns.length === 0) {
        aiSuggestions.innerHTML = '<p class="muted">Öneri gösterecek bir açık bulunamadı.</p>';
        return;
    }

    let suggestionsHTML = '<h3>Önerilen Çözümler</h3>';
    const suggestionMap = {}; 

    vulns.forEach(vuln => {
        if (suggestionMap[vuln.type]) return; 

        switch (vuln.type) {
            case 'xss':
                suggestionsHTML += `<div class="ai-advice"><h4>XSS Zafiyetleri İçin</h4><p>Kullanıcıdan gelen verileri DOM'a yazdırırken <strong>textContent</strong> kullanın. Eğer HTML yazdırmak zorundaysanız, bilinen bir "DOMPurify" gibi bir kütüphane ile veriyi temizleyin. Asla <strong>innerHTML</strong>'e güvenmeyin.</p></div>`;
                suggestionMap.xss = true;
                break;
            case 'csp':
                suggestionsHTML += `<div class="ai-advice"><h4>CSP Eksikliği İçin</h4><p>HTTP başlıklarına (header) katı bir <strong>Content-Security-Policy</strong> ekleyin. Bu, tarayıcının sadece güvendiğiniz kaynaklardan script çalıştırmasına izin vererek XSS saldırılarının etkisini büyük ölçüde azaltır.</p></div>`;
                suggestionMap.csp = true;
                break;
            case 'csrf':
            case 'cookie':
                suggestionsHTML += `<div class="ai-advice"><h4>Cookie & CSRF Güvenliği</h4><p>Tüm oturum cookielerinin <strong>HttpOnly</strong>, <strong>Secure</strong> ve <strong>SameSite=Lax</strong> veya <strong>Strict</strong> bayraklarına sahip olduğundan emin olun. Bu, cookielerin JavaScript tarafından çalınmasını ve siteler arası sahte istekleri önler.</p></div>`;
                suggestionMap.csrf = true;
                suggestionMap.cookie = true;
                break;
        }
    });

    if (Object.keys(suggestionMap).length === 0) {
         aiSuggestions.innerHTML = '<p class="muted">Bu açık türleri için henüz bir öneri tanımlanmadı.</p>';
    } else {
         aiSuggestions.innerHTML = suggestionsHTML;
    }
};