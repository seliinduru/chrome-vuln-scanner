// content.js  (SON HAL – PRO)
(() => {
  if (window.SEC_SCANNER_PRO) return;   // çift yüklenmeyi engelle
  window.SEC_SCANNER_PRO = true;

  const vulns = [];
  const seen = new Set();               // duplicate önlemi

  function addVuln(id, title, details, type, severity = 'medium', evidence = null, location = 'inline', matchCount = 1, contextFactors = false, userInteraction = false, externalFactors = false) {
    const key = `${id}-${JSON.stringify(evidence)}`;
    if (seen.has(key)) return;
    seen.add(key);
    vulns.push({ id, title, details, type, severity, evidence, location, matchCount, contextFactors, userInteractionRequired: userInteraction, isMaliciousURL: externalFactors });
  }

  function extractSnippet(src, terms) {
    for (const t of terms) { const i = src.indexOf(t); if (i >= 0) return src.slice(Math.max(0, i - 80), i + 200); }
    return src.slice(0, 200);
  }
  function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '...' : s; }

  /* ---------- 1. DOM MUTATION OBSERVER (DOM-XSS) ---------- */
  const obs = new MutationObserver(ms => {
    for (const m of ms) {
      if (m.type === 'childList') {
        m.addedNodes.forEach(n => {
          if (n.nodeType !== 1) return;
          if (n.tagName === 'SCRIPT' && n.textContent.includes('innerHTML')) {
            addVuln('dom_mutation_script', 'DOM XSS (mutation)', 'innerHTML kullanan script eklendi', 'xss', 'high', n.textContent.slice(0, 200), 'dom-mutation');
          }
        });
      }
    }
  });
  obs.observe(document, { childList: true, subtree: true });

  /* ---------- 2. PROTOTYPE POLLUTION ---------- */
  const _define = Object.defineProperty;
  Object.defineProperty = function (o, p, desc) {
    if (p === '__proto__' || p === 'constructor' || p === 'prototype') {
      addVuln('proto_pollution', 'Prototype Pollution', `Object.defineProperty ile ${p} değiştirilmeye çalışıldı`, 'proto', 'high', p);
    }
    return _define.call(this, o, p, desc);
  };

  /* ---------- 3. ReDoS ---------- */
  document.querySelectorAll('*').forEach(el => {
    ['onclick', 'onmouseover', 'onchange', 'oninput'].forEach(ev => {
      const v = el.getAttribute(ev);
      if (v && v.length > 500 && /(\w+)\1{5,}/.test(v)) {
        addVuln('redos_inline', 'ReDoS riski (inline handler)', `${ev} çok tekrar içeriyor`, 'redos', 'medium', v.slice(0, 100));
      }
    });
  });

  /* ---------- 4. INSECURE JSON.parse ---------- */
  const _parse = JSON.parse;
  JSON.parse = function (str, rev) {
    if (typeof str === 'string' && (str.includes('__proto__') || str.includes('constructor'))) {
      addVuln('insecure_json_parse', 'Insecure JSON.parse', 'JSON içinde prototype keyword geçiyor', 'deserialization', 'high', str.slice(0, 150));
    }
    return _parse.call(this, str, rev);
  };

  /* ---------- 5. MISSING SECURITY HEADERS (meta) ---------- */
  const meta = document.querySelectorAll('meta[http-equiv]');
  ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Referrer-Policy'].forEach(h => {
    if (!Array.from(meta).some(m => m.httpEquiv.toLowerCase() === h.toLowerCase())) {
      addVuln('missing_header_' + h, 'Eksik güvenlik headerı (meta)', `${h} meta etiketi yok`, 'header', 'medium', h);
    }
  });

  /* ---------- 6. BROKEN ACCESS CONTROL – hidden params ---------- */
  const hiddenParams = ['debug', 'admin', 'test', 'override'];
  const url = new URL(location.href);
  hiddenParams.forEach(p => {
    if (url.searchParams.has(p)) addVuln('bac_hidden_param', 'Gizli parametre aktif', `Potansiyel BAC açığı: ${p}`, 'bac', 'high', p);
  });

  /* ---------- 7. WEAK CRYPTO ---------- */
  const scripts = Array.from(document.scripts).map(s => s.textContent).join('\n');
  ['md5', 'sha1', 'DES', 'RC4'].forEach(alg => {
    const re = new RegExp(`\\b${alg}\\(`, 'gi');
    const m = scripts.match(re);
    if (m) addVuln('weak_crypto_' + alg, 'Zayıf kripto', `${alg} kullanımı`, 'crypto', 'high', alg, 'script', m.length);
  });

  /* ---------- 8. TYPE CONFUSION ---------- */
  if (/\b(\w+)\s*=\s*["']\d+["']\s*-\s*["']\d+["']/.test(scripts)) {
    addVuln('type_confusion', 'Type juggling riski', 'String – number karışımı', 'type', 'medium', 'type-coercion');
  }

  /* ---------- 9. 3rd-PARTY SCRIPT REP ---------- */
  document.querySelectorAll('script[src]').forEach(s => {
    if (s.src.startsWith(location.origin)) return;
    const host = new URL(s.src).hostname;
    const bad = ['unsafe', 'malware', 'example-malicious']; // genişletin
    if (bad.some(b => host.includes(b))) addVuln('3rd_party_untrusted', 'Şüpheli external script', host, '3rdparty', 'high', host);
  });

  /* ---------- 10. FETCH/XHR DEEP INSPECT ---------- */
  const _fetch = window.fetch;
  window.fetch = async (url, opts = {}) => { inspect(url, opts); return _fetch(url, opts); };
  const _open = XMLHttpRequest.prototype.open, _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this._url = u; this._method = m; return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (body) { inspect(this._url, { method: this._method, body }); return _send.call(this, body); };
  function inspect(url, opts) {
    const u = new URL(url, location.origin);
    if (!u.protocol.startsWith('http')) return;
    if (u.search.includes('password') || opts.body?.toString().includes('password')) addVuln('leak_in_request', 'İstekte hassas veri', u.href, 'network', 'high', u.href);
    if (!u.protocol.includes('https')) addVuln('insecure_request', 'Güvensiz HTTP isteği', u.href, 'transport', 'high', u.href);
  }

  /* ---------- 11. WASM INTEGRITY ---------- */
  document.querySelectorAll('link[rel=modulepreload]').forEach(l => {
    if (l.href.endsWith('.wasm') && !l.integrity) addVuln('wasm_no_integrity', 'WASM dosyasında integrity yok', l.href, 'wasm', 'medium', l.href);
  });

  /* ---------- 12. SERVICE-WORKER INJECTION ---------- */
  navigator.serviceWorker.ready.then(reg => {
    if (reg.active && reg.active.scriptURL.includes('eval')) addVuln('sw_eval', 'ServiceWorker içinde eval', reg.active.scriptURL, 'sw', 'critical', reg.active.scriptURL);
  });

  /* ---------- 13. ORIGINAL TARAMALAR (kısaltılmış) ---------- */
  function checkURLParameters() {
    const p = new URLSearchParams(location.search);
    for (const [k, v] of p) {
      if (/[<>\"']|javascript:/i.test(v)) addVuln('url_xss_' + k, 'URL XSS', `${k} parametresi HTML karakterleri içeriyor`, 'xss', 'high', v, 'url');
      if (/'|--|union|select/i.test(v)) addVuln('url_sqli_' + k, 'URL SQLi', `${k} SQL keyword içeriyor`, 'sqli', 'high', v, 'url');
    }
  }
  function checkForXSSVulnerabilities() {
    const src = document.documentElement.outerHTML;
    if (/innerHTML\s*=/.test(src)) addVuln('xss_innerhtml', 'innerHTML kullanımı', 'innerHTML doğrudan kullanılmış', 'xss', 'high', src.match(/innerHTML\s*=[^;]+/g)[0], 'script');
    if (/document\.write/.test(src)) addVuln('xss_docwrite', 'document.write', 'document.write tespit edildi', 'xss', 'medium', null, 'script');
    if (/\beval\s*\(/.test(src)) addVuln('xss_eval', 'eval kullanımı', 'eval çağrısı bulundu', 'xss', 'high', null, 'script');
    document.querySelectorAll('*').forEach(el => Array.from(el.attributes).forEach(a => {
      if (/^on/i.test(a.name) && a.value) addVuln('xss_inline', 'Inline event handler', `${el.tagName} ${a.name}`, 'xss', 'medium', a.value, 'html');
    }));
  }
  function checkCookieSecurity() {
    if (location.protocol !== 'https:') addVuln('no_https', 'Sayfa HTTPS değil', 'HTTP üzerinden iletişim', 'transport', 'high', null, 'network');
    document.cookie.split(';').forEach(c => {
      if (!c.includes('Secure')) addVuln('cookie_no_secure', 'Cookie Secure yok', c.split('=')[0], 'cookie', 'medium', c, 'dom');
      if (!c.includes('SameSite')) addVuln('cookie_no_samesite', 'Cookie SameSite yok', c.split('=')[0], 'csrf', 'medium', c, 'dom');
    });
  }
  function checkStorageSecurity() {
    const sensitive = ['token', 'session', 'auth', 'password', 'jwt'];
    ['localStorage', 'sessionStorage'].forEach(name => {
      const st = window[name];
      for (let i = 0; i < st.length; i++) {
        const k = st.key(i);
        if (sensitive.some(s => k.toLowerCase().includes(s))) addVuln(name + '_' + k, 'Hassas veri ' + name, k, 'storage', 'high', k, 'dom');
      }
    });
  }
  function checkPasswordFields() {
    document.querySelectorAll('input[type=password]').forEach((f, i) => {
      const form = f.closest('form');
      if (form && form.action && form.action.startsWith('http://')) addVuln('pwd_http_' + i, 'Şifre formu HTTP', form.action, 'transport', 'critical', form.action, 'form');
    });
  }
  function checkCSP() {
    const csp = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.content;
    if (!csp) { addVuln('csp_missing', 'CSP yok', 'Meta CSP bulunamadı', 'csp', 'high', null, 'header'); return; }
    if (/\bunsafe-inline\b/i.test(csp) && !csp.includes('nonce')) addVuln('csp_unsafe_inline', 'CSP unsafe-inline', csp, 'csp', 'medium', csp, 'header');
  }

  /* ---------- 14. ANA TARAYICI ---------- */
  function scanPage() {
    vulns.length = 0; seen.clear();
    checkURLParameters();
    checkForXSSVulnerabilities();
    checkCookieSecurity();
    checkStorageSecurity();
    checkPasswordFields();
    checkCSP();
    setTimeout(() => chrome.runtime.sendMessage({ action: 'vulnerabilitiesDetected', vulnerabilities: vulns }), 300);
  }

  /* ---------- 15. MESSAGE LOOP ---------- */
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanPage') { scanPage(); sendResponse({ vulnerabilities }); return true; }
    if (request.action === 'checkStatus') { sendResponse({ status: 'ready' }); return true; }
  });
})();