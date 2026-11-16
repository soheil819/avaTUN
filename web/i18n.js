(() => {
  const supported = ['fa', 'en', 'ru', 'zh-CN', 'tr'];
  const names = { fa: 'پارسی', en: 'English', ru: 'Русский', 'zh-CN': '简体中文', tr: 'Türkçe' };
  const localeTags = { fa: 'fa-IR', en: 'en-US', ru: 'ru-RU', 'zh-CN': 'zh-CN', tr: 'tr-TR' };
  const textOriginals = new WeakMap();
  const attrOriginals = new WeakMap();
  let active = 'fa';
  try { active = localStorage.getItem('avatun.language') || 'fa'; } catch { /* Keep the default language when storage is unavailable. */ }
  if (!supported.includes(active)) active = 'fa';
  let messages = {};
  let patterns = [];
  let observer;

  function lookup(key, depth = 0) {
    if (depth > 4) return '';
    if (messages[key]) return messages[key];
    for (const item of patterns) {
      try {
        const match = key.match(new RegExp(item.pattern));
        if (match) return key.replace(new RegExp(item.pattern), () => item.replace.replace(/\$(\d+)/g, (_, index) => {
          const captured = match[Number(index)] || '';
          return messages[captured] || lookup(captured, depth + 1) || captured;
        }));
      } catch { /* Ignore malformed optional patterns and keep the source text. */ }
    }
    return '';
  }

  function translate(value) {
    const source = String(value ?? '');
    return source.split(/(\r?\n)/).map(line => {
      if (/^\r?\n$/.test(line)) return line;
      const normalized = line.replace(/\s+/g, ' ').trim();
      return lookup(normalized) || line;
    }).join('');
  }

  function translateText(node) {
    let record = textOriginals.get(node);
    if (!record) {
      record = { original: node.nodeValue, last: node.nodeValue };
      textOriginals.set(node, record);
    } else if (node.nodeValue !== record.last) {
      record.original = node.nodeValue;
      record.last = node.nodeValue;
    }
    const original = record.original;
    const value = translate(original);
    if (node.nodeValue !== value) node.nodeValue = value;
    record.last = value;
  }

  function translateElement(element) {
    const attrs = ['placeholder', 'title', 'aria-label', 'alt'];
    for (const attr of attrs) {
      if (!element.hasAttribute?.(attr)) continue;
      let originals = attrOriginals.get(element);
      if (!originals) { originals = {}; attrOriginals.set(element, originals); }
      if (!(attr in originals)) originals[attr] = { original: element.getAttribute(attr), last: element.getAttribute(attr) };
      else if (element.getAttribute(attr) !== originals[attr].last) originals[attr] = { original: element.getAttribute(attr), last: element.getAttribute(attr) };
      const record = originals[attr];
      const original = record.original;
      const translated = lookup(original.trim());
      if (translated) { element.setAttribute(attr, translated); record.last = translated; }
      else { if (element.getAttribute(attr) !== original) element.setAttribute(attr, original); record.last = original; }
    }
  }

  function translateTree(root = document.body) {
    if (!root) return;
    if (root.nodeType === Node.TEXT_NODE) { translateText(root); return; }
    if (root.nodeType === Node.ELEMENT_NODE) translateElement(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) translateText(node);
    root.querySelectorAll?.('[placeholder],[title],[aria-label],[alt]').forEach(translateElement);
  }

  async function setLocale(locale) {
    if (!supported.includes(locale)) return;
    active = locale;
    try { localStorage.setItem('avatun.language', locale); } catch { /* The current choice still applies for this page. */ }
    const response = await fetch(`/locales/${encodeURIComponent(locale)}.json`, { cache: 'no-cache' });
    const catalog = response.ok ? await response.json() : {};
    messages = catalog.messages || {};
    patterns = catalog.patterns || [];
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === 'fa' ? 'rtl' : 'ltr';
    document.querySelectorAll('[data-avatun-language]').forEach(select => {
      select.value = locale;
      select.setAttribute('aria-label', locale === 'fa' ? 'زبان' : locale === 'ru' ? 'Язык' : locale === 'zh-CN' ? '语言' : locale === 'tr' ? 'Dil' : 'Language');
    });
    translateTree();
    window.dispatchEvent(new CustomEvent('avatun:languagechange', { detail: { locale, name: names[locale] } }));
  }

  function addSelector(container, extraClass = '') {
    if (!container || container.querySelector('[data-avatun-language]')) return;
    const select = document.createElement('select');
    select.dataset.avatunLanguage = '';
    select.className = `language-select ${extraClass}`.trim();
    select.setAttribute('aria-label', 'زبان');
    for (const code of supported) {
      const option = document.createElement('option');
      option.value = code;
      option.textContent = names[code];
      select.append(option);
    }
    select.value = active;
    select.addEventListener('change', () => setLocale(select.value));
    container.append(select);
  }

  const ready = (async () => {
    try {
      const response = await fetch(`/locales/${encodeURIComponent(active)}.json`, { cache: 'no-cache' });
      const catalog = response.ok ? await response.json() : {};
      messages = catalog.messages || {};
      patterns = catalog.patterns || [];
    } catch { messages = {}; patterns = []; }
    const start = () => {
      addSelector(document.querySelector('.right'));
      addSelector(document.querySelector('.top-actions'));
      addSelector(document.querySelector('.topbar'));
      if (document.querySelector('.boot-card')) addSelector(document.querySelector('.boot-card'));
      const login = document.querySelector('#loginForm');
      if (login) addSelector(login.querySelector('.brand'));
      document.documentElement.lang = active;
      document.documentElement.dir = active === 'fa' ? 'rtl' : 'ltr';
      translateTree();
      const nativeAlert = window.alert.bind(window);
      const nativeConfirm = window.confirm.bind(window);
      window.alert = message => nativeAlert(translate(message));
      window.confirm = message => nativeConfirm(translate(message));
      observer = new MutationObserver(records => {
        for (const record of records) {
          if (record.type === 'characterData') translateText(record.target);
          for (const node of record.addedNodes || []) translateTree(node);
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    };
    if (document.body) start();
    else document.addEventListener('DOMContentLoaded', start, { once: true });
  })();

  window.avaTUNI18n = { ready, setLocale, translate, get locale() { return active; }, get formatLocale() { return localeTags[active]; }, get name() { return names[active]; } };
})();
