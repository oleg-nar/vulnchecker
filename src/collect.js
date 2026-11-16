/**
 * Runs inside the audited page (injected via chrome.scripting in the MAIN
 * world, so it can also read library globals like `jQuery.fn.jquery`). It only
 * *reads* the page and returns a plain, serialisable snapshot — it never
 * modifies the DOM or sends anything anywhere.
 *
 * Kept as a single self-contained function because that's what executeScript
 * injects.
 */
export function vulncheckerCollect() {
  const origin = location.origin
  const isSameOrigin = (url) => {
    try {
      return new URL(url, location.href).origin === origin
    } catch {
      return true
    }
  }
  const abs = (url) => {
    try {
      return new URL(url, location.href).href
    } catch {
      return url
    }
  }

  // ── Scripts & subresources ────────────────────────────────────────────────
  const scripts = [...document.scripts].map((s) => ({
    src: s.src || null,
    inline: !s.src,
    integrity: s.integrity || null,
    crossorigin: s.crossOrigin || null,
    async: s.async,
    defer: s.defer,
    inHead: !!s.closest('head'),
    external: s.src ? !isSameOrigin(s.src) : false,
    text: s.src ? '' : (s.textContent || '').slice(0, 20000),
  }))

  const stylesheets = [...document.querySelectorAll('link[rel~="stylesheet"]')].map((l) => ({
    href: l.href || null,
    integrity: l.integrity || null,
    external: l.href ? !isSameOrigin(l.href) : false,
  }))

  // ── Mixed content (http subresources on an https page) ────────────────────
  const mixed = []
  if (location.protocol === 'https:') {
    const attrEls = [...document.querySelectorAll('[src],[href]')]
    for (const el of attrEls) {
      const raw = el.getAttribute('src') || el.getAttribute('href') || ''
      if (/^http:\/\//i.test(raw)) mixed.push({ tag: el.tagName.toLowerCase(), url: raw.slice(0, 300) })
    }
  }

  // ── Forms ─────────────────────────────────────────────────────────────────
  const forms = [...document.forms].map((f) => {
    const fields = [...f.elements].filter((e) => e.tagName === 'INPUT')
    return {
      action: abs(f.getAttribute('action') || location.href),
      actionInsecure: /^http:\/\//i.test(abs(f.getAttribute('action') || location.href)),
      method: (f.method || 'get').toLowerCase(),
      hasPassword: fields.some((e) => e.type === 'password'),
      passwordAutocompleteOff: fields.some(
        (e) => e.type === 'password' && (e.autocomplete || '').toLowerCase() === 'off'
      ),
    }
  })

  // ── Links opening new tabs without rel=noopener ───────────────────────────
  const unsafeTargetBlank = [...document.querySelectorAll('a[target="_blank"]')]
    .filter((a) => {
      const rel = (a.rel || '').toLowerCase()
      return !rel.includes('noopener') && !rel.includes('noreferrer') && !isSameOrigin(a.href)
    })
    .slice(0, 20)
    .map((a) => a.href.slice(0, 200))

  // ── Inline event handlers (a CSP with unsafe-inline smell) ────────────────
  const inlineHandlers = document.querySelectorAll(
    '[onclick],[onload],[onerror],[onmouseover],[onsubmit]'
  ).length

  // ── Meta / SEO / social ───────────────────────────────────────────────────
  const meta = (name) =>
    document.querySelector(`meta[name="${name}" i]`)?.content ||
    document.querySelector(`meta[property="${name}" i]`)?.content ||
    null
  const seo = {
    title: document.title || null,
    description: meta('description'),
    canonical: document.querySelector('link[rel="canonical"]')?.href || null,
    viewport: !!document.querySelector('meta[name="viewport" i]'),
    robots: meta('robots'),
    charset: document.characterSet || null,
    lang: document.documentElement.lang || null,
    favicon: !!document.querySelector('link[rel~="icon"]'),
    ogTitle: meta('og:title'),
    ogImage: meta('og:image'),
    ogDescription: meta('og:description'),
    twitterCard: meta('twitter:card'),
    h1Count: document.querySelectorAll('h1').length,
  }

  // ── Accessibility quick signals ───────────────────────────────────────────
  const imgs = [...document.images]
  const inputs = [...document.querySelectorAll('input, select, textarea')].filter(
    (e) => !['hidden', 'submit', 'button', 'reset'].includes(e.type)
  )
  const labelledInput = (e) => {
    if (e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') || e.getAttribute('title')) return true
    if (e.id && document.querySelector(`label[for="${CSS.escape(e.id)}"]`)) return true
    return !!e.closest('label')
  }
  const namedControl = (el) =>
    (el.textContent || '').trim() ||
    el.getAttribute('aria-label') ||
    el.getAttribute('title') ||
    el.querySelector('img[alt]')?.getAttribute('alt')
  const a11y = {
    imagesTotal: imgs.length,
    imagesNoAlt: imgs.filter((i) => !i.hasAttribute('alt')).length,
    inputsTotal: inputs.length,
    inputsNoLabel: inputs.filter((e) => !labelledInput(e)).length,
    buttonsNoName: [...document.querySelectorAll('button, a[href]')].filter((el) => !namedControl(el)).length,
    hasLang: !!document.documentElement.lang,
    imagesNoDimensions: imgs.filter((i) => !i.getAttribute('width') || !i.getAttribute('height')).length,
    imagesLazy: imgs.filter((i) => (i.loading || '') === 'lazy').length,
  }

  // ── Legal / privacy signals ───────────────────────────────────────────────
  const links = [...document.querySelectorAll('a[href]')]
  const linkMatch = (re) => links.some((a) => re.test((a.textContent || '') + ' ' + a.href))
  const legal = {
    privacyPolicy: linkMatch(/privacy/i),
    terms: linkMatch(/terms|conditions|tos\b/i),
    cookiePolicy: linkMatch(/cookie/i),
    contact: linkMatch(/contact|imprint|impressum/i),
    cookieBanner: !!document.querySelector(
      '[id*="cookie" i],[class*="cookie" i],[id*="consent" i],[class*="consent" i],[aria-label*="cookie" i]'
    ),
  }

  // ── Third-party trackers, by script origin ────────────────────────────────
  const TRACKERS = [
    ['Google Analytics', /google-analytics\.com|googletagmanager\.com|gtag\/js/i],
    ['Google Ads', /googlesyndication|doubleclick\.net|adservice\.google/i],
    ['Meta Pixel', /connect\.facebook\.net|facebook\.com\/tr/i],
    ['TikTok Pixel', /analytics\.tiktok\.com/i],
    ['Hotjar', /static\.hotjar\.com|hotjar\.com/i],
    ['Segment', /cdn\.segment\.com/i],
    ['Mixpanel', /cdn\.mxpnl\.com|mixpanel/i],
    ['LinkedIn', /snap\.licdn\.com/i],
    ['Sentry', /browser\.sentry-cdn|sentry\.io/i],
    ['Intercom', /widget\.intercom\.io/i],
  ]
  const allUrls = [...scripts.map((s) => s.src), ...stylesheets.map((s) => s.href)].filter(Boolean)
  const trackers = TRACKERS.filter(([, re]) => allUrls.some((u) => re.test(u))).map(([name]) => name)

  // ── Library versions (from globals + src filenames) ───────────────────────
  const libs = []
  try {
    const w = window
    const jq = w.jQuery || w.$
    if (jq && jq.fn && jq.fn.jquery) libs.push({ name: 'jQuery', version: jq.fn.jquery })
    if (w.React && w.React.version) libs.push({ name: 'React', version: w.React.version })
    if (w.angular && w.angular.version) libs.push({ name: 'AngularJS', version: w.angular.version.full })
    if (w.Vue && w.Vue.version) libs.push({ name: 'Vue', version: w.Vue.version })
    if (w.bootstrap && w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION)
      libs.push({ name: 'Bootstrap', version: w.bootstrap.Tooltip.VERSION })
    if (w.moment && w.moment.version) libs.push({ name: 'Moment.js', version: w.moment.version })
    if (w._ && w._.VERSION) libs.push({ name: 'Lodash', version: w._.VERSION })
  } catch {
    /* cross-origin frame or locked-down global */
  }
  // Also pull versions out of CDN filenames like /jquery-3.4.1.min.js
  for (const url of allUrls) {
    const m = /\/([a-z][a-z0-9._-]*?)[-@](\d+\.\d+(?:\.\d+)?)(?:[.-]min)?\.(?:js|css)/i.exec(url)
    if (m && !libs.some((l) => l.name.toLowerCase() === m[1].toLowerCase()))
      libs.push({ name: m[1], version: m[2], fromUrl: true })
  }

  // ── Source maps referenced in inline scripts ──────────────────────────────
  const sourceMaps = scripts.some((s) => /sourceMappingURL=/.test(s.text))

  return {
    url: location.href,
    origin,
    protocol: location.protocol,
    title: document.title,
    cookiesVisible: document.cookie ? document.cookie.split(';').length : 0,
    hasServiceWorker: 'serviceWorker' in navigator && !!navigator.serviceWorker.controller,
    counts: {
      scripts: scripts.length,
      externalScripts: scripts.filter((s) => s.external).length,
      inlineScripts: scripts.filter((s) => s.inline).length,
    },
    scripts: scripts.map(({ text, ...rest }) => ({ ...rest, inlineLen: text.length })),
    inlineScriptText: scripts.filter((s) => s.inline).map((s) => s.text),
    stylesheets,
    mixed,
    forms,
    unsafeTargetBlank,
    inlineHandlers,
    seo,
    a11y,
    legal,
    trackers,
    libs,
    sourceMaps,
  }
}
