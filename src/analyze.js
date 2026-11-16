/**
 * The rules engine. Pure and side-effect free: it takes the header capture, the
 * page snapshot and the probe results, and returns a flat list of findings plus
 * a score. No network, no DOM, no chrome APIs — which also makes it trivial to
 * reason about and test.
 *
 * Finding: { id, category, severity, title, detail, evidence?, fix, ref? }
 *   category : security | legal | seo | a11y | performance
 *   severity : critical | high | medium | low | info | good
 */

const SEVERITY_WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0, good: 0 }

/** Semver-ish "is a older than b" (missing patch treated as 0). */
function olderThan(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0)
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0)
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) < (pb[i] || 0)) return true
    if ((pa[i] || 0) > (pb[i] || 0)) return false
  }
  return false
}

const SECRET_PATTERNS = [
  ['AWS access key ID', /\bAKIA[0-9A-Z]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Stripe live secret key', /\bsk_live_[0-9a-zA-Z]{24,}\b/],
  ['GitHub personal token', /\bghp_[0-9A-Za-z]{36}\b/],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['Generic secret assignment', /["'`](?:api[_-]?key|secret|passwd|password|token)["'`]\s*[:=]\s*["'][^"']{12,}["']/i],
]

const LIB_ADVISORIES = {
  jquery: { safe: '3.5.0', note: 'jQuery < 3.5 is affected by XSS CVE-2020-11022 / 11023.' },
  angularjs: { safe: '99', note: 'AngularJS (1.x) is end-of-life and no longer receives security fixes.' },
  angular: { safe: '99', note: 'If this is AngularJS 1.x it is end-of-life; confirm the version.' },
  bootstrap: { safe: '4.3.1', note: 'Bootstrap < 4.3.1 has an XSS in data-target/tooltips (CVE-2019-8331).' },
  lodash: { safe: '4.17.21', note: 'Lodash < 4.17.21 has prototype-pollution advisories.' },
  moment: { safe: '2.29.4', note: 'Moment < 2.29.4 has a ReDoS/path-traversal advisory; the library is also in maintenance mode.' },
}

const headerVal = (headers, name) => (headers?.[name.toLowerCase()] || []).join(', ')
const hasHeader = (headers, name) => Boolean(headers?.[name.toLowerCase()]?.length)

export function analyze({ capture, page, probes, isOwner }) {
  const findings = []
  const add = (f) => findings.push(f)
  const headers = capture?.headers || {}
  const https = page.protocol === 'https:'

  // ══ TRANSPORT ════════════════════════════════════════════════════════════
  if (!https) {
    add({
      id: 'no-https',
      category: 'security',
      severity: 'critical',
      title: 'Site is served over plain HTTP',
      detail: 'Traffic is unencrypted and can be read or modified by anyone on the network path.',
      fix: 'Serve the site over HTTPS with a valid certificate (Let’s Encrypt is free) and redirect all HTTP traffic to HTTPS.',
      ref: 'https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security',
    })
  } else {
    add({ id: 'https', category: 'security', severity: 'good', title: 'Served over HTTPS', fix: '' })
  }

  const httpProbe = probes?.httpRedirect
  if (https && httpProbe && httpProbe.ok) {
    const redirects = httpProbe.status >= 300 && httpProbe.status < 400 && /^https:/i.test(httpProbe.location || '')
    if (!redirects) {
      add({
        id: 'no-http-redirect',
        category: 'security',
        severity: 'medium',
        owner: true,
        title: 'HTTP does not redirect to HTTPS',
        detail: `Requesting the http:// version returned ${httpProbe.status}${httpProbe.location ? ' → ' + httpProbe.location : ''} instead of a redirect to https://.`,
        fix: 'Add a 301 redirect from http:// to https:// at the server or CDN edge.',
      })
    }
  }

  // ══ SECURITY HEADERS ═════════════════════════════════════════════════════
  const csp = headerVal(headers, 'content-security-policy')
  if (!csp) {
    add({
      id: 'no-csp',
      category: 'security',
      severity: 'high',
      title: 'No Content-Security-Policy header',
      detail: 'Without a CSP the browser has no allow-list for scripts, so an injected script runs with full trust — the main defence against XSS is absent.',
      fix: "Add a Content-Security-Policy. Start in report-only mode, e.g. default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self', then tighten.",
      ref: 'https://developer.mozilla.org/docs/Web/HTTP/CSP',
    })
  } else {
    const weak = /unsafe-inline|unsafe-eval/i.test(csp)
    add({
      id: weak ? 'weak-csp' : 'csp',
      category: 'security',
      severity: weak ? 'medium' : 'good',
      title: weak ? 'CSP allows unsafe-inline / unsafe-eval' : 'Content-Security-Policy present',
      detail: weak ? 'These directives let inline scripts and eval() run, which defeats much of what a CSP is for.' : undefined,
      evidence: weak ? csp.slice(0, 300) : undefined,
      fix: weak ? "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for any scripts that must be inline." : '',
    })
  }

  const hsts = headerVal(headers, 'strict-transport-security')
  if (https && !hsts) {
    add({
      id: 'no-hsts',
      category: 'security',
      severity: 'medium',
      title: 'No HTTP Strict-Transport-Security header',
      detail: 'Without HSTS a first visit (or a stripped link) can be downgraded to HTTP before the redirect fires.',
      fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload once you are confident).',
      ref: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security',
    })
  } else if (https && hsts) {
    add({ id: 'hsts', category: 'security', severity: 'good', title: 'HSTS enabled', fix: '' })
  }

  const xfo = headerVal(headers, 'x-frame-options')
  const frameAncestors = /frame-ancestors/i.test(csp)
  if (!xfo && !frameAncestors) {
    add({
      id: 'no-clickjacking',
      category: 'security',
      severity: 'medium',
      title: 'No clickjacking protection',
      detail: 'Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be embedded in a hostile iframe.',
      fix: "Send X-Frame-Options: DENY (or SAMEORIGIN), or add frame-ancestors 'self' to the CSP.",
    })
  } else {
    add({ id: 'clickjacking', category: 'security', severity: 'good', title: 'Framing is restricted', fix: '' })
  }

  if (!hasHeader(headers, 'x-content-type-options')) {
    add({
      id: 'no-nosniff',
      category: 'security',
      severity: 'low',
      title: 'No X-Content-Type-Options: nosniff',
      detail: 'The browser may MIME-sniff responses, which can turn an uploaded file into executable script.',
      fix: 'Send X-Content-Type-Options: nosniff on all responses.',
    })
  }
  if (!hasHeader(headers, 'referrer-policy')) {
    add({
      id: 'no-referrer-policy',
      category: 'security',
      severity: 'low',
      title: 'No Referrer-Policy header',
      detail: 'Full URLs (which may carry tokens or IDs) can leak to third parties via the Referer header.',
      fix: 'Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).',
    })
  }
  if (!hasHeader(headers, 'permissions-policy')) {
    add({
      id: 'no-permissions-policy',
      category: 'security',
      severity: 'info',
      title: 'No Permissions-Policy header',
      detail: 'Powerful features (camera, microphone, geolocation, ...) are not explicitly disabled.',
      fix: 'Send a Permissions-Policy that disables features you don’t use, e.g. geolocation=(), camera=(), microphone=().',
    })
  }

  // Version disclosure
  for (const name of ['server', 'x-powered-by']) {
    const val = headerVal(headers, name)
    if (val && /\d/.test(val)) {
      add({
        id: `disclosure-${name}`,
        category: 'security',
        severity: 'low',
        title: `Software version disclosed in ${name} header`,
        detail: 'Exposing exact versions makes it trivial to look up matching exploits.',
        evidence: `${name}: ${val}`,
        fix: `Suppress or genericise the ${name} header at the server/proxy.`,
      })
    }
  }

  // ══ COOKIES ══════════════════════════════════════════════════════════════
  for (const raw of capture?.setCookie || []) {
    const nameMatch = /^\s*([^=]+)=/.exec(raw)
    const cname = nameMatch ? nameMatch[1].trim() : 'cookie'
    const flags = raw.toLowerCase()
    const missing = []
    if (!/;\s*secure/.test(flags) && https) missing.push('Secure')
    if (!/;\s*httponly/.test(flags)) missing.push('HttpOnly')
    if (!/;\s*samesite/.test(flags)) missing.push('SameSite')
    if (missing.length) {
      add({
        id: `cookie-${cname}`,
        category: 'security',
        severity: missing.includes('HttpOnly') ? 'medium' : 'low',
        title: `Cookie “${cname}” missing ${missing.join(', ')}`,
        detail: 'HttpOnly keeps a cookie out of reach of JavaScript (and XSS); Secure keeps it off HTTP; SameSite limits CSRF.',
        fix: `Set the ${missing.join(', ')} attribute${missing.length > 1 ? 's' : ''} on this cookie.`,
        ref: 'https://developer.mozilla.org/docs/Web/HTTP/Cookies',
      })
    }
  }

  // ══ MIXED CONTENT ══════════════════════════════════════════════════════════
  if (page.mixed?.length) {
    add({
      id: 'mixed-content',
      category: 'security',
      severity: 'high',
      title: `${page.mixed.length} insecure (HTTP) resource${page.mixed.length > 1 ? 's' : ''} on an HTTPS page`,
      detail: 'Mixed content is blocked or downgrades the page’s security; an attacker can tamper with these resources.',
      evidence: page.mixed.slice(0, 5).map((m) => `<${m.tag}> ${m.url}`).join('\n'),
      fix: 'Load every subresource over https:// (or use protocol-relative //).',
    })
  }

  // ══ FORMS ══════════════════════════════════════════════════════════════════
  for (const f of page.forms || []) {
    if (f.hasPassword && (!https || f.actionInsecure)) {
      add({
        id: 'password-insecure',
        category: 'security',
        severity: 'critical',
        title: 'Password field submitted without HTTPS',
        detail: `A form with a password field posts to ${f.action}, which is not secure.`,
        fix: 'Serve the page and post the form over HTTPS.',
      })
    }
  }

  // ══ SRI ON EXTERNAL SCRIPTS ══════════════════════════════════════════════
  const externalNoSri = (page.scripts || []).filter((s) => s.external && !s.integrity)
  if (externalNoSri.length) {
    add({
      id: 'no-sri',
      category: 'security',
      severity: 'low',
      title: `${externalNoSri.length} third-party script${externalNoSri.length > 1 ? 's' : ''} without Subresource Integrity`,
      detail: 'If the CDN is compromised, a script without an integrity hash runs unchanged in your users’ browsers.',
      evidence: externalNoSri.slice(0, 5).map((s) => s.src).join('\n'),
      fix: 'Add an integrity="sha384-…" and crossorigin="anonymous" attribute to each third-party <script>.',
      ref: 'https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity',
    })
  }

  // ══ INLINE HANDLERS ══════════════════════════════════════════════════════
  if (page.inlineHandlers > 0 && csp && /unsafe-inline/i.test(csp)) {
    add({
      id: 'inline-handlers',
      category: 'security',
      severity: 'info',
      title: `${page.inlineHandlers} inline event handler(s) in the markup`,
      detail: 'Inline handlers require unsafe-inline in the CSP, which weakens it.',
      fix: 'Move handlers into addEventListener in a separate script so the CSP can drop unsafe-inline.',
    })
  }

  // ══ SECRETS IN SOURCE ══════════════════════════════════════════════════════
  const haystack = (page.inlineScriptText || []).join('\n')
  for (const [label, re] of SECRET_PATTERNS) {
    const m = re.exec(haystack)
    if (m) {
      const snippet = m[0].slice(0, 12) + '…'
      add({
        id: `secret-${label}`,
        category: 'security',
        severity: 'high',
        title: `Possible ${label} exposed in page source`,
        detail: 'Anything in client-side source is public. Live keys here should be treated as compromised.',
        evidence: `${snippet} (matched ${label})`,
        fix: 'Move the secret server-side, rotate the exposed key, and restrict it by referrer/scope where possible.',
      })
    }
  }

  // ══ SOURCE MAPS ══════════════════════════════════════════════════════════
  if (page.sourceMaps) {
    add({
      id: 'source-maps',
      category: 'security',
      severity: 'info',
      title: 'Source maps referenced',
      detail: 'Source maps expose your original, unminified source. Fine for staging; usually undesirable in production.',
      fix: 'Disable source-map emission (or restrict access) for production builds.',
    })
  }

  // ══ OUTDATED LIBRARIES ════════════════════════════════════════════════════
  for (const lib of page.libs || []) {
    const adv = LIB_ADVISORIES[lib.name.toLowerCase()]
    if (adv && lib.version && olderThan(lib.version, adv.safe)) {
      add({
        id: `lib-${lib.name}`,
        category: 'security',
        severity: 'high',
        title: `Outdated ${lib.name} (${lib.version})`,
        detail: adv.note,
        fix: `Upgrade ${lib.name} to a current release.`,
      })
    }
  }

  // ══ EXPOSED FILES (probes) ════════════════════════════════════════════════
  for (const p of probes?.files || []) {
    if (p.ok && p.status === 200 && !/<!doctype html|<html/i.test(p.bodyStart || '')) {
      add({
        id: `exposed-${p.label}`,
        category: 'security',
        severity: p.severity || 'high',
        owner: true,
        title: `Sensitive path is publicly reachable: ${p.path}`,
        detail: p.note,
        evidence: `HTTP 200 · ${p.contentType || 'unknown type'}`,
        fix: `Block or remove ${p.path}. It should never be served to the public.`,
      })
    }
  }
  const securityTxt = probes?.securityTxt
  if (securityTxt && !(securityTxt.ok && securityTxt.status === 200)) {
    add({
      id: 'no-security-txt',
      category: 'security',
      severity: 'info',
      owner: true,
      title: 'No /.well-known/security.txt',
      detail: 'A security.txt gives researchers a way to report vulnerabilities to you.',
      fix: 'Publish /.well-known/security.txt with a Contact: and Expires: field.',
      ref: 'https://securitytxt.org',
    })
  }

  // ══ ACTIVE PROBE: REFLECTED INPUT ═════════════════════════════════════════
  const refl = probes?.reflection
  if (isOwner && refl) {
    if (refl.reflected) {
      add({
        id: 'reflected-input',
        category: 'security',
        severity: 'high',
        owner: true,
        title: 'Query input reflected into the response unencoded',
        detail: 'A unique marker placed in the URL came back in the HTML without encoding. That is the pre-condition for reflected XSS — worth manual confirmation.',
        evidence: `Marker reflected from ?${refl.param}=`,
        fix: 'HTML-encode all user input on output, and add a Content-Security-Policy as defence in depth.',
        ref: 'https://owasp.org/www-community/attacks/xss/',
      })
    } else if (refl.ok) {
      add({ id: 'reflection-clean', category: 'security', severity: 'good', owner: true, title: 'Test marker was not reflected unencoded', fix: '' })
    }
  }

  // ══ LEGAL / PRIVACY ═══════════════════════════════════════════════════════
  const L = page.legal || {}
  if (!L.privacyPolicy)
    add({ id: 'no-privacy', category: 'legal', severity: 'medium', title: 'No privacy policy link found', detail: 'Most jurisdictions (GDPR, CCPA) require a privacy policy once you collect any personal data — including via analytics.', fix: 'Add a clearly linked privacy policy, usually in the footer.' })
  if (!L.terms)
    add({ id: 'no-terms', category: 'legal', severity: 'low', title: 'No terms / conditions link found', detail: 'Terms of service set the rules for using your site and limit your liability.', fix: 'Add a terms of service / legal notice link.' })
  if (!L.contact)
    add({ id: 'no-contact', category: 'legal', severity: 'low', title: 'No contact / imprint link found', detail: 'Some regions (e.g. Germany’s Impressum) legally require identifiable contact details.', fix: 'Add a contact or imprint page.' })

  const trackers = page.trackers || []
  if (trackers.length && !L.cookieBanner) {
    add({
      id: 'trackers-no-consent',
      category: 'legal',
      severity: 'high',
      title: `${trackers.length} tracker(s) load with no visible consent banner`,
      detail: `Detected: ${trackers.join(', ')}. Under GDPR/ePrivacy, non-essential trackers need consent *before* they load.`,
      fix: 'Add a consent banner that blocks these until the visitor opts in (a Consent Management Platform handles this).',
    })
  } else if (trackers.length) {
    add({
      id: 'trackers-present',
      category: 'legal',
      severity: 'info',
      title: `${trackers.length} third-party tracker(s) present`,
      detail: `Detected: ${trackers.join(', ')}. Make sure your consent banner actually gates these before they run.`,
      fix: 'Verify the banner blocks trackers until consent, and list them in your privacy policy.',
    })
  }
  if (page.cookiesVisible > 0 && !L.cookieBanner && trackers.length === 0) {
    add({ id: 'cookies-no-banner', category: 'legal', severity: 'low', title: 'Cookies set without a visible consent banner', detail: 'If any cookies are non-essential, they likely require consent first.', fix: 'Add a cookie consent banner, or confirm every cookie is strictly necessary.' })
  }

  // ══ SEO ════════════════════════════════════════════════════════════════════
  const s = page.seo || {}
  if (!s.title) add({ id: 'no-title', category: 'seo', severity: 'medium', title: 'Missing <title>', fix: 'Add a unique, descriptive <title> (50–60 characters).' })
  else if (s.title.length > 65) add({ id: 'long-title', category: 'seo', severity: 'low', title: 'Title is long and may be truncated in search results', evidence: `${s.title.length} characters`, fix: 'Aim for roughly 50–60 characters.' })
  if (!s.description) add({ id: 'no-description', category: 'seo', severity: 'low', title: 'Missing meta description', fix: 'Add a meta description (~150 characters) summarising the page.' })
  if (!s.viewport) add({ id: 'no-viewport', category: 'seo', severity: 'medium', title: 'No responsive viewport meta tag', detail: 'The page will render zoomed-out and hard to use on phones.', fix: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.' })
  if (!s.ogTitle || !s.ogImage) add({ id: 'no-og', category: 'seo', severity: 'low', title: 'Incomplete Open Graph tags', detail: 'Links shared to social platforms won’t show a rich preview.', fix: 'Add og:title, og:description and og:image meta tags.' })
  if (!s.canonical) add({ id: 'no-canonical', category: 'seo', severity: 'info', title: 'No canonical URL', fix: 'Add <link rel="canonical"> to avoid duplicate-content ambiguity.' })
  if (s.h1Count === 0) add({ id: 'no-h1', category: 'seo', severity: 'low', title: 'No <h1> heading on the page', fix: 'Add exactly one <h1> describing the page.' })
  else if (s.h1Count > 1) add({ id: 'many-h1', category: 'seo', severity: 'info', title: `${s.h1Count} <h1> headings`, fix: 'Prefer a single <h1> per page.' })
  const robots = probes?.robots
  if (robots && !(robots.ok && robots.status === 200)) add({ id: 'no-robots', category: 'seo', severity: 'info', title: 'No robots.txt', fix: 'Add a robots.txt (even an allow-all one) and reference your sitemap.' })
  const sitemap = probes?.sitemap
  if (sitemap && !(sitemap.ok && sitemap.status === 200)) add({ id: 'no-sitemap', category: 'seo', severity: 'info', title: 'No sitemap.xml at the site root', fix: 'Publish a sitemap.xml so search engines can crawl every page.' })

  // ══ ACCESSIBILITY ═══════════════════════════════════════════════════════════
  const a = page.a11y || {}
  if (!a.hasLang) add({ id: 'no-lang', category: 'a11y', severity: 'medium', title: 'No lang attribute on <html>', detail: 'Screen readers use it to pick the right pronunciation.', fix: 'Add lang="en" (or the correct language) to the <html> tag.' })
  if (a.imagesNoAlt > 0) add({ id: 'img-no-alt', category: 'a11y', severity: 'medium', title: `${a.imagesNoAlt} of ${a.imagesTotal} images have no alt attribute`, detail: 'Images without alt text are invisible to screen-reader users.', fix: 'Add descriptive alt text (or alt="" for purely decorative images).' })
  if (a.inputsNoLabel > 0) add({ id: 'input-no-label', category: 'a11y', severity: 'medium', title: `${a.inputsNoLabel} form field(s) without an associated label`, fix: 'Associate each field with a <label for>, or add aria-label.' })
  if (a.buttonsNoName > 0) add({ id: 'btn-no-name', category: 'a11y', severity: 'low', title: `${a.buttonsNoName} button/link(s) with no accessible name`, detail: 'Icon-only controls announce as “button” with no purpose.', fix: 'Add visible text or an aria-label.' })

  // ══ PERFORMANCE ═════════════════════════════════════════════════════════════
  const blocking = (page.scripts || []).filter((sc) => sc.inHead && sc.src && !sc.async && !sc.defer)
  if (blocking.length) add({ id: 'render-blocking', category: 'performance', severity: 'low', title: `${blocking.length} render-blocking script(s) in <head>`, detail: 'Synchronous scripts in the head delay first paint.', fix: 'Add defer (or async) to these <script> tags, or move them before </body>.' })
  if (a.imagesTotal > 0 && a.imagesNoDimensions > 0) add({ id: 'img-no-dims', category: 'performance', severity: 'info', title: `${a.imagesNoDimensions} image(s) without width/height`, detail: 'Missing dimensions cause layout shift (CLS) as images load.', fix: 'Set explicit width and height (or an aspect-ratio) on images.' })
  if (a.imagesTotal >= 5 && a.imagesLazy === 0) add({ id: 'no-lazy', category: 'performance', severity: 'info', title: 'No images use lazy loading', fix: 'Add loading="lazy" to below-the-fold images.' })

  // ══ SCORE ════════════════════════════════════════════════════════════════
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, good: 0 }
  let penalty = 0
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1
    penalty += SEVERITY_WEIGHT[f.severity] || 0
  }
  const score = Math.max(0, Math.min(100, 100 - penalty))
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F'

  return { findings, counts, score, grade, scannedUrl: page.url, scannedAt: Date.now() }
}
