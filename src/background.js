/**
 * VulnChecker service worker.
 *
 * Two jobs the page context can't do on its own:
 *
 *  1. Capture the *response headers* of the main document as it loads. A page
 *     can't read its own response headers from JS, so security headers (CSP,
 *     HSTS, X-Frame-Options, Set-Cookie flags, ...) are invisible to a content
 *     script. We snapshot them here per tab via webRequest.
 *
 *  2. Run GET-only probes for a handful of well-known paths (/.git/HEAD, /.env,
 *     security.txt, robots.txt ...) and follow the http->https redirect. The
 *     extension has host permissions, so unlike page fetch() it can read
 *     cross-origin responses. Probes are read-only: no POST, no bodies, nothing
 *     that changes server state.
 *
 * Everything stays local to the browser. Nothing is ever sent to a server.
 */

/** tabId -> { url, headers: {name->value[]}, setCookie: string[], statusCode, remoteIp } */
const captures = new Map()

function lower(name) {
  return String(name || '').toLowerCase()
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return
    const headers = {}
    const setCookie = []
    for (const h of details.responseHeaders || []) {
      const name = lower(h.name)
      if (name === 'set-cookie') {
        setCookie.push(h.value || '')
        continue
      }
      ;(headers[name] ||= []).push(h.value || '')
    }
    captures.set(details.tabId, {
      url: details.url,
      headers,
      setCookie,
      statusCode: details.statusCode,
      remoteIp: details.ip || null,
      capturedAt: Date.now(),
    })
  },
  { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders']
)

chrome.tabs.onRemoved.addListener((tabId) => captures.delete(tabId))

/** Follow up to a few redirects manually so we can see each Location hop. */
async function probe(url, options = {}) {
  const { method = 'GET', timeout = 7000 } = options
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)
  try {
    const res = await fetch(url, {
      method,
      redirect: 'manual',
      credentials: 'omit',
      cache: 'no-store',
      signal: controller.signal,
    })
    let bodyStart = ''
    let matched = false
    try {
      const text = await res.text()
      bodyStart = text.slice(0, 2048)
      // Reflection check: did our exact marker come back unencoded anywhere?
      if (options.match) matched = text.includes(options.match)
    } catch {
      /* opaque or empty */
    }
    return {
      ok: true,
      status: res.status,
      type: res.type,
      location: res.headers.get('location'),
      contentType: res.headers.get('content-type'),
      bodyStart,
      matched,
    }
  } catch (err) {
    return { ok: false, error: String(err && err.name === 'AbortError' ? 'timeout' : err) }
  } finally {
    clearTimeout(timer)
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'getCapture') {
    sendResponse(captures.get(msg.tabId) || null)
    return false
  }
  if (msg?.type === 'probe') {
    probe(msg.url, msg.options).then(sendResponse)
    return true // async
  }
  if (msg?.type === 'probeMany') {
    Promise.all(
      (msg.urls || []).map((u) => probe(u, msg.options).then((r) => ({ url: u, ...r })))
    ).then(sendResponse)
    return true
  }
  return false
})
