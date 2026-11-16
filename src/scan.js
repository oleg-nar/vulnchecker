/**
 * Orchestrates a single scan and hands back the analysed result. Shared by the
 * popup and the "Re-scan" button. Read-only throughout: it collects, probes
 * with GET requests, and analyses — it never changes the page or the server.
 */
import { vulncheckerCollect } from './collect.js'
import { analyze } from './analyze.js'

const send = (msg) => chrome.runtime.sendMessage(msg)

/** Sensitive paths worth a look. All GET, all harmless to request. */
const FILE_PROBES = [
  { path: '/.env', label: 'env', severity: 'critical', note: 'Environment files typically hold database credentials, API keys and secrets.' },
  { path: '/.git/HEAD', label: 'git-head', severity: 'high', note: 'An exposed .git directory lets anyone reconstruct your full source and history.' },
  { path: '/.git/config', label: 'git-config', severity: 'high', note: 'Reveals repository remotes and structure; part of an exposed .git directory.' },
  { path: '/.DS_Store', label: 'dsstore', severity: 'low', note: 'A macOS index file that leaks your directory listing.' },
  { path: '/.env.local', label: 'env-local', severity: 'critical', note: 'A local environment file that usually contains secrets.' },
]

export async function runScan(tab, { isOwner = false } = {}) {
  const url = new URL(tab.url)
  const base = url.origin

  // 1) Response headers, captured by the background worker as the page loaded.
  //    If we somehow missed them (e.g. served from BFCache), reload-less
  //    fallback: they'll simply be treated as absent.
  const capture = await send({ type: 'getCapture', tabId: tab.id })

  // 2) DOM / library snapshot, gathered inside the page.
  let page
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: 'MAIN',
      func: vulncheckerCollect,
    })
    page = result
  } catch (err) {
    throw new Error('Could not read this page. Chrome blocks extensions on internal pages (chrome://, the Web Store, PDFs). Open a normal http(s) site and try again.')
  }
  if (!page) throw new Error('The page returned no data — try reloading it first.')

  // 3) Read-only probes, in parallel.
  const marker = `vz${Math.random().toString(36).slice(2, 8)}"><vzmark>`
  const [files, securityTxt, robots, sitemap, httpRedirect, reflection] = await Promise.all([
    send({ type: 'probeMany', urls: FILE_PROBES.map((f) => base + f.path) }).then((res) =>
      (res || []).map((r, i) => ({ ...FILE_PROBES[i], ...r }))
    ),
    send({ type: 'probe', url: base + '/.well-known/security.txt' }),
    send({ type: 'probe', url: base + '/robots.txt' }),
    send({ type: 'probe', url: base + '/sitemap.xml' }),
    url.protocol === 'https:'
      ? send({ type: 'probe', url: 'http://' + url.host + '/' })
      : Promise.resolve(null),
    isOwner
      ? send({
          type: 'probe',
          url: base + url.pathname + (url.search ? url.search + '&' : '?') + 'vzprobe=' + encodeURIComponent(marker),
          options: { match: marker },
        }).then((r) => ({ ...r, reflected: !!r?.matched, param: 'vzprobe' }))
      : Promise.resolve(null),
  ])

  const probes = { files, securityTxt, robots, sitemap, httpRedirect, reflection }
  const result = analyze({ capture, page, probes, isOwner })
  return { result, capture, page, probes }
}
