import { runScan } from './scan.js'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'good']
const SEV_COLOR = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  info: 'var(--info)',
  good: 'var(--good)',
}

const $ = (id) => document.getElementById(id)
let currentTab = null

async function getTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  return tab
}

const ownerKey = (origin) => `owner:${origin}`

async function isOwner(origin) {
  const stored = await chrome.storage.local.get(ownerKey(origin))
  return !!stored[ownerKey(origin)]
}

function setStatus(text, spinning) {
  $('status').innerHTML = spinning ? `<span class="spinner"></span> ${text}` : text
}

function renderTallies(counts) {
  const el = $('tallies')
  el.innerHTML = ''
  for (const sev of SEV_ORDER) {
    if (!counts[sev]) continue
    const b = document.createElement('span')
    b.className = 'badge'
    b.style.color = SEV_COLOR[sev]
    b.innerHTML = `<span class="dot"></span>${counts[sev]} ${sev}`
    el.appendChild(b)
  }
}

function renderRing(score, grade) {
  const circumference = 2 * Math.PI * 33
  const fill = $('ringFill')
  fill.style.strokeDashoffset = String(circumference * (1 - score / 100))
  fill.setAttribute('stroke', score >= 80 ? 'var(--good)' : score >= 45 ? 'var(--medium)' : 'var(--critical)')
  $('grade').textContent = grade
  $('score').textContent = score
}

function renderTop(findings) {
  const issues = findings
    .filter((f) => f.severity !== 'good')
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .slice(0, 4)
  const ul = $('top')
  ul.innerHTML = ''
  if (!issues.length) {
    const li = document.createElement('li')
    li.style.color = 'var(--good)'
    li.innerHTML = `<span class="dot"></span><span class="t">No issues found — nicely done.</span>`
    ul.appendChild(li)
    return
  }
  for (const f of issues) {
    const li = document.createElement('li')
    li.style.color = SEV_COLOR[f.severity]
    li.innerHTML = `<span class="dot"></span><span class="t">${escapeHtml(f.title)}</span>`
    ul.appendChild(li)
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])
}

async function scan() {
  $('report').disabled = true
  $('scoreRow').classList.add('hidden')
  $('top').innerHTML = ''
  setStatus('Scanning this page…', true)

  currentTab = await getTab()
  if (!currentTab || !/^https?:/.test(currentTab.url || '')) {
    $('host').textContent = currentTab?.url || ''
    setStatus('Open a normal http(s) page to scan it. Chrome pages, the Web Store and PDFs are off-limits to extensions.', false)
    return
  }

  const origin = new URL(currentTab.url).origin
  $('host').textContent = origin
  const owner = await isOwner(origin)
  $('ownerToggle').checked = owner

  try {
    const bundle = await runScan(currentTab, { isOwner: owner })
    await chrome.storage.session.set({ lastResult: bundle })

    renderRing(bundle.result.score, bundle.result.grade)
    renderTallies(bundle.result.counts)
    renderTop(bundle.result.findings)
    $('scoreRow').classList.remove('hidden')
    const issues = bundle.result.findings.filter((f) => f.severity !== 'good').length
    setStatus(`${issues} issue${issues === 1 ? '' : 's'} found across security, legal, SEO, accessibility and performance.`, false)
    $('report').disabled = false
  } catch (err) {
    setStatus(err.message || 'Scan failed.', false)
  }
}

$('rescan').addEventListener('click', scan)
$('report').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('src/report.html') })
})
$('ownerToggle').addEventListener('change', async (e) => {
  if (!currentTab) return
  const origin = new URL(currentTab.url).origin
  await chrome.storage.local.set({ [ownerKey(origin)]: e.target.checked })
  scan()
})

const manifest = chrome.runtime.getManifest()
$('verBadge').textContent = 'v' + manifest.version

scan()
