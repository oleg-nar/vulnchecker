const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'good']
const SEV_COLOR = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  info: 'var(--info)',
  good: 'var(--good)',
}
const CATEGORIES = [
  ['security', 'Security', 'Headers, transport, cookies and client-side exposure.'],
  ['legal', 'Legal & privacy', 'Privacy, consent and the disclosures a site is expected to carry.'],
  ['seo', 'SEO', 'How clearly search engines and social platforms can read the page.'],
  ['a11y', 'Accessibility', 'Whether assistive technology can make sense of the page.'],
  ['performance', 'Performance', 'What holds up the first render.'],
]
const CAT_LABEL = Object.fromEntries(CATEGORIES.map(([k, l]) => [k, l]))
const CAT_INTRO = Object.fromEntries(CATEGORIES.map(([k, , d]) => [k, d]))

const $ = (id) => document.getElementById(id)
const escapeHtml = (s) =>
  String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])

let bundle = null
let activeCat = 'all'
let showGood = false
let view = 'standard' // 'standard' | 'owner'

let standardFindings = []
let ownerFindings = []
let activeRan = false

function safeHost(url) {
  try {
    return new URL(url).host
  } catch {
    return 'the site'
  }
}

/** First sentence of a string, casing preserved. */
function firstSentence(text) {
  if (!text) return ''
  const m = String(text).match(/^.*?[.!?](\s|$)/)
  return (m ? m[0] : String(text)).trim()
}

/** "a", "a and b", "a, b and c" */
function listJoin(arr) {
  if (arr.length <= 1) return arr.join('')
  if (arr.length === 2) return `${arr[0]} and ${arr[1]}`
  return `${arr.slice(0, -1).join(', ')} and ${arr[arr.length - 1]}`
}

async function load() {
  const { lastResult } = await chrome.storage.session.get('lastResult')
  if (!lastResult) {
    $('exec').classList.add('hidden')
    $('viewswitch').classList.add('hidden')
    $('groups').innerHTML =
      '<p class="empty">No scan yet. Open the VulnChecker popup on a page and run a scan first.</p>'
    return
  }
  bundle = lastResult
  standardFindings = bundle.result.findings.filter((f) => !f.owner)
  ownerFindings = bundle.result.findings.filter((f) => f.owner)
  activeRan = !!bundle.probes?.reflection

  renderSummary()
  renderExec()
  renderFilters()
  render()
}

function renderSummary() {
  const { result } = bundle
  const circumference = 2 * Math.PI * 56
  const fill = $('ringFill')
  fill.style.strokeDashoffset = String(circumference * (1 - result.score / 100))
  fill.setAttribute('stroke', result.score >= 80 ? 'var(--good)' : result.score >= 45 ? 'var(--medium)' : 'var(--critical)')
  $('grade').textContent = result.grade
  $('score').textContent = result.score
  $('url').textContent = result.scannedUrl
  $('when').textContent = 'Scanned ' + new Date(result.scannedAt).toLocaleString()
  const t = $('tallies')
  t.innerHTML = ''
  for (const sev of SEV_ORDER) {
    if (!result.counts[sev]) continue
    const b = document.createElement('span')
    b.className = 'badge'
    b.style.color = SEV_COLOR[sev]
    b.innerHTML = `<span class="dot"></span>${result.counts[sev]} ${sev}`
    t.appendChild(b)
  }
}

// ── Written summary ──────────────────────────────────────────────────────────
function execSentences(result) {
  const { score, grade, counts, findings } = result
  const host = safeHost(result.scannedUrl)
  const issues = findings.filter((f) => f.severity !== 'good')
  const gradeWord = { A: 'strong', B: 'solid', C: 'mixed', D: 'weak', F: 'poor' }[grade] || 'mixed'
  const out = []

  out.push(`This audit of <b>${escapeHtml(host)}</b> scores <b>${score}/100</b> (grade ${grade}) — a ${gradeWord} overall posture.`)

  if (!issues.length) {
    out.push('None of the checks flagged a problem, which is a genuinely clean result across the board.')
  } else {
    const parts = ['critical', 'high', 'medium', 'low', 'info']
      .filter((s) => counts[s])
      .map((s) => `<b>${counts[s]}</b> ${s === 'info' ? 'advisory' : s}`)
    out.push(`It raised ${issues.length} ${issues.length === 1 ? 'item' : 'items'} in total — ${listJoin(parts)}.`)

    const worst = issues.slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))[0]
    const clause = firstSentence(worst.detail || '')
    out.push(`The most pressing is <b>${escapeHtml(worst.title)}</b>.${clause ? ' ' + escapeHtml(clause) : ''}`)

    const cats = [...new Set(issues.map((f) => f.category))]
    out.push(`Findings span ${listJoin(cats.map((c) => (CAT_LABEL[c] || c).toLowerCase()))}.`)

    if (ownerFindings.filter((f) => f.severity !== 'good').length) {
      out.push(
        `Some findings come from checks that query your server directly — those are collected under the <b>“I own this site”</b> view.`
      )
    }
  }

  out.push('Every item below carries the evidence found and a specific fix; work down from the most severe.')
  return out
}

function renderExec() {
  const { result } = bundle
  const issues = result.findings.filter((f) => f.severity !== 'good')
  const priorities = issues
    .slice()
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .slice(0, 3)

  let html = `<h2>Executive summary</h2><p class="lede">${execSentences(result).join(' ')}</p>`
  if (priorities.length) {
    html += `<h3>Fix these first</h3><ol class="prio">`
    for (const f of priorities) {
      html += `<li><b>${escapeHtml(f.title)}.</b> ${escapeHtml(f.detail || '')}${
        f.fix ? ` <span class="fixline">Fix: ${escapeHtml(f.fix)}</span>` : ''
      }</li>`
    }
    html += `</ol>`
  }
  $('exec').innerHTML = html
}

// ── View switch + filters ────────────────────────────────────────────────────
function currentSource() {
  return view === 'owner' ? ownerFindings : standardFindings
}

function renderFilters() {
  const wrap = $('filters')
  wrap.innerHTML = ''
  const source = currentSource()
  const cats = [['all', 'All'], ...CATEGORIES.map(([k, l]) => [k, l])]
  for (const [key, label] of cats) {
    const total = source.filter((f) => key === 'all' || f.category === key).length
    if (key !== 'all' && total === 0) continue
    const chip = document.createElement('button')
    chip.className = 'chip'
    chip.setAttribute('aria-pressed', String(activeCat === key))
    chip.textContent = label
    chip.addEventListener('click', () => {
      activeCat = key
      renderFilters()
      render()
    })
    wrap.appendChild(chip)
  }
}

function renderOwnerBanner() {
  const banner = $('ownerBanner')
  if (view !== 'owner') {
    banner.classList.add('hidden')
    return
  }
  banner.classList.remove('hidden')
  banner.innerHTML = activeRan
    ? `<b>Owner-only checks.</b> These come from requests VulnChecker made straight to your server — probing for exposed paths like <code>/.env</code> and <code>/.git</code>, the HTTP→HTTPS redirect, <code>security.txt</code>, and the active reflected-input test you enabled. They only make sense on a site you control, so they live here rather than in the standard report. All are counted in the score above.`
    : `<b>Owner-only checks.</b> These come from requests made straight to your server (exposed paths like <code>/.env</code> and <code>/.git</code>, the HTTP→HTTPS redirect, and <code>security.txt</code>). To also run the active <b>reflected-input</b> test, re-open the popup, tick <b>“I own this site”</b>, and re-scan.`
}

function render() {
  renderOwnerBanner()
  const groups = $('groups')
  groups.innerHTML = ''
  const source = currentSource()
  const cats = CATEGORIES.filter(([key]) => activeCat === 'all' || key === activeCat)

  let shown = 0
  for (const [key, label] of cats) {
    let items = source.filter((f) => f.category === key)
    if (!showGood) items = items.filter((f) => f.severity !== 'good')
    if (!items.length) continue
    items.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    shown += items.length

    const section = document.createElement('section')
    section.className = 'group'
    const issueCount = items.filter((f) => f.severity !== 'good').length
    section.innerHTML =
      `<h2><span>${label}</span><span style="color:var(--text-faint)">${issueCount} issue${issueCount === 1 ? '' : 's'}</span></h2>` +
      `<p class="catintro">${CAT_INTRO[key]}</p>`
    for (const f of items) section.appendChild(findingEl(f))
    groups.appendChild(section)
  }
  if (!shown) {
    groups.innerHTML =
      view === 'owner' && !ownerFindings.length
        ? '<p class="empty">No owner-level findings — nothing was exposed by the server-side checks.</p>'
        : '<p class="empty">Nothing to show in this view.</p>'
  }
}

function findingEl(f) {
  const el = document.createElement('div')
  el.className = 'finding'
  el.style.borderLeftColor = SEV_COLOR[f.severity]
  const parts = [
    `<div class="fhead"><span class="sevtag sev-${f.severity}">${f.severity}</span><h3>${escapeHtml(f.title)}</h3></div>`,
  ]
  if (f.detail) parts.push(`<p class="detail">${escapeHtml(f.detail)}</p>`)
  if (f.evidence) parts.push(`<pre>${escapeHtml(f.evidence)}</pre>`)
  if (f.fix) parts.push(`<p class="fix"><b>Fix &middot;</b> ${escapeHtml(f.fix)}</p>`)
  if (f.ref) parts.push(`<a class="ref" href="${escapeHtml(f.ref)}" target="_blank" rel="noopener">Reference ↗</a>`)
  el.innerHTML = parts.join('')
  return el
}

// ── Exports ──────────────────────────────────────────────────────────────────
function download(name, text, mime) {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const stripTags = (s) => String(s).replace(/<[^>]+>/g, '')

function findingsMarkdown(items) {
  const lines = []
  for (const [key, label] of CATEGORIES) {
    const group = items.filter((f) => f.category === key && f.severity !== 'good')
    if (!group.length) continue
    group.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    lines.push(`### ${label}`, '')
    for (const f of group) {
      lines.push(`#### [${f.severity.toUpperCase()}] ${f.title}`)
      if (f.detail) lines.push('', f.detail)
      if (f.evidence) lines.push('', '```', f.evidence, '```')
      if (f.fix) lines.push('', `**Fix:** ${f.fix}`)
      if (f.ref) lines.push('', `Reference: ${f.ref}`)
      lines.push('')
    }
  }
  return lines
}

function toMarkdown() {
  const { result } = bundle
  const host = safeHost(result.scannedUrl)
  const lines = [
    `# VulnChecker report — ${host}`,
    ``,
    `- **URL:** ${result.scannedUrl}`,
    `- **Scanned:** ${new Date(result.scannedAt).toISOString()}`,
    `- **Score:** ${result.score}/100 (grade ${result.grade})`,
    `- **Findings:** ` + SEV_ORDER.filter((s) => result.counts[s]).map((s) => `${result.counts[s]} ${s}`).join(', '),
    ``,
    `## Executive summary`,
    ``,
    execSentences(result).map(stripTags).join(' '),
    ``,
    `## Standard report`,
    ``,
    ...findingsMarkdown(standardFindings),
    `## Owner-only checks (I own this site)`,
    ``,
    ownerFindings.some((f) => f.severity !== 'good')
      ? 'Findings from requests made directly to the server. Included in the score above.'
      : 'No owner-level issues were found.',
    ``,
    ...findingsMarkdown(ownerFindings),
    `---`,
    `_Generated locally by VulnChecker. Heuristic guidance, not a substitute for a professional audit._`,
  ]
  return lines.join('\n')
}

$('exportJson').addEventListener('click', () => {
  download('vulnchecker-report.json', JSON.stringify(bundle.result, null, 2), 'application/json')
})
$('exportMd').addEventListener('click', () => {
  download('vulnchecker-report.md', toMarkdown(), 'text/markdown')
})
$('showGood').addEventListener('change', (e) => {
  showGood = e.target.checked
  render()
})

for (const seg of document.querySelectorAll('.seg')) {
  seg.addEventListener('click', () => {
    if (view === seg.dataset.view) return
    view = seg.dataset.view
    activeCat = 'all'
    for (const s of document.querySelectorAll('.seg')) s.setAttribute('aria-pressed', String(s.dataset.view === view))
    renderFilters()
    render()
  })
}

load()
