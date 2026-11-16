<div align="center">

<img src="icons/icon-128.png" width="96" alt="VulnChecker icon" />

# VulnChecker

**One-click security, privacy and quality audit for websites you own.**

A Manifest V3 Chrome extension that inspects the site you're on and gives you a
plain-English report with a severity, an explanation and a fix for every finding,
plus an overall grade.

![Manifest V3](https://img.shields.io/badge/Manifest-V3-000000?style=flat-square&logo=googlechrome&logoColor=white)
![JavaScript](https://img.shields.io/badge/Vanilla-JavaScript-000000?style=flat-square&logo=javascript&logoColor=white)
![No tracking](https://img.shields.io/badge/data_sent-none-000000?style=flat-square)

</div>

Everything runs locally in your browser. Nothing about the sites you scan is
ever stored or sent anywhere.

## Install

1. Clone this repo or download it as a ZIP and unzip it.
2. Open `chrome://extensions`.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the folder that contains `manifest.json`.
5. Pin VulnChecker, open any `http(s)` site and click the icon.

## What it checks

- **Security**: HTTPS and HTTP→HTTPS redirect, CSP, HSTS, clickjacking
  protection, `nosniff`, Referrer-Policy, Permissions-Policy, cookie flags
  (Secure / HttpOnly / SameSite), mixed content, passwords over HTTP, Subresource
  Integrity on third-party scripts, secrets in page source, outdated JS
  libraries with known CVEs, version-disclosing headers, and exposed paths
  (`/.env`, `/.git/…`, `/.DS_Store`).
- **Legal & privacy**: privacy policy / terms / contact links, third-party
  trackers, and whether they load before a consent banner.
- **SEO**: title, meta description, viewport, Open Graph, canonical, headings,
  `robots.txt`, `sitemap.xml`.
- **Accessibility**: `lang`, image alt text, form labels, accessible names.
- **Performance**: render-blocking scripts, image dimensions, lazy loading.

## How it works

| File | Role |
|---|---|
| `src/background.js` | Service worker. Captures response headers (which a page can't read itself) and runs read-only GET probes for exposed paths, `security.txt`, `robots.txt`, `sitemap.xml` and the HTTP→HTTPS redirect |
| `src/collect.js` | Injected into the page. Read-only snapshot of the DOM, library versions, forms, trackers, possible secrets and accessibility signals |
| `src/analyze.js` | Turns headers + snapshot into findings with severity, detail and fix |
| `src/scan.js` | Exposed-path probe list |
| `src/popup.*` / `src/report.*` | The popup and the full report page (executive summary, Standard and "I own this site" views) |

## Active check (owned sites only)

Ticking **"I own this site"** enables one extra, **read-only** GET request that
appends a harmless marker to the URL and checks whether it is reflected back
unencoded, the precondition for reflected XSS. It sends no payloads that change
server state. Only enable it on sites you control or are authorised to test.

## Author

Built by [Oleg Narainen](https://www.olegnar.com) · [@oleg-nar](https://github.com/oleg-nar)
