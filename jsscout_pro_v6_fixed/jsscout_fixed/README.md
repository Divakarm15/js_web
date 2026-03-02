# JS Scout Pro v5 — Selenium + Chromium Edition

Real browser-powered JavaScript security scanner with context-aware XSS detection.

---

## Install

### Step 1: Python deps
```bash
pip install -r requirements.txt
```

### Step 2: Chromium + chromedriver

**Kali Linux / Ubuntu / Debian:**
```bash
apt install chromium chromium-driver
```

**Other Linux:**
```bash
# webdriver-manager will auto-download chromedriver
pip install webdriver-manager
```

**Windows / Mac:**
```bash
pip install webdriver-manager
# chromedriver downloaded automatically on first run
```

---

## Usage

```bash
# Full scan with browser (default)
python3 jsscout.py http://zero.webappsecurity.com/

# Deeper scan
python3 jsscout.py https://target.com --depth 4 --pages 300

# Without browser (requests only, faster but misses JS-rendered content)
python3 jsscout.py https://target.com --no-selenium

# With cookies (authenticated scan)
python3 jsscout.py https://target.com --cookies "session=abc123; auth=xyz"

# With custom headers
python3 jsscout.py https://target.com --header "Authorization: Bearer TOKEN"

# JSON output
python3 jsscout.py https://target.com --json > results.json

# Web UI
python3 server.py   # then open http://localhost:7331
```

---

## What It Does

### Phase 1: Browser Crawl
- Launches headless Chromium via Selenium
- Loads each page with full JS execution
- Captures ALL network requests the browser makes (not just HTML src= tags)
- Intercepts dynamically loaded scripts, lazy chunks, XHR calls
- Scrolls pages to trigger lazy-loaded content
- Also runs requests-based crawler for speed

### Phase 2: Manifest Probing
- Probes common paths: `/asset-manifest.json`, `/webpack-manifest.json`, etc.
- Extracts JS file references from manifests

### Phase 3: JS Download
- Downloads all discovered JS files
- Deduplicates by SHA256

### Phase 4: Deep JS Crawl (JS→JS→JS)
- Scans every downloaded JS file for references to MORE JS files
- Handles: Webpack 4 hash chunks, Webpack 4 named chunks, Webpack 5, Next.js, Vite, AMD/RequireJS
- Repeats until no new files found (fixed-point)

### Phase 5: Analysis
- Scans all JS files + inline scripts for:
  - XSS sinks (innerHTML, eval, document.write, etc.) with false-positive filtering
  - Secrets (API keys, tokens, passwords, JWTs)
  - API endpoints
  - Prototype pollution patterns
  - DOM clobbering patterns

### Phase 6: Context-Aware XSS Probing
1. **Canary test**: sends `jsSc0utXxZ99` to each parameter
2. **Context detection**: finds WHERE in the page it's reflected:
   - Raw HTML body → `<img src=x onerror=alert(1)>`
   - Inside `<script>var x="HERE"` → `";alert(1)//`
   - Inside attribute `value="HERE"` → `" onmouseover=alert(1) x="`
   - Inside `href="HERE"` → `javascript:alert(1)`
   - Inside template literal → `` `);alert(1)// ``
3. **Context-matched payloads**: picks the right payload for the right context
4. **Browser confirmation**: actually loads payload in Chromium, checks if alert() fires

### Phase 7: Report
- `report.txt` — human-readable summary
- `reflected_xss.txt` — all confirmed XSS PoCs with browser confirmation status
- `summary.json` — machine-readable summary
- `full_results.json` — all findings

---

## Output Structure

```
jsscout_output/
└── zero.webappsecurity.com/
    ├── js/                     <- all downloaded JS files
    │   ├── jquery.min.js
    │   ├── app.js
    │   └── chunk.1a2b3c.js
    ├── report.txt              <- main report
    ├── reflected_xss.txt       <- XSS PoCs
    ├── summary.json
    └── full_results.json
```

---

## Context-Aware Payload Table

| Reflection Context | Example | Payload Used |
|---|---|---|
| Raw HTML | `<div>HERE</div>` | `<img src=x onerror=alert(1)>` |
| HTML attribute | `value="HERE"` | `" onmouseover=alert(1) x="` |
| href/src attribute | `href="HERE"` | `javascript:alert(1)` |
| JS double-quoted string | `var x = "HERE"` | `";alert(1)//` |
| JS single-quoted string | `var x = 'HERE'` | `';alert(1)//` |
| JS template literal | `` var x = `HERE` `` | `` `);alert(1)// `` |
| JS comment | `// HERE` | `\nalert(1)\n//` |
| URL parameter | `?next=HERE` | `javascript:alert(1)` |
