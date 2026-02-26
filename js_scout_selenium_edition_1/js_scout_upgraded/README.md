# JS Scout — Selenium + Chromium Edition

**Dynamic JavaScript Intelligence Crawler** powered by Selenium WebDriver with click automation.

---

## Features

- 🤖 **Selenium + Chromium** — Headless/non-headless Chromium with performance logging to capture all network-loaded JS
- 🖱️ **Click Automation Engine** — Automatically clicks buttons, links, dropdowns, modals to reveal dynamically loaded JS
- ⚡ **WebDriverWait** — No `time.sleep()` — uses proper WebDriver waits for SPA navigation (React/Vue/Angular)
- 🔒 **Auth Support** — Cookie injection, JWT/Bearer token headers, auto form login
- 📦 **Prioritized Output** — JS files saved in priority order: `main.js`, `app.js`, `bundle.js`, chunks, large files
- 🔍 **Security Analysis** — Detects API keys, JWT tokens, AWS/GCP/Azure credentials, Firebase configs, GraphQL endpoints
- 📊 **Real-time UI** — Live log viewer, progress bar, SocketIO updates
- 📥 **ZIP Download** — Download all results as a ZIP archive

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Playwright browsers (for auth crawling)

```bash
playwright install chromium
```

### 3. Install Chrome/Chromium for Selenium

**Ubuntu/Debian:**
```bash
apt-get install -y chromium-browser
# or
apt-get install -y google-chrome-stable
```

**macOS:**
```bash
brew install --cask google-chrome
```

**Windows:**
Download from https://www.google.com/chrome/

> **Note:** `webdriver-manager` is included in requirements.txt and will auto-download the matching ChromeDriver.

### 4. Run

```bash
python app.py
```

Navigate to `http://localhost:5000`

---

## Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| **Target** | URL or domain to scan | required |
| **Depth** | Selenium crawl depth (how many page levels deep) | 2 |
| **Max Clicks** | Maximum click automation actions per crawl | 50 |
| **Headless** | Run Chromium without visible window | ✅ enabled |
| **Deep Crawl** | Extended crawling with more pages | ❌ disabled |
| **GAU Passive** | Use GAU tool for passive URL discovery | ✅ enabled |
| **Katana Active** | Use Katana for active crawling | ✅ enabled |
| **Rate Limit** | Request rate in req/s | 10 |

---

## Output Structure

```
output/
├── <target>/
│   ├── prioritized/          ← main.js, app.js, bundle.js, large files (>200KB)
│   ├── other_js/             ← all remaining JS files
│   ├── inline_js/            ← extracted inline scripts
│   ├── dynamic_chunks/       ← webpack/vite/next chunks
│   ├── js/                   ← all downloaded JS (raw)
│   ├── findings_report.json  ← security findings
│   ├── metadata.json         ← scan metadata + output structure
│   └── summary.json          ← scan summary
```

### Prioritization Order

1. `main.js`
2. `app.js`
3. `bundle.js`
4. `main.*.js` (hashed variants)
5. `chunk.*.js`
6. `vendor.*.js`
7. `runtime.*.js`
8. Files > 200KB
9. All remaining JS

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan/start` | POST | Start a new scan |
| `/api/scan/<id>/status` | GET | Get scan status |
| `/api/scan/<id>/results` | GET | Get scan results |
| `/api/scans` | GET | List all scans |
| `/api/scan/<id>/download` | GET | Download scan output as ZIP |
| `/download` | GET | Download all output as ZIP |
| `/api/scan/<id>/report` | GET | Download text report |

---

## Security Detection

The analyzer automatically detects:

- AWS Access Keys / Secret Keys
- Google Cloud / Azure credentials
- Firebase API configs
- Stripe / Twilio / Supabase keys
- JWT tokens
- Hardcoded passwords
- GraphQL endpoints
- Internal API routes
- Hidden admin routes
- Sensitive code comments (TODO, FIXME, hardcoded)

Results saved to `output/<target>/findings_report.json`

---

## Architecture

```
app.py                      ← Flask + SocketIO backend (main entry)
crawler/
  selenium_crawler.py       ← ★ NEW: Selenium + Chromium click automation
  playwright_crawler.py     ← Playwright auth-aware crawler
  direct_scraper.py         ← HTTP scraper
  gau_crawler.py            ← GAU passive crawl
  katana_crawler.py         ← Katana active crawl
downloader/
  js_downloader.py          ← Parallel JS downloader with dedup
analyzer/
  js_analyzer.py            ← Security pattern analysis
reporter/
  report_generator.py       ← Report generation
```
