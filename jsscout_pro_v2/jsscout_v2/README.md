# JS Scout Pro v3.0

A complete JavaScript security recon tool. No external CLI tools required.
Built on Python + requests only.

## Installation

```bash
pip install requests flask
```

## CLI Usage

```bash
# Basic scan
python3 jsscout.py https://target.com

# With cookies + more threads
python3 jsscout.py https://target.com --cookies "session=abc; token=xyz" --threads 20

# With auth token, custom depth and pages
python3 jsscout.py https://target.com --header "Authorization: Bearer eyJ..." --depth 5 --pages 500

# Output results as JSON
python3 jsscout.py https://target.com --json > results.json
```

## Web UI Usage

```bash
python3 server.py
# Open http://localhost:7331
```

## What it finds

- **JS Files** — discovers and downloads ALL JavaScript (script tags, webpack chunks, dynamic imports, manifests)
- **API Endpoints** — extracts /api/v1/*, /graphql, /rest/*, route definitions, fetch() calls
- **Secrets** — API keys, JWTs, AWS keys, Stripe, GitHub tokens, DB connection strings, Firebase, Supabase
- **XSS Sinks** — innerHTML, eval, document.write, insertAdjacentHTML, dangerouslySetInnerHTML, location.href=, $.html(), createContextualFragment, and more
- **Confirmed XSS flows** — when a source (location.search, URLSearchParams, document.cookie) flows into a sink
- **DOM Clobbering** — clobberable element properties, window.name, document.forms[], config objects from DOM
- **Prototype Pollution** — __proto__ assign, constructor.prototype, lodash merge, $.extend(true,...), for-in without guard
- **XSS Payload Library** — polyglot, basic, encoded, filter bypass, DOM, exfil, WAF bypass, prototype pollution, DOM clobbering payloads

## Output

Results are saved to `jsscout_output/<domain>/`:
- `report.txt` — full human-readable report
- `full_results.json` — everything in JSON
- `endpoints.txt` — extracted endpoints
- `secrets.txt` — found secrets
- `xss_sinks.txt` — XSS sink locations
- `payload_library.json` — XSS payload library
- `js/` — all downloaded JS files

## How discovery works (7 phases)

1. **BFS crawl** — crawls all pages up to configured depth using threads
2. **Manifest probing** — checks /asset-manifest.json, /webpack-manifest.json, /sw.js etc.
3. **HTML regex sweep** — extracts JS from script tags, link preloads, webpack bootstrap
4. **Download** — downloads all discovered JS files with dedup by SHA256 hash
5. **JS deep crawl** — scans downloaded JS for more chunk URLs, dynamic imports
6. **Analysis** — regex pattern matching on all JS files
7. **Report generation**
