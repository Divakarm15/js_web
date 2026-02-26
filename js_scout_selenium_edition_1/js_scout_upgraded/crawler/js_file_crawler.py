"""
JS File Content Crawler — Deep Edition
=======================================
Scans EVERY downloaded JS file on disk for embedded references to more JS files,
fetches those, saves them, then scans those too. Repeats until nothing new is found.

Works synchronously (gevent-compatible, no asyncio conflicts).

Catches ALL of the following inside JS content:
  - ES module:          import './chunk.js'  |  export from './lib.js'
  - Dynamic import:     import('./module.js')
  - CommonJS:           require('./dep.js')
  - Webpack runtime:    {0:"abc123",1:"def456"} chunk hash maps + publicPath
  - Webpack chunks:     "static/js/" + chunkId + "." + chunkHash + ".js"
  - Next.js manifests:  _buildManifest, __BUILD_MANIFEST, __NEXT_DATA__
  - Vite chunks:        /assets/index.abc123.js
  - Source map refs:    //# sourceMappingURL=file.js.map
  - Asset manifests:    {"main.js": "/static/js/main.abc.js"}
  - Absolute URLs:      https://cdn.example.com/bundle.min.js
  - Root-relative:      /static/js/vendor.chunk.js
  - Protocol-relative:  //cdn.example.com/lib.js
  - Relative paths:     ./chunk.js  |  ../vendor/lib.js
  - Lazy loading:       React.lazy(() => import('./Page'))
"""

import hashlib
import json
import os
import re
import time
from collections import deque
from pathlib import Path
from typing import Dict, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Compiled patterns ────────────────────────────────────────────────────────

_IMPORT_FROM     = re.compile(r'''(?:import|export)[^'"`;]{0,80}from\s+["'`]([^"'`\s]+\.(?:js|mjs))["'`]''')
_DYNAMIC_IMPORT  = re.compile(r'''import\s*\(\s*["'`]([^"'`\s]+\.(?:js|mjs))["'`]\s*\)''')
_REQUIRE_CALL    = re.compile(r'''require\s*\(\s*["'`]([^"'`\s]+\.(?:js|mjs))["'`]\s*\)''')
_LAZY_IMPORT     = re.compile(r'''lazy\s*\(\s*(?:\(\s*\))?\s*=>\s*import\s*\(\s*["'`]([^"'`\s]+\.(?:js|mjs))["'`]''')
_DEFINE_DEPS     = re.compile(r'''define\s*\(\s*\[([^\]]+)\]''')
_ABS_JS_URL      = re.compile(r'''["'`](https?://[^\s"'`<>{}\\\[\]]{4,}\.(?:js|mjs)(?:\?[^"'`\s]*)?)["'`]''')
_PROTO_REL_URL   = re.compile(r'''["'`](//[a-zA-Z0-9][^\s"'`<>{}\\\[\]]{4,}\.(?:js|mjs)(?:\?[^"'`\s]*)?)["'`]''')
_NEXT_CHUNK_PATH = re.compile(r'''["'`](/_next/static/[^"'`\s]+\.js)["'`]''')
_VITE_ASSET      = re.compile(r'''["'`](/assets/[a-zA-Z0-9._\-]+\.js)["'`]''')
_WP_CHUNK_MAP    = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}')
_WP_CHUNK_NAMES  = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-zA-Z0-9~_\-]+"(?:\s*,\s*\d+\s*:\s*"[a-zA-Z0-9~_\-]+")*\s*)\}')
_WP_PUBLIC_PATH  = re.compile(r'(?:__webpack_require__\.p|__webpack_public_path__|publicPath)\s*[=+]\s*["\'`](/?[^"\'`\s]{0,200})["\'`]')
_SOURCE_MAP_URL  = re.compile(r'//[#@]\s*sourceMappingURL=(\S+\.map)')
_ASSET_MANIFEST  = re.compile(r'"([^"]+\.(?:js|mjs))"')
_ANY_JS_STRING   = re.compile(r'''["'`]([^"'`\s\\]{3,200}\.(?:js|mjs)(?:\?[^"'`\s]*)?)["'`]''')
_JSON_BLOB       = re.compile(r'\{[^{}]{50,8000}\}', re.DOTALL)


class JSFileCrawler:
    """
    Synchronous BFS crawler — reads every JS file, extracts embedded
    JS URLs, fetches and saves new ones, repeats until exhausted.
    """

    def __init__(
        self,
        base_url: str,
        js_dir: str,
        logger_obj=None,
        max_depth: int = 10,
        max_files: int = 2000,
        timeout: int = 20,
        rate_limit: float = 15.0,
        cookies: Optional[str] = None,
        auth_headers: Optional[Dict] = None,
    ):
        self.base_url    = base_url.rstrip('/')
        self.base_scheme = urlparse(base_url).scheme or 'https'
        self.base_domain = urlparse(base_url).netloc
        self.js_dir      = Path(js_dir)
        self.log         = logger_obj
        self.max_depth   = max_depth
        self.max_files   = max_files
        self.timeout     = timeout
        self.min_delay   = 1.0 / max(rate_limit, 1.0)

        self.session = self._build_session(cookies, auth_headers)

        self._tried_urls:  Set[str] = set()
        self._seen_hashes: Set[str] = set()
        self._url_to_file: Dict[str, str] = {}
        self._saved_count: int = 0

    # ── Public entry ─────────────────────────────────────────────────────────

    def run(self, known_urls: Set[str]) -> Set[str]:
        """BFS over all JS URLs. Returns complete set of all discovered URLs."""
        self._index_existing_files()

        all_urls = set(known_urls)
        frontier = deque(known_urls)
        self._tried_urls = set(known_urls)

        depth = 0
        while frontier and depth < self.max_depth and self._saved_count < self.max_files:
            depth += 1
            batch = list(frontier)
            frontier.clear()

            self._info(f'[js-crawler] Depth {depth}: scanning {len(batch)} JS files...')
            newly: Set[str] = set()

            for url in batch:
                content = self._get_content(url)
                if not content:
                    continue
                for new_url in self._extract_all(content, url):
                    if new_url not in self._tried_urls:
                        self._tried_urls.add(new_url)
                        newly.add(new_url)

            if newly:
                self._info(f'[js-crawler] Found {len(newly)} new JS references at depth {depth}')
                for u in newly:
                    all_urls.add(u)
                    frontier.append(u)
            else:
                self._info(f'[js-crawler] No new JS URLs found at depth {depth} — done')
                break

        self._info(f'[js-crawler] Done. {len(all_urls)} total URLs | {self._saved_count} new files saved')
        return all_urls

    # ── Async wrapper so existing app.py await call works ────────────────────

    async def crawl_all_js_files(self, known_urls: Set[str]) -> Set[str]:
        """Async shim — runs synchronous BFS in executor to not block event loop."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run, known_urls)

    # ── File access ──────────────────────────────────────────────────────────

    def _index_existing_files(self):
        for f in self.js_dir.glob('*.js'):
            try:
                self._seen_hashes.add(hashlib.sha256(f.read_bytes()).hexdigest())
            except Exception:
                pass

    def _get_content(self, url: str) -> Optional[bytes]:
        # Check disk first by URL mapping
        fname = self._url_to_file.get(url)
        if fname:
            p = self.js_dir / fname
            if p.exists():
                try:
                    return p.read_bytes()
                except Exception:
                    pass

        # Try guessing filename
        guess = self._guess_filename(url)
        if guess:
            p = self.js_dir / guess
            if p.exists():
                try:
                    data = p.read_bytes()
                    self._url_to_file[url] = guess
                    return data
                except Exception:
                    pass

        # Also scan all files on disk for a match by URL basename
        try:
            basename = os.path.basename(urlparse(url).path.split('?')[0])
            if basename:
                for f in self.js_dir.glob('*.js'):
                    if basename in f.name or f.name in basename:
                        try:
                            data = f.read_bytes()
                            self._url_to_file[url] = f.name
                            return data
                        except Exception:
                            pass
        except Exception:
            pass

        # Fetch from network
        content = self._fetch(url)
        if content:
            saved = self._save(url, content)
            if saved:
                self._url_to_file[url] = saved
        return content

    def _fetch(self, url: str) -> Optional[bytes]:
        try:
            time.sleep(self.min_delay)
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                # Accept if content-type is JS or URL ends in .js
                ct = resp.headers.get('content-type', '')
                path = urlparse(url).path.lower().split('?')[0]
                if ('javascript' in ct or 'text/' in ct or 'application/' in ct
                        or path.endswith('.js') or path.endswith('.mjs')):
                    self._debug(f'[js-crawler] Fetched: {url} ({len(resp.content):,}b)')
                    return resp.content
            else:
                self._debug(f'[js-crawler] HTTP {resp.status_code}: {url}')
        except Exception as e:
            self._debug(f'[js-crawler] Error {url}: {e}')
        return None

    def _save(self, url: str, content: bytes) -> Optional[str]:
        if self._saved_count >= self.max_files:
            return None
        sha = hashlib.sha256(content).hexdigest()
        if sha in self._seen_hashes:
            return None
        self._seen_hashes.add(sha)
        try:
            existing = {f.name for f in self.js_dir.glob('*.js')}
            fname = self._make_filename(url, existing)
            (self.js_dir / fname).write_bytes(content)
            self._saved_count += 1
            self._info(f'[js-crawler] Saved: {fname}  ({len(content):,}b)  <- {url}')
            return fname
        except Exception as e:
            self._debug(f'[js-crawler] Save error: {e}')
        return None

    def _guess_filename(self, url: str) -> Optional[str]:
        try:
            base = os.path.basename(urlparse(url).path.split('?')[0])
            if not base:
                return None
            if not base.endswith('.js'):
                base += '.js'
            return re.sub(r'[^\w.\-]', '_', base)[:180] or None
        except Exception:
            return None

    def _make_filename(self, url: str, existing: Set[str]) -> str:
        try:
            path = urlparse(url).path
            base = os.path.basename(path.split('?')[0]) or 'script'
            if not base.endswith('.js'):
                base += '.js'
            safe = re.sub(r'[^\w.\-]', '_', base)[:180]
            if not safe or safe == '.js':
                safe = 'script.js'
            if safe not in existing:
                return safe
            stem, i = safe[:-3], 1
            while True:
                c = f'{stem}_{i}.js'
                if c not in existing:
                    return c
                i += 1
        except Exception:
            return f'script_{self._saved_count}.js'

    # ── URL extraction ────────────────────────────────────────────────────────

    def _extract_all(self, content: bytes, source_url: str) -> Set[str]:
        try:
            text = content.decode('utf-8', errors='replace')
        except Exception:
            return set()

        raw: Set[str] = set()

        # Targeted framework patterns
        for pat in [_IMPORT_FROM, _DYNAMIC_IMPORT, _REQUIRE_CALL, _LAZY_IMPORT]:
            for m in pat.finditer(text):
                raw.add(m.group(1))

        # AMD define
        for m in _DEFINE_DEPS.finditer(text):
            for dep in re.findall(r'''["'`]([^"'`]+\.(?:js|mjs))["'`]''', m.group(1)):
                raw.add(dep)

        # Absolute & protocol-relative URLs
        for m in _ABS_JS_URL.finditer(text):
            raw.add(m.group(1))
        for m in _PROTO_REL_URL.finditer(text):
            raw.add(self.base_scheme + ':' + m.group(1))

        # Next.js & Vite
        for m in _NEXT_CHUNK_PATH.finditer(text):
            raw.add(m.group(1))
        for m in _VITE_ASSET.finditer(text):
            raw.add(m.group(1))

        # Webpack chunk reconstruction
        pub = self._get_public_path(text)
        names = self._get_chunk_names(text)
        for m in _WP_CHUNK_MAP.finditer(text):
            for cid, chash in self._parse_chunk_map(m.group(0)).items():
                raw.update(self._build_chunk_urls(pub, cid, chash, names.get(cid, cid)))

        # Generic .js string sweep (catches everything else)
        for m in _ANY_JS_STRING.finditer(text):
            v = m.group(1)
            if v and ' ' not in v and '\\n' not in v and len(v) < 300:
                raw.add(v)

        # JSON blobs
        for m in _JSON_BLOB.finditer(text):
            blob = m.group(0)
            if '.js"' not in blob:
                continue
            for am in _ASSET_MANIFEST.finditer(blob):
                p = am.group(1)
                if ('/' in p or p.startswith('.')) and not p.startswith('//'):
                    raw.add(p)

        # Source maps
        for m in _SOURCE_MAP_URL.finditer(text):
            self._follow_source_map(self._resolve(m.group(1), source_url), raw)

        # Resolve + filter
        result: Set[str] = set()
        for r in raw:
            u = self._resolve(r, source_url)
            if u and self._is_js_url(u):
                result.add(u)
        return result

    # ── Webpack helpers ───────────────────────────────────────────────────────

    def _get_public_path(self, text: str) -> str:
        m = _WP_PUBLIC_PATH.search(text)
        if m:
            p = m.group(1).strip()
            if p.startswith('http') or p.startswith('//'):
                return p.rstrip('/')
            return urljoin(self.base_url, p).rstrip('/')
        return self.base_url

    def _get_chunk_names(self, text: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for m in _WP_CHUNK_NAMES.finditer(text):
            for km in re.finditer(r'(\d+)\s*:\s*"([a-zA-Z0-9~_\-]+)"', m.group(0)):
                result[km.group(1)] = km.group(2)
        return result

    def _parse_chunk_map(self, s: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for m in re.finditer(r'(\d+)\s*:\s*"([a-f0-9]{4,})"', s):
            result[m.group(1)] = m.group(2)
        return result

    def _build_chunk_urls(self, pub: str, cid: str, chash: str, name: str) -> Set[str]:
        urls: Set[str] = set()
        base = (pub or self.base_url).rstrip('/') + '/'
        for prefix in ['static/js/', 'static/chunks/', 'chunks/', 'js/', '_next/static/chunks/', '']:
            for tmpl in [
                f'{prefix}{cid}.{chash}.chunk.js',
                f'{prefix}{cid}.{chash}.js',
                f'{prefix}{name}.{chash}.chunk.js',
                f'{prefix}{name}.{chash}.js',
                f'{prefix}{chash}.chunk.js',
                f'{prefix}{chash}.js',
            ]:
                urls.add(urljoin(base, tmpl))
        return urls

    # ── Source map ────────────────────────────────────────────────────────────

    def _follow_source_map(self, map_url: str, found: Set[str]):
        try:
            resp = self.session.get(map_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for src in data.get('sources', []):
                    if isinstance(src, str) and src.endswith('.js'):
                        found.add(src)
        except Exception:
            pass

    # ── URL helpers ──────────────────────────────────────────────────────────

    def _resolve(self, path: str, base: str) -> str:
        if not path:
            return ''
        path = path.strip()
        try:
            if path.startswith(('data:', 'blob:', 'javascript:')):
                return ''
            if path.startswith('//'):
                return f'{self.base_scheme}:{path}'
            if path.startswith('http'):
                return path
            return urljoin(base, path)
        except Exception:
            return ''

    def _is_js_url(self, url: str) -> bool:
        if not url or len(url) > 600:
            return False
        try:
            p = urlparse(url)
            if not p.scheme or not p.netloc:
                return False
            if p.scheme not in ('http', 'https'):
                return False
            path = p.path.lower().split('?')[0]
            if not (path.endswith('.js') or path.endswith('.mjs')):
                return False
            for skip in ['node_modules/', '.spec.js', '.test.js', '__tests__/']:
                if skip in path:
                    return False
            return True
        except Exception:
            return False

    # ── Session ──────────────────────────────────────────────────────────────

    def _build_session(self, cookies, auth_headers) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.verify = False
        s.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
            ),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Fetch-Dest': 'script',
            'Sec-Fetch-Mode': 'no-cors',
        })
        if auth_headers:
            s.headers.update(auth_headers)
        if cookies:
            for pair in cookies.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    name, _, val = pair.partition('=')
                    s.cookies.set(name.strip(), val.strip())
        return s

    # ── Logging ──────────────────────────────────────────────────────────────

    def _info(self, msg: str):
        if self.log:
            self.log.info(msg)

    def _debug(self, msg: str):
        if self.log:
            self.log.debug(msg)
