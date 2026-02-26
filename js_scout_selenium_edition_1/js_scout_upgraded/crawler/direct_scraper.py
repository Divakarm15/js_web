"""
Deep Direct HTTP Scraper
========================
Crawls the target site page by page (BFS), extracts every JS URL from:
  - <script src="...">
  - <link rel="modulepreload">
  - <link rel="preload" as="script">
  - Inline webpack bootstrap (lists all chunk hashes)
  - Next.js __NEXT_DATA__ JSON
  - Any string matching *.js in the HTML
  - asset-manifest.json / manifest.json / asset-manifest.json endpoints
  - service worker registration scripts
  - data-src, data-main attributes
  - All subpages discovered via <a href> links (BFS, same domain)
"""

import asyncio
import json
import re
from typing import Set
from urllib.parse import urljoin, urlparse

import httpx


class DirectScraper:

    HEADERS = {
        'User-Agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    # Known manifest/config endpoints that list JS files
    MANIFEST_PATHS = [
        '/asset-manifest.json',
        '/static/asset-manifest.json',
        '/assets/asset-manifest.json',
        '/manifest.json',
        '/assets-manifest.json',
        '/_next/static/development/_buildManifest.js',
        '/webpack-manifest.json',
        '/mix-manifest.json',
        '/parcel-manifest.json',
        '/precache-manifest.js',
        '/service-worker.js',
        '/sw.js',
        '/workbox-*.js',
    ]

    def __init__(self, base_url: str, logger, timeout: int = 30, max_pages: int = 100):
        self.base_url   = base_url.rstrip('/')
        self.logger     = logger
        self.timeout    = timeout
        self.max_pages  = max_pages
        self.base_domain = urlparse(base_url).netloc

    async def scrape(self) -> Set[str]:
        js_urls: Set[str] = set()

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
            headers=self.HEADERS,
        ) as client:

            # ── BFS page crawl ────────────────────────────────────────────────
            visited_pages: Set[str] = set()
            page_queue = [self.base_url]

            while page_queue and len(visited_pages) < self.max_pages:
                url = page_queue.pop(0)
                if url in visited_pages:
                    continue
                visited_pages.add(url)

                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    ct = resp.headers.get('content-type', '')
                    if 'html' not in ct and 'javascript' not in ct and 'text' not in ct:
                        continue

                    html = resp.text
                    self.logger.info(f'[scraper] Scanning page: {url}')

                    # Extract JS from this page
                    found = self._extract_js_from_html(html, url)
                    js_urls.update(found)
                    self.logger.info(f'[scraper] Found {len(found)} JS URLs on {url}')

                    # Discover more pages to visit (same domain only)
                    new_pages = self._extract_page_links(html, url)
                    for p in new_pages:
                        if p not in visited_pages:
                            page_queue.append(p)

                except Exception as e:
                    self.logger.debug(f'[scraper] Error at {url}: {e}')

            self.logger.info(f'[scraper] Crawled {len(visited_pages)} pages, found {len(js_urls)} JS URLs')

            # ── Probe known manifest endpoints ────────────────────────────────
            for path in self.MANIFEST_PATHS:
                manifest_url = self.base_url + path
                try:
                    resp = await client.get(manifest_url)
                    if resp.status_code == 200:
                        found = self._extract_js_from_manifest(resp.text, manifest_url)
                        if found:
                            self.logger.info(f'[scraper] Manifest {path}: +{len(found)} JS URLs')
                            js_urls.update(found)
                except Exception:
                    pass

        return js_urls

    def _extract_js_from_html(self, html: str, page_url: str) -> Set[str]:
        found: Set[str] = set()

        # <script src="...">
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            found.add(self._abs(m.group(1), page_url))

        # <link rel="modulepreload" href="..."> and <link rel="preload" as="script" href="...">
        for m in re.finditer(
            r'<link[^>]+(?:rel=["\'](?:modulepreload|preload)["\'][^>]*href=["\']([^"\']+)["\']'
            r'|href=["\']([^"\']+)["\'][^>]*rel=["\'](?:modulepreload|preload)["\'])',
            html, re.IGNORECASE
        ):
            src = m.group(1) or m.group(2)
            if src and src.endswith('.js'):
                found.add(self._abs(src, page_url))

        # data-main (RequireJS)
        for m in re.finditer(r'data-main=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            if src:
                if not src.endswith('.js'):
                    src += '.js'
                found.add(self._abs(src, page_url))

        # Next.js __NEXT_DATA__
        for m in re.finditer(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
                             html, re.IGNORECASE | re.DOTALL):
            try:
                data = json.loads(m.group(1))
                build_id = data.get('buildId', '')
                if build_id:
                    # Main next chunks
                    for chunk in ['main', 'webpack', 'framework', 'pages/_app', 'pages/_document']:
                        found.add(f'{self.base_url}/_next/static/chunks/pages/{chunk}.js')
                        found.add(f'{self.base_url}/_next/static/{build_id}/_buildManifest.js')
                        found.add(f'{self.base_url}/_next/static/{build_id}/_ssgManifest.js')
            except Exception:
                pass

        # Inline script content — scan for JS URL references
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
            inline = m.group(1)
            if len(inline) < 10:
                continue
            for js_url in self._extract_js_from_inline(inline, page_url):
                found.add(js_url)

        # Any string in HTML ending in .js (catches data-src, custom attrs, etc.)
        for m in re.finditer(
            r'''["']((?:https?://|/)[^"'\s<>]{3,200}\.js(?:\?[^"'\s<>]*)?)["']''',
            html
        ):
            u = self._abs(m.group(1), page_url)
            if u:
                found.add(u)

        # Filter empty / invalid
        return {u for u in found if u and u.startswith('http')}

    def _extract_js_from_inline(self, script: str, page_url: str) -> Set[str]:
        """Extract JS URLs from inline script content."""
        found: Set[str] = set()

        # Webpack chunk hash maps
        for m in re.finditer(r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}', script):
            chunk_map = {}
            for cm in re.finditer(r'(\d+)\s*:\s*"([a-f0-9]{4,})"', m.group(0)):
                chunk_map[cm.group(1)] = cm.group(2)

            # Find publicPath
            pub = self.base_url
            pm = re.search(r'publicPath\s*[=:]\s*["\']([^"\']+)["\']', script)
            if pm:
                pub = self._abs(pm.group(1), page_url).rstrip('/')

            for cid, chash in chunk_map.items():
                for tmpl in [
                    f'/static/js/{cid}.{chash}.chunk.js',
                    f'/static/chunks/{cid}.{chash}.js',
                    f'/chunks/{cid}.{chash}.js',
                    f'/{cid}.{chash}.js',
                ]:
                    found.add(pub + tmpl)

        # Next.js chunk paths
        for m in re.finditer(r'''["'](/_next/static/[^"'\s]+\.js)["']''', script):
            found.add(self._abs(m.group(1), page_url))

        # Vite assets
        for m in re.finditer(r'''["'](/assets/[a-zA-Z0-9._\-]+\.js)["']''', script):
            found.add(self._abs(m.group(1), page_url))

        # Generic root-relative .js paths
        for m in re.finditer(r'''["'](/[a-zA-Z0-9._/\-]{3,150}\.js(?:\?[^"'\s]*)?)["']''', script):
            u = self._abs(m.group(1), page_url)
            if u:
                found.add(u)

        return {u for u in found if u and u.startswith('http')}

    def _extract_js_from_manifest(self, text: str, manifest_url: str) -> Set[str]:
        """Parse asset-manifest.json / mix-manifest.json / service worker for JS paths."""
        found: Set[str] = set()
        try:
            # Try JSON manifest
            data = json.loads(text)
            def walk(obj):
                if isinstance(obj, dict):
                    for v in obj.values():
                        walk(v)
                elif isinstance(obj, list):
                    for v in obj:
                        walk(v)
                elif isinstance(obj, str) and obj.endswith('.js'):
                    found.add(self._abs(obj, self.base_url))
            walk(data)
        except Exception:
            pass

        # Also scan as text for .js references
        for m in re.finditer(r'''["'](/[^"'\s]+\.js(?:\?[^"'\s]*)?)["']''', text):
            found.add(self._abs(m.group(1), self.base_url))

        return {u for u in found if u and u.startswith('http')}

    def _extract_page_links(self, html: str, page_url: str) -> Set[str]:
        """Extract same-domain page links for BFS crawling."""
        links: Set[str] = set()
        for m in re.finditer(r'<a[^>]+href=["\']([^"\'#?][^"\']*)["\']', html, re.IGNORECASE):
            href = m.group(1).strip()
            if not href or href.startswith(('mailto:', 'tel:', 'javascript:')):
                continue
            abs_url = self._abs(href, page_url)
            if abs_url and self._is_same_domain(abs_url):
                # Only HTML pages, not files
                path = urlparse(abs_url).path.lower()
                if not any(path.endswith(ext) for ext in
                           ['.js', '.css', '.png', '.jpg', '.gif', '.svg',
                            '.ico', '.woff', '.woff2', '.ttf', '.map', '.json']):
                    links.add(abs_url.split('#')[0].split('?')[0])
        return links

    def _abs(self, path: str, base: str) -> str:
        if not path:
            return ''
        try:
            if path.startswith('//'):
                scheme = urlparse(base).scheme or 'https'
                return f'{scheme}:{path}'
            if path.startswith('http'):
                return path
            return urljoin(base, path)
        except Exception:
            return ''

    def _is_same_domain(self, url: str) -> bool:
        try:
            nl = urlparse(url).netloc
            return nl == self.base_domain or nl.endswith('.' + self.base_domain)
        except Exception:
            return False
