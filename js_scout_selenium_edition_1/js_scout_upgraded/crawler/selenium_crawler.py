"""
Selenium + Chromium Deep Crawler
=================================
- Visits every page on the target site (BFS, no depth limit on link following)
- Collects ALL JS from Chrome performance logs (includes CDN, cross-origin chunks)
- Scrolls pages to trigger lazy loading
- Clicks interactive elements to trigger dynamic imports
- Waits for SPA rendering (React/Vue/Angular/Next.js)
- No domain restriction on JS collection (CDN JS is always included)
"""

import hashlib
import json
import re
import time
from typing import Dict, Optional, Set, List
from urllib.parse import urljoin, urlparse

DANGEROUS_PATTERNS = re.compile(
    r'(logout|log.out|sign.?out|signout|delete|destroy|remove|'
    r'reset|unsubscribe|cancel.?account|deactivate)',
    re.IGNORECASE,
)


class SeleniumCrawler:

    def __init__(
        self,
        base_url: str,
        logger_obj=None,
        headless: bool = True,
        depth: int = 3,
        max_clicks: int = 100,
        timeout: int = 30,
        rate_limit: float = 5.0,
        cookies: Optional[str] = None,
        auth_headers: Optional[Dict] = None,
    ):
        self.base_url    = base_url.rstrip('/')
        self.log         = logger_obj
        self.headless    = headless
        self.depth       = depth
        self.max_clicks  = max_clicks
        self.timeout     = timeout
        self.delay       = max(0.2, 1.0 / max(rate_limit, 0.1))
        self.cookies_str = cookies
        self.auth_headers = auth_headers or {}
        self.base_domain = urlparse(base_url).netloc

        self._visited_urls: Set[str] = set()
        self._dom_hashes:   Set[str] = set()
        self._js_urls:      Set[str] = set()
        self._click_count:  int = 0

    # ── Public entry ──────────────────────────────────────────────────────────

    def crawl(self) -> Set[str]:
        try:
            from selenium import webdriver
        except ImportError:
            self.log and self.log.warning('[selenium] selenium not installed')
            return set()

        driver = self._build_driver()
        if driver is None:
            return set()

        try:
            # Go to base URL first (needed before setting cookies)
            driver.get(self.base_url)
            self._inject_cookies(driver)
            if self.auth_headers:
                try:
                    driver.execute_cdp_cmd('Network.setExtraHTTPHeaders',
                                           {'headers': self.auth_headers})
                except Exception:
                    pass
            self._bfs_crawl(driver)
        except Exception as e:
            self.log and self.log.error(f'[selenium] Fatal: {e}')
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        self.log and self.log.info(
            f'[selenium] Done. {len(self._js_urls)} JS URLs | '
            f'{len(self._visited_urls)} pages visited | '
            f'{self._click_count} clicks'
        )
        return self._js_urls

    # ── Driver ────────────────────────────────────────────────────────────────

    def _build_driver(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            opts = Options()
            if self.headless:
                opts.add_argument('--headless=new')
            opts.add_argument('--no-sandbox')
            opts.add_argument('--disable-setuid-sandbox')
            opts.add_argument('--disable-dev-shm-usage')
            opts.add_argument('--disable-gpu')
            opts.add_argument('--disable-blink-features=AutomationControlled')
            opts.add_argument('--window-size=1280,900')
            opts.add_argument('--ignore-certificate-errors')
            opts.add_argument('--allow-insecure-localhost')
            opts.add_argument(
                '--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
            )
            opts.add_experimental_option('excludeSwitches', ['enable-automation'])
            opts.add_experimental_option('useAutomationExtension', False)
            # Performance log to capture ALL network JS requests
            opts.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

            driver = webdriver.Chrome(options=opts)
            driver.set_page_load_timeout(self.timeout)
            return driver
        except Exception as e:
            self.log and self.log.error(f'[selenium] Chrome start failed: {e}')
            return None

    # ── Cookie injection ──────────────────────────────────────────────────────

    def _inject_cookies(self, driver):
        if not self.cookies_str:
            return
        try:
            count = 0
            for pair in self.cookies_str.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    name, _, value = pair.partition('=')
                    driver.add_cookie({'name': name.strip(), 'value': value.strip()})
                    count += 1
            self.log and self.log.info(f'[selenium] Injected {count} cookie(s)')
        except Exception as e:
            self.log and self.log.warning(f'[selenium] Cookie error: {e}')

    # ── BFS page crawl ────────────────────────────────────────────────────────

    def _bfs_crawl(self, driver):
        """
        BFS over all pages of the target site.
        Collects JS from every page visited.
        """
        queue = [self.base_url]
        depth_map = {self.base_url: 0}

        while queue:
            url = queue.pop(0)
            if url in self._visited_urls:
                continue

            current_depth = depth_map.get(url, 0)
            self._visited_urls.add(url)

            self.log and self.log.info(
                f'[selenium] [{current_depth}/{self.depth}] Visiting: {url}'
            )

            try:
                driver.get(url)
                self._wait_for_page(driver)
            except Exception as e:
                self.log and self.log.debug(f'[selenium] Nav error {url}: {e}')
                continue

            # Collect JS immediately
            self._collect_all_js(driver, url)

            # Scroll to trigger lazy loading + collect more
            self._scroll_page(driver)
            self._collect_from_perf_log(driver)

            # Click interactive elements
            if self._click_count < self.max_clicks:
                self._click_elements(driver, url)

            # Collect again after clicks
            self._collect_all_js(driver, url)

            # Discover links for next BFS level
            if current_depth < self.depth:
                links = self._get_page_links(driver, url)
                for link in links:
                    if link not in self._visited_urls and link not in depth_map:
                        depth_map[link] = current_depth + 1
                        queue.append(link)

    # ── JS collection ─────────────────────────────────────────────────────────

    def _collect_all_js(self, driver, page_url: str):
        """Collect JS from all sources on the current page."""
        # 1. <script src="..."> tags — includes CDN scripts
        try:
            srcs = driver.execute_script(
                "return Array.from(document.querySelectorAll('script[src]'))"
                ".map(s=>s.src).filter(Boolean)"
            )
            for src in srcs:
                if src.startswith('http'):
                    self._js_urls.add(src)
        except Exception:
            pass

        # 2. <link rel="modulepreload"> and <link rel="preload" as="script">
        try:
            preloads = driver.execute_script("""
                return Array.from(document.querySelectorAll(
                    'link[rel="modulepreload"], link[rel="preload"][as="script"]'
                )).map(l=>l.href).filter(Boolean)
            """)
            for p in preloads:
                if p.startswith('http') and p.endswith('.js'):
                    self._js_urls.add(p)
        except Exception:
            pass

        # 3. Extract from page source (webpack maps, inline bootstrap)
        try:
            source = driver.page_source
            self._extract_from_source(source, page_url)
        except Exception:
            pass

        # 4. Performance log — catches EVERYTHING loaded over the network
        self._collect_from_perf_log(driver)

    def _collect_from_perf_log(self, driver):
        """Extract ALL JS URLs from Chrome DevTools performance log."""
        try:
            logs = driver.get_log('performance')
            for entry in logs:
                try:
                    msg = json.loads(entry.get('message', '{}'))
                    params = msg.get('message', {}).get('params', {})
                    method = msg.get('message', {}).get('method', '')

                    # Network requests
                    if method == 'Network.requestWillBeSent':
                        url = params.get('request', {}).get('url', '')
                        if url and self._is_js_url(url):
                            self._js_urls.add(url)

                    # Responses (catches redirected URLs)
                    elif method == 'Network.responseReceived':
                        url = params.get('response', {}).get('url', '')
                        ct  = params.get('response', {}).get('mimeType', '')
                        if url and (self._is_js_url(url) or 'javascript' in ct):
                            self._js_urls.add(url)

                    # Script parsed events — catches eval'd scripts, workers
                    elif method == 'Debugger.scriptParsed':
                        url = params.get('url', '')
                        if url and self._is_js_url(url):
                            self._js_urls.add(url)

                except Exception:
                    continue
        except Exception as e:
            self.log and self.log.debug(f'[selenium] Perf log error: {e}')

    def _extract_from_source(self, html: str, page_url: str):
        """Extract JS URLs from page HTML source."""
        patterns = [
            # Explicit src attributes
            re.compile(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'),
            # Next.js static chunks
            re.compile(r'["\'](\/_next\/static\/[^"\']*\.js(?:\?[^"\']*)?)["\']'),
            # Vite assets
            re.compile(r'["\'](/assets/[a-zA-Z0-9._\-]+\.js)["\']'),
            # Any root-relative .js
            re.compile(r'["\'](/[a-zA-Z0-9._/\-]{3,200}\.js(?:\?[^"\']*)?)["\']'),
            # Absolute JS URLs
            re.compile(r'["\'](https?://[^\s"\'<>]{4,300}\.js(?:\?[^"\']*)?)["\']'),
            # Webpack chunk hashes pattern
            re.compile(r'["\']([^"\']*chunk[^"\']*\.js(?:\?[^"\']*)?)["\']'),
        ]

        for pat in patterns:
            for m in pat.finditer(html):
                src = m.group(1).strip()
                if src:
                    abs_url = self._abs(src, page_url)
                    if abs_url and abs_url.startswith('http'):
                        self._js_urls.add(abs_url)

        # Webpack chunk hash map reconstruction
        pub_path = self.base_url
        pm = re.search(r'publicPath\s*[=:]\s*["\']([^"\']+)["\']', html)
        if pm:
            pub_path = self._abs(pm.group(1), page_url).rstrip('/')

        for m in re.finditer(
            r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}',
            html
        ):
            for cm in re.finditer(r'(\d+)\s*:\s*"([a-f0-9]{4,})"', m.group(0)):
                cid, chash = cm.group(1), cm.group(2)
                for tmpl in [
                    f'/static/js/{cid}.{chash}.chunk.js',
                    f'/static/chunks/{cid}.{chash}.js',
                    f'/_next/static/chunks/{cid}.{chash}.js',
                ]:
                    self._js_urls.add(pub_path + tmpl)

    # ── Click automation ──────────────────────────────────────────────────────

    def _click_elements(self, driver, page_url: str):
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait

        selectors = [
            'button:not([type="submit"]):not([type="reset"])',
            '[role="button"]',
            '[data-toggle]',
            '.dropdown-toggle',
            '.accordion-button',
            'details > summary',
            'a[onclick]',
            '[data-modal]',
            '.tab',
            '.nav-link',
            '[aria-expanded="false"]',
        ]

        candidates = []
        for sel in selectors:
            try:
                candidates.extend(driver.find_elements(By.CSS_SELECTOR, sel))
            except Exception:
                pass

        for el in candidates:
            if self._click_count >= self.max_clicks:
                break
            try:
                if not el.is_displayed() or not el.is_enabled():
                    continue
                text = (el.text or el.get_attribute('aria-label') or
                        el.get_attribute('title') or '').lower()
                href = el.get_attribute('href') or ''

                if DANGEROUS_PATTERNS.search(text) or DANGEROUS_PATTERNS.search(href):
                    continue
                if href.startswith('http') and not self._is_same_domain(href):
                    continue
                if href.startswith(('mailto:', 'tel:', 'javascript:void')):
                    continue

                driver.execute_script('arguments[0].scrollIntoView({block:"center"})', el)
                time.sleep(0.15)
                el.click()
                self._click_count += 1
                time.sleep(0.4)
                self._collect_from_perf_log(driver)

                # Navigate back if we left the page
                try:
                    if driver.current_url.rstrip('/') != page_url.rstrip('/'):
                        if self._is_same_domain(driver.current_url):
                            self._collect_all_js(driver, driver.current_url)
                        driver.back()
                        time.sleep(0.4)
                except Exception:
                    pass

            except Exception:
                try:
                    if driver.current_url.rstrip('/') != page_url.rstrip('/'):
                        driver.back()
                        time.sleep(0.4)
                except Exception:
                    pass

    # ── Page utilities ────────────────────────────────────────────────────────

    def _wait_for_page(self, driver):
        from selenium.webdriver.support.ui import WebDriverWait
        try:
            WebDriverWait(driver, self.timeout).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
            # Extra wait for SPA frameworks
            time.sleep(0.8)
        except Exception:
            pass

    def _scroll_page(self, driver):
        try:
            total = driver.execute_script('return document.body.scrollHeight')
            step = 300
            for pos in range(0, min(total, 8000), step):
                driver.execute_script(f'window.scrollTo(0, {pos})')
                time.sleep(0.05)
            driver.execute_script('window.scrollTo(0, 0)')
        except Exception:
            pass

    def _get_page_links(self, driver, page_url: str) -> List[str]:
        try:
            hrefs = driver.execute_script(
                "return Array.from(document.querySelectorAll('a[href]'))"
                ".map(a=>a.href).filter(h=>h&&h.startsWith('http'))"
            )
            links = []
            for h in hrefs:
                if self._is_same_domain(h) and h not in self._visited_urls:
                    # Skip file downloads
                    path = urlparse(h).path.lower()
                    if not any(path.endswith(ext) for ext in
                               ['.js', '.css', '.png', '.jpg', '.pdf', '.zip',
                                '.svg', '.ico', '.woff', '.ttf', '.map']):
                        links.append(h.split('#')[0])
            return list(set(links))
        except Exception:
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

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

    def _is_js_url(self, url: str) -> bool:
        if not url or url.startswith('data:') or url.startswith('blob:'):
            return False
        clean = url.split('?')[0].split('#')[0]
        return clean.endswith('.js') or clean.endswith('.mjs')

    def _is_same_domain(self, url: str) -> bool:
        try:
            nl = urlparse(url).netloc
            return nl == self.base_domain or nl.endswith('.' + self.base_domain)
        except Exception:
            return False

    def _dom_hash(self, driver) -> str:
        try:
            body = driver.execute_script(
                'return document.body ? document.body.innerHTML.substring(0, 4096) : ""'
            )
            return hashlib.md5(body.encode()).hexdigest()
        except Exception:
            return ''
