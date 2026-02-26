"""
Playwright-based headless browser crawler with full authentication support.

Supports:
  1. Cookie/session header injection (pass raw cookie string or dict)
  2. Auto-login via form fill (username + password selectors)
  3. Fallback: unauthenticated crawl of public pages

Login strategy order:
  - If cookies provided  → inject them before crawling
  - If credentials provided → perform auto-login, then crawl
  - Both provided → inject cookies first, verify auth, fallback to form login
"""

import asyncio
import re
from typing import Optional, Set
from urllib.parse import urljoin, urlparse


class PlaywrightCrawler:
    """Playwright-powered crawler with cookie injection and form-based auto-login."""

    def __init__(
        self,
        base_url: str,
        logger,
        deep: bool = False,
        rate_limit: float = 5.0,
        cookies: Optional[str] = None,
        auth_headers: Optional[dict] = None,
        login_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        username_selector: str = "input[name='email'], input[name='username'], input[type='email'], #username, #email",
        password_selector: str = "input[name='password'], input[type='password'], #password",
        submit_selector: str = "button[type='submit'], input[type='submit']",
        login_wait_selector: Optional[str] = None,
        two_factor: bool = False,
    ):
        self.base_url = base_url
        self.logger = logger
        self.deep = deep
        self.rate_limit = rate_limit
        self.delay = 1.0 / max(rate_limit, 0.1)
        self.base_domain = urlparse(base_url).netloc

        self.cookies_str = cookies
        self.auth_headers = auth_headers or {}
        self.login_url = login_url or base_url
        self.username = username
        self.password = password
        self.username_selector = username_selector
        self.password_selector = password_selector
        self.submit_selector = submit_selector
        self.login_wait_selector = login_wait_selector
        self.two_factor = two_factor

        self._has_cookie_auth = bool(cookies or auth_headers)
        self._has_cred_auth = bool(username and password)

    async def crawl(self) -> Set[str]:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.logger.warning("    [!] playwright not installed: pip install playwright && playwright install chromium")
            return set()

        js_urls: Set[str] = set()

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=not self.two_factor,
                args=["--no-sandbox","--disable-setuid-sandbox","--disable-dev-shm-usage","--disable-gpu","--disable-blink-features=AutomationControlled"],
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
                extra_http_headers=self.auth_headers,
                viewport={"width": 1280, "height": 800},
            )

            if self.cookies_str:
                await self._inject_cookies(context)

            if self._has_cred_auth:
                login_success = await self._attempt_login(context)
                if not login_success:
                    self.logger.warning("    [!] Login failed — continuing unauthenticated")
                else:
                    self.logger.info("    [+] Authentication successful")
            elif self._has_cookie_auth:
                verified = await self._verify_auth(context)
                if verified:
                    self.logger.info("    [+] Cookie auth verified")
                else:
                    self.logger.warning("    [~] Cookie auth unverified — proceeding anyway")

            async def handle_request(request):
                if self._is_js_url(request.url):
                    js_urls.add(request.url)

            context.on("request", handle_request)
            await self._crawl_pages(context, js_urls)
            await self._export_session_cookies(context)
            await browser.close()

        self.logger.info(f"    [+] Playwright collected {len(js_urls)} JS URLs")
        return js_urls

    async def _inject_cookies(self, context):
        self.logger.info("    [*] Injecting session cookies...")
        domain = self.base_domain
        secure = urlparse(self.base_url).scheme == "https"
        cookies_to_add = []
        for part in self.cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies_to_add.append({
                    "name": name.strip(), "value": value.strip(),
                    "domain": domain, "path": "/",
                    "secure": secure, "httpOnly": False, "sameSite": "Lax",
                })
        if cookies_to_add:
            await context.add_cookies(cookies_to_add)
            self.logger.info(f"    [+] Injected {len(cookies_to_add)} cookie(s): {', '.join(c['name'] for c in cookies_to_add)}")
        else:
            self.logger.warning("    [!] Could not parse cookies from provided string")

    async def _verify_auth(self, context) -> bool:
        self.logger.info("    [*] Verifying cookie authentication...")
        page = await context.new_page()
        try:
            await page.goto(self.base_url, wait_until="domcontentloaded", timeout=20000)
            await asyncio.sleep(1)
            final_url = page.url
            content = (await page.content()).lower()
            title = await page.title()
            login_indicators = ["/login", "/signin", "/sign-in", "/auth", "login required", "please log in", "forgot password"]
            for indicator in login_indicators:
                if indicator in final_url.lower() or indicator in content:
                    self.logger.warning(f"    [!] Auth check failed — login indicator: '{indicator}'")
                    await page.close()
                    return False
            self.logger.info(f"    [+] Auth check passed — title: '{title}'")
            await page.close()
            return True
        except Exception as e:
            self.logger.warning(f"    [!] Auth verification error: {e}")
            try: await page.close()
            except: pass
            return False

    async def _attempt_login(self, context) -> bool:
        self.logger.info(f"    [*] Auto-login at: {self.login_url}")
        page = await context.new_page()
        try:
            await page.goto(self.login_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(1)
            self.logger.info(f"    [*] Login page loaded: {page.url}")

            # Fill username
            username_filled = False
            for selector in self.username_selector.split(","):
                selector = selector.strip()
                try:
                    el = page.locator(selector).first
                    if await el.count() > 0 and await el.is_visible():
                        await el.click()
                        await el.fill(self.username)
                        self.logger.info(f"    [+] Filled username: {selector}")
                        username_filled = True
                        break
                except: continue

            if not username_filled:
                # Fallback: first visible text/email input
                try:
                    inputs = page.locator("input:visible")
                    for i in range(await inputs.count()):
                        inp = inputs.nth(i)
                        t = await inp.get_attribute("type") or "text"
                        if t in ("text", "email", "tel"):
                            await inp.fill(self.username)
                            self.logger.info(f"    [+] Filled username (fallback)")
                            username_filled = True
                            break
                except: pass

            if not username_filled:
                self.logger.warning("    [!] Username field not found")
                await page.close()
                return False

            await asyncio.sleep(0.3)

            # Fill password
            password_filled = False
            for selector in self.password_selector.split(","):
                selector = selector.strip()
                try:
                    el = page.locator(selector).first
                    if await el.count() > 0 and await el.is_visible():
                        await el.fill(self.password)
                        self.logger.info(f"    [+] Filled password: {selector}")
                        password_filled = True
                        break
                except: continue

            if not password_filled:
                self.logger.warning("    [!] Password field not found")
                await page.close()
                return False

            await asyncio.sleep(0.3)

            if self.two_factor:
                self.logger.info("    [!] 2FA mode — submit manually then press Enter...")
                input("    Press ENTER after completing 2FA...")

            # Submit
            submitted = False
            for selector in self.submit_selector.split(","):
                selector = selector.strip()
                try:
                    el = page.locator(selector).first
                    if await el.count() > 0 and await el.is_visible():
                        await el.click()
                        self.logger.info(f"    [+] Clicked submit: {selector}")
                        submitted = True
                        break
                except: continue

            if not submitted:
                # Fallback: press Enter on password field
                for selector in self.password_selector.split(","):
                    selector = selector.strip()
                    try:
                        el = page.locator(selector).first
                        if await el.count() > 0:
                            await el.press("Enter")
                            self.logger.info("    [+] Submitted via Enter key")
                            submitted = True
                            break
                    except: continue

            if not submitted:
                self.logger.warning("    [!] Could not submit login form")
                await page.close()
                return False

            # Wait for post-login navigation
            try:
                if self.login_wait_selector:
                    await page.wait_for_selector(self.login_wait_selector, timeout=15000)
                else:
                    await page.wait_for_load_state("networkidle", timeout=15000)
            except:
                await asyncio.sleep(3)

            post_url = page.url
            post_content = (await page.content()).lower()
            title = await page.title()

            failed_indicators = [
                "invalid password", "incorrect password", "wrong password",
                "invalid credentials", "login failed", "authentication failed",
                "incorrect email", "user not found", "no account found",
                "invalid username", "account not found",
            ]
            for indicator in failed_indicators:
                if indicator in post_content:
                    self.logger.warning(f"    [!] Login failed — error: '{indicator}'")
                    await page.close()
                    return False

            self.logger.info(f"    [+] Logged in → {post_url} ('{title}')")
            await page.close()
            return True

        except Exception as e:
            self.logger.warning(f"    [!] Auto-login exception: {e}")
            try: await page.close()
            except: pass
            return False

    async def _crawl_pages(self, context, js_urls: Set[str]):
        visited: Set[str] = set()
        queue = [self.base_url]
        max_pages = 30 if self.deep else 10

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            page = await context.new_page()
            try:
                self.logger.info(f"    [*] Visiting: {url}")
                page.on("response", lambda r: asyncio.ensure_future(self._capture_js_response(r, js_urls)))

                await page.goto(url, wait_until="networkidle", timeout=30000)
                await asyncio.sleep(1.5)

                srcs = await page.evaluate("() => Array.from(document.querySelectorAll('script[src]')).map(s=>s.src).filter(Boolean)")
                for s in srcs:
                    js_urls.add(s)

                chunk_urls = self._extract_chunk_urls(await page.content(), url)
                js_urls.update(chunk_urls)

                if self.deep:
                    links = await page.evaluate("() => Array.from(document.querySelectorAll('a[href]')).map(a=>a.href).filter(h=>h&&h.startsWith('http'))")
                    for link in links:
                        if self._same_domain(link) and link not in visited:
                            queue.append(link)

            except Exception as e:
                self.logger.info(f"    [~] Page error ({url}): {e}")
            finally:
                try: await page.close()
                except: pass
                await asyncio.sleep(self.delay)

    async def _capture_js_response(self, response, js_urls: Set[str]):
        try:
            url = response.url
            ct = response.headers.get("content-type", "")
            if "javascript" in ct or self._is_js_url(url):
                js_urls.add(url)
        except: pass

    def _extract_chunk_urls(self, html: str, page_url: str) -> Set[str]:
        found = set()
        for pat in [
            re.compile(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'),
            re.compile(r'["\']([^"\']*chunk[^"\']*\.js(?:\?[^"\']*)?)["\']'),
        ]:
            for m in pat.finditer(html):
                src = m.group(1).strip()
                if src:
                    abs_url = urljoin(page_url, src)
                    if abs_url.startswith("http"):
                        found.add(abs_url)
        return found

    async def _export_session_cookies(self, context):
        try:
            cookies = await context.cookies()
            if cookies:
                self.logger.info(f"    [*] Active session cookies: {', '.join(c['name'] for c in cookies[:10])}")
        except: pass

    def _is_js_url(self, url: str) -> bool:
        clean = url.split("?")[0].split("#")[0]
        return clean.endswith(".js") or ".js?" in url

    def _same_domain(self, url: str) -> bool:
        try:
            nl = urlparse(url).netloc
            return nl == self.base_domain or nl.endswith("." + self.base_domain)
        except: return False
