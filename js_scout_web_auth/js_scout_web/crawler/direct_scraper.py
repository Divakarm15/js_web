"""
Direct HTTP scraper - fallback when external tools aren't available.
Fetches the target page and extracts script src URLs.
"""

import asyncio
import re
from typing import Set
from urllib.parse import urljoin, urlparse

import httpx


class DirectScraper:
    """Simple HTTP-based scraper to find JS URLs in page HTML."""

    def __init__(self, base_url: str, logger, timeout: int = 30):
        self.base_url = base_url
        self.logger = logger
        self.timeout = timeout
        self.base_domain = urlparse(base_url).netloc

    async def scrape(self) -> Set[str]:
        """Fetch the target URL and extract all script src references."""
        js_urls = set()

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=self.timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36"
                }
            ) as client:
                # Fetch main page
                urls_to_check = [self.base_url]
                visited = set()

                for url in urls_to_check[:5]:  # Limit to 5 pages
                    if url in visited:
                        continue
                    visited.add(url)

                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            js_found = self._extract_js_urls(resp.text, url)
                            js_urls.update(js_found)
                            self.logger.debug(f"    [*] Found {len(js_found)} JS URLs at {url}")
                    except Exception as e:
                        self.logger.debug(f"    [!] Scrape error at {url}: {e}")

        except Exception as e:
            self.logger.warning(f"    [!] DirectScraper error: {e}")

        return js_urls

    def _extract_js_urls(self, html: str, page_url: str) -> Set[str]:
        """Extract script src attributes from HTML."""
        js_urls = set()

        # Match <script src="...">
        pattern = re.compile(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in pattern.finditer(html):
            src = match.group(1).strip()
            if src:
                absolute = urljoin(page_url, src)
                if absolute.startswith("http"):
                    js_urls.add(absolute)

        # Match JS files referenced in webpack/bundle configs
        bundle_pattern = re.compile(
            r'["\']((?:https?://[^"\']*)?/[^"\']*\.js(?:\?[^"\']*)?)["\']',
            re.IGNORECASE
        )
        for match in bundle_pattern.finditer(html):
            src = match.group(1).strip()
            if src:
                absolute = urljoin(page_url, src)
                if absolute.startswith("http"):
                    js_urls.add(absolute)

        return js_urls
