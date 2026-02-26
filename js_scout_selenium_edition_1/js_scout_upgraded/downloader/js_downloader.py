"""
JavaScript file downloader with SHA256-based deduplication.
Downloads, saves, and tracks all JS files with metadata.
"""

import asyncio
import hashlib
import json
import re
import time
import warnings
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse, unquote

import httpx
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

from utils.target import safe_filename


class JSDownloader:
    """Downloads JS files, deduplicates by content hash, saves metadata.

    Auth support:
      - cookies: raw cookie string "session=abc; token=xyz"
      - auth_headers: dict of extra request headers {"Authorization": "Bearer ..."}
    """

    BASE_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(
        self,
        js_urls: List[str],
        js_dir: str,
        metadata_dir: str,
        logger,
        rate_limit: float = 10.0,
        timeout: int = 30,
        max_concurrent: int = 10,
        cookies: str = None,
        auth_headers: dict = None,
    ):
        self.js_urls = list(set(js_urls))
        self.js_dir = Path(js_dir)
        self.metadata_dir = Path(metadata_dir)
        self.logger = logger
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay = 1.0 / max(rate_limit, 0.1)

        # Build merged request headers
        self.HEADERS = dict(self.BASE_HEADERS)
        if auth_headers:
            self.HEADERS.update(auth_headers)
        if cookies:
            self.HEADERS["Cookie"] = cookies

        # State tracking
        self.hashes: Dict[str, str] = {}   # sha256 -> filename
        self.url_map: Dict[str, dict] = {} # url -> {filename, sha256, size, minified, ...}
        self.saved_filenames: Set[str] = set()

        # Load existing metadata if re-running
        self._load_existing_metadata()

    def _load_existing_metadata(self):
        """Load existing metadata to support safe re-runs."""
        hash_file = self.metadata_dir / "hashes.json"
        map_file = self.metadata_dir / "js-map.json"

        if hash_file.exists():
            try:
                self.hashes = json.loads(hash_file.read_text())
            except:
                pass

        if map_file.exists():
            try:
                self.url_map = json.loads(map_file.read_text())
                self.saved_filenames = {v['filename'] for v in self.url_map.values() if 'filename' in v}
            except:
                pass

    def _sha256(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _is_minified(self, content: str) -> bool:
        """Heuristic: minified if avg line length > 500 chars."""
        lines = content.split('\n')
        if not lines:
            return False
        avg_len = sum(len(l) for l in lines) / len(lines)
        return avg_len > 500

    async def download_all(self) -> dict:
        """Download all JS URLs concurrently, respecting rate limits."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = {"downloaded": 0, "duplicates": 0, "failed": 0, "skipped": 0}

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
            headers=self.HEADERS,
        ) as client:
            tasks = []
            for url in self.js_urls:
                tasks.append(self._download_one(client, url, semaphore, results))

            await asyncio.gather(*tasks, return_exceptions=True)

        # Save metadata
        self._save_metadata()

        results['total_discovered'] = len(self.js_urls)
        results['unique_saved'] = len({v['sha256'] for v in self.url_map.values() if 'sha256' in v})
        return results

    async def _download_one(self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, results: dict):
        """Download a single JS file."""
        # Skip if already downloaded in this run
        if url in self.url_map and 'filename' in self.url_map[url]:
            results['skipped'] += 1
            return

        async with semaphore:
            await asyncio.sleep(self.delay)
            try:
                self.logger.debug(f"    [*] Downloading: {url}")
                resp = await client.get(url)

                if resp.status_code != 200:
                    self.logger.debug(f"    [!] HTTP {resp.status_code}: {url}")
                    results['failed'] += 1
                    self.url_map[url] = {"url": url, "status": resp.status_code, "error": f"HTTP {resp.status_code}"}
                    return

                content = resp.content
                content_str = content.decode('utf-8', errors='replace')
                sha256 = self._sha256(content)

                entry = {
                    "url": url,
                    "sha256": sha256,
                    "size": len(content),
                    "content_type": resp.headers.get("content-type", ""),
                    "status": resp.status_code,
                    "minified": self._is_minified(content_str),
                    "inline": False,
                }

                # Check for duplicate content
                if sha256 in self.hashes:
                    existing_filename = self.hashes[sha256]
                    entry["filename"] = existing_filename
                    entry["duplicate_of"] = existing_filename
                    self.url_map[url] = entry
                    results['duplicates'] += 1
                    self.logger.debug(f"    [~] Duplicate (same as {existing_filename}): {url}")
                    return

                # Generate safe filename
                filename = safe_filename(url, self.saved_filenames)
                self.saved_filenames.add(filename)
                self.hashes[sha256] = filename

                # Save file
                out_path = self.js_dir / filename
                out_path.write_bytes(content)

                entry["filename"] = filename
                self.url_map[url] = entry
                results['downloaded'] += 1
                self.logger.debug(f"    [+] Saved: {filename} ({len(content)} bytes)")

            except httpx.TimeoutException:
                self.logger.debug(f"    [!] Timeout: {url}")
                results['failed'] += 1
                self.url_map[url] = {"url": url, "error": "timeout"}

            except Exception as e:
                self.logger.debug(f"    [!] Error downloading {url}: {e}")
                results['failed'] += 1
                self.url_map[url] = {"url": url, "error": str(e)}

    def _save_metadata(self):
        """Save hash registry and URL map to disk."""
        (self.metadata_dir / "hashes.json").write_text(
            json.dumps(self.hashes, indent=2)
        )
        (self.metadata_dir / "js-map.json").write_text(
            json.dumps(self.url_map, indent=2)
        )
