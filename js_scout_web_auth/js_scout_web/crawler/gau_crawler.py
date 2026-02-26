"""
GAU (GetAllURLs) crawler - fetches URLs from Wayback Machine, CommonCrawl, OTX
"""

import asyncio
import re
import shutil
import subprocess
from typing import Set


class GauCrawler:
    """Wrapper around the 'gau' CLI tool for passive URL discovery."""

    def __init__(self, domain: str, logger):
        self.domain = domain
        self.logger = logger

    def _is_available(self) -> bool:
        return shutil.which("gau") is not None

    async def crawl(self) -> Set[str]:
        """Run gau and return discovered URLs."""
        if not self._is_available():
            self.logger.warning("    [!] gau not found in PATH - skipping (install: go install github.com/lc/gau/v2/cmd/gau@latest)")
            return set()

        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    self._run_gau
                ),
                timeout=120
            )
            return result
        except asyncio.TimeoutError:
            self.logger.warning("    [!] GAU timed out after 120s")
            return set()
        except Exception as e:
            self.logger.warning(f"    [!] GAU error: {e}")
            return set()

    def _run_gau(self) -> Set[str]:
        """Synchronously run gau subprocess."""
        try:
            proc = subprocess.run(
                ["gau", "--subs", self.domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            urls = set()
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(line)
            return urls
        except subprocess.TimeoutExpired:
            return set()
        except FileNotFoundError:
            return set()
