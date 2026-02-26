"""
Katana crawler - active web crawler for JS discovery
Falls back to hakrawler if katana is not available
"""

import asyncio
import shutil
import subprocess
from typing import Set


class KatanaCrawler:
    """Wrapper around katana (or hakrawler) CLI tool."""

    def __init__(self, base_url: str, logger, deep: bool = False):
        self.base_url = base_url
        self.logger = logger
        self.deep = deep

    def _find_tool(self):
        """Return (tool_name, cmd_args) for available crawler."""
        if shutil.which("katana"):
            depth = "5" if self.deep else "3"
            cmd = [
                "katana",
                "-u", self.base_url,
                "-d", depth,
                "-jc",           # JS crawling
                "-fx",           # form extraction
                "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf",
                "-silent",
                "-o", "/dev/stdout"
            ]
            if self.deep:
                cmd += ["-c", "20", "-p", "10"]
            return "katana", cmd

        if shutil.which("hakrawler"):
            cmd = [
                "hakrawler",
                "-url", self.base_url,
                "-depth", "3" if self.deep else "2",
                "-js",
            ]
            return "hakrawler", cmd

        return None, None

    async def crawl(self) -> Set[str]:
        """Run crawler and return discovered JS URLs."""
        tool, cmd = self._find_tool()

        if not tool:
            self.logger.warning(
                "    [!] Neither katana nor hakrawler found - skipping. "
                "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )
            return set()

        self.logger.debug(f"    [*] Using {tool}: {' '.join(cmd)}")

        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._run_cmd(cmd)
                ),
                timeout=180
            )
            return result
        except asyncio.TimeoutError:
            self.logger.warning(f"    [!] {tool} timed out after 180s")
            return set()
        except Exception as e:
            self.logger.warning(f"    [!] {tool} error: {e}")
            return set()

    def _run_cmd(self, cmd) -> Set[str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
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
