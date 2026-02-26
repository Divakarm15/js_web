"""
JavaScript Analyzer - regex and AST-based analysis for endpoints, secrets, and keywords.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


# ─── Pattern Definitions ──────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    # API paths
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_\-\.{}:]+)["\']'),
    re.compile(r'["\'](/api/[a-zA-Z0-9/_\-\.{}:]+)["\']'),
    re.compile(r'["\'](/graphql/?)["\']'),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\']'),
    re.compile(r'["\'](/v[123]/[a-zA-Z0-9/_\-\.{}:]+)["\']'),
    # Generic paths ending with json/xml
    re.compile(r'["\']([a-zA-Z0-9/_\-\.{}:]+\.(?:json|xml))["\']'),
    # fetch/axios/xhr calls
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'(?:url|endpoint|baseURL|baseUrl|apiUrl|API_URL)\s*[:=]\s*["\']([^"\']{4,100})["\']'),
]

SECRET_PATTERNS = [
    # API Keys - generic
    (re.compile(r'(?:api[_\-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', re.IGNORECASE), "api_key"),
    # Tokens
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', re.IGNORECASE), "access_token"),
    (re.compile(r'(?:refresh[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', re.IGNORECASE), "refresh_token"),
    # Bearer tokens
    (re.compile(r'["\']Bearer\s+([a-zA-Z0-9_\-\.]{16,})["\']'), "bearer_token"),
    # JWT
    (re.compile(r'(?:jwt|JWT)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.IGNORECASE), "jwt"),
    (re.compile(r'["\']eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}["\']'), "jwt_token"),
    # Passwords
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.IGNORECASE), "password"),
    # Secrets
    (re.compile(r'(?:secret|client[_\-]?secret|private[_\-]?key)\s*[:=]\s*["\']([^"\']{4,})["\']', re.IGNORECASE), "secret"),
    # AWS
    (re.compile(r'(?:aws[_\-]?access[_\-]?key[_\-]?id)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', re.IGNORECASE), "aws_access_key"),
    (re.compile(r'(?:aws[_\-]?secret[_\-]?access[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9/+]{30,})["\']', re.IGNORECASE), "aws_secret_key"),
    # Firebase
    (re.compile(r'(?:firebase|firebaseConfig)[^{]*apiKey\s*:\s*["\']([^"\']{10,})["\']'), "firebase_api_key"),
    # Supabase
    (re.compile(r'supabase[^;]*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.IGNORECASE), "supabase_key"),
    # Stripe
    (re.compile(r'["\'](?:pk|sk)_(?:test|live)_[a-zA-Z0-9]{20,}["\']'), "stripe_key"),
    # Twilio
    (re.compile(r'AC[a-zA-Z0-9]{32}'), "twilio_account_sid"),
    # Generic private key
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "private_key_pem"),
    # Authorization header value
    (re.compile(r'["\']authorization["\']:\s*["\']([^"\']{10,})["\']', re.IGNORECASE), "auth_header"),
]

KEYWORD_PATTERNS = {
    "admin": re.compile(r'\badmin\b', re.IGNORECASE),
    "internal": re.compile(r'\binternal\b', re.IGNORECASE),
    "debug": re.compile(r'\bdebug\b', re.IGNORECASE),
    "dev": re.compile(r'\bdev(?:elopment)?\b', re.IGNORECASE),
    "staging": re.compile(r'\bstaging\b', re.IGNORECASE),
    "test": re.compile(r'\btest(?:ing)?\b', re.IGNORECASE),
    "beta": re.compile(r'\bbeta\b', re.IGNORECASE),
    "featureflag": re.compile(r'\bfeature[_\-]?flag\b', re.IGNORECASE),
    "experiment": re.compile(r'\bexperiment\b', re.IGNORECASE),
    "mock": re.compile(r'\bmock\b', re.IGNORECASE),
    "sandbox": re.compile(r'\bsandbox\b', re.IGNORECASE),
    "todo": re.compile(r'\bTODO\b', re.IGNORECASE),
    "fixme": re.compile(r'\bFIXME\b', re.IGNORECASE),
    "hardcoded": re.compile(r'\bhardcoded?\b', re.IGNORECASE),
    "localhost": re.compile(r'\blocalhost\b', re.IGNORECASE),
    "127.0.0.1": re.compile(r'127\.0\.0\.1'),
}

URL_PATTERNS = [
    re.compile(r'["\`](https?://[a-zA-Z0-9._\-/:%?#=&+@\[\]{}]+)["\`]'),
    re.compile(r'["\`](//[a-zA-Z0-9._\-/:%?#=&+@\[\]{}]+)["\`]'),
]

# ─── Analyzer Class ───────────────────────────────────────────────────────────

class JSAnalyzer:
    """Analyzes downloaded JS files for endpoints, secrets, keywords, and URLs."""

    def __init__(self, js_dir: str, analysis_dir: str, metadata_dir: str, logger):
        self.js_dir = Path(js_dir)
        self.analysis_dir = Path(analysis_dir)
        self.metadata_dir = Path(metadata_dir)
        self.logger = logger

    def analyze_all(self) -> dict:
        """Analyze all JS files in js_dir. Returns aggregated results."""
        endpoints: Dict[str, Set[str]] = defaultdict(set)  # endpoint -> set of filenames
        secrets: List[dict] = []
        keywords: Dict[str, List[dict]] = defaultdict(list)
        urls: Dict[str, Set[str]] = defaultdict(set)
        file_stats: List[dict] = []

        js_files = list(self.js_dir.glob("*.js"))
        self.logger.info(f"    [*] Analyzing {len(js_files)} JS files...")

        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                filename = js_file.name

                # Extract endpoints
                file_endpoints = self._extract_endpoints(content)
                for ep in file_endpoints:
                    endpoints[ep].add(filename)

                # Extract secrets
                file_secrets = self._extract_secrets(content, filename)
                secrets.extend(file_secrets)

                # Extract keywords
                file_keywords = self._extract_keywords(content, filename)
                for kw, matches in file_keywords.items():
                    keywords[kw].extend(matches)

                # Extract URLs
                file_urls = self._extract_urls(content)
                for u in file_urls:
                    urls[u].add(filename)

                # File stats
                file_stats.append({
                    "filename": filename,
                    "size": js_file.stat().st_size,
                    "endpoints": len(file_endpoints),
                    "secrets": len(file_secrets),
                    "minified": self._is_minified(content),
                })

            except Exception as e:
                self.logger.debug(f"    [!] Error analyzing {js_file.name}: {e}")

        # Try AST analysis for non-minified files
        self._ast_analysis(js_files, endpoints, secrets)

        # Write analysis files
        self._write_analysis(endpoints, secrets, keywords, urls)

        return {
            "endpoints": dict(endpoints),
            "secrets": secrets,
            "keywords": dict(keywords),
            "urls": dict(urls),
            "file_stats": file_stats,
        }

    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints using regex patterns."""
        found = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                ep = match.group(1).strip()
                # Filter noise
                if len(ep) > 3 and len(ep) < 200:
                    if not ep.startswith('//') or ep.startswith('/api') or ep.startswith('/v'):
                        found.add(ep)
        return found

    def _extract_secrets(self, content: str, filename: str) -> List[dict]:
        """Extract potential secrets and credentials."""
        found = []
        seen_values = set()

        for pattern, secret_type in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                try:
                    value = match.group(1) if match.lastindex else match.group(0)
                except:
                    value = match.group(0)

                value = value.strip()

                # Skip obvious placeholders
                if value.lower() in {'your_api_key', 'xxx', 'yyy', 'placeholder', 'example',
                                     'changeme', 'your-secret', 'insert_key_here', ''}:
                    continue
                if len(value) < 4:
                    continue

                # Get context (surrounding line)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ').strip()

                key = f"{filename}:{secret_type}:{value[:20]}"
                if key not in seen_values:
                    seen_values.add(key)
                    found.append({
                        "file": filename,
                        "type": secret_type,
                        "value": value[:100],  # truncate for safety
                        "context": context[:200],
                    })

        return found

    def _extract_keywords(self, content: str, filename: str) -> Dict[str, List[dict]]:
        """Flag files containing interesting keywords."""
        found = defaultdict(list)
        lines = content.split('\n')

        for kw, pattern in KEYWORD_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    found[kw].append({
                        "file": filename,
                        "line": i,
                        "content": line.strip()[:200],
                    })
                    if len(found[kw]) >= 10:  # cap per keyword per file
                        break

        return found

    def _extract_urls(self, content: str) -> Set[str]:
        """Extract all URLs from JS content."""
        found = set()
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(content):
                url = match.group(1).strip()
                if len(url) > 10 and len(url) < 500:
                    # Filter out common noise
                    if not any(noise in url for noise in [
                        'w3.org', 'schema.org', 'mozilla.org', 'ecma-international.org'
                    ]):
                        found.add(url)
        return found

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines:
            return False
        avg_len = sum(len(l) for l in lines) / max(len(lines), 1)
        return avg_len > 500

    def _ast_analysis(self, js_files, endpoints, secrets):
        """Try AST-based analysis using esprima or tree-sitter."""
        # Try esprima first
        try:
            import esprima
            self._esprima_analysis(js_files, endpoints, secrets)
            return
        except ImportError:
            pass

        # Fallback: try tree-sitter
        try:
            import tree_sitter
            self.logger.debug("    [*] tree-sitter available but AST analysis uses esprima - install: pip install esprima")
        except ImportError:
            pass

        self.logger.debug("    [~] AST analysis skipped (install esprima: pip install esprima)")

    def _esprima_analysis(self, js_files, endpoints, secrets):
        """Use esprima for AST-based endpoint and string extraction."""
        import esprima

        self.logger.debug("    [*] Running esprima AST analysis...")
        parsed_count = 0

        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')

                # Skip very large or minified files for AST
                if len(content) > 500_000 or self._is_minified(content):
                    continue

                tree = esprima.parseScript(content, tolerant=True)
                filename = js_file.name

                def visit(node):
                    if node is None:
                        return
                    if isinstance(node, dict):
                        node_type = node.get('type')
                        # Look for string literals that look like endpoints
                        if node_type == 'Literal' and isinstance(node.get('value'), str):
                            val = node['value']
                            if val.startswith('/api') or val.startswith('/v1') or val.startswith('/v2'):
                                if len(val) > 4:
                                    endpoints[val].add(f"{filename}(AST)")
                        # Recurse
                        for key, child in node.items():
                            if isinstance(child, dict):
                                visit(child)
                            elif isinstance(child, list):
                                for item in child:
                                    if isinstance(item, dict):
                                        visit(item)

                visit(tree.toDict())
                parsed_count += 1

            except Exception:
                pass

        self.logger.debug(f"    [+] AST parsed {parsed_count} non-minified files")

    def _write_analysis(self, endpoints, secrets, keywords, urls):
        """Write analysis results to text files."""

        # endpoints.txt
        ep_lines = []
        for ep in sorted(endpoints.keys()):
            files = ', '.join(sorted(endpoints[ep]))
            ep_lines.append(f"{ep}\t[{files}]")
        (self.analysis_dir / "endpoints.txt").write_text('\n'.join(ep_lines))

        # secrets.txt
        secret_lines = []
        for s in secrets:
            secret_lines.append(
                f"[{s['type'].upper()}] File: {s['file']}\n"
                f"  Value: {s['value']}\n"
                f"  Context: {s['context']}\n"
            )
        (self.analysis_dir / "secrets.txt").write_text('\n'.join(secret_lines))

        # keywords.txt
        kw_lines = []
        for kw in sorted(keywords.keys()):
            kw_lines.append(f"\n=== {kw.upper()} ===")
            for match in keywords[kw][:20]:  # limit output
                kw_lines.append(f"  File: {match['file']} Line {match['line']}: {match['content']}")
        (self.analysis_dir / "keywords.txt").write_text('\n'.join(kw_lines))

        # urls.txt
        url_lines = sorted(urls.keys())
        (self.analysis_dir / "urls.txt").write_text('\n'.join(url_lines))

        self.logger.debug(f"    [+] Analysis files written to {self.analysis_dir}")
