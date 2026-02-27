#!/usr/bin/env python3
"""
audit.py
========
Scans your Flask/Django project for common XSS vulnerabilities.
Run from your project root:

    python3 audit.py .
    python3 audit.py /path/to/your/project
"""

import sys
import os
import re
from pathlib import Path
from collections import defaultdict


# ── Patterns that indicate potential XSS ─────────────────────────────────────

VULN_PATTERNS = [
    # Python / view layer
    ("CRITICAL", "Unsafe render_template_string with user input",
     re.compile(r'render_template_string\s*\(.*request\.(args|form|GET|POST|json)', re.I)),

    ("CRITICAL", "f-string / format() putting request data directly into HTML",
     re.compile(r'(?:f["\']|\.format\s*\().*request\.(args|form|GET|POST)', re.I)),

    ("CRITICAL", "HttpResponse / make_response with raw user input",
     re.compile(r'(?:HttpResponse|make_response)\s*\(.*request\.(args|form|GET|POST)', re.I)),

    ("CRITICAL", "String concatenation building HTML with user input",
     re.compile(r'(?:<[a-z]+>|<script).*\+.*request\.(args|form|GET|POST)', re.I)),

    ("HIGH", "Direct return of user input as HTML",
     re.compile(r'return\s+.*request\.(args|form|GET|POST)\.get\s*\(', re.I)),

    ("HIGH", "Jinja2 |safe filter used on a variable",
     re.compile(r'\{\{[^}]*\|\s*safe[^}]*\}\}')),

    ("HIGH", "Django {% autoescape off %}",
     re.compile(r'\{%\s*autoescape\s+off\s*%\}')),

    ("HIGH", "Django mark_safe() — only safe after sanitize()",
     re.compile(r'\bmark_safe\s*\(')),

    ("MEDIUM", "redirect() with user-supplied URL — check for open redirect",
     re.compile(r'redirect\s*\(\s*request\.(args|GET)\.get', re.I)),

    ("MEDIUM", "No sanitize() call found before DB save — check for stored XSS",
     re.compile(r'(?:\.save\(\)|\.create\(|objects\.create)(?!.*sanitize)', re.I)),

    ("INFO", "innerHTML assignment in JS — check if value is sanitized",
     re.compile(r'\.innerHTML\s*=')),

    ("INFO", "document.write in JS",
     re.compile(r'document\.write\s*\(')),

    ("INFO", "eval() in JS",
     re.compile(r'\beval\s*\(')),
]

# ── Patterns that indicate the code IS protected ─────────────────────────────

SAFE_INDICATORS = [
    re.compile(r'\bsanitize\s*\('),
    re.compile(r'\bescape_output\s*\('),
    re.compile(r'\bhtmlspecialchars\s*\('),
    re.compile(r'\bhtml\.escape\s*\('),
    re.compile(r'\bDOMPurify\.sanitize\s*\('),
    re.compile(r'\bbleach\.clean\s*\('),
]

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', 'env', '.venv', 'migrations', 'static'}
SCAN_EXTS = {'.py', '.html', '.js', '.jinja', '.jinja2', '.htm'}


def scan_file(filepath: Path) -> list:
    findings = []
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return findings

    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        for severity, description, pattern in VULN_PATTERNS:
            if pattern.search(line):
                # Check if this line or nearby lines have a safe indicator
                context_start = max(0, i - 5)
                context_end   = min(len(lines), i + 3)
                context       = '\n'.join(lines[context_start:context_end])
                is_protected  = any(p.search(context) for p in SAFE_INDICATORS)

                findings.append({
                    'file':        str(filepath),
                    'line':        i,
                    'severity':    severity,
                    'description': description,
                    'code':        stripped[:120],
                    'protected':   is_protected,
                })
                break  # one finding per line

    return findings


def scan_directory(root: str) -> dict:
    root_path = Path(root)
    all_findings = defaultdict(list)
    files_scanned = 0

    for filepath in root_path.rglob('*'):
        # Skip dirs
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix.lower() not in SCAN_EXTS:
            continue
        if not filepath.is_file():
            continue

        findings = scan_file(filepath)
        if findings:
            all_findings[str(filepath)].extend(findings)
        files_scanned += 1

    return dict(all_findings), files_scanned


def print_report(findings: dict, files_scanned: int):
    SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    SEV_COLOR = {
        'CRITICAL': '\033[91m',  # red
        'HIGH':     '\033[93m',  # yellow
        'MEDIUM':   '\033[96m',  # cyan
        'INFO':     '\033[90m',  # grey
    }
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    GREEN   = '\033[92m'
    STRIKE  = '\033[9m'

    total     = sum(len(v) for v in findings.values())
    protected = sum(1 for flist in findings.values() for f in flist if f['protected'])
    actual    = total - protected

    print(f"\n{BOLD}JS Scout — XSS Audit Report{RESET}")
    print(f"{'─' * 60}")
    print(f"  Files scanned : {files_scanned}")
    print(f"  Issues found  : {total} ({actual} unprotected, {protected} likely OK)")
    print(f"{'─' * 60}\n")

    if not findings:
        print(f"{GREEN}  ✓ No XSS patterns detected.{RESET}\n")
        return

    # Sort by severity
    all_flat = []
    for flist in findings.values():
        all_flat.extend(flist)
    all_flat.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 99), x['file'], x['line']))

    for finding in all_flat:
        sev   = finding['severity']
        color = SEV_COLOR.get(sev, '')
        prot  = finding['protected']

        prefix = f"  {GREEN}[LIKELY OK]{RESET} " if prot else f"  {color}[{sev}]{RESET} "
        print(f"{prefix}{finding['description']}")
        print(f"    {finding['file']}:{finding['line']}")
        print(f"    {BOLD}Code:{RESET} {finding['code']}")
        if prot:
            print(f"    {GREEN}↳ Sanitize/escape call detected nearby — verify manually{RESET}")
        print()


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    if not os.path.exists(target):
        print(f"[!] Path not found: {target}")
        sys.exit(1)

    print(f"[*] Scanning: {os.path.abspath(target)}")
    findings, count = scan_directory(target)
    print_report(findings, count)

    # Exit code: 1 if any unprotected CRITICAL/HIGH found
    has_critical = any(
        f['severity'] in ('CRITICAL', 'HIGH') and not f['protected']
        for flist in findings.values()
        for f in flist
    )
    sys.exit(1 if has_critical else 0)


if __name__ == '__main__':
    main()
