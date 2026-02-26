"""
Report Generator - produces final aggregated reports from analysis results.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


class ReportGenerator:
    """Generates summary.json, analysis text files, and the final findings report."""

    def __init__(
        self,
        target: str,
        base_url: str,
        dirs: dict,
        download_results: dict,
        analysis_results: dict,
        logger,
        scan_duration: float = 0,
    ):
        self.target = target
        self.base_url = base_url
        self.dirs = dirs
        self.dl = download_results
        self.ar = analysis_results
        self.logger = logger
        self.scan_duration = scan_duration

    def generate_all(self):
        """Generate all reports."""
        self._generate_summary_json()
        self._generate_final_report()

    def _generate_summary_json(self):
        """Write summary.json to root output directory."""
        secrets = self.ar.get('secrets', [])
        endpoints = self.ar.get('endpoints', {})
        keywords = self.ar.get('keywords', {})

        # Classify risk level
        high_risk_secrets = [s for s in secrets if s['type'] in {
            'aws_access_key', 'aws_secret_key', 'stripe_key', 'private_key_pem',
            'firebase_api_key', 'supabase_key', 'password'
        }]

        summary = {
            "target": self.target,
            "base_url": self.base_url,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(self.scan_duration, 2),
            "js_files": {
                "total_discovered": self.dl.get('total_discovered', 0),
                "downloaded": self.dl.get('downloaded', 0),
                "duplicates_skipped": self.dl.get('duplicates', 0),
                "failed": self.dl.get('failed', 0),
                "unique_files": self.dl.get('unique_saved', 0),
            },
            "analysis": {
                "total_endpoints": len(endpoints),
                "total_secrets": len(secrets),
                "high_risk_secrets": len(high_risk_secrets),
                "total_keywords": sum(len(v) for v in keywords.values()),
                "total_urls": len(self.ar.get('urls', {})),
            },
            "risk_level": self._compute_risk_level(high_risk_secrets, endpoints, keywords),
            "output_structure": {
                "js_files": "js/",
                "analysis": "analysis/",
                "findings": "findings/",
                "metadata": "metadata/",
            }
        }

        out_path = Path(self.dirs['root']) / "summary.json"
        out_path.write_text(json.dumps(summary, indent=2))
        self.logger.debug(f"    [+] summary.json written")

    def _compute_risk_level(self, high_risk_secrets, endpoints, keywords) -> str:
        if high_risk_secrets:
            return "CRITICAL"
        if len(self.ar.get('secrets', [])) > 5:
            return "HIGH"
        dangerous_keywords = {"admin", "debug", "internal", "staging"}
        if any(k in keywords for k in dangerous_keywords):
            return "MEDIUM"
        if endpoints:
            return "LOW"
        return "INFO"

    def _generate_final_report(self):
        """Generate the comprehensive findings/target-final.txt report."""
        target_clean = self.target.replace('.', '_').replace('/', '_')
        out_path = Path(self.dirs['findings']) / f"{target_clean}-final.txt"

        secrets = self.ar.get('secrets', [])
        endpoints = self.ar.get('endpoints', {})
        keywords = self.ar.get('keywords', {})
        urls = self.ar.get('urls', {})
        file_stats = self.ar.get('file_stats', [])

        lines = []
        sep = "=" * 70

        # Header
        lines += [
            sep,
            f"  JS SCOUT - FINAL FINDINGS REPORT",
            sep,
            f"  Target       : {self.target}",
            f"  Base URL     : {self.base_url}",
            f"  Scan Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Duration     : {self.scan_duration:.1f}s",
            sep,
            "",
        ]

        # Executive Summary
        high_risk_secrets = [s for s in secrets if s['type'] in {
            'aws_access_key', 'aws_secret_key', 'stripe_key', 'private_key_pem',
            'firebase_api_key', 'supabase_key', 'password'
        }]
        risk_level = self._compute_risk_level(high_risk_secrets, endpoints, keywords)

        lines += [
            "[ EXECUTIVE SUMMARY ]",
            "-" * 40,
            f"  Risk Level          : {risk_level}",
            f"  JS Files Discovered : {self.dl.get('total_discovered', 0)}",
            f"  Unique JS Files     : {self.dl.get('unique_saved', 0)}",
            f"  Duplicates Skipped  : {self.dl.get('duplicates', 0)}",
            f"  API Endpoints Found : {len(endpoints)}",
            f"  Secrets Detected    : {len(secrets)} ({len(high_risk_secrets)} HIGH RISK)",
            f"  Keyword Matches     : {sum(len(v) for v in keywords.values())}",
            f"  URLs Extracted      : {len(urls)}",
            "",
        ]

        # High-Risk Findings
        if high_risk_secrets:
            lines += [
                "[ !! HIGH RISK FINDINGS !! ]",
                "-" * 40,
            ]
            for s in high_risk_secrets:
                lines += [
                    f"  TYPE    : {s['type'].upper()}",
                    f"  FILE    : {s['file']}",
                    f"  VALUE   : {s['value']}",
                    f"  CONTEXT : {s['context']}",
                    "",
                ]

        # API Endpoints
        lines += [
            "[ API ENDPOINTS ]",
            "-" * 40,
        ]
        if endpoints:
            for ep in sorted(endpoints.keys()):
                files_str = ', '.join(sorted(endpoints[ep]))
                lines.append(f"  {ep:<60} [{files_str}]")
        else:
            lines.append("  No endpoints found.")
        lines.append("")

        # All Secrets
        lines += [
            "[ SECRETS & CREDENTIALS ]",
            "-" * 40,
        ]
        if secrets:
            for s in secrets:
                lines += [
                    f"  [{s['type'].upper()}]",
                    f"    File    : {s['file']}",
                    f"    Value   : {s['value']}",
                    f"    Context : {s['context']}",
                    "",
                ]
        else:
            lines.append("  No secrets detected.")
        lines.append("")

        # Interesting Keywords
        lines += [
            "[ INTERESTING KEYWORDS ]",
            "-" * 40,
        ]
        if keywords:
            for kw in sorted(keywords.keys()):
                matches = keywords[kw]
                lines.append(f"\n  [{kw.upper()}] - {len(matches)} occurrences")
                for m in matches[:5]:  # show first 5
                    lines.append(f"    {m['file']} (line {m['line']}): {m['content'][:120]}")
        else:
            lines.append("  No interesting keywords found.")
        lines.append("")

        # JS File Details
        lines += [
            "[ JAVASCRIPT FILE INVENTORY ]",
            "-" * 40,
        ]
        for stat in sorted(file_stats, key=lambda x: x.get('size', 0), reverse=True):
            minified_tag = "[MINIFIED]" if stat.get('minified') else "[READABLE]"
            lines.append(
                f"  {stat['filename']:<50} {minified_tag}  "
                f"{stat.get('size', 0):>8} bytes  "
                f"endpoints:{stat.get('endpoints', 0)}  "
                f"secrets:{stat.get('secrets', 0)}"
            )
        lines.append("")

        # External URLs
        lines += [
            "[ EXTRACTED URLS (sample) ]",
            "-" * 40,
        ]
        for u in sorted(urls.keys())[:50]:
            lines.append(f"  {u}")
        if len(urls) > 50:
            lines.append(f"  ... and {len(urls) - 50} more (see analysis/urls.txt)")
        lines.append("")

        # Footer
        lines += [
            sep,
            "  Generated by JS Scout - https://github.com/js-scout",
            "  For security research and authorized testing only.",
            sep,
        ]

        out_path.write_text('\n'.join(lines))
        self.logger.debug(f"    [+] Final report written: {out_path}")
