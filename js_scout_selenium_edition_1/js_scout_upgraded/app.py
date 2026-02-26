#!/usr/bin/env python3
"""
JS Scout Web Application — Selenium + Chromium Edition
Dynamic JavaScript Intelligence Crawler

Features:
  - Selenium + Chromium WebDriver with performance logging
  - Click automation engine (buttons, links, modals, dropdowns)
  - Depth + max-clicks controls
  - Prioritized JS file saving
  - Security analysis: API keys, JWTs, credentials, etc.
  - Real-time SocketIO updates
  - ZIP download of all results
"""

# ── gevent monkey-patch MUST be first before all other imports ───────────────
from gevent import monkey
monkey.patch_all()
# ─────────────────────────────────────────────────────────────────────────────

# Suppress SSL warnings (we scan targets with self-signed certs)
import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=Warning, message='.*InsecureRequest.*')

import asyncio
import io
import json
import os
import sys
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, abort
from flask_socketio import SocketIO

sys.path.insert(0, str(Path(__file__).parent))

from utils.target import normalize_target, create_output_dirs
from crawler.selenium_crawler import SeleniumCrawler
from crawler.js_file_crawler import JSFileCrawler
from crawler.gau_crawler import GauCrawler
from crawler.katana_crawler import KatanaCrawler
from crawler.playwright_crawler import PlaywrightCrawler
from crawler.direct_scraper import DirectScraper
from downloader.js_downloader import JSDownloader
from analyzer.js_analyzer import JSAnalyzer
from reporter.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='gevent',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
)

OUTPUT_BASE = Path(__file__).parent / 'output'
OUTPUT_BASE.mkdir(exist_ok=True)

active_scans = {}


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    options = data.get('options', {})

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    auth = data.get('auth', {})
    cookies      = auth.get('cookies', '').strip()
    auth_token   = auth.get('auth_token', '').strip()
    username     = auth.get('username', '').strip()
    password     = auth.get('password', '').strip()
    login_url    = auth.get('login_url', '').strip()
    usr_selector = auth.get('username_selector', '').strip()
    pwd_selector = auth.get('password_selector', '').strip()

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {
        'id': scan_id,
        'target': target,
        'status': 'queued',
        'progress': 0,
        'phase': 'Starting...',
        'started_at': datetime.now().isoformat(),
        'options': options,
        'auth_mode': _detect_auth_mode(cookies, auth_token, username, password),
        'log': [],
        'results': None,
    }

    from gevent import spawn
    spawn(run_scan_greenlet, scan_id, target, options, {
        'cookies': cookies,
        'auth_token': auth_token,
        'username': username,
        'password': password,
        'login_url': login_url,
        'username_selector': usr_selector,
        'password_selector': pwd_selector,
    })
    return jsonify({'scan_id': scan_id})


def _detect_auth_mode(cookies, auth_token, username, password):
    if username and password and (cookies or auth_token):
        return 'both'
    if username and password:
        return 'credentials'
    if cookies or auth_token:
        return 'cookies'
    return 'none'


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = active_scans[scan_id]
    return jsonify({
        'id': scan['id'],
        'status': scan['status'],
        'progress': scan['progress'],
        'phase': scan['phase'],
        'log': scan['log'][-30:],
    })


@app.route('/api/scan/<scan_id>/results')
def scan_results(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = active_scans[scan_id]
    if scan['status'] != 'complete':
        return jsonify({'error': 'Scan not complete'}), 400
    return jsonify(scan['results'])


@app.route('/api/scans')
def list_scans():
    scans = []
    for s in active_scans.values():
        scans.append({
            'id': s['id'],
            'target': s['target'],
            'status': s['status'],
            'progress': s['progress'],
            'phase': s['phase'],
            'started_at': s['started_at'],
            'auth_mode': s.get('auth_mode', 'none'),
        })
    if OUTPUT_BASE.exists():
        active_targets = {s['target'] for s in active_scans.values()}
        for d in OUTPUT_BASE.iterdir():
            if d.is_dir():
                summary_file = d / 'summary.json'
                if summary_file.exists():
                    try:
                        summary = json.loads(summary_file.read_text())
                        sid = summary.get('scan_id', d.name)
                        if sid not in active_scans and summary.get('target') not in active_targets:
                            scans.append({
                                'id': sid,
                                'target': summary.get('target', d.name),
                                'status': 'complete',
                                'progress': 100,
                                'phase': 'Complete',
                                'started_at': summary.get('scan_timestamp', ''),
                                'auth_mode': summary.get('auth_mode', 'none'),
                            })
                    except Exception:
                        pass
    return jsonify(sorted(scans, key=lambda x: x.get('started_at', ''), reverse=True))


@app.route('/api/scan/<scan_id>/report')
def download_report(scan_id):
    scan = active_scans.get(scan_id)
    if not scan or scan['status'] != 'complete':
        abort(404)
    target_name = scan['results'].get('target', '')
    safe_target = target_name.replace('.', '_')
    report_path = OUTPUT_BASE / target_name / 'findings' / f'{safe_target}-final.txt'
    if report_path.exists():
        return send_file(report_path, as_attachment=True)
    abort(404)


@app.route('/api/scan/<scan_id>/file/<filename>')
def download_js_file(scan_id, filename):
    scan = active_scans.get(scan_id)
    if not scan:
        abort(404)
    target_name = scan['results'].get('target', '') if scan.get('results') else ''
    file_path = OUTPUT_BASE / target_name / 'js' / filename
    if file_path.exists():
        return send_file(file_path, as_attachment=True)
    abort(404)


@app.route('/download')
@app.route('/api/download')
def download_output():
    """Compress entire output/ directory and return as downloadable ZIP."""
    if not OUTPUT_BASE.exists() or not any(OUTPUT_BASE.iterdir()):
        return jsonify({'error': 'No output available yet'}), 404

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in OUTPUT_BASE.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(OUTPUT_BASE.parent)
                zf.write(file_path, arcname)

    buf.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'js_scout_output_{timestamp}.zip',
    )


@app.route('/api/scan/<scan_id>/download')
def download_scan_output(scan_id):
    """Download output for a specific scan as ZIP."""
    scan = active_scans.get(scan_id)
    target_name = None

    if scan and scan.get('results'):
        target_name = scan['results'].get('target')
    else:
        for d in OUTPUT_BASE.iterdir():
            if d.is_dir():
                sf = d / 'summary.json'
                if sf.exists():
                    try:
                        s = json.loads(sf.read_text())
                        if s.get('scan_id') == scan_id:
                            target_name = s.get('target')
                            break
                    except Exception:
                        pass

    if not target_name:
        abort(404)

    scan_dir = OUTPUT_BASE / target_name
    if not scan_dir.exists():
        abort(404)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in scan_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(scan_dir.parent)
                zf.write(file_path, arcname)
    buf.seek(0)

    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'js_scout_{target_name}_{scan_id}.zip',
    )


# ─── Scan Runner ──────────────────────────────────────────────────────────────

def run_scan_greenlet(scan_id, target, options, auth):
    """Eventlet greenlet entry point — runs async scan in a new event loop."""
    import asyncio as _asyncio
    # Create a brand-new event loop for this greenlet
    loop = _asyncio.new_event_loop()
    _asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_scan_async(scan_id, target, options, auth))
    except Exception as e:
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['phase'] = f'Error: {str(e)}'
        _emit_log(scan_id, f'[ERROR] {e}', level='error')
    finally:
        loop.close()


def run_scan_sync(scan_id, target, options, auth):
    """Legacy threading entry point (kept for compatibility)."""
    run_scan_greenlet(scan_id, target, options, auth)


async def run_scan_async(scan_id, target, options, auth):
    scan = active_scans[scan_id]
    scan['status'] = 'running'
    start_time = time.time()
    selenium_js = set()

    def log(msg, level='info'):
        scan['log'].append({'msg': msg, 'level': level, 'time': datetime.now().strftime('%H:%M:%S')})
        _emit_log(scan_id, msg, level)

    def progress(pct, phase):
        scan['progress'] = pct
        scan['phase'] = phase
        socketio.emit('scan_progress', {'scan_id': scan_id, 'progress': pct, 'phase': phase})

    try:
        target_name, base_url = normalize_target(target)
        dirs = create_output_dirs(str(OUTPUT_BASE), target_name)

        rate_limit  = float(options.get('rate_limit', 10))
        timeout     = int(options.get('timeout', 30))
        deep        = bool(options.get('deep', False))
        headless    = bool(options.get('headless', True))
        depth       = int(options.get('depth', 3))
        max_clicks  = int(options.get('max_clicks', 100))

        cookies      = auth.get('cookies', '') or ''
        auth_token   = auth.get('auth_token', '') or ''
        username     = auth.get('username', '') or ''
        password     = auth.get('password', '') or ''
        login_url    = auth.get('login_url', '') or base_url
        usr_selector = auth.get('username_selector', '') or ''
        pwd_selector = auth.get('password_selector', '') or ''

        has_cookies = bool(cookies or auth_token)
        has_creds   = bool(username and password)

        auth_headers = {}
        if auth_token:
            auth_headers['Authorization'] = f'Bearer {auth_token}'

        auth_mode = scan.get('auth_mode', 'none')
        log(f'[*] Target     : {base_url}')
        log(f'[*] Auth mode  : {auth_mode.upper()}')
        log(f'[*] Headless   : {headless}')
        log(f'[*] Depth      : {depth} | Max clicks: {max_clicks}')

        all_js_urls = set()

        # Phase 1: GAU
        progress(5, 'GAU passive crawling...')
        log('[*] Phase 1: GAU passive crawling...')
        try:
            gau = GauCrawler(target_name, _make_logger(log))
            gau_urls = await gau.crawl()
            js_from_gau = {u for u in gau_urls if u.endswith('.js') or '.js?' in u}
            all_js_urls.update(js_from_gau)
            log(f'[+] GAU: {len(gau_urls)} URLs, {len(js_from_gau)} JS files')
        except Exception as e:
            log(f'[!] GAU error: {e}', 'warn')

        # Phase 2: Katana
        progress(12, 'Active crawling with Katana...')
        log('[*] Phase 2: Active crawling (Katana)...')
        try:
            katana = KatanaCrawler(base_url, _make_logger(log), deep=deep)
            katana_urls = await katana.crawl()
            js_from_katana = {u for u in katana_urls if u.endswith('.js') or '.js?' in u}
            all_js_urls.update(js_from_katana)
            log(f'[+] Katana: {len(katana_urls)} URLs, {len(js_from_katana)} JS files')
        except Exception as e:
            log(f'[!] Katana error: {e}', 'warn')

        # Phase 3: Direct scrape
        progress(20, 'Direct HTTP scraping...')
        log('[*] Phase 3: Direct HTTP scraping...')
        try:
            scraper = DirectScraper(base_url, _make_logger(log), timeout=timeout, max_pages=200)
            scraped = await scraper.scrape()
            all_js_urls.update(scraped)
            log(f'[+] Direct scrape: {len(scraped)} JS files')
        except Exception as e:
            log(f'[!] Direct scrape error: {e}', 'warn')

        # Phase 4: Selenium click automation
        progress(30, f'Selenium click automation (depth={depth}, max-clicks={max_clicks})...')
        log(f'[*] Phase 4: Selenium + Chromium (depth={depth}, max-clicks={max_clicks}, headless={headless})...')
        try:
            selenium_crawler = SeleniumCrawler(
                base_url=base_url,
                logger_obj=_make_logger(log),
                headless=headless,
                depth=depth,
                max_clicks=max_clicks,
                timeout=timeout,
                rate_limit=rate_limit,
                cookies=cookies if cookies else None,
                auth_headers=auth_headers if auth_headers else None,
            )
            loop = asyncio.get_event_loop()
            selenium_js = await loop.run_in_executor(None, selenium_crawler.crawl)
            all_js_urls.update(selenium_js)
            log(f'[+] Selenium: {len(selenium_js)} JS URLs via click automation')
        except Exception as e:
            log(f'[!] Selenium error: {e}', 'warn')

        # Phase 5: Playwright (auth-aware, only if credentials/cookies provided)
        if has_creds or has_cookies:
            mode_label = []
            if has_cookies: mode_label.append('cookie-inject')
            if has_creds:   mode_label.append('auto-login')

            progress(45, f'Playwright [{", ".join(mode_label)}]...')
            log(f'[*] Phase 5: Playwright ({", ".join(mode_label)})...')

            pw_kwargs = dict(
                base_url=base_url,
                logger=_make_logger(log),
                deep=deep,
                rate_limit=rate_limit,
                cookies=cookies if cookies else None,
                auth_headers=auth_headers if auth_headers else None,
                login_url=login_url if login_url else None,
                username=username if username else None,
                password=password if password else None,
            )
            if usr_selector: pw_kwargs['username_selector'] = usr_selector
            if pwd_selector: pw_kwargs['password_selector'] = pwd_selector

            try:
                pw = PlaywrightCrawler(**pw_kwargs)
                pw_urls = await pw.crawl()
                all_js_urls.update(pw_urls)
                log(f'[+] Playwright: {len(pw_urls)} JS files discovered')
            except Exception as e:
                log(f'[!] Playwright error: {e}', 'warn')

        log(f'[*] Total unique JS URLs: {len(all_js_urls)}')

        # Phase 6: Download
        progress(55, f'Downloading + prioritizing {len(all_js_urls)} JS files...')
        log(f'[*] Phase 6: Downloading {len(all_js_urls)} JS files (prioritized)...')
        downloader = JSDownloader(
            js_urls=list(all_js_urls),
            js_dir=dirs['js'],
            metadata_dir=dirs['metadata'],
            logger=_make_logger(log),
            rate_limit=rate_limit,
            timeout=timeout,
            cookies=cookies if cookies else None,
            auth_headers=auth_headers if auth_headers else None,
        )
        dl_results = await downloader.download_all()
        log(f'[+] Downloaded: {dl_results["downloaded"]} | Dupes: {dl_results["duplicates"]} | Failed: {dl_results["failed"]}')

        # ── Phase 6b: Crawl every JS file for embedded URLs ──────────────────
        progress(62, 'Deep crawling: scanning every JS file for embedded URLs...')
        log(f'[*] Phase 6b: JS file content crawl — scanning {dl_results.get("downloaded", 0)} downloaded files for imports, chunks, manifests...')
        try:
            js_file_crawler = JSFileCrawler(
                base_url=base_url,
                js_dir=dirs['js'],
                logger_obj=_make_logger(log),
                max_depth=max(depth, 5),
                max_files=2000,
                timeout=timeout,
                rate_limit=rate_limit,
                cookies=cookies if cookies else None,
                auth_headers=auth_headers if auth_headers else None,
            )
            urls_before = len(all_js_urls)
            # Run synchronous BFS in thread executor so it doesn't block the event loop
            loop = asyncio.get_event_loop()
            all_js_urls = await loop.run_in_executor(None, js_file_crawler.run, all_js_urls)
            new_count = len(all_js_urls) - urls_before
            log(f'[+] JS file crawl complete: +{new_count} new URLs | {len(all_js_urls)} total | {js_file_crawler._saved_count} new files saved')
        except Exception as e:
            import traceback as _tb
            log(f'[!] JS file crawl error: {e}', 'warn')
            log(_tb.format_exc(), 'debug')

        # Organize into prioritized output structure
        progress(67, 'Organizing prioritized output...')
        log('[*] Phase 6c: Organizing files by priority...')
        _organize_prioritized_output(dirs, dl_results, log)

        # Phase 7: Analyze
        progress(75, 'Analyzing JavaScript files...')
        log('[*] Phase 7: Security analysis...')
        analyzer = JSAnalyzer(
            js_dir=dirs['js'],
            analysis_dir=dirs['analysis'],
            metadata_dir=dirs['metadata'],
            logger=_make_logger(log),
        )
        analysis = analyzer.analyze_all()
        log(f'[+] Endpoints: {len(analysis["endpoints"])} | Secrets: {len(analysis["secrets"])} | Keywords: {sum(len(v) for v in analysis["keywords"].values())}')

        if analysis['secrets']:
            socketio.emit('scan_findings', {
                'scan_id': scan_id,
                'secrets': analysis['secrets'][:20],
                'endpoints': list(analysis['endpoints'].keys())[:30],
            })

        # Phase 8: Report
        progress(90, 'Generating reports...')
        log('[*] Phase 8: Generating findings report...')
        duration = time.time() - start_time
        reporter = ReportGenerator(
            target=target_name,
            base_url=base_url,
            dirs=dirs,
            download_results=dl_results,
            analysis_results=analysis,
            logger=_make_logger(log),
            scan_duration=duration,
        )
        reporter.generate_all()
        _save_findings_report(dirs, analysis, all_js_urls, log)

        summary_path = Path(dirs['root']) / 'summary.json'
        if summary_path.exists():
            summary = json.loads(summary_path.read_text())
            summary['scan_id'] = scan_id
            summary['auth_mode'] = auth_mode
            summary['selenium'] = {'depth': depth, 'max_clicks': max_clicks, 'headless': headless}
            summary_path.write_text(json.dumps(summary, indent=2))

        js_files = []
        for f in Path(dirs['js']).glob('*.js'):
            size = f.stat().st_size
            js_files.append({'name': f.name, 'size': size, 'size_human': _human_size(size)})

        js_map = {}
        jmap_path = Path(dirs['metadata']) / 'js-map.json'
        if jmap_path.exists():
            js_map = json.loads(jmap_path.read_text())

        filename_to_urls = {}
        for url, meta in js_map.items():
            fn = meta.get('filename')
            if fn:
                filename_to_urls.setdefault(fn, []).append(url)

        for f in js_files:
            f['urls'] = filename_to_urls.get(f['name'], [])
            f['minified'] = any(meta.get('minified') for url, meta in js_map.items() if meta.get('filename') == f['name'])

        high_risk_types = {'aws_access_key','aws_secret_key','stripe_key','private_key_pem',
                           'firebase_api_key','supabase_key','password'}
        scan['results'] = {
            'target': target_name,
            'base_url': base_url,
            'scan_id': scan_id,
            'auth_mode': auth_mode,
            'duration': round(duration, 1),
            'js_files': js_files,
            'total_discovered': dl_results.get('total_discovered', 0),
            'unique_files': dl_results.get('unique_saved', 0),
            'duplicates': dl_results.get('duplicates', 0),
            'failed': dl_results.get('failed', 0),
            'endpoints': [{'path': ep, 'files': list(files)} for ep, files in sorted(analysis['endpoints'].items())],
            'secrets': analysis['secrets'],
            'high_risk_secrets': [s for s in analysis['secrets'] if s['type'] in high_risk_types],
            'keywords': {kw: matches[:10] for kw, matches in analysis['keywords'].items()},
            'urls': list(analysis['urls'].keys())[:100],
            'risk_level': _compute_risk(analysis, high_risk_types),
            'dirs': dirs,
            'selenium_stats': {
                'depth': depth,
                'max_clicks': max_clicks,
                'headless': headless,
                'urls_from_selenium': len(selenium_js),
            },
        }

        progress(100, 'Scan complete!')
        scan['status'] = 'complete'
        log(f'[+] Done in {duration:.1f}s | Risk: {scan["results"]["risk_level"]}', 'success')
        socketio.emit('scan_complete', {'scan_id': scan_id, 'results': scan['results']})

    except Exception as e:
        import traceback
        scan['status'] = 'error'
        scan['phase'] = f'Error: {str(e)}'
        log(f'[ERROR] {e}', 'error')
        log(traceback.format_exc(), 'error')


# ─── Output Organization ──────────────────────────────────────────────────────

def _organize_prioritized_output(dirs, dl_results, log):
    """Organize JS files into prioritized/ other_js/ inline_js/ dynamic_chunks/."""
    import shutil
    import re as _re

    js_dir = Path(dirs['js'])
    root_dir = Path(dirs['root'])

    prioritized_dir = root_dir / 'prioritized'
    other_dir       = root_dir / 'other_js'
    inline_dir      = root_dir / 'inline_js'
    dynamic_dir     = root_dir / 'dynamic_chunks'

    for d in [prioritized_dir, other_dir, inline_dir, dynamic_dir]:
        d.mkdir(parents=True, exist_ok=True)

    priority_rules = [
        (lambda n, s: n.lower() == 'main.js',),
        (lambda n, s: n.lower() == 'app.js',),
        (lambda n, s: n.lower() == 'bundle.js',),
        (lambda n, s: bool(_re.match(r'main\.[a-z0-9]+\.js$', n, _re.I)),),
        (lambda n, s: bool(_re.match(r'chunk[.\-][a-z0-9]+\.js$', n, _re.I)),),
        (lambda n, s: bool(_re.match(r'vendor[.\-][a-z0-9]+\.js$', n, _re.I)),),
        (lambda n, s: bool(_re.match(r'runtime[.\-][a-z0-9]+\.js$', n, _re.I)),),
        (lambda n, s: s > 200 * 1024,),
    ]

    prioritized_count = other_count = 0

    for js_file in sorted(js_dir.glob('*.js')):
        fname = js_file.name
        fsize = js_file.stat().st_size
        is_priority = False

        for (rule_fn,) in priority_rules:
            try:
                if rule_fn(fname, fsize):
                    is_priority = True
                    break
            except Exception:
                pass

        dest_dir = prioritized_dir if is_priority else other_dir
        dest = dest_dir / fname
        if not dest.exists():
            try:
                shutil.copy2(js_file, dest)
                if is_priority:
                    prioritized_count += 1
                else:
                    other_count += 1
            except Exception:
                pass

    log(f'[+] Output: {prioritized_count} prioritized, {other_count} other JS files')

    metadata = {
        'scan_timestamp': datetime.now().isoformat(),
        'output_structure': {
            'prioritized': str(prioritized_dir),
            'other_js': str(other_dir),
            'inline_js': str(inline_dir),
            'dynamic_chunks': str(dynamic_dir),
        },
        'counts': {'prioritized': prioritized_count, 'other': other_count},
    }
    (root_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2))


def _save_findings_report(dirs, analysis, all_js_urls, log):
    root_dir = Path(dirs['root'])
    report = {
        'generated_at': datetime.now().isoformat(),
        'total_js_urls_found': len(all_js_urls),
        'secrets': analysis.get('secrets', []),
        'endpoints': {ep: list(files) for ep, files in analysis.get('endpoints', {}).items()},
        'urls': list(analysis.get('urls', {}).keys())[:200],
        'keywords': {kw: matches[:5] for kw, matches in analysis.get('keywords', {}).items()},
        'summary': {
            'secrets_found': len(analysis.get('secrets', [])),
            'endpoints_found': len(analysis.get('endpoints', {})),
            'keywords_found': sum(len(v) for v in analysis.get('keywords', {}).values()),
        },
    }
    (root_dir / 'findings_report.json').write_text(json.dumps(report, indent=2))
    log(f'[+] Saved findings_report.json ({len(analysis.get("secrets", []))} secrets)')


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _url_to_filename_guess(url: str) -> str:
    """Quick guess at what filename a URL would save as (for exists-check)."""
    import re as _re
    try:
        from urllib.parse import urlparse as _urlparse
        path = _urlparse(url).path
        import os
        base = os.path.basename(path) or 'index.js'
        if not base.endswith('.js'):
            base += '.js'
        return _re.sub(r'[^\w.\-]', '_', base)
    except Exception:
        return 'unknown.js'


def _compute_risk(analysis, high_risk_types):
    secrets   = analysis.get('secrets', [])
    endpoints = analysis.get('endpoints', {})
    keywords  = analysis.get('keywords', {})
    if [s for s in secrets if s['type'] in high_risk_types]: return 'CRITICAL'
    if len(secrets) > 5: return 'HIGH'
    if any(k in keywords for k in {'admin', 'debug', 'internal'}): return 'MEDIUM'
    if endpoints: return 'LOW'
    return 'INFO'


def _human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024: return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


def _emit_log(scan_id, msg, level='info'):
    socketio.emit('scan_log', {
        'scan_id': scan_id, 'msg': msg, 'level': level,
        'time': datetime.now().strftime('%H:%M:%S'),
    })


class _SimpleLogger:
    def __init__(self, fn):
        self.fn = fn
    def info(self, m):    self.fn(m, 'info')
    def warning(self, m): self.fn(m, 'warn')
    def debug(self, m):   self.fn(m, 'debug')
    def error(self, m):   self.fn(m, 'error')

def _make_logger(fn): return _SimpleLogger(fn)


if __name__ == '__main__':
    print('[*] Starting JS Scout on http://0.0.0.0:5000')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
