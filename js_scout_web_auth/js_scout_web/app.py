#!/usr/bin/env python3
"""
JS Scout Web Application — with full auth support
Cookie injection + Playwright auto-login
"""

import asyncio
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, abort
from flask_socketio import SocketIO

sys.path.insert(0, str(Path(__file__).parent))

from utils.target import normalize_target, create_output_dirs
from crawler.gau_crawler import GauCrawler
from crawler.katana_crawler import KatanaCrawler
from crawler.playwright_crawler import PlaywrightCrawler
from crawler.direct_scraper import DirectScraper
from downloader.js_downloader import JSDownloader
from analyzer.js_analyzer import JSAnalyzer
from reporter.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

OUTPUT_BASE = Path(__file__).parent / "output"
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

    # Auth validation
    auth = data.get('auth', {})
    cookies    = auth.get('cookies', '').strip()
    auth_token = auth.get('auth_token', '').strip()
    username   = auth.get('username', '').strip()
    password   = auth.get('password', '').strip()
    login_url  = auth.get('login_url', '').strip()
    username_selector = auth.get('username_selector', '').strip()
    password_selector = auth.get('password_selector', '').strip()

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

    thread = threading.Thread(
        target=run_scan_sync,
        args=(scan_id, target, options, {
            'cookies': cookies,
            'auth_token': auth_token,
            'username': username,
            'password': password,
            'login_url': login_url,
            'username_selector': username_selector,
            'password_selector': password_selector,
        }),
        daemon=True
    )
    thread.start()
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
    # Also load completed scans from disk
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
                    except:
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


# ─── Scan Runner ──────────────────────────────────────────────────────────────

def run_scan_sync(scan_id, target, options, auth):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_scan_async(scan_id, target, options, auth))
    except Exception as e:
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['phase'] = f'Error: {str(e)}'
        _emit_log(scan_id, f'[ERROR] {e}', level='error')
    finally:
        loop.close()


async def run_scan_async(scan_id, target, options, auth):
    scan = active_scans[scan_id]
    scan['status'] = 'running'
    start_time = time.time()

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
        headless    = bool(options.get('headless', False))

        # ── Auth params ──────────────────────────────────────────────────
        cookies        = auth.get('cookies', '') or ''
        auth_token     = auth.get('auth_token', '') or ''
        username       = auth.get('username', '') or ''
        password       = auth.get('password', '') or ''
        login_url      = auth.get('login_url', '') or base_url
        usr_selector   = auth.get('username_selector', '') or ''
        pwd_selector   = auth.get('password_selector', '') or ''

        has_cookies = bool(cookies or auth_token)
        has_creds   = bool(username and password)

        # Build auth_headers dict
        auth_headers = {}
        if auth_token:
            # Auto-detect: if it starts with "ey" it's likely a JWT
            prefix = "Bearer" if auth_token.startswith("ey") else "Bearer"
            auth_headers["Authorization"] = f"{prefix} {auth_token}"

        auth_mode = scan.get('auth_mode', 'none')
        log(f'[*] Target    : {base_url}')
        log(f'[*] Auth mode : {auth_mode.upper()}')
        if has_cookies:
            log(f'[*] Cookies   : {len(cookies.split(";"))} cookie(s) provided')
        if has_creds:
            log(f'[*] Credentials: {username} @ {login_url or base_url}')

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
        progress(15, 'Active crawling with Katana...')
        log('[*] Phase 2: Active crawling (Katana/Hakrawler)...')
        try:
            katana = KatanaCrawler(base_url, _make_logger(log), deep=deep)
            katana_urls = await katana.crawl()
            js_from_katana = {u for u in katana_urls if u.endswith('.js') or '.js?' in u}
            all_js_urls.update(js_from_katana)
            log(f'[+] Katana: {len(katana_urls)} URLs, {len(js_from_katana)} JS files')
        except Exception as e:
            log(f'[!] Katana error: {e}', 'warn')

        # Phase 3: Direct scrape (public, no auth needed)
        progress(25, 'Direct HTTP scraping...')
        log('[*] Phase 3: Direct HTTP scraping (public pages)...')
        try:
            # Pass cookie for authenticated scrape too
            scraper = DirectScraper(base_url, _make_logger(log), timeout=timeout)
            scraped = await scraper.scrape()
            all_js_urls.update(scraped)
            log(f'[+] Direct scrape: {len(scraped)} JS files')
        except Exception as e:
            log(f'[!] Direct scrape error: {e}', 'warn')

        # Phase 4: Playwright (auth-aware)
        if headless or has_creds or has_cookies:
            mode_label = []
            if has_cookies: mode_label.append('cookie-inject')
            if has_creds:   mode_label.append('auto-login')
            if not mode_label: mode_label.append('headless')

            progress(35, f'Playwright [{", ".join(mode_label)}]...')
            log(f'[*] Phase 4: Playwright ({", ".join(mode_label)})...')

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
            if usr_selector:
                pw_kwargs['username_selector'] = usr_selector
            if pwd_selector:
                pw_kwargs['password_selector'] = pwd_selector

            try:
                pw = PlaywrightCrawler(**pw_kwargs)
                pw_urls = await pw.crawl()
                all_js_urls.update(pw_urls)
                log(f'[+] Playwright: {len(pw_urls)} JS files discovered')
            except Exception as e:
                log(f'[!] Playwright error: {e}', 'warn')

        log(f'[*] Total unique JS URLs: {len(all_js_urls)}')

        # Phase 5: Download
        progress(50, f'Downloading {len(all_js_urls)} JS files...')
        log(f'[*] Phase 5: Downloading {len(all_js_urls)} JS files...')
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

        # Phase 6: Analyze
        progress(75, 'Analyzing JavaScript files...')
        log('[*] Phase 6: Analyzing JavaScript...')
        analyzer = JSAnalyzer(
            js_dir=dirs['js'],
            analysis_dir=dirs['analysis'],
            metadata_dir=dirs['metadata'],
            logger=_make_logger(log),
        )
        analysis = analyzer.analyze_all()
        log(f'[+] Endpoints: {len(analysis["endpoints"])} | Secrets: {len(analysis["secrets"])} | Keywords: {sum(len(v) for v in analysis["keywords"].values())}')

        # Phase 7: Report
        progress(90, 'Generating report...')
        log('[*] Phase 7: Generating reports...')
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

        # Save scan metadata
        summary_path = Path(dirs['root']) / 'summary.json'
        if summary_path.exists():
            summary = json.loads(summary_path.read_text())
            summary['scan_id'] = scan_id
            summary['auth_mode'] = auth_mode
            summary_path.write_text(json.dumps(summary, indent=2))

        # Build results payload
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

        high_risk_types = {'aws_access_key','aws_secret_key','stripe_key','private_key_pem','firebase_api_key','supabase_key','password'}
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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _compute_risk(analysis, high_risk_types):
    secrets = analysis.get('secrets', [])
    endpoints = analysis.get('endpoints', {})
    keywords = analysis.get('keywords', {})
    if [s for s in secrets if s['type'] in high_risk_types]: return 'CRITICAL'
    if len(secrets) > 5: return 'HIGH'
    if any(k in keywords for k in {'admin','debug','internal'}): return 'MEDIUM'
    if endpoints: return 'LOW'
    return 'INFO'


def _human_size(size):
    for unit in ['B','KB','MB','GB']:
        if size < 1024: return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


def _emit_log(scan_id, msg, level='info'):
    socketio.emit('scan_log', {
        'scan_id': scan_id, 'msg': msg, 'level': level,
        'time': datetime.now().strftime('%H:%M:%S')
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
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
