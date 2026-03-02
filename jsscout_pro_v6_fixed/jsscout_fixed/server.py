#!/usr/bin/env python3
"""
JS Scout Pro — Web Server
Run: python3 server.py
Open: http://localhost:7331
"""

import json, sys, os, threading, time, uuid
from pathlib import Path
from urllib.parse import urlparse

try:
    from flask import Flask, request, jsonify, send_file, make_response
except ImportError:
    print("[!] pip install flask"); sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
from jsscout import JSScout, XSS_PAYLOADS

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)

SCANS = {}
OUTPUT_BASE = Path(__file__).parent / 'output'
OUTPUT_BASE.mkdir(exist_ok=True)


@app.route('/')
def index():
    return send_file(Path(__file__).parent / 'static' / 'index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data       = request.get_json() or {}
    target     = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    options    = data.get('options', {})
    cookies    = data.get('cookies', '').strip()
    auth_token = data.get('auth_token', '').strip()

    extra_headers = {}
    if auth_token:
        extra_headers['Authorization'] = f'Bearer {auth_token}'

    scan_id    = str(uuid.uuid4())[:8]
    domain     = urlparse(target if '://' in target else 'https://' + target).netloc.replace(':', '_')
    output_dir = OUTPUT_BASE / domain / scan_id

    state = {
        'id': scan_id, 'target': target,
        'status': 'running', 'progress': 0,
        'phase': 'Starting...', 'log': [],
        'results': None, 'report_url': None,
        'output_dir': str(output_dir),
    }
    SCANS[scan_id] = state

    def run():
        def log_fn(msg):
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': msg})
            if   '[*] Phase 1' in msg:
                state['progress'] = 5;  state['phase'] = 'Phase 1: Crawling pages...'
            elif '[+] Crawl'   in msg:
                state['progress'] = 30; state['phase'] = 'Crawl complete'
            elif '[*] Phase 2' in msg:
                state['progress'] = 35; state['phase'] = 'Phase 2: Probing manifests...'
            elif '[*] Phase 3' in msg:
                state['progress'] = 45; state['phase'] = 'Phase 3: Downloading JS files...'
            elif '[+] Downloaded' in msg or '[+] Download' in msg:
                state['progress'] = 55; state['phase'] = 'JS files downloaded'
            elif '[*] Phase 4' in msg:
                state['progress'] = 60; state['phase'] = 'Phase 4: Deep JS crawl...'
            elif '[*] Phase 5' in msg:
                state['progress'] = 70; state['phase'] = 'Phase 5: Analyzing JS files...'
            elif '[analyze]'   in msg:
                state['progress'] = min(state['progress'] + 1, 88)
            elif '[*] Phase 6' in msg:
                state['progress'] = 90; state['phase'] = 'Phase 6: Probing parameters...'
            elif '[probe]'     in msg:
                state['progress'] = 92; state['phase'] = 'Phase 6: Testing XSS params...'
            elif '[⚡ XSS FOUND]' in msg or '[⚡ REFLECTED' in msg:
                state['progress'] = min(state['progress'] + 1, 97)
                state['phase'] = 'Phase 6: Reflected XSS found!'
            elif '[*] Phase 7' in msg:
                state['progress'] = 98; state['phase'] = 'Phase 7: Writing report...'

        try:
            scout = JSScout(
                target=target,
                output_dir=str(output_dir),
                threads=int(options.get('threads', 10)),
                timeout=int(options.get('timeout', 15)),
                max_pages=int(options.get('max_pages', 200)),
                depth=int(options.get('depth', 3)),
                cookies=cookies or None,
                extra_headers=extra_headers or None,
                use_selenium=options.get('use_selenium', True),
                log_fn=log_fn,
            )
            results = scout.run()
            results['external_urls'] = list(results.get('external_urls', []))
            state['results']    = results
            state['status']     = 'complete'
            state['progress']   = 100
            state['phase']      = 'Complete'
            # Report URL that the browser can open directly
            state['report_url'] = f'/report/{scan_id}'
        except Exception as e:
            import traceback
            state['status'] = 'error'
            state['phase']  = f'Error: {e}'
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': f'[ERROR] {e}'})
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': traceback.format_exc()})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    return jsonify({
        'id':         s['id'],
        'status':     s['status'],
        'progress':   s['progress'],
        'phase':      s['phase'],
        'log':        s['log'][-60:],
        'report_url': s.get('report_url'),
    })


@app.route('/api/scan/<scan_id>/results')
def scan_results(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    if s['status'] != 'complete':
        return jsonify({'error': 'Scan not complete'}), 400
    return jsonify(s['results'])


# Serve the HTML report directly in the browser
@app.route('/report/<scan_id>')
def view_report(scan_id):
    if scan_id not in SCANS:
        return 'Scan not found', 404
    s = SCANS[scan_id]
    html_path = Path(s['output_dir']) / 'report.html'
    if html_path.exists():
        resp = make_response(html_path.read_text(encoding='utf-8'))
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp
    return 'Report not ready yet', 404


# Download raw text report
@app.route('/api/scan/<scan_id>/report')
def download_report(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    rp = Path(s['output_dir']) / 'report.txt'
    if rp.exists():
        return send_file(str(rp), as_attachment=True, download_name='jsscout_report.txt')
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/payloads')
def get_payloads():
    return jsonify(XSS_PAYLOADS)


@app.route('/api/scans')
def list_scans():
    return jsonify([
        {'id': s['id'], 'target': s['target'],
         'status': s['status'], 'progress': s['progress'],
         'report_url': s.get('report_url')}
        for s in SCANS.values()
    ])


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7331))
    print(f'\n  JS Scout Pro')
    print(f'  Open: http://localhost:{port}\n')
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
