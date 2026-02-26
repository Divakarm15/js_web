# JS Scout Web 🔍

A production-ready **macOS-styled web application** for automated JavaScript discovery and analysis. Features a full macOS desktop UI including menu bar, window chrome with traffic lights, sidebar navigation, and dock.

## Quick Start

```bash
cd js_scout_web/

# Install dependencies
pip install -r requirements.txt

# Install Playwright (optional, for --headless mode)
playwright install chromium

# Run the server
python app.py

# Open browser
open http://localhost:5000
```

## Features

- **macOS Desktop UI** — authentic menu bar, window chrome, sidebar, dock
- **Live Scanning** — real-time log terminal with WebSocket updates
- **Full Analysis** — endpoints, secrets, keywords, URLs, JS file inventory
- **Scan History** — persist and revisit previous scans
- **Download Reports** — export final findings as text file
- **Dark Theme** — native macOS dark mode aesthetic

## Architecture

```
js_scout_web/
├── app.py                  # Flask + SocketIO backend
├── templates/index.html    # Single-page application shell
├── static/
│   ├── css/app.css         # macOS design system
│   └── js/app.js           # Frontend SPA logic
└── output/                 # Scan results (auto-created)
```

The web app reuses all modules from the `js_scout/` CLI tool.

## Production Deployment

```bash
# Use gunicorn with eventlet worker
pip install gunicorn eventlet

gunicorn --worker-class eventlet -w 1 app:app --bind 0.0.0.0:5000
```
