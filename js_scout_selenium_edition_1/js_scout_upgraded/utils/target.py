"""
Target URL normalization and output directory management
"""

import re
from pathlib import Path
from urllib.parse import urlparse


def normalize_target(target: str) -> tuple[str, str]:
    """
    Normalize target input to (folder_name, base_url).
    
    Examples:
        "target.com" -> ("target.com", "https://target.com")
        "https://target.com/app" -> ("target.com", "https://target.com")
        "http://sub.target.com" -> ("sub.target.com", "http://sub.target.com")
    """
    # Add scheme if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    host = parsed.netloc or parsed.path

    # Strip www. prefix for folder name
    folder_name = re.sub(r'^www\.', '', host)

    # Reconstruct base URL
    base_url = f"{parsed.scheme}://{host}"

    return folder_name, base_url


def create_output_dirs(output_base: str, target_name: str) -> dict:
    """Create all required output directories and return paths."""
    root = Path(output_base) / target_name

    dirs = {
        'root': root,
        'js': root / 'js',
        'analysis': root / 'analysis',
        'findings': root / 'findings',
        'metadata': root / 'metadata',
    }

    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)

    return {k: str(v) for k, v in dirs.items()}


def safe_filename(url: str, existing: set = None, max_len: int = 200) -> str:
    """
    Convert a JS URL to a safe, readable filename.
    
    - Strips query strings
    - Removes path prefix
    - Handles collisions by appending counter
    """
    from urllib.parse import urlparse, unquote
    import os

    parsed = urlparse(url)
    path = unquote(parsed.path)

    # Get basename
    basename = os.path.basename(path) or "index.js"

    # Ensure .js extension
    if not basename.endswith('.js'):
        basename = basename + '.js'

    # Remove unsafe characters
    safe = re.sub(r'[^\w\.\-]', '_', basename)
    safe = safe[:max_len]

    if not safe or safe == '.js':
        safe = 'script.js'

    if existing is None:
        return safe

    # Handle collisions
    if safe not in existing:
        return safe

    stem = safe[:-3]  # remove .js
    counter = 1
    while True:
        candidate = f"{stem}_{counter}.js"
        if candidate not in existing:
            return candidate
        counter += 1
