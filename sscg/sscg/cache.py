"""HTTP JSON with an on-disk cache, so scans also work offline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent  # the sscg/ project folder
CACHE = ROOT / ".cache"
OFFLINE = False  # set by the CLI (--offline): only answer from the cache


def http_json(method: str, url: str, body=None):
    key = hashlib.sha1(f"{method} {url} {json.dumps(body, sort_keys=True)}".encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if OFFLINE:
        return None
    try:
        r = requests.request(method, url, json=body, timeout=30)
        data = r.json() if r.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None  # transient error: don't cache
    CACHE.mkdir(exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data
