"""HTTP JSON with an on-disk cache, so scans also work offline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent  # the sscg/ project folder
CACHE = ROOT / ".cache"
OFFLINE = False  # set by the CLI (--offline): only answer from the cache


def _path(method: str, url: str, body=None) -> Path:
    key = hashlib.sha1(f"{method} {url} {json.dumps(body, sort_keys=True)}".encode()).hexdigest()
    return CACHE / f"{key}.json"


def answered(method: str, url: str, body=None) -> bool:
    """True if the service gave a definite answer (cached), so a None from http_json means 'not found'
    rather than 'offline / unreachable'."""
    return _path(method, url, body).exists()


def http_json(method: str, url: str, body=None):
    path = _path(method, url, body)
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
