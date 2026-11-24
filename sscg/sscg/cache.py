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


def http_json_daily(url: str):
    """GET JSON for feeds that change every day (CISA KEV, EPSS): cached per calendar day.

    Offline, or when the service fails: the newest earlier cached copy is used, so scans stay reproducible.
    Returns (data, date_of_data) or (None, None).
    """
    from datetime import date
    stem = hashlib.sha1(f"daily GET {url}".encode()).hexdigest()
    today = date.today().isoformat()
    path = CACHE / f"{stem}-{today}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8")), today
    data = None
    if not OFFLINE:
        try:
            r = requests.get(url, timeout=60)
            data = r.json() if r.status_code == 200 else None
        except (requests.RequestException, ValueError):
            data = None
    if data is not None:
        CACHE.mkdir(exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return data, today
    older = sorted(CACHE.glob(f"{stem}-*.json"))
    if older:  # file name: <sha1>-YYYY-MM-DD.json
        return json.loads(older[-1].read_text(encoding="utf-8")), "-".join(older[-1].stem.split("-")[-3:])
    return None, None


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
    if r.status_code not in (200, 404, 410):
        return None  # rate limit / server error: transient, never cache it (a retry later may succeed)
    CACHE.mkdir(exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data
