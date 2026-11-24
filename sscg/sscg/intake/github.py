"""GitHub intake without a clone (ported from VulnerabilityVision).

ref -> commit SHA, recursive tree, then only the files the scanner reads: manifests, lockfiles, Dockerfiles,
workflows, plus application source (size-capped, tests skipped) for the import-reachability analysis.
Only api.github.com and raw.githubusercontent.com are contacted. GITHUB_TOKEN is sent as a header, never logged.
"""
from __future__ import annotations

import fnmatch
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from .. import cache
from ..reachability import LANG, TEST_DIR, TEST_FILE
from ..reachability import SKIP_DIRS as SOURCE_SKIP
from ..safety import SafetyError, jail

API, RAW = "https://api.github.com", "https://raw.githubusercontent.com"
ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "target", "dist", "build", "__pycache__",
             "bower_components", "vendor", ".tox", "site-packages"}
FILE_PATTERNS = [
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", ".npmrc", "Dockerfile", "Dockerfile.*",
    "*.Dockerfile", "*.dockerfile", "Containerfile", "docker-compose*.yml", "docker-compose*.yaml", "compose*.yml",
    "compose*.yaml", "pyproject.toml", "uv.lock", "poetry.lock", "requirements*.txt", "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml", "*.csproj", "Directory.Packages.props"]
SOURCE_EXT = tuple(e for exts in LANG.values() for e in exts) + (".sh",)   # .sh: install hooks the rules read
MAX_FILE, MAX_SOURCE_FILE = 20 * 1024 * 1024, 400 * 1024
MAX_FILES, MAX_SOURCES = 3000, 1500
MAX_TOTAL, MAX_SOURCE_TOTAL = 300 * 1024 * 1024, 30 * 1024 * 1024
MAX_TREE_CALLS = 400


class FetchError(RuntimeError):
    pass


def wanted(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False
    if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")) and len(parts) == 3:
        return True
    return any(fnmatch.fnmatch(parts[-1], pat) for pat in FILE_PATTERNS)


def wanted_source(path: str) -> bool:
    """Application source that reachability reads. Test code is skipped: it cannot raise exposure."""
    parts = PurePosixPath(path).parts
    if any(p in SOURCE_SKIP or p.startswith(".") for p in parts[:-1]) or path.endswith(".min.js"):
        return False
    return path.lower().endswith(SOURCE_EXT) and not (TEST_DIR.search(path) or TEST_FILE.search(path))


class GitHubClient:
    def __init__(self, token: str | None = None, transport: httpx.BaseTransport | None = None):
        tok = os.getenv("GITHUB_TOKEN", "") if token is None else token
        self.headers = {"Authorization": f"Bearer {tok}"} if tok else {}
        self.http = httpx.Client(headers={"User-Agent": "sscg-scanner", "X-GitHub-Api-Version": "2022-11-28"},
                                 timeout=httpx.Timeout(30.0, read=120.0), follow_redirects=False, transport=transport)

    def get(self, url: str, accept: str = "application/vnd.github+json", cap: int | None = None) -> httpx.Response:
        host = httpx.URL(url).host
        if host not in ALLOWED_HOSTS:
            raise FetchError(f"host not allowed: {host}")
        if cache.OFFLINE:
            raise FetchError("offline: this commit has not been fetched before")
        for attempt in range(3):
            try:
                r = self.http.get(url, headers={"Accept": accept, **self.headers})
            except httpx.HTTPError as e:
                if attempt == 2:
                    raise FetchError(f"network error for {url}: {type(e).__name__}") from e
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code in (403, 429) and r.headers.get("x-ratelimit-remaining") == "0":
                raise FetchError("GitHub API rate limit exhausted"
                                 + ("" if self.headers else ": set GITHUB_TOKEN in sscg/.env for 5000 requests/hour"))
            if r.status_code >= 500 and attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue
            if cap is not None and len(r.content) > cap:
                raise FetchError(f"{url} is larger than {cap} bytes")
            return r
        raise FetchError(f"giving up on {url}")

    def api(self, path: str, accept: str = "application/vnd.github+json") -> httpx.Response:
        r = self.get(f"{API}{path}", accept)
        if r.status_code in (301, 302, 307, 308):     # renamed repository; get() re-checks the host
            r = self.get(r.headers.get("location", ""), accept)
        if r.status_code in (404, 422):
            raise FetchError(f"not found on GitHub: {path} (private repository, typo or unknown ref)")
        if r.status_code >= 400:
            raise FetchError(f"GitHub API {r.status_code} for {path}")
        return r

    def resolve(self, owner: str, name: str, ref: str | None) -> str:
        ref = ref or self.api(f"/repos/{owner}/{name}").json()["default_branch"]
        sha = self.api(f"/repos/{owner}/{name}/commits/{quote(ref, safe='')}", "application/vnd.github.sha").text.strip()
        if len(sha) != 40:
            raise FetchError(f"could not resolve {ref!r} to a commit")
        return sha

    def tree(self, owner: str, name: str, sha: str) -> tuple[list[dict], bool]:
        """All regular files [{path, size}]; a truncated recursive tree is walked folder by folder."""
        data = self.api(f"/repos/{owner}/{name}/git/trees/{sha}?recursive=1").json()

        def regular(e):
            return e["type"] == "blob" and e.get("mode") != "120000"   # symlinks are not files

        if not data.get("truncated"):
            return [{"path": e["path"], "size": e.get("size", 0)} for e in data["tree"] if regular(e)], True
        out, stack, calls = [], [("", sha)], 0
        while stack:
            if calls >= MAX_TREE_CALLS:
                return out, False
            prefix, tsha = stack.pop()
            calls += 1
            for e in self.api(f"/repos/{owner}/{name}/git/trees/{tsha}").json()["tree"]:
                p = prefix + e["path"]
                if regular(e):
                    out.append({"path": p, "size": e.get("size", 0)})
                elif e["type"] == "tree" and e["path"] not in SKIP_DIRS:
                    stack.append((p + "/", e["sha"]))
        return out, True

    def raw(self, owner: str, name: str, sha: str, path: str, cap: int = MAX_FILE) -> bytes:
        r = self.get(f"{RAW}/{owner}/{name}/{sha}/{quote(path)}", "*/*", cap)
        if r.status_code != 200:
            raise FetchError(f"download failed ({r.status_code}) for {path}")
        return r.content


def select(entries: list[dict]) -> tuple[list[dict], list[str]]:
    """(files to download, skipped because of a cap). Manifests first, then source by path."""
    out, skipped, total = [], [], 0
    by_path = sorted(entries, key=lambda e: e["path"])
    for e in (e for e in by_path if wanted(e["path"])):
        if e["size"] > MAX_FILE or total + e["size"] > MAX_TOTAL or len(out) >= MAX_FILES:
            skipped.append(e["path"])
            continue
        total += e["size"]
        out.append(e)
    n = src_total = 0
    for e in (e for e in by_path if not wanted(e["path"]) and wanted_source(e["path"])):
        if e["size"] > MAX_SOURCE_FILE or n >= MAX_SOURCES or src_total + e["size"] > MAX_SOURCE_TOTAL:
            skipped.append(e["path"])
            continue
        n, src_total = n + 1, src_total + e["size"]
        out.append(e)
    return out, skipped


def fetch(gh: GitHubClient, owner: str, name: str, sha: str, base: Path, leaf: str) -> tuple[Path, dict]:
    """Download the selected files of one commit to base/<sha>/<leaf>. Content-addressed: fetched once."""
    root, man = base / sha[:12] / leaf, base / sha[:12] / "fetch.json"   # short: Windows MAX_PATH
    if man.is_file():
        return root, json.loads(man.read_text(encoding="utf-8"))
    entries, complete = gh.tree(owner, name, sha)
    picked, skipped = select(entries)
    root.mkdir(parents=True, exist_ok=True)
    unsafe, failed = [], []

    def one(e):
        try:
            dest = jail(root, e["path"])
        except SafetyError:
            unsafe.append(e["path"])
            return
        try:
            data = gh.raw(owner, name, sha, e["path"])
        except FetchError as ex:
            if wanted(e["path"]):      # a missing manifest would silently hide dependencies
                raise
            failed.append(f"{e['path']}: {ex}")
            return
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        except OSError as ex:      # e.g. path too long on Windows
            if wanted(e["path"]):
                raise FetchError(f"cannot store {e['path']}: {ex}") from ex
            failed.append(f"{e['path']}: {type(ex).__name__}")

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(one, picked))
    info = {"sha": sha, "tree_entries": len(entries), "tree_complete": complete, "downloaded": len(picked),
            "skipped": skipped, "unsafe": sorted(unsafe), "failed": sorted(failed),
            "paths": sorted(e["path"] for e in entries)}
    man.write_text(json.dumps(info), encoding="utf-8")
    return root, info
