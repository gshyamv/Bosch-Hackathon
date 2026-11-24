"""What is scanned: a local folder, a GitHub repository (by URL, no clone) or one live web page.

Every pipeline step takes a Target (or a plain Path, wrapped by as_target). head_dir() is always a local folder of
readable files; nothing in it is executed. checkout_url() is only used inside the sandbox container (validation).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import quote, urlsplit

from . import cache, gitutil
from .cache import ROOT
from .safety import SafetyError, check_rev, parse_github_target

WORK = Path(os.getenv("SSCG_WORK_DIR") or ROOT / ".work")


class Target(Protocol):
    kind: Literal["local", "github", "live"]   # LinkedTarget (live page + its source repo) is "github"
    name: str                # folder-safe name used for out/<name>/
    display: str             # github.com/o/r@c9f9922
    source: str              # pass this to the CLI to get exactly this target again
    sha: str | None
    notes: list[str]

    def head_dir(self) -> Path: ...
    def resolve(self, rev: str) -> str | None: ...
    def base_dir(self, rev: str, dest: Path) -> Path | None: ...
    def commit_info(self, rev: str) -> dict | None: ...
    def changed_files(self, base: str) -> list[tuple[str, str]]: ...
    def first_time_author(self, sha: str, email: str) -> bool | None: ...
    def is_dirty(self) -> bool: ...
    def permalink(self, rel: str, line: int | None = None) -> str | None: ...
    def checkout_url(self) -> tuple[str, str] | None: ...   # (clone URL, SHA)


class LocalTarget:
    kind = "local"

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.name = self.path.name
        self.display = self.source = str(self.path)
        self.notes: list[str] = []
        self.is_git = gitutil.is_repo_root(self.path)

    @property
    def sha(self) -> str | None:
        return gitutil.resolve(self.path, "HEAD") if self.is_git else None

    def head_dir(self) -> Path:
        return self.path

    def resolve(self, rev: str) -> str | None:
        return gitutil.resolve(self.path, check_rev(rev)) if self.is_git else None

    def base_dir(self, rev: str, dest: Path) -> Path | None:
        sha = self.resolve(rev)
        if not sha:
            return None
        dest.mkdir(parents=True, exist_ok=True)
        return dest if gitutil.extract(self.path, sha, dest) else None

    def commit_info(self, rev: str) -> dict | None:
        return gitutil.commit_info(self.path, rev) if self.is_git else None

    def changed_files(self, base: str) -> list[tuple[str, str]]:
        return gitutil.changed_files(self.path, base)

    def first_time_author(self, sha: str, email: str) -> bool | None:
        return gitutil.first_time_author(self.path, sha, email)

    def is_dirty(self) -> bool:
        return gitutil.is_dirty(self.path)

    def permalink(self, rel: str, line: int | None = None) -> str | None:
        return None

    def checkout_url(self) -> tuple[str, str] | None:
        return None


STATUS = {"added": "A", "modified": "M", "removed": "D", "renamed": "R", "copied": "A", "changed": "M"}


class GitHubTarget:
    kind = "github"

    def __init__(self, url: str, client=None, work: Path | None = None):
        from .intake.github import GitHubClient
        self.owner, self.repo, self.ref, self.sub = parse_github_target(url)
        self.name = f"{self.owner}__{self.repo}" + ("__" + re.sub(r"[^\w.-]", "_", self.sub) if self.sub else "")
        self.dir = (work or WORK) / "gh" / f"{self.owner}__{self.repo}"
        self.gh = client or GitHubClient()
        self.notes: list[str] = []
        self.sha = self._sha(self.ref)
        self.display = f"github.com/{self.owner}/{self.repo}@{self.sha[:7]}" + (f"/{self.sub}" if self.sub else "")
        self.source = f"https://github.com/{self.owner}/{self.repo}" + (
            f"/tree/{self.sha}/{self.sub}" if self.sub else f"@{self.sha}")
        self._info: dict | None = None
        self._paths: set = set()

    # -- commits are immutable, so their metadata is stored; branches and tags are re-resolved unless offline
    def _stored(self, key: str, fn):
        p = self.dir / "meta" / (re.sub(r"[^\w.-]", "_", key) + ".json")
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
        val = fn()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(val), encoding="utf-8")
        return val

    def _sha(self, ref: str | None) -> str:
        from .intake.github import FetchError
        if ref and re.fullmatch(r"[0-9a-f]{40}", ref):
            return ref
        p, key = self.dir / "refs.json", ref or "HEAD"
        refs = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
        if cache.OFFLINE:
            if key in refs:
                return refs[key]
            raise FetchError(f"offline: {key} of {self.owner}/{self.repo} was never fetched")
        refs[key] = self.gh.resolve(self.owner, self.repo, ref)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(refs), encoding="utf-8")
        return refs[key]

    def _fetch(self, sha: str) -> tuple[Path, dict]:
        from .intake.github import fetch
        return fetch(self.gh, self.owner, self.repo, sha, self.dir, self.repo)

    def head_dir(self) -> Path:
        root, info = self._fetch(self.sha)
        if self._info is None:
            self._info, self._paths = info, set(info["paths"])
            if self.sub and not any(p.startswith(self.sub + "/") for p in info["paths"]):
                raise SafetyError(f"sub-path {self.sub!r} does not exist at {self.sha[:10]}")
            for key, txt in (("skipped", "over the download caps"), ("unsafe", "with unsafe names"),
                             ("failed", "that could not be downloaded")):
                if info[key]:
                    self.notes.append(f"GitHub intake: {len(info[key])} file(s) {txt} were not analysed "
                                      f"({', '.join(info[key][:3])})")
            if not info["tree_complete"]:
                self.notes.append("GitHub intake: the repository tree is incomplete (too large)")
        d = root / self.sub if self.sub else root
        d.mkdir(parents=True, exist_ok=True)
        return d

    def resolve(self, rev: str) -> str | None:
        from .intake.github import FetchError
        m = re.fullmatch(r"(.+?)(?:(~)(\d*)|(\^))?", check_rev(rev))
        n = int(m[3] or 1) if m[2] else 1 if m[4] else 0
        try:
            sha = self.sha if m[1] == "HEAD" else self._sha(m[1])
            for _ in range(n):
                parents = self._commit(sha)["parents"]
                if not parents:
                    return None
                sha = parents[0]["sha"]
            return sha
        except FetchError as e:
            self.notes.append(f"GitHub intake: {rev}: {e}")
            return None

    def _commit(self, sha: str) -> dict:
        def get():
            d = self.gh.api(f"/repos/{self.owner}/{self.repo}/commits/{sha}").json()
            return {k: d[k] for k in ("sha", "commit", "parents")}
        return self._stored(f"commit-{sha}", get)

    def base_dir(self, rev: str, dest: Path) -> Path | None:
        sha = self.resolve(rev)
        if not sha:
            return None
        root, _ = self._fetch(sha)
        d = root / self.sub if self.sub else root
        return d if d.is_dir() else None

    def commit_info(self, rev: str) -> dict | None:
        sha = self.resolve(rev)
        if not sha:
            return None
        c = self._commit(sha)["commit"]
        return {"sha": sha, "short": sha[:7], "author": c["author"]["name"], "email": c["author"]["email"],
                "date": c["author"]["date"], "message": (c["message"] or "").split("\n")[0]}

    def changed_files(self, base: str) -> list[tuple[str, str]]:
        def get():
            d = self.gh.api(f"/repos/{self.owner}/{self.repo}/compare/{base}...{self.sha}").json()
            return [[STATUS.get(f["status"], "M"), f["filename"]] for f in d.get("files", [])]
        rows = self._stored(f"compare-{base}-{self.sha}", get)
        pre = f"{self.sub}/" if self.sub else ""
        return [(s, p[len(pre):]) for s, p in rows if p.startswith(pre)]

    def first_time_author(self, sha: str, email: str) -> bool | None:
        from .intake.github import FetchError
        parents = self._commit(sha)["parents"]
        if not parents:
            return None
        try:
            return self._stored(f"author-{sha}", lambda: not self.gh.api(
                f"/repos/{self.owner}/{self.repo}/commits?sha={parents[0]['sha']}&author={quote(email)}&per_page=1").json())
        except FetchError:
            return None

    def is_dirty(self) -> bool:
        return False

    def permalink(self, rel: str, line: int | None = None) -> str | None:
        path = f"{self.sub}/{rel}" if self.sub else rel
        if path not in self._paths:
            return None
        return f"https://github.com/{self.owner}/{self.repo}/blob/{self.sha}/{quote(path)}" + (f"#L{line}" if line else "")

    def checkout_url(self) -> tuple[str, str] | None:
        return f"https://github.com/{self.owner}/{self.repo}.git", self.sha


class LiveTarget:
    """One web page: what a browser would load, fetched passively (discover/livepage.py)."""
    kind, sha = "live", None

    def __init__(self, url: str, work: Path | None = None, transport=None):
        self.url = self.display = self.source = url
        host = re.sub(r"[^\w.-]", "_", urlsplit(url).hostname or "page")
        self.name = f"live_{host}_{hashlib.sha1(url.encode()).hexdigest()[:6]}"
        self.dir = (work or WORK) / "live" / self.name
        self.transport, self.page = transport, None
        self.notes: list[str] = []

    def head_dir(self) -> Path:
        if self.page is None:
            from .discover.livepage import fetch_page
            self.page = fetch_page(self.url, self.dir, self.transport)
        return self.dir

    def resolve(self, rev):
        return None

    def base_dir(self, rev, dest):
        return None

    def commit_info(self, rev):
        return None

    def changed_files(self, base):
        return []

    def first_time_author(self, sha, email):
        return None

    def is_dirty(self):
        return False

    def permalink(self, rel: str, line: int | None = None) -> str | None:
        return self.page["final_url"] if self.page and rel == "page.html" else None

    def checkout_url(self):
        return None


class LinkedTarget:
    """A live page plus the GitHub repository that builds it (e.g. a deployed Juice Shop + its source repo).

    Everything a Target does (files, commits, permalinks, sandbox checkout) is the source repository's, so the
    remediation loop can patch, build and rescan it; the live page is added to the same graph by pipeline.build.
    """
    kind = "github"

    def __init__(self, live_url: str, source_url: str, client=None, work: Path | None = None, transport=None):
        if not re.match(r"^https?://", live_url) or re.match(r"^https?://github\.com/", live_url):
            raise SafetyError("a linked source repository needs a live page URL (http(s), not github.com) as the target")
        self.src = GitHubTarget("https://" + source_url.strip().split("://")[-1], client, work)
        self.live = LiveTarget(live_url, work, transport)
        self.name, self.source, self.notes = self.src.name, self.src.source, self.src.notes
        self.display = f"{self.src.display} + live {live_url}"

    def __getattr__(self, attr):          # owner, repo, sub, gh, ... of the source repository
        if attr in ("src", "live"):
            raise AttributeError(attr)
        return getattr(self.src, attr)

    @property
    def sha(self) -> str | None:
        return self.src.sha

    def head_dir(self) -> Path:
        return self.src.head_dir()

    def resolve(self, rev: str) -> str | None:
        return self.src.resolve(rev)

    def base_dir(self, rev: str, dest: Path) -> Path | None:
        return self.src.base_dir(rev, dest)

    def commit_info(self, rev: str) -> dict | None:
        return self.src.commit_info(rev)

    def changed_files(self, base: str) -> list[tuple[str, str]]:
        return self.src.changed_files(base)

    def first_time_author(self, sha: str, email: str) -> bool | None:
        return self.src.first_time_author(sha, email)

    def is_dirty(self) -> bool:
        return False

    def permalink(self, rel: str, line: int | None = None) -> str | None:
        return self.src.permalink(rel, line) or self.live.permalink(rel, line)

    def checkout_url(self) -> tuple[str, str] | None:
        return self.src.checkout_url()


def as_target(x) -> Target:
    """Path / str / Target -> Target. github.com URLs use the API intake, other http(s) URLs are live pages."""
    if not isinstance(x, (str, Path)):
        return x
    if isinstance(x, str) and re.match(r"^(https?://)?github\.com/", x):
        return GitHubTarget("https://" + x.split("://")[-1])
    if isinstance(x, str) and re.match(r"^https?://", x):
        return LiveTarget(x)
    if isinstance(x, str) and "://" in x:
        raise SafetyError(f"unsupported target {x!r}")
    return LocalTarget(Path(x).expanduser())
