"""Repository input: a git URL (fetched into sscg/repos/<name>) or a local folder.

    python -m sscg scan https://github.com/snyk-labs/nodejs-goof
    python -m sscg scan https://github.com/juice-shop/juice-shop/tree/v17.0.0      (a branch, tag or commit)
    python -m sscg scan github.com/OWASP/NodeGoat                                   (https:// is implied)
    python -m sscg scan ..\\targets\\sscg-demo-target                                (a local folder, as before)

The clone is a *blobless partial clone*: the full commit history (needed for "what changed" against HEAD~1 and for the
first-time-contributor rule R18) but file contents only for the checked-out commit; the base commit's files are
fetched on demand by `git archive`. Nothing in the clone is built or executed.

Safety: https only; credential helpers and prompts are disabled, so a private repository fails fast instead of asking
for (or using) credentials; symlinks are checked out as plain files; submodules are not fetched.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .cache import ROOT

REPOS = ROOT / "repos"
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_SHORTHAND = re.compile(r"^(github\.com|gitlab\.com|bitbucket\.org)/[\w.-]+/[\w.-]+", re.I)
_NAME = re.compile(r"[^\w.-]+")


class SourceError(RuntimeError):
    """The repository argument cannot be used (bad URL, clone failed, private repository, ...)."""


@dataclass
class RemoteRepo:
    url: str           # https clone URL, without a trailing .git
    ref: str | None    # branch, tag or commit from /tree/<ref> or #<ref>; None = the default branch
    owner: str
    name: str


def is_remote(arg: str) -> bool:
    a = str(arg).strip()
    return bool(_SCHEME.match(a) or _SHORTHAND.match(a) or a.startswith("git@"))


def parse(arg: str) -> RemoteRepo:
    a = str(arg).strip()
    if a.startswith("git@") or a.lower().startswith(("ssh://", "git://", "file://")):
        raise SourceError("only https:// repository URLs are supported (ssh and git URLs need credentials or are "
                          "unauthenticated plain-text transports)")
    if _SHORTHAND.match(a):
        a = "https://" + a
    if not a.lower().startswith("https://"):
        raise SourceError(f"not an https repository URL: {arg}")
    ref = None
    if "#" in a:
        a, ref = a.split("#", 1)
    a = a.split("?", 1)[0].rstrip("/")
    host_path = a[len("https://"):]
    host, _, path = host_path.partition("/")
    parts = [p for p in path.split("/") if p]
    for marker in ("-", "tree", "commit"):        # gitlab: /-/tree/<ref>; github: /tree/<ref>, /commit/<sha>
        if marker in parts[2:]:
            i = parts.index(marker, 2)
            rest = parts[i + 1:]
            if marker == "-" and rest[:1] in (["tree"], ["commit"]):
                rest = rest[1:]
            ref = ref or ("/".join(rest) or None)
            parts = parts[:i]
            break
    if len(parts) < 2 or "@" in host:
        raise SourceError(f"expected https://<host>/<owner>/<repository>, got: {arg}")
    owner, name = parts[-2], re.sub(r"\.git$", "", parts[-1])
    url = f"https://{host}/{'/'.join(parts[:-1])}/{name}"
    return RemoteRepo(url=url, ref=ref or None, owner=_NAME.sub("-", owner), name=_NAME.sub("-", name))


def _git(*args: str, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GIT_ASKPASS": "",
           "SSH_ASKPASS": "", "GIT_LFS_SKIP_SMUDGE": "1"}
    cmd = ["git", "-c", "credential.helper=", "-c", "core.symlinks=false", "-c", "core.longpaths=true",
           "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args]
    try:
        return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise SourceError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise SourceError(f"git {args[0]} timed out after {timeout}s") from None


def _origin(d: Path) -> str | None:
    r = _git("-C", str(d), "remote", "get-url", "origin")
    return re.sub(r"\.git$", "", r.stdout.strip().rstrip("/")) if r.returncode == 0 else None


def local_dir(remote: RemoteRepo) -> Path:
    """sscg/repos/<name>, or <owner>-<name> when <name> is already taken by a different repository."""
    for cand in (REPOS / remote.name, REPOS / f"{remote.owner}-{remote.name}"):
        if not cand.exists() or (_origin(cand) or "").lower() == remote.url.lower():
            return cand
    raise SourceError(f"{REPOS / remote.name} and {REPOS / (remote.owner + '-' + remote.name)} are both used by "
                      f"other repositories")


def target_name(arg: str) -> str:
    """The folder name (= output folder name out/<name>) a repository argument resolves to."""
    return local_dir(parse(arg)).name if is_remote(arg) else Path(arg).expanduser().resolve().name


def _fail(what: str, r: subprocess.CompletedProcess, url: str) -> SourceError:
    msg = (r.stderr or r.stdout or "").strip().splitlines()
    text = " ".join(msg[-3:])[-500:]
    if re.search(r"couldn't find remote ref|not our ref|unadvertised object", text, re.I):
        return SourceError(f"branch, tag or commit not found in {url} (commits need the full 40-character SHA). ({text})")
    if re.search(r"authentication|could not read username|repository not found|403|401", text, re.I):
        text = (f"{url} is not publicly readable (private, renamed or deleted). Only public repositories are "
                f"supported: no credentials are used. ({text})")
    return SourceError(f"{what} failed: {text}")


def _log(msg: str) -> None:
    print(msg, flush=True)


def fetch(arg: str, *, update: bool = True, offline: bool = False, log=_log) -> Path:
    """Clone (or update) a repository URL into sscg/repos/ and return the local folder."""
    remote = parse(arg)
    dest = local_dir(remote)
    exists = (dest / ".git").is_dir()
    if exists and (offline or not update):
        log(f"[Source] using the existing clone of {remote.url} in {dest}"
            + (" (offline: not updated)" if offline else ""))
        return dest
    if offline:
        raise SourceError(f"--offline: {remote.url} has not been fetched yet (no clone in {dest})")
    REPOS.mkdir(parents=True, exist_ok=True)
    if not exists:
        log(f"[Source] cloning {remote.url}{f' @ {remote.ref}' if remote.ref else ''} into {dest} "
            "(full history, file contents on demand) ...")
        r = _git("clone", "--filter=blob:none", "--single-branch", "--no-tags", "--", remote.url, str(dest))
        if r.returncode != 0 and "filter" in (r.stderr or "").lower():          # server without partial clone
            r = _git("clone", "--depth", "200", "--single-branch", "--no-tags", "--", remote.url, str(dest))
        if r.returncode != 0:
            raise _fail("git clone", r, remote.url)
    else:
        log(f"[Source] updating the clone of {remote.url} in {dest} ...")
    want = remote.ref or "HEAD"
    if exists or remote.ref:
        r = _git("-C", str(dest), "fetch", "--filter=blob:none", "--no-tags", "origin", want)
        if r.returncode != 0:
            raise _fail(f"git fetch {want}", r, remote.url)
        for step in (("checkout", "--force", "--detach", "FETCH_HEAD"), ("clean", "-ffdx")):
            r = _git("-C", str(dest), *step)
            if r.returncode != 0:
                raise _fail("git " + step[0], r, remote.url)
    head = _git("-C", str(dest), "log", "-1", "--format=%h %s").stdout.strip()
    log(f"[Source] {remote.owner}/{remote.name} at {head}")
    return dest


def resolve(arg, *, update: bool = True, offline: bool = False, log=_log) -> Path:
    """The CLI's repository argument -> a local folder (cloning URLs). Raises SourceError with a readable message."""
    a = str(arg).strip()
    if is_remote(a):
        return fetch(a, update=update, offline=offline, log=log).resolve()
    p = Path(a).expanduser().resolve()
    if not p.is_dir():
        raise SourceError(f"folder not found: {p} (give a local folder or an https repository URL)")
    return p
