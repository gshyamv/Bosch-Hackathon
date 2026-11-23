"""Read-only git helpers: commit metadata, changed files, and a base commit's files extracted to a temp folder."""
from __future__ import annotations

import io
import subprocess
import tarfile
from pathlib import Path


def git(repo: Path, *args: str) -> str | None:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return r.stdout.strip() if r.returncode == 0 else None


def is_repo_root(repo: Path) -> bool:
    """True only if `repo` is itself the top of a git repository (not a folder inside another repo)."""
    top = git(repo, "rev-parse", "--show-toplevel")
    return bool(top) and Path(top).resolve() == repo.resolve()


def resolve(repo: Path, rev: str) -> str | None:
    return git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")


def commit_info(repo: Path, rev: str) -> dict | None:
    out = git(repo, "log", "-1", "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s", rev)
    if not out:
        return None
    sha, name, email, date, msg = out.split("\x1f")
    return {"sha": sha, "short": sha[:7], "author": name, "email": email, "date": date, "message": msg}


def first_time_author(repo: Path, sha: str, email: str) -> bool | None:
    """Did this author make any commit before `sha`? None if there is no earlier history to check."""
    prior = git(repo, "log", "--format=%ae", f"{sha}~1")
    if prior is None:
        return None
    return email.lower() not in {e.lower() for e in prior.splitlines()}


def changed_files(repo: Path, base: str) -> list[tuple[str, str]]:
    """(status, path) between `base` and the working tree (A added, M modified, D deleted, R renamed)."""
    out = git(repo, "diff", "--name-status", base)
    rows = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        rows.append((parts[0][0], parts[-1]))
    return rows


def is_dirty(repo: Path) -> bool:
    return bool(git(repo, "status", "--porcelain", "--untracked-files=no"))


def extract(repo: Path, rev: str, dest: Path) -> bool:
    """Write the files of commit `rev` into `dest` (git archive; nothing is checked out or executed)."""
    r = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", rev], capture_output=True)
    if r.returncode != 0:
        return False
    with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
        tf.extractall(dest, filter="data")  # 'data' filter: no absolute paths, links out of dest, devices
    return True
