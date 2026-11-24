"""Safety helpers for user-supplied targets (ported from VulnerabilityVision): URL allow-list, path jail, SSRF guard."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit


class SafetyError(ValueError):
    """An input violates a safety rule."""


REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
REV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}(~\d{0,2}|\^)?$")
GITHUB_RE = re.compile(
    r"^(?:https://)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:@(?P<at>[A-Za-z0-9._/-]+)|/tree/(?P<ref>[A-Za-z0-9._-]+)(?:/(?P<sub>[A-Za-z0-9._/ -]+?))?)?/?$")
WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com\d|lpt\d)(\.|$)", re.I)


def parse_github_target(url: str) -> tuple[str, str, str | None, str | None]:
    """https://github.com/o/r[@ref] or .../tree/<ref>[/<sub-path>] -> (owner, name, ref|None, sub|None)."""
    m = GITHUB_RE.match(url.strip())
    if not m:
        raise SafetyError(f"only https://github.com/<owner>/<repo>[@ref | /tree/<ref>/<path>] is accepted, got {url!r}")
    owner, name, sub = m["owner"], m["name"], m["sub"]
    ref = m["at"] or m["ref"]
    if any(p.startswith(".") or ".." in p for p in (owner, name)):
        raise SafetyError("invalid owner / repository")
    if ref:
        check_ref(ref)
    if sub:
        sub = sub.strip("/")
        if any(p in ("", ".", "..") for p in sub.split("/")):
            raise SafetyError("invalid sub-path")
    return owner, name, ref, sub or None


def check_ref(ref: str) -> str:
    if not REF_RE.match(ref) or ".." in ref:
        raise SafetyError(f"invalid git ref {ref!r}")
    return ref


def check_rev(rev: str) -> str:
    """A ref, optionally followed by ~N or ^. Never starts with '-', so git cannot read it as an option."""
    if not REV_RE.match(rev) or ".." in rev:
        raise SafetyError(f"invalid revision {rev!r}")
    return rev


def jail(root: Path, rel: str | os.PathLike) -> Path:
    """Resolve a repository path inside root. Refuses .., absolute paths, and names Windows would reinterpret."""
    root, s = root.resolve(), str(rel)
    parts = s.split("/")
    if s.startswith("/") or any(c in s for c in "\\:\0") or any(p in ("", ".", "..") for p in parts) \
            or any(WINDOWS_RESERVED.match(p) for p in parts):
        raise SafetyError(f"unsafe path {s!r}")
    return root / s       # purely lexical: resolve() is unreliable on Windows while other threads create folders


def allow_local() -> bool:
    return os.getenv("ALLOW_LOCAL_TARGETS", "").strip().lower() in ("1", "true", "yes")


def check_target(url: str, local_ok: bool | None = None) -> str:
    """SSRF guard: http(s) only, no credentials, and every address the host resolves to must be public."""
    local_ok = allow_local() if local_ok is None else local_ok
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SafetyError(f"only http(s) URLs can be scanned, got {parts.scheme!r}")
    if parts.username or parts.password:
        raise SafetyError("URLs with credentials are not allowed")
    if not parts.hostname:
        raise SafetyError("URL has no host")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except (socket.gaierror, ValueError) as e:
        raise SafetyError(f"cannot resolve {parts.hostname}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not local_ok and (not ip.is_global or ip.is_multicast or ip.is_reserved):
            raise SafetyError(f"refused: {parts.hostname} resolves to a non-public address ({ip}); set "
                              "ALLOW_LOCAL_TARGETS=true only for your own local demo targets")
    return parts.hostname
