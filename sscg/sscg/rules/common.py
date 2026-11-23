"""Shared pieces for the column 4 detectors: rule catalogue, context, finding constructor, file helpers."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

# rule id -> (slide category, default level, why it matters)
RULES = {
    "R01_TYPOSQUAT": ("Typosquatted package", "High",
                      "A name that imitates a popular package is a common way to get malicious code installed by mistake."),
    "R02_KNOWN_MALICIOUS": ("Typosquatted package", "Critical",
                            "This package (version) is publicly documented as malicious."),
    "R03_INSTALL_SCRIPT": ("Unsafe install script", "Medium",
                           "Install scripts run arbitrary code on every machine that installs the package, including CI."),
    "R04_INSTALL_SCRIPT_CONTENT": ("Unsafe install script", "High",
                                   "The install script contains behaviour typical of credential theft or droppers."),
    "R05_LOCKFILE_UNTRUSTED_SOURCE": ("Modified lockfile", "High",
                                      "The package is downloaded from a host other than the official registry."),
    "R06_LOCKFILE_INTEGRITY_CHANGED": ("Modified lockfile", "Critical",
                                       "Same name and version but a different content hash: the package tarball was swapped."),
    "R07_LOCKFILE_DRIFT": ("Modified lockfile", "High",
                           "The lockfile entry changed although the manifest did not ask for a change."),
    "R08_UNEXPECTED_DEPENDENCY": ("Unexpected dependency", "Medium",
                                  "A new direct dependency enters the application and should be reviewed."),
    "R09_UNPINNED_DEPENDENCY": ("Suspicious package update", "Low",
                                "Without an exact version, a future (possibly compromised) release is installed silently."),
    "R10_UNTRUSTED_BASE_IMAGE": ("Untrusted image", "High",
                                 "The image is not an official or verified-publisher image."),
    "R11_MUTABLE_IMAGE_TAG": ("Untrusted image", "Medium",
                              "A 'latest' / missing tag without a digest can point to different content tomorrow."),
    "R12_REMOTE_SCRIPT_EXEC": ("Unsafe install script", "High",
                               "A script is downloaded and executed without any integrity check."),
    "R13_CONTAINER_HARDENING": ("Untrusted image", "Medium",
                                "The container build or runtime is less isolated than it could be."),
    "R14_CI_PWN_REQUEST": ("Unsafe CI/CD component", "Critical",
                           "pull_request_target runs with repository secrets; checking out the PR's code runs untrusted code with them."),
    "R15_CI_UNPINNED_ACTION": ("Unsafe CI/CD component", "High",
                               "A third-party action referenced by tag/branch can be changed by its owner at any time."),
    "R16_CI_EXCESSIVE_PERMISSIONS": ("Unsafe CI/CD component", "High",
                                     "The workflow token can write to the repository, so any compromised step can too."),
    "R17_CI_SECRET_EXPOSURE": ("Unsafe CI/CD component", "Critical",
                               "A secret is handed to code that was downloaded at run time or comes from a mutable third-party action."),
    "R18_NEW_AUTHOR_SENSITIVE_CHANGE": ("Suspicious package update", "High",
                                        "A first-time contributor changed files that control what gets built and installed."),
    "R19_SUSPICIOUS_UPDATE": ("Suspicious package update", "High",
                              "A version update that also changed where the package comes from or added an install script."),
}


@dataclass
class Ctx:
    repo: Path
    dg: object                 # DepGraph
    change: object = None      # diff.Change or None


def mk(rule: str, title: str, *, level: str | None = None, node: str | None = None, location: str | None = None,
       evidence: list | None = None, key: tuple, classification: str = "heuristic", confidence: str = "high",
       new: bool | None = None) -> dict:
    cat, default, why = RULES[rule]
    return {"rule": rule, "type": cat, "title": title, "level": level or default, "node": node,
            "location": location, "evidence": evidence or [], "why": why, "key": (rule, *key),
            "classification": classification, "confidence": confidence, "new": new}


def read(repo: Path, rel: str) -> str | None:
    p = (repo / rel).resolve()
    if not p.is_relative_to(repo.resolve()) or not p.is_file():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


def line_of(text: str | None, needle: str) -> int:
    for i, line in enumerate((text or "").splitlines(), 1):
        if needle in line:
            return i
    return 0


def file_ev(path: str, line: int, text: str | None = None, snippet: str | None = None) -> dict:
    if snippet is None and text and line:
        snippet = text.splitlines()[line - 1].strip()
    return {"type": "file", "path": path, "line": line, "snippet": (snippet or "")[:300]}


def load_lines(name: str) -> set:
    return {l.strip() for l in (DATA / name).read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")}


def load_json(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))
