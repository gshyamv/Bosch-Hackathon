"""CI/CD rules for GitHub Actions: R14 pwn request, R15 unpinned third-party action, R16 permissions,
R12 curl | sh in run steps, R17 secrets handed to remote / mutable code."""
from __future__ import annotations

import re

import yaml

from ..discover.docker import line_finder
from ..discover.gha import SHA_RE
from .common import Ctx, file_ev, mk, read
from .container import PIPE_TO_SHELL

FIRST_PARTY = {"actions", "github"}
UNTRUSTED_REF = re.compile(r"github\.event\.pull_request\.head|github\.head_ref")


def _third_party_unpinned(uses: str) -> bool:
    if uses.startswith(("./", "docker://")):
        return False
    path, _, ref = uses.partition("@")
    return path.split("/")[0] not in FIRST_PARTY and not SHA_RE.fullmatch(ref)


def workflows(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    for n, a in G.nodes(data=True):
        if a["kind"] != "app" or a["ecosystem"] != "github-actions":
            continue
        src, text = a["source"], read(ctx.repo, a["source"])
        try:
            wf = yaml.safe_load(text or "")
        except yaml.YAMLError:
            continue
        if not isinstance(wf, dict):
            continue
        find, lines = line_finder(text), (text or "").splitlines()
        ev = lambda ln: file_ev(src, ln, text)
        triggers = set(a.get("triggers") or [])
        perms = wf.get("permissions")
        if perms == "write-all":
            ln = find("write-all")
            out.append(mk("R16_CI_EXCESSIVE_PERMISSIONS", f"{src}: workflow token has 'permissions: write-all'",
                          location=f"{src}:{ln}", key=(src, "top"), evidence=[ev(ln)], classification="verified_fact"))
        elif perms is None:
            out.append(mk("R16_CI_EXCESSIVE_PERMISSIONS", f"{src}: no top-level 'permissions:' (token gets the "
                          "repository default, often read/write)", level="Low", location=src, key=(src, "missing"),
                          classification="verified_fact",
                          evidence=[{"type": "fact", "detail": f"{src} has no top-level permissions block"}]))
        for jid, job in (wf.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("permissions") == "write-all":
                ln = find("write-all")
                out.append(mk("R16_CI_EXCESSIVE_PERMISSIONS", f"{src}: job '{jid}' has 'permissions: write-all'",
                              location=f"{src}:{ln}", key=(src, jid), evidence=[ev(ln)], classification="verified_fact"))
            job_secrets = "secrets." in str(job.get("env", ""))
            for i, st in enumerate(job.get("steps") or []):
                if not isinstance(st, dict):
                    continue
                uses, run = st.get("uses") or "", st.get("run") or ""
                if uses and _third_party_unpinned(uses):
                    ln = find(uses)
                    node = next((c for c in G.successors(n) if G.nodes[c].get("label") == uses), None)
                    out.append(mk("R15_CI_UNPINNED_ACTION", f"{src}: third-party action '{uses}' is not pinned to a "
                                  "commit SHA", node=node, location=f"{src}:{ln}", key=(src, uses), evidence=[ev(ln)],
                                  classification="verified_fact"))
                ref = str((st.get("with") or {}).get("ref", ""))
                if "pull_request_target" in triggers and uses.startswith("actions/checkout") and UNTRUSTED_REF.search(ref):
                    ln = find(ref)
                    out.append(mk("R14_CI_PWN_REQUEST", f"{src}: 'pull_request_target' workflow checks out the pull "
                                  "request's own code", location=f"{src}:{ln}", key=(src, jid, ref),
                                  evidence=[ev(ln), {"type": "fact", "detail": f"triggers: {', '.join(sorted(triggers))}"}],
                                  classification="verified_fact"))
                remote = bool(run and PIPE_TO_SHELL.search(run))
                if remote:
                    ln = find(PIPE_TO_SHELL.search(run).group(0)) or find(run.splitlines()[0])
                    out.append(mk("R12_REMOTE_SCRIPT_EXEC", f"{src}: job '{jid}' downloads a script and pipes it "
                                  "into a shell", location=f"{src}:{ln}", key=(src, " ".join(run.split())),
                                  evidence=[ev(ln)], classification="verified_fact"))
                step_secrets = "secrets." in str(st.get("env", "")) or "secrets." in str(st.get("with", ""))
                if (step_secrets or job_secrets) and (remote or (uses and _third_party_unpinned(uses))):
                    names = sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)",
                                                  str(st.get("env", "")) + str(st.get("with", "")) + str(job.get("env", "")))))
                    ln = find(f"secrets.{names[0]}") if names else 0
                    what = "a downloaded script" if remote else f"the unpinned action '{uses}'"
                    out.append(mk("R17_CI_SECRET_EXPOSURE", f"{src}: secret(s) {', '.join(names)} are passed to {what}",
                                  location=f"{src}:{ln}", key=(src, jid, i), evidence=[ev(ln)],
                                  classification="verified_fact"))
    return out
