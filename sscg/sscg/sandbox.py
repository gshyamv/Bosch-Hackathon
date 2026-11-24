"""Container sandbox: the only place where code of a scanned repository runs.

* images pinned by digest; non-root; read-only root filesystem; no capabilities; CPU / memory / PID limits; no host
  environment, no host mounts. The work tree is a throw-away named volume (install and test need to share it).
* install steps: an --internal network whose only exit is an allow-list proxy (package registries).
* build / test steps: --network none.
There is no host fallback: without Docker, callers must not run the step.
"""
from __future__ import annotations

import io
import os
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

IMAGES = {
    "npm": "node:22-bookworm-slim@sha256:170fab707454b1350981adcdc2f536ec21f24d06d7f008e8d40064afeacb8a94",
    "pypi": "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df",
    "maven": "maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320",
    "git": "alpine/git@sha256:29cff25811f790b9f72fc266bf8009a5a911714c0e03c31c47339c50909d9aef",
}
REGISTRIES = ["registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
              "repo.maven.apache.org", "repo1.maven.org"]
CHECKOUT = ["github.com"]
PROXY = r'''
import os, select, socket, threading
ALLOW = set(os.environ["ALLOW"].split(","))
def pipe(a, b):
    while True:
        r, _, _ = select.select([a, b], [], [], 120)
        if not r: return
        for s in r:
            d = s.recv(65536)
            if not d: return
            (b if s is a else a).sendall(d)
def serve(c):
    try:
        h = b""
        while b"\r\n\r\n" not in h and len(h) < 8192:
            d = c.recv(4096)
            if not d: return
            h += d
        m, t = h.split(b"\r\n")[0].decode().split()[:2]
        host, _, port = t.partition(":")
        if m != "CONNECT" or host not in ALLOW or port != "443":
            return c.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        u = socket.create_connection((host, 443), 20)
        c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        pipe(c, u); u.close()
    except Exception: pass
    finally: c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 3128)); s.listen(64); print("ready", flush=True)
while True: threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
'''
HARDEN = ["--rm", "--read-only", "--tmpfs", "/tmp:rw,size=512m,mode=1777", "--cpus", "2", "--memory", "2g",
          "--memory-swap", "2g", "--pids-limit", "512", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
          "--user", "1000:1000"]


def docker(*args: str, timeout: int = 120, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout, input=stdin if stdin is not None else b"")


def available() -> bool:
    if os.getenv("SSCG_NO_DOCKER"):
        return False
    try:
        r = docker("version", "--format", "{{.Server.Version}}", timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


class Sandbox:
    """with Sandbox() as sb: sb.put(dir); sb.run("npm", ["npm", "ci"], cwd, net=True); sb.read(path)"""

    def __init__(self):
        self.id = "sscg-" + uuid.uuid4().hex[:10]
        self.vol, self.net, self.proxy = self.id, f"{self.id}-net", f"{self.id}-proxy"

    def _must(self, *args, **kw):
        r = docker(*args, **kw)
        if r.returncode != 0:
            raise RuntimeError(f"docker {args[0]}: {r.stderr.decode(errors='replace').strip()[-300:]}")
        return r

    def __enter__(self):
        try:
            self._must("volume", "create", self.vol)
            self._must("network", "create", "--internal", self.net)
            self._must("run", "--rm", "--network", "none", "-v", f"{self.vol}:/work", "--entrypoint", "chown",
                       IMAGES["npm"], "1000:1000", "/work", timeout=600)
            self.open_proxy(REGISTRIES)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        for a in (("rm", "-f", self.proxy), ("volume", "rm", "-f", self.vol), ("network", "rm", self.net)):
            try:
                docker(*a)
            except (subprocess.TimeoutExpired, OSError):
                pass

    def open_proxy(self, allow: list[str]) -> None:
        docker("rm", "-f", self.proxy)
        hard = [x for x in HARDEN if x != "--rm"]
        self._must("run", "-d", "--name", self.proxy, *hard, "-e", "ALLOW=" + ",".join(allow), IMAGES["pypi"],
                   "python", "-c", PROXY, timeout=600)
        self._must("network", "connect", self.net, self.proxy)
        for _ in range(40):
            if b"ready" in docker("logs", self.proxy).stdout:
                return
            time.sleep(0.25)
        raise RuntimeError("the sandbox proxy did not start")

    def put(self, src: Path, dest: str, ignore=frozenset()) -> None:
        """Copy a folder into the volume as data. Symlinks are not followed or copied."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for root, dirs, files in os.walk(src):
                dirs[:] = [d for d in dirs if d not in ignore and not (Path(root) / d).is_symlink()]
                for f in files:
                    p = Path(root) / f
                    if not p.is_symlink():
                        tf.add(p, p.relative_to(src).as_posix(), recursive=False)
        self._must("run", "-i", *HARDEN, "--network", "none", "-v", f"{self.vol}:/work", "--entrypoint", "sh",
                   IMAGES["npm"], "-c", f"mkdir -p /work/{dest} && tar -xf - --no-same-owner --no-same-permissions -C /work/{dest}",
                   stdin=buf.getvalue(), timeout=600)

    def checkout(self, url: str, sha: str, dest: str) -> None:
        """git clone inside the container: the host never holds an executable checkout."""
        self.open_proxy(CHECKOUT)
        try:
            r = self.run("git", ["sh", "-c", 'git init -q . && git fetch -q --depth 2 "$1" "$2" && git checkout -q FETCH_HEAD',
                                 "x", url, sha], dest, net=True, timeout=600)
            if r["exit"] != 0:
                raise RuntimeError(f"checkout failed: {r['log'][-300:]}")
        finally:
            self.open_proxy(REGISTRIES)

    def run(self, image: str, cmd: list[str], cwd: str, net: bool = False, timeout: int = 600) -> dict:
        name = f"{self.id}-{uuid.uuid4().hex[:6]}"
        env = {"HOME": "/tmp", "CI": "true", "npm_config_cache": "/work/.npm", "PIP_CACHE_DIR": "/tmp/pip",
               "npm_config_update_notifier": "false", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "TMPDIR": "/work/.tmp" if image == "pypi" else "/tmp"}
        if net:
            env |= {k: f"http://{self.proxy}:3128" for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
            if image == "maven":
                env["MAVEN_OPTS"] = f"-Dhttps.proxyHost={self.proxy} -Dhttps.proxyPort=3128"
        flags = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
        shell = 'mkdir -p "$1" "$TMPDIR" && cd "$1" && shift && exec "$@"'
        t = time.perf_counter()
        try:
            r = docker("run", "--name", name, *HARDEN, "--network", self.net if net else "none", *flags,
                       "-v", f"{self.vol}:/work", "--entrypoint", "sh", IMAGES[image], "-c", shell, "x",
                       f"/work/{cwd}", *cmd, timeout=timeout)
            out = (r.stdout + b"\n" + r.stderr).decode("utf-8", errors="replace")
            res = {"status": "ok" if r.returncode == 0 else "failed", "exit": r.returncode, "log": out}
        except subprocess.TimeoutExpired:
            docker("rm", "-f", name)
            res = {"status": "timeout", "exit": None, "log": f"stopped after {timeout}s"}
        return {**res, "seconds": round(time.perf_counter() - t, 1)}

    def read(self, path: str) -> str | None:
        r = docker("run", *HARDEN, "--network", "none", "-v", f"{self.vol}:/work:ro", "--entrypoint", "cat",
                   IMAGES["npm"], f"/work/{path}", timeout=120)
        return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None
