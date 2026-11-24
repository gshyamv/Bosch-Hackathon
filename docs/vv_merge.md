# What the VulnerabilityVision merge added

| Area | Use | Code |
|---|---|---|
| Scan by URL, no clone | `python -m sscg scan https://github.com/o/r[@ref]` (set `GITHUB_TOKEN` in `sscg/.env` for more than 60 API calls/hour) | `target.py`, `intake/github.py`, `safety.py` |
| Live page (passive) | `python -m sscg scan https://example.com/`; rules R20-R22 | `discover/livepage.py`, `rules/livepage.py` |
| Ruby, Rust, Go, .NET, uv | automatic; fixes are guidance only (no patch) | `discover/ecosystems.py`, `vv_parsers.py` |
| Exact npm tree without a lockfile | `--resolve-npm` (Docker) | `discover/npm.py` |
| Container sandbox | automatic during validation; without Docker the verdict is at most `partially_verified` | `sandbox.py`, `validation.py` |
| Root-cause clusters | `clusters` in `agentic.json`, `cluster_ids` on proposals | `relevance.py` |
| Context store + OKF | `.context/context.db`, `.okf/`; `python -m sscg okf` lints; `/api/okf/*`, `/api/runs/{id}/okf.zip` | `context.py`, `okf.py` |
| Local LLM | `OLLAMA_MODEL=qwen2.5:7b`, `--llm ollama` | `agents/llm.py` |
| Live job events | `/api/jobs/{id}/events` (SSE) | `server.py` |

## Sandbox
Non-root, read-only root filesystem, no capabilities, 2 CPUs, 2 GB, PID limit, images pinned by digest, no host mounts
or environment. Installs run on an internal network whose only exit is a proxy that allows package registries; tests run
with no network. The work tree is a throw-away Docker volume, not tmpfs, because install and test run in separate
containers. `docker build` of a scanned Dockerfile is skipped: its RUN steps would get unrestricted network.

## Tests
`pip install pytest`, then in `sscg/`: `python -m pytest tests` and `python scripts/check_acceptance.py`.

## Known limits
Cluster hints ("upgrading X may resolve several findings") are not resolved or verified. The SSRF guard checks DNS before
the request, so it does not stop DNS rebinding. PyPI wheel choice uses the host's Python, while the sandbox is Linux 3.12.
