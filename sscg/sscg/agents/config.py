"""Settings for the agent graph, read from environment variables / a .env file.

Keys are never written to outputs, logs or the LLM prompt. Placeholder values ("your-...") count as "not set".
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from ..cache import ROOT

PROVIDERS = ("claude", "gemini", "groq", "grok")       # order used by provider=auto
# groq = Groq / GroqCloud (console.groq.com); grok = xAI Grok (console.x.ai). Two different services.
KEY_ENV = {"claude": ("ANTHROPIC_API_KEY",), "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
           "groq": ("GROQ_API_KEY",), "grok": ("XAI_API_KEY",)}
MODEL_ENV = {"claude": "CLAUDE_MODEL", "gemini": "GEMINI_MODEL", "groq": "GROQ_MODEL", "grok": "GROK_MODEL"}
# a value may list fallbacks, comma-separated; runner.preflight() picks the first that answers
DEFAULT_MODEL = {"claude": "claude-opus-5-5", "gemini": "gemini-3.5-flash,gemini-3.8-flash",
                 "groq": "openai/gpt-oss-120b,openai/gpt-oss-20b", "grok": "grok-4"}


def load_env() -> None:
    """sscg/.env first, then the repository root .env. Real environment variables always win."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    for p in (ROOT / ".env", ROOT.parent / ".env"):
        if p.is_file():
            load_dotenv(p, override=False)


def api_key(provider: str) -> str | None:
    for name in KEY_ENV[provider]:
        v = os.getenv(name, "").strip()
        if v and not v.lower().startswith(("your-", "<", "changeme", "xxx")):
            return v
    return None


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _float(name: str) -> float | None:
    v = os.getenv(name, "").strip()
    try:
        return float(v) if v else None
    except ValueError:
        return None


@dataclass(frozen=True)
class AgentSettings:
    provider: str              # claude | gemini | grok | none
    model: str | None
    max_triage: int            # findings sent to the triage agent per scan (cost cap)
    max_rounds: int            # triage <-> evidence-gathering loops per finding
    max_tokens: int
    temperature: float | None  # None = provider default
    concurrency: int           # parallel triage calls
    reason: str                # why this provider was chosen (shown on the console and in agentic.json)

    @property
    def engine(self) -> str:
        return f"{self.provider}:{self.model}" if self.provider != "none" else "rules-fallback (no LLM)"


def resolve(provider_arg: str | None = None, max_triage: int | None = None) -> AgentSettings:
    want = (provider_arg or os.getenv("SSCG_LLM_PROVIDER", "auto")).strip().lower() or "auto"
    if want not in (*PROVIDERS, "auto", "none"):
        want, note = "auto", f"unknown SSCG_LLM_PROVIDER '{want}', using auto"
    else:
        note = ""
    if want == "none":
        provider, reason = "none", "LLM disabled (--llm none / SSCG_LLM_PROVIDER=none)"
    elif want == "auto":
        provider = next((p for p in PROVIDERS if api_key(p)), "none")
        reason = f"auto: first provider with an API key ({provider})" if provider != "none" else \
            "auto: no API key set in .env, using the rules-only fallback"
    elif api_key(want):
        provider, reason = want, f"{want} requested"
    else:
        provider, reason = "none", f"{want} requested but {KEY_ENV[want][0]} is not set: rules-only fallback"
    model = (os.getenv(MODEL_ENV[provider], "").strip() or DEFAULT_MODEL[provider]) if provider != "none" else None
    return AgentSettings(
        provider=provider, model=model,
        max_triage=max_triage if max_triage is not None else _int("SSCG_LLM_MAX_TRIAGE", 15),
        max_rounds=max(1, _int("SSCG_LLM_MAX_ROUNDS", 2)),
        max_tokens=_int("SSCG_LLM_MAX_TOKENS", 4096),
        temperature=_float("SSCG_LLM_TEMPERATURE"),
        concurrency=max(1, _int("SSCG_LLM_CONCURRENCY", 4)),
        reason="; ".join(x for x in (note, reason) if x),
    )
