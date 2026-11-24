"""Agentic layer: the Guardian pipeline as a LangGraph multi-agent workflow (see docs/agentic.md).

Deterministic agents (Discovery, Vulnerability Intel, Detection, Reporter) wrap the existing sscg modules as tools.
LLM agents (Triage, Narrator) are used only where judgement is needed, and fall back to rules when no key is set.
Prioritise, remediate, human approval and validate are nodes of the same graph and state (--remediate).
"""
