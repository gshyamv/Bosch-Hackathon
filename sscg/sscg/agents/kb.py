"""Knowledge base for the agents: rule playbooks, attack-pattern catalogue, organisation policy.

Retrieval is a keyed lookup by rule ID (the corpus is a few dozen entries), so it is exact and repeatable.
`retrieve(finding)` is the single entry point: swap in an embedding retriever here if the corpus grows
(e.g. application docs or past scan reports), without touching the agents.

Vulnerability facts (affected ranges, fixed versions, CVSS) are deliberately NOT in the knowledge base: they come
from OSV via vulns.py, so the model never sees a fuzzy or outdated copy of them.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import yaml

DIR = Path(__file__).resolve().parent / "knowledge"
FILES = ("playbooks.yaml", "attack_patterns.yaml", "policy.yaml")

# policy sections relevant to each rule family (keeps the prompt small)
POLICY_FOR = {"R05": ["registries"], "R07": ["registries"], "R10": ["container_images"], "R11": ["container_images"],
              "R13": ["container_images"], "R03": ["dependencies"], "R04": ["dependencies"], "R08": ["dependencies"],
              "R09": ["dependencies"], "R01": ["dependencies"], "R19": ["dependencies", "registries"],
              "R18": ["change_management"], "R12": ["ci_cd"], "R14": ["ci_cd"], "R15": ["ci_cd"], "R16": ["ci_cd"],
              "R17": ["ci_cd"]}


class KnowledgeBase:
    def __init__(self, directory: Path = DIR):
        texts = {f: (directory / f).read_text(encoding="utf-8") for f in FILES}
        self.playbooks: dict = yaml.safe_load(texts["playbooks.yaml"]) or {}
        self.patterns: list = yaml.safe_load(texts["attack_patterns.yaml"]) or []
        self.policy: dict = yaml.safe_load(texts["policy.yaml"]) or {}
        self.version = hashlib.sha256("".join(texts[f] for f in FILES).encode()).hexdigest()[:12]

    def playbook(self, rule: str) -> dict:
        return self.playbooks.get(rule, {})

    def needs_triage(self, rule: str) -> bool:
        return bool(self.playbook(rule).get("triage"))

    def patterns_for(self, rule: str) -> list:
        return [p for p in self.patterns if rule in p.get("rules", [])]

    def retrieve(self, finding: dict) -> dict:
        """Everything the triage agent should know about this kind of finding."""
        rule = finding["rule"]
        pb = {k: v for k, v in self.playbook(rule).items() if k not in ("triage", "default_tools", "remediation_options")}
        pats = [{k: p[k] for k in ("id", "name", "example", "indicators") if k in p} for p in self.patterns_for(rule)]
        pol = {k: self.policy[k] for k in POLICY_FOR.get(rule[:3], []) if k in self.policy}
        return {"playbook": pb, "attack_patterns": pats, "policy": pol}


@lru_cache(maxsize=1)
def load() -> KnowledgeBase:
    return KnowledgeBase()
