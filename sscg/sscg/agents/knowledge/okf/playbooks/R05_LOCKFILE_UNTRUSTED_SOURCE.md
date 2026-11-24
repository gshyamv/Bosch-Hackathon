---
type: playbook
title: R05_LOCKFILE_UNTRUSTED_SOURCE
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Lockfile resolves a package from a host that is not the official registry.
  confirms:
  - host is not in policy.registries for the ecosystem
  - lockfile change introduced the host in the latest change (R07) or the integrity hash changed (R06)
  false_positives:
  - a corporate mirror / proxy (Artifactory, Nexus, Verdaccio) that is listed in the organisation policy
  default_tools:
  - commit_history
  - graph_context
  fallback_verdict: suspicious
  remediation_options:
  - action: pin
    when: regenerate the lockfile against the official registry and pin the version
  - action: block
    when: host is unknown
---

Lockfile resolves a package from a host that is not the official registry.

## Confirms
- host is not in policy.registries for the ecosystem
- lockfile change introduced the host in the latest change (R07) or the integrity hash changed (R06)

## False positives
- a corporate mirror / proxy (Artifactory, Nexus, Verdaccio) that is listed in the organisation policy

## Remediation
- pin: regenerate the lockfile against the official registry and pin the version
- block: host is unknown
