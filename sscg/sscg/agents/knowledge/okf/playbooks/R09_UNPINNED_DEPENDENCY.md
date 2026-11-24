---
type: playbook
title: R09_UNPINNED_DEPENDENCY
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Dependency without an exact version (Python ranges / no version) or a wide npm range without a lockfile.
  confirms:
  - no lockfile in that ecosystem, so every build may resolve a different version
  - production scope
  false_positives:
  - libraries that intentionally declare ranges and are always installed from a lockfile
  default_tools:
  - graph_context
  fallback_verdict: needs_human_review
  remediation_options:
  - action: pin
    when: always; use a lockfile or exact pins with hashes (pip --require-hashes)
---

Dependency without an exact version (Python ranges / no version) or a wide npm range without a lockfile.

## Confirms
- no lockfile in that ecosystem, so every build may resolve a different version
- production scope

## False positives
- libraries that intentionally declare ranges and are always installed from a lockfile

## Remediation
- pin: always; use a lockfile or exact pins with hashes (pip --require-hashes)
