---
type: playbook
title: R08_UNEXPECTED_DEPENDENCY
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: A new direct dependency was added in the latest change.
  confirms:
  - commit message does not explain the new dependency, or the author is a first-time contributor
  - the package is young / has few maintainers / overlaps with another rule (typosquat, install script)
  - it is a production dependency of a service that handles secrets or network traffic
  false_positives:
  - a well-known package added in a feature commit that clearly needs it
  - dev / test tooling added together with matching config files
  default_tools:
  - commit_history
  - registry_metadata
  - graph_context
  fallback_verdict: needs_human_review
  remediation_options:
  - action: escalate_review
    when: no justification in the change
  - action: remove
    when: not used by the code
---

A new direct dependency was added in the latest change.

## Confirms
- commit message does not explain the new dependency, or the author is a first-time contributor
- the package is young / has few maintainers / overlaps with another rule (typosquat, install script)
- it is a production dependency of a service that handles secrets or network traffic

## False positives
- a well-known package added in a feature commit that clearly needs it
- dev / test tooling added together with matching config files

## Remediation
- escalate_review: no justification in the change
- remove: not used by the code
