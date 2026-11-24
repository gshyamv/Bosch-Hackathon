---
type: playbook
title: R01_TYPOSQUAT
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Package name is within a small edit distance of a popular package name.
  confirms:
  - package is new in the latest change, or was added by a first-time contributor
  - registry shows a young package, few versions, few maintainers, or no repository link
  - the package has an install script, or is also listed as documented malicious (R02)
  false_positives:
  - legitimate packages with similar names (for example forks or scoped variants with an active repository)
  - long-standing dependency present before the latest change and with a long release history
  default_tools:
  - registry_metadata
  - graph_context
  - commit_history
  fallback_verdict: suspicious
  remediation_options:
  - action: replace
    when: 'the intended popular package exists: switch to it'
  - action: remove
    when: the dependency is not needed
  - action: block
    when: registry metadata or other rules show malicious behaviour
---

Package name is within a small edit distance of a popular package name.

## Confirms
- package is new in the latest change, or was added by a first-time contributor
- registry shows a young package, few versions, few maintainers, or no repository link
- the package has an install script, or is also listed as documented malicious (R02)

## False positives
- legitimate packages with similar names (for example forks or scoped variants with an active repository)
- long-standing dependency present before the latest change and with a long release history

## Remediation
- replace: the intended popular package exists: switch to it
- remove: the dependency is not needed
- block: registry metadata or other rules show malicious behaviour
