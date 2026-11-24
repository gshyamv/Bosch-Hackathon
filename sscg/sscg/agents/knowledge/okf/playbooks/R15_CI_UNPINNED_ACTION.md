---
type: playbook
title: R15_CI_UNPINNED_ACTION
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Third-party GitHub Action referenced by tag or branch instead of a full commit SHA.
  confirms:
  - the 'uses:' line
  false_positives:
  - first-party actions/* and github/* are lower risk but still recommended to pin
  default_tools: []
  fallback_verdict: needs_human_review
  remediation_options:
  - action: pin
    when: always; pin to the full 40-character commit SHA
---

Third-party GitHub Action referenced by tag or branch instead of a full commit SHA.

## Confirms
- the 'uses:' line

## False positives
- first-party actions/* and github/* are lower risk but still recommended to pin

## Remediation
- pin: always; pin to the full 40-character commit SHA
