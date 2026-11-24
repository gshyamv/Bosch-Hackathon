---
type: playbook
title: R17_CI_SECRET_EXPOSURE
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: A secret is passed to downloaded code or a mutable third-party action.
  confirms:
  - the workflow step
  false_positives:
  - 'none: treat as exposure until the step is pinned and verified'
  default_tools: []
  fallback_verdict: suspicious
  remediation_options:
  - action: mitigate
    when: pin the action / verify the script; rotate the secret if the workflow has run
---

A secret is passed to downloaded code or a mutable third-party action.

## Confirms
- the workflow step

## False positives
- none: treat as exposure until the step is pinned and verified

## Remediation
- mitigate: pin the action / verify the script; rotate the secret if the workflow has run
