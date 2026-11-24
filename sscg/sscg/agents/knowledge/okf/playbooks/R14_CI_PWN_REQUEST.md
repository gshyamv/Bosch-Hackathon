---
type: playbook
title: R14_CI_PWN_REQUEST
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: pull_request_target workflow checks out and runs the pull request's code.
  confirms:
  - the workflow file
  false_positives:
  - workflows that only label / comment and never check out PR code
  default_tools: []
  fallback_verdict: suspicious
  remediation_options:
  - action: mitigate
    when: use pull_request instead, or never check out PR head in pull_request_target
---

pull_request_target workflow checks out and runs the pull request's code.

## Confirms
- the workflow file

## False positives
- workflows that only label / comment and never check out PR code

## Remediation
- mitigate: use pull_request instead, or never check out PR head in pull_request_target
