---
type: playbook
title: R16_CI_EXCESSIVE_PERMISSIONS
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Workflow token has write-all or broad write permissions.
  confirms:
  - the permissions block
  false_positives:
  - 'release workflows that need ''contents: write'', scoped to one job'
  default_tools: []
  fallback_verdict: needs_human_review
  remediation_options:
  - action: mitigate
    when: 'permissions: read-all at workflow level, grant writes per job'
---

Workflow token has write-all or broad write permissions.

## Confirms
- the permissions block

## False positives
- release workflows that need 'contents: write', scoped to one job

## Remediation
- mitigate: permissions: read-all at workflow level, grant writes per job
