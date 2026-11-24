---
type: playbook
title: R12_REMOTE_SCRIPT_EXEC
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: A script is downloaded and piped into a shell (curl | sh) in a Dockerfile or workflow.
  confirms:
  - the command itself
  false_positives:
  - 'none for integrity: even official installers should be verified by checksum'
  default_tools: []
  fallback_verdict: suspicious
  remediation_options:
  - action: mitigate
    when: download to a file, verify a pinned checksum or signature, then run
---

A script is downloaded and piped into a shell (curl | sh) in a Dockerfile or workflow.

## Confirms
- the command itself

## False positives
- none for integrity: even official installers should be verified by checksum

## Remediation
- mitigate: download to a file, verify a pinned checksum or signature, then run
