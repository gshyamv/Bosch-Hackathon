---
type: playbook
title: R13_CONTAINER_HARDENING
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Container runs as root, or installs with scripts enabled, or similar hardening gaps.
  confirms:
  - the Dockerfile line
  false_positives:
  - build stages of multi-stage images that are not shipped
  default_tools: []
  fallback_verdict: needs_human_review
  remediation_options:
  - action: mitigate
    when: add USER, use npm ci --ignore-scripts, multi-stage builds
---

Container runs as root, or installs with scripts enabled, or similar hardening gaps.

## Confirms
- the Dockerfile line

## False positives
- build stages of multi-stage images that are not shipped

## Remediation
- mitigate: add USER, use npm ci --ignore-scripts, multi-stage builds
