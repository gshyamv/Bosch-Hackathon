---
type: playbook
title: R11_MUTABLE_IMAGE_TAG
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Image referenced by 'latest' or no tag and without a digest.
  confirms:
  - the reference itself
  false_positives:
  - local development compose files that are never built in CI
  default_tools: []
  fallback_verdict: needs_human_review
  remediation_options:
  - action: pin
    when: always; pin to image@sha256:<digest>
---

Image referenced by 'latest' or no tag and without a digest.

## Confirms
- the reference itself

## False positives
- local development compose files that are never built in CI

## Remediation
- pin: always; pin to image@sha256:<digest>
