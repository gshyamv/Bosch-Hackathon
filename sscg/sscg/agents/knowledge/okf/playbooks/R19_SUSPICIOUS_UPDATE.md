---
type: playbook
title: R19_SUSPICIOUS_UPDATE
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: A version update also changed the download source or added an install script.
  confirms:
  - new version adds an install script that the previous version did not have
  - source host changed together with the version
  - release published very recently or by a different maintainer than earlier releases
  false_positives:
  - major version that legitimately adds a native build step
  default_tools:
  - registry_metadata
  - commit_history
  - graph_context
  fallback_verdict: suspicious
  remediation_options:
  - action: pin
    when: pin to the last known-good version
  - action: escalate_review
    when: always
---

A version update also changed the download source or added an install script.

## Confirms
- new version adds an install script that the previous version did not have
- source host changed together with the version
- release published very recently or by a different maintainer than earlier releases

## False positives
- major version that legitimately adds a native build step

## Remediation
- pin: pin to the last known-good version
- escalate_review: always
