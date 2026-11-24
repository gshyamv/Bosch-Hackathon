---
type: playbook
title: R06_LOCKFILE_INTEGRITY_CHANGED
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Same package name and version but a different integrity hash between base and head.
  confirms:
  - the hash change is the evidence; registries do not allow re-publishing the same version
  false_positives:
  - switching between registry mirrors that repack tarballs (rare
  - should still be reviewed)
  default_tools: []
  fallback_verdict: likely_malicious
  remediation_options:
  - action: pin
    when: restore the base lockfile entry and verify the hash against the official registry
  - action: escalate_review
    when: always
---

Same package name and version but a different integrity hash between base and head.

## Confirms
- the hash change is the evidence; registries do not allow re-publishing the same version

## False positives
- switching between registry mirrors that repack tarballs (rare
- should still be reviewed)

## Remediation
- pin: restore the base lockfile entry and verify the hash against the official registry
- escalate_review: always
