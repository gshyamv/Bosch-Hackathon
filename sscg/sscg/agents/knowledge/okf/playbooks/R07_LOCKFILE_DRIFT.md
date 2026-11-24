---
type: playbook
title: R07_LOCKFILE_DRIFT
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Lockfile entry changed although the manifest did not request a change.
  confirms:
  - resolved URL or integrity changed (not only the version within the allowed range)
  - change made by a first-time contributor or in a commit whose message does not mention dependencies
  false_positives:
  - npm update / npm dedupe within the allowed semver range (version moves, host and hash pattern stay normal)
  - lockfile format upgrade (lockfileVersion 1 -> 2/3)
  default_tools:
  - commit_history
  - repo_file_context
  fallback_verdict: suspicious
  remediation_options:
  - action: pin
    when: revert the lockfile entry and regenerate it from the manifest
---

Lockfile entry changed although the manifest did not request a change.

## Confirms
- resolved URL or integrity changed (not only the version within the allowed range)
- change made by a first-time contributor or in a commit whose message does not mention dependencies

## False positives
- npm update / npm dedupe within the allowed semver range (version moves, host and hash pattern stay normal)
- lockfile format upgrade (lockfileVersion 1 -> 2/3)

## Remediation
- pin: revert the lockfile entry and regenerate it from the manifest
