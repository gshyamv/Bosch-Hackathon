---
type: playbook
title: R18_NEW_AUTHOR_SENSITIVE_CHANGE
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: A first-time contributor changed build / dependency / CI files.
  confirms:
  - the same change introduces other findings (new dependency, lockfile change, untrusted image, CI change)
  - commit message understates the change ("routine", "chore", "bump") compared with what changed
  false_positives:
  - new team member making a reviewed, documented change
  - bots (dependabot, renovate) with expected author identities
  default_tools:
  - commit_history
  fallback_verdict: needs_human_review
  remediation_options:
  - action: escalate_review
    when: always; require a second reviewer for build and dependency files
---

A first-time contributor changed build / dependency / CI files.

## Confirms
- the same change introduces other findings (new dependency, lockfile change, untrusted image, CI change)
- commit message understates the change ("routine", "chore", "bump") compared with what changed

## False positives
- new team member making a reviewed, documented change
- bots (dependabot, renovate) with expected author identities

## Remediation
- escalate_review: always; require a second reviewer for build and dependency files
