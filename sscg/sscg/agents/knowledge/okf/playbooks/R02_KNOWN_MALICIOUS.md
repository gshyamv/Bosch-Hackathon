---
type: playbook
title: R02_KNOWN_MALICIOUS
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: false
  checks: Package (version) is listed in known_malicious.json or has an OSV MAL-* record.
  confirms:
  - the listing itself is the evidence
  false_positives:
  - name reused later by a different
  - legitimate owner (check the version)
  default_tools: []
  fallback_verdict: likely_malicious
  remediation_options:
  - action: remove
    when: always
  - action: block
    when: always; add to a deny-list
  - action: escalate_review
    when: 'the package was installed anywhere: rotate secrets present on those machines'
---

Package (version) is listed in known_malicious.json or has an OSV MAL-* record.

## Confirms
- the listing itself is the evidence

## False positives
- name reused later by a different
- legitimate owner (check the version)

## Remediation
- remove: always
- block: always; add to a deny-list
- escalate_review: the package was installed anywhere: rotate secrets present on those machines
