---
type: playbook
title: R10_UNTRUSTED_BASE_IMAGE
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Container base image is not an official / verified-publisher image.
  confirms:
  - image namespace is a personal account, especially one that also authored the change
  - image not found on the registry, or no digest pin
  false_positives:
  - the organisation's own registry or a vendor image listed in policy.container_images.trusted_publishers
  default_tools:
  - registry_metadata
  - commit_history
  fallback_verdict: suspicious
  remediation_options:
  - action: update_base_image
    when: switch to the official image (docker.io/library/...) pinned by digest
---

Container base image is not an official / verified-publisher image.

## Confirms
- image namespace is a personal account, especially one that also authored the change
- image not found on the registry, or no digest pin

## False positives
- the organisation's own registry or a vendor image listed in policy.container_images.trusted_publishers

## Remediation
- update_base_image: switch to the official image (docker.io/library/...) pinned by digest
