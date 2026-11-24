---
type: playbook
title: R04_INSTALL_SCRIPT_CONTENT
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: Install script content matches indicators (child_process / shell, network download, env or credential reads, obfuscation).
  confirms:
  - script reads secrets (env vars, ~/.npmrc, ~/.ssh, cloud credentials) AND sends data over the network
  - obfuscated code (long base64 / hex strings, eval of decoded text)
  - script was introduced in the latest change by a first-time contributor
  false_positives:
  - build scripts that shell out to compilers and read build-related env vars (CI, NODE_ENV)
  default_tools:
  - repo_file_context
  - commit_history
  fallback_verdict: suspicious
  remediation_options:
  - action: block
    when: secret read + network send are both present
  - action: escalate_review
    when: always
---

Install script content matches indicators (child_process / shell, network download, env or credential reads, obfuscation).

## Confirms
- script reads secrets (env vars, ~/.npmrc, ~/.ssh, cloud credentials) AND sends data over the network
- obfuscated code (long base64 / hex strings, eval of decoded text)
- script was introduced in the latest change by a first-time contributor

## False positives
- build scripts that shell out to compilers and read build-related env vars (CI, NODE_ENV)

## Remediation
- block: secret read + network send are both present
- escalate_review: always
