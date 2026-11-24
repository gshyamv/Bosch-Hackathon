---
type: playbook
title: R03_INSTALL_SCRIPT
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  triage: true
  checks: A package declares preinstall / install / postinstall scripts (they run on every install, including CI).
  confirms:
  - script content downloads or executes code, reads environment variables or credentials (see R04)
  - script was added in a version update (R19) or by a new maintainer
  - package is also flagged as typosquat / malicious
  false_positives:
  - native build steps (node-gyp rebuild, prebuild-install, cmake-js) in well-known packages
  - git hook installers (husky) and donation / telemetry messages (core-js, opencollective)
  - the application's own lifecycle scripts that only build or copy local files
  default_tools:
  - repo_file_context
  - registry_metadata
  - graph_context
  fallback_verdict: needs_human_review
  remediation_options:
  - action: mitigate
    when: install with --ignore-scripts and allow-list scripts that are needed
  - action: replace
    when: an alternative without install scripts exists
---

A package declares preinstall / install / postinstall scripts (they run on every install, including CI).

## Confirms
- script content downloads or executes code, reads environment variables or credentials (see R04)
- script was added in a version update (R19) or by a new maintainer
- package is also flagged as typosquat / malicious

## False positives
- native build steps (node-gyp rebuild, prebuild-install, cmake-js) in well-known packages
- git hook installers (husky) and donation / telemetry messages (core-js, opencollective)
- the application's own lifecycle scripts that only build or copy local files

## Remediation
- mitigate: install with --ignore-scripts and allow-list scripts that are needed
- replace: an alternative without install scripts exists
