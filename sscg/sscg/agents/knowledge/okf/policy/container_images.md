---
type: policy
title: container_images
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  trusted_publishers:
  - docker.io/library
  - gcr.io/distroless
  - cgr.dev/chainguard
  - mcr.microsoft.com
  - public.ecr.aws/docker/library
  require_digest: true
  forbidden_tags:
  - latest
  run_as_non_root: true
---

```yaml
forbidden_tags:
- latest
require_digest: true
run_as_non_root: true
trusted_publishers:
- docker.io/library
- gcr.io/distroless
- cgr.dev/chainguard
- mcr.microsoft.com
- public.ecr.aws/docker/library
```
