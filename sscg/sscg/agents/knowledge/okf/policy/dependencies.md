---
type: policy
title: dependencies
status: stable
generated:
  by: process:yaml-migration
  at: '2026-11-24T00:00:00+00:00'
vv:
  require_lockfile: true
  python_exact_pins: true
  new_direct_dependency_requires_review: true
  install_scripts: blocked unless the package is on the allow-list
  install_script_allowlist:
  - node-gyp
  - esbuild
  - sharp
  - bcrypt
  - sqlite3
  - puppeteer
  - husky
  - core-js
---

```yaml
install_script_allowlist:
- node-gyp
- esbuild
- sharp
- bcrypt
- sqlite3
- puppeteer
- husky
- core-js
install_scripts: blocked unless the package is on the allow-list
new_direct_dependency_requires_review: true
python_exact_pins: true
require_lockfile: true
```
