# sscg: quick start

The full documentation (scope, architecture, rules, risk formula, outputs, verification, limitations) is in the **[main README](../README.md)**.

```powershell
cd sscg
pip install -r requirements.txt                          # Python 3.11.4+ (3.12 recommended)

python -m sscg scan ..\targets\sscg-demo-target          # full Day 1 pipeline -> out\sscg-demo-target\
python -m sscg scan ..\targets\sscg-demo-target --base bf0e651   # "what changed" against a chosen commit
python -m sscg scan ..\targets\nodejs-goof --why qs
python -m sscg scan <repo> --sbom bom.cdx.json           # consume an existing CycloneDX SBOM
python -m sscg scan <repo> --offline                     # cached API answers only

streamlit run ui/app.py                                  # dashboard
```

Outputs per scan: `sbom.cdx.json` (CycloneDX 1.5), `graph.html`, `graph.json`, `summary.json`, **`findings.json`** (vulnerabilities + anomalies with evidence and initial risk), **`report.md`** (evidence report), `graph.mmd` (small graphs).
