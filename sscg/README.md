# sscg: quick start

The full documentation (scope, architecture, rules, risk formula, outputs, verification, limitations) is in the **[main README](../README.md)**.

```powershell
cd sscg
pip install -r requirements.txt                          # Python 3.11.4+ (3.12 recommended)

python -m sscg scan ..\targets\sscg-demo-target          # discover + detect + evidence -> out\sscg-demo-target\
python -m sscg scan ..\targets\sscg-demo-target --base bf0e651   # "what changed" against a chosen commit
python -m sscg scan ..\targets\nodejs-goof --why qs
python -m sscg scan <repo> --sbom bom.cdx.json           # consume an existing CycloneDX SBOM
python -m sscg scan <repo> --offline                     # cached API answers only

cd web; npm install; npm run build; cd ..                # build the dashboard once (Node.js 18+)
python -m sscg serve                                     # dashboard at http://127.0.0.1:8000

# agentic version (LangGraph agents + LLM triage): ../docs/agentic.md
copy .env.example .env                                   # put ONE API key (Claude / Gemini / Groq / DeepSeek / Grok) in .env
python -m sscg agent ..\targets\sscg-demo-target          # no key: rules-only fallback
python -m sscg agent ..\targets\sscg-demo-target --llm groq --remediate --decisions later   # ../docs/remediation.md
python -m sscg approve ..\targets\sscg-demo-target --approve all-patchable --by "Your Name"
```

Outputs per scan: `sbom.cdx.json` (CycloneDX 1.5), `graph.html`, `graph.json`, `summary.json`, **`findings.json`** (vulnerabilities + anomalies with evidence and initial risk), **`report.md`** (evidence report, also as `report.html` and `report.pdf`), `graph.mmd` (small graphs).

The `agent` command also writes **`agentic.json`** (AI triage, tool evidence, summary, audit trail) and adds a clearly separated AI section to the report; with `--remediate` also `remediation/` (remediation report, `remediation.json`, `remediation.patch`).
