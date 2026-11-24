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

# agentic version (LangGraph agents + LLM triage): ../docs/agentic.md
copy .env.example .env                                   # put ONE API key (Claude / Gemini / Groq / Grok) in .env
python -m sscg agent ..\targets\sscg-demo-target          # no key: rules-only fallback
python -m sscg agent ..\targets\sscg-demo-target --llm groq --day2 --decisions later   # Day 2: ../docs/day2.md
python -m sscg approve ..\targets\sscg-demo-target --approve all-patchable --by "Your Name"
```

Outputs per scan: `sbom.cdx.json` (CycloneDX 1.5), `graph.html`, `graph.json`, `summary.json`, **`findings.json`** (vulnerabilities + anomalies with evidence and initial risk), **`report.md`** (evidence report, also as `report.html` and `report.pdf`), `graph.mmd` (small graphs).

The `agent` command also writes **`agentic.json`** (AI triage, tool evidence, summary, audit trail) and adds a clearly separated AI section to the report; with `--day2` also `day2/` (remediation report, `day2.json`, `remediation.patch`).
