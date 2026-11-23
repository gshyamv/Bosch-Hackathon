"""OSV.dev overlay: marks package versions that have published advisories (graph colouring only)."""
from __future__ import annotations

import re

from .cache import http_json
from .model import DepGraph

OSV_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}


def osv_overlay(dg: DepGraph):
    G = dg.G
    pk = [(n, a) for n, a in G.nodes(data=True) if a["kind"] == "package"
          and a["ecosystem"] in OSV_ECO and re.match(r"\d", str(a.get("version", "")))]
    for i in range(0, len(pk), 500):
        batch = pk[i:i + 500]
        q = {"queries": [{"package": {"ecosystem": OSV_ECO[a["ecosystem"]], "name": a["name"]},
                          "version": a["version"]} for _, a in batch]}
        res = http_json("POST", "https://api.osv.dev/v1/querybatch", q)
        if not res:
            dg.notes.append("OSV unavailable (offline / network)")
            return
        for (n, _), r in zip(batch, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                G.nodes[n]["vulns"] = ids
