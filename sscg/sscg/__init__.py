"""Software Supply Chain Guardian (SSCG): Day 1, pillars 1-2.

1 Discover components  -> sscg.discover  (npm, PyPI, Maven manifests + lockfiles)
2 Supply chain view    -> sscg.sbom      (CycloneDX 1.5: generate + consume)
                          sscg.graph     (dependency graph, origins, paths)
                          sscg.discover.docker / .gha (container images, CI/CD workflows)
"""

__version__ = "0.1.0"
