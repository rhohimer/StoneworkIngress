"""Converters from non-STIX source formats into STIX 2.1 bundles.

Distinct from parsers/ (file -> stonework-ingress-specific graph-ready
model, e.g. BomManifest) and writers/ (model -> SPARQL UPDATE): a
converter here produces a plain STIX 2.1 bundle dict, meant to be fed
into an existing STIX 2.1 import pipeline (e.g. moai's
stix21-to-ctienc.sparql transform) rather than written to the graph
directly. Use this package when the source format maps naturally onto
existing STIX 2.1 object types (e.g. a firewall log is Observed Data),
so the target system's own STIX ingest handles case-scoping,
materialization, and everything else for free.
"""

