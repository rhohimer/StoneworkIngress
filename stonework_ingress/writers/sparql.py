"""Generate SPARQL UPDATE statements from a BomManifest."""

from collections import defaultdict
from stonework_ingress.model import BomManifest, BomEntry

_STONEWORK = "https://cyberterrain.org/ns/stonework#"
_STONES    = "https://cyberterrain.org/ns/stones#"
_CPE       = "https://cyberterrain.org/ns/frameworks/cpe#"


def to_insert_update(manifest: BomManifest) -> str:
    """Return a single SPARQL UPDATE inserting all SBOM and BomEntry triples.

    Graph layout, both case-scoped (see model.py's sbom_graph/inventory_graph):
    - SBOM metadata graph (<case-<id>/sbom-<slug>>):
        SoftwareBillOfMaterials IRI, serialNumber, bomFormat,
        describesInfrastructure, hasBomEntry links, Infrastructure typing.
    - Per-type graphs (<case-<id>/inventory-software|hardware|firmware>):
        BomEntry IRI, installationOf → VersionedProduct, cpe:cpeName.
    """
    if not manifest.entries:
        return ""

    blocks = []

    # ── SBOM metadata graph ───────────────────────────────────────────────────
    def _lit(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    sbom_triples = [
        f"    <{manifest.sbom_iri}> a <{_STONEWORK}SoftwareBillOfMaterials> .",
        f'    <{manifest.sbom_iri}> <{_STONEWORK}serialNumber> "{_lit(manifest.serial_number)}" .',
        f'    <{manifest.sbom_iri}> <{_STONEWORK}bomFormat> "{_lit(manifest.bom_format)}" .',
        f"    <{manifest.sbom_iri}> <{_STONEWORK}describesInfrastructure> <{manifest.infra_iri}> .",
        f"    <{manifest.infra_iri}> a <{_STONES}Infrastructure> .",
    ]
    for entry in manifest.entries:
        sbom_triples.append(
            f"    <{manifest.sbom_iri}> <{_STONEWORK}hasBomEntry> <{entry.entry_iri}> ."
        )
    blocks.append(
        f"  GRAPH <{manifest.sbom_graph}> {{\n"
        + "\n".join(sbom_triples)
        + "\n  }"
    )

    # ── Per-type inventory graphs ─────────────────────────────────────────────
    by_graph: dict[str, list[BomEntry]] = defaultdict(list)
    for entry in manifest.entries:
        by_graph[manifest.inventory_graphs[entry.inventory_type]].append(entry)

    for graph_iri, entries in by_graph.items():
        triples = []
        for entry in entries:
            triples.extend([
                f"    <{entry.entry_iri}> a <{_STONEWORK}BomEntry> .",
                f"    <{entry.entry_iri}> <{_STONEWORK}installationOf> <{entry.product_iri}> .",
                f'    <{entry.entry_iri}> <{_CPE}cpeName> "{_lit(entry.cpe_str)}" .',
            ])
        blocks.append(
            f"  GRAPH <{graph_iri}> {{\n"
            + "\n".join(triples)
            + "\n  }"
        )

    return "INSERT DATA {\n" + "\n".join(blocks) + "\n}"
