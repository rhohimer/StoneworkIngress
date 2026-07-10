"""Generate SPARQL UPDATE statements from InventoryAssertions."""

from collections import defaultdict
from stonework_ingress.model import InventoryAssertion, INVENTORY_GRAPHS

_STONEWORK = "https://cyberterrain.org/ns/stonework#"
_STONES    = "https://cyberterrain.org/ns/stones#"
_CPE       = "https://cyberterrain.org/ns/frameworks/cpe#"


def to_insert_update(assertions: list[InventoryAssertion]) -> str:
    """Return a single SPARQL UPDATE that inserts all assertions grouped by named graph."""
    if not assertions:
        return ""

    by_graph: dict[str, list[InventoryAssertion]] = defaultdict(list)
    for a in assertions:
        by_graph[INVENTORY_GRAPHS[a.inventory_type]].append(a)

    blocks = []
    for graph_iri, items in by_graph.items():
        triples = []
        infra_iri = items[0].infra_iri
        triples.append(f"    <{infra_iri}> a <{_STONES}Infrastructure> .")
        for item in items:
            triples.append(f"    <{infra_iri}> <{_STONEWORK}hasInstalledProduct> <{item.product_iri}> .")
            safe = item.cpe_str.replace("\\", "\\\\").replace('"', '\\"')
            triples.append(f'    <{item.product_iri}> <{_CPE}cpeName> "{safe}" .')
        blocks.append(f"  GRAPH <{graph_iri}> {{\n" + "\n".join(triples) + "\n  }")

    return "INSERT DATA {\n" + "\n".join(blocks) + "\n}"
