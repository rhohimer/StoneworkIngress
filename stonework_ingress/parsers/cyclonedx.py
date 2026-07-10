"""Parser for CycloneDX JSON SBOMs (spec versions 1.4–1.6).

Extracts components that carry a CPE 2.3 identifier and maps them to
InventoryAssertions targeting the appropriate user-inventory named graph.
"""

import json
from stonework_ingress.model import InventoryAssertion, DEFAULT_INFRA_IRI, cpe_to_iri, cpe_inventory_type


def parse(content: str | bytes, infra_iri: str = DEFAULT_INFRA_IRI) -> list[InventoryAssertion]:
    """Parse a CycloneDX JSON document and return inventory assertions.

    Components without a CPE field are silently skipped — PURL-only components
    cannot be resolved against the CTI Encyclopedia without a separate lookup.
    """
    data = json.loads(content) if isinstance(content, (bytes, bytearray)) else json.loads(content)

    assertions: list[InventoryAssertion] = []
    seen: set[str] = set()

    for component in _iter_components(data):
        cpe = (component.get("cpe") or "").strip()
        if not cpe or not cpe.startswith("cpe:2.3:"):
            continue
        if cpe in seen:
            continue
        seen.add(cpe)

        inv_type = cpe_inventory_type(cpe)
        if inv_type is None:
            continue

        assertions.append(InventoryAssertion(
            product_iri=cpe_to_iri(cpe),
            cpe_str=cpe,
            inventory_type=inv_type,
            infra_iri=infra_iri,
        ))

    return assertions


def _iter_components(data: dict):
    """Yield all component objects, including nested sub-components."""
    for c in data.get("components", []):
        yield c
        yield from _iter_components(c)
    # metadata.component is the top-level subject of the SBOM
    meta_component = data.get("metadata", {}).get("component")
    if meta_component:
        yield meta_component
