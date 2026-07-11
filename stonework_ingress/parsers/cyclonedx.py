"""Parser for CycloneDX JSON SBOMs (spec versions 1.4–1.6).

Extracts components that carry a CPE 2.3 identifier and maps them to
BomEntry instances within a BomManifest targeting the appropriate
user-inventory named graphs.
"""

import json
from stonework_ingress.model import (
    BomManifest, BomEntry, DEFAULT_INFRA_IRI,
    cpe_to_iri, cpe_inventory_type, entry_iri, new_manifest,
)


def parse(content: str | bytes, infra_iri: str = DEFAULT_INFRA_IRI) -> BomManifest:
    """Parse a CycloneDX JSON document and return a BomManifest.

    Components without a CPE 2.3 field are silently skipped — PURL-only
    components cannot be resolved against the CTI Encyclopedia without a
    separate NVD lookup.
    """
    data = json.loads(content)

    serial = data.get("serialNumber", "")
    spec_version = data.get("specVersion", "")
    bom_format = f"CycloneDX {spec_version}" if spec_version else "CycloneDX"

    manifest = new_manifest(
        serial_number=serial,
        bom_format=bom_format,
        infra_iri=infra_iri,
    )

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

        manifest.entries.append(BomEntry(
            entry_iri=entry_iri(manifest.sbom_iri, cpe),
            product_iri=cpe_to_iri(cpe),
            cpe_str=cpe,
            inventory_type=inv_type,
        ))

    return manifest


def _iter_components(data: dict):
    """Yield all component objects, including nested sub-components."""
    for c in data.get("components", []):
        yield c
        yield from _iter_components(c)
    meta_component = data.get("metadata", {}).get("component")
    if meta_component:
        yield meta_component
