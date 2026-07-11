import uuid
from dataclasses import dataclass, field

INVENTORY_GRAPHS: dict[str, str] = {
    "software": "https://cyberterrain.org/graph/user-inventory/software",
    "hardware": "https://cyberterrain.org/graph/user-inventory/hardware",
    "firmware": "https://cyberterrain.org/graph/user-inventory/firmware",
}

CTIENC_BASE        = "https://cyberterrain.org/cti-encyclopedia/resource/"
DEFAULT_INFRA_IRI  = "https://cyberterrain.org/user-data/my-infrastructure"
_SBOM_RESOURCE_BASE = "https://cyberterrain.org/user-data/sbom/"
_SBOM_GRAPH_BASE    = "https://cyberterrain.org/graph/user-inventory/sbom/"

_CPE_PART_TO_TYPE: dict[str, str] = {"a": "software", "h": "hardware", "o": "firmware"}


def cpe_to_iri(cpe_str: str) -> str:
    """Derive the CTI Encyclopedia VersionedProduct IRI from a CPE 2.3 string.

    Must match the IRI minting convention used in the skotarch pipeline.
    cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
      → https://cyberterrain.org/cti-encyclopedia/resource/_VersionedProduct_cpe_2-3_a_apache_log4j_2-14-1_X_X_X_X_X_X_X
    """
    slug = cpe_str.replace(".", "-").replace(":", "_").replace("*", "X")
    return f"{CTIENC_BASE}_VersionedProduct_{slug}"


def cpe_inventory_type(cpe_str: str) -> str | None:
    """Return 'software', 'hardware', or 'firmware' from CPE 2.3 part field; None if unrecognised."""
    parts = cpe_str.split(":")
    if len(parts) < 3:
        return None
    return _CPE_PART_TO_TYPE.get(parts[2])


def _serial_to_slug(serial: str) -> str:
    """Convert a serial number / URN to a safe IRI slug."""
    return serial.replace(":", "_").replace("-", "_").replace(".", "_").replace("/", "_")


def entry_iri(sbom_iri: str, cpe_str: str) -> str:
    """Derive a BomEntry IRI scoped to this SBOM from a CPE string."""
    slug = cpe_str.replace(".", "-").replace(":", "_").replace("*", "X")
    return f"{sbom_iri}/entry/{slug}"


@dataclass
class BomEntry:
    entry_iri: str
    product_iri: str
    cpe_str: str
    inventory_type: str   # software | hardware | firmware


@dataclass
class BomManifest:
    sbom_iri: str
    sbom_graph: str
    serial_number: str
    bom_format: str
    infra_iri: str
    entries: list[BomEntry] = field(default_factory=list)


def new_manifest(
    serial_number: str = "",
    bom_format: str = "",
    infra_iri: str = DEFAULT_INFRA_IRI,
) -> BomManifest:
    """Create a BomManifest with a UUID-based IRI, using the document's serial if present."""
    uid = serial_number or f"urn:uuid:{uuid.uuid4()}"
    slug = _serial_to_slug(uid)
    return BomManifest(
        sbom_iri=f"{_SBOM_RESOURCE_BASE}{slug}",
        sbom_graph=f"{_SBOM_GRAPH_BASE}{slug}",
        serial_number=uid,
        bom_format=bom_format,
        infra_iri=infra_iri,
    )
