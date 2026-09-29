import re
import uuid
from dataclasses import dataclass, field

# Legacy fixed graphs — no longer written to (see inventory_graphs() below),
# kept only in case anything external still reads this constant.
INVENTORY_GRAPHS: dict[str, str] = {
    "software": "https://cyberterrain.org/graph/user-inventory/software",
    "hardware": "https://cyberterrain.org/graph/user-inventory/hardware",
    "firmware": "https://cyberterrain.org/graph/user-inventory/firmware",
}

CTIENC_BASE        = "https://cyberterrain.org/cti-encyclopedia/resource/"
DEFAULT_INFRA_IRI  = "https://cyberterrain.org/user-data/my-infrastructure"
DEFAULT_CASE_ID    = "default"
_SBOM_RESOURCE_BASE = "https://cyberterrain.org/user-data/sbom/"


def slugify_case_id(raw: str | None) -> str:
    """Mirror moai backend's app/routers/user_graph.py::_slugify_case_id —
    keep these in sync if either changes."""
    if not raw or not raw.strip():
        return DEFAULT_CASE_ID
    slug = re.sub(r"[^a-z0-9]+", "-", raw.strip().lower()).strip("-")
    return slug or DEFAULT_CASE_ID


def inventory_graph(case_id: str, inventory_type: str) -> str:
    """Mirror moai backend's _inventory_graph — same IRI convention, so SBOM
    and manually-added inventory items land in the same graph per case/type."""
    return f"https://cyberterrain.org/graph/case-{case_id}/inventory-{inventory_type}"


def sbom_graph(case_id: str, slug: str) -> str:
    return f"https://cyberterrain.org/graph/case-{case_id}/sbom-{slug}"

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
    case_id: str
    inventory_graphs: dict[str, str]  # inventory_type -> case-scoped graph IRI
    entries: list[BomEntry] = field(default_factory=list)


def new_manifest(
    serial_number: str = "",
    bom_format: str = "",
    infra_iri: str = DEFAULT_INFRA_IRI,
    case_id: str | None = None,
) -> BomManifest:
    """Create a BomManifest with a UUID-based IRI, using the document's serial if present."""
    case = slugify_case_id(case_id)
    uid = serial_number or f"urn:uuid:{uuid.uuid4()}"
    slug = _serial_to_slug(uid)
    return BomManifest(
        sbom_iri=f"{_SBOM_RESOURCE_BASE}{slug}",
        sbom_graph=sbom_graph(case, slug),
        case_id=case,
        inventory_graphs={t: inventory_graph(case, t) for t in ("software", "hardware", "firmware")},
        serial_number=uid,
        bom_format=bom_format,
        infra_iri=infra_iri,
    )
