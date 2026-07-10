from dataclasses import dataclass

INVENTORY_GRAPHS: dict[str, str] = {
    "software": "https://cyberterrain.org/graph/user-inventory/software",
    "hardware": "https://cyberterrain.org/graph/user-inventory/hardware",
    "firmware": "https://cyberterrain.org/graph/user-inventory/firmware",
}

CTIENC_BASE = "https://cyberterrain.org/cti-encyclopedia/resource/"
DEFAULT_INFRA_IRI = "https://cyberterrain.org/user-data/my-infrastructure"

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


@dataclass
class InventoryAssertion:
    product_iri: str
    cpe_str: str
    inventory_type: str   # software | hardware | firmware
    infra_iri: str = DEFAULT_INFRA_IRI
