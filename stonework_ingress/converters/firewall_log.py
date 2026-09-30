"""Convert a simple firewall-log CSV into a STIX 2.1 bundle.

A firewall connection event is already exactly what STIX 2.1 calls
Observed Data: a network-traffic object referencing ipv4-addr Cyber
Observables. Producing real STIX here — rather than a new ad-hoc
ingest schema — means any existing STIX 2.1 import pipeline handles
the rest (case-scoping, materialization, sync) with zero new code on
the consuming side.

Expected CSV columns: timestamp, src_ip, dst_ip, dst_port, protocol
("action" is commonly present too; not currently mapped to an RDF
property, kept in the source CSV for human readability only.)
"""
import csv
import uuid
from pathlib import Path

# Fixed namespace so converting the same CSV twice produces the same
# object IDs every time (no duplicate-triple bloat on re-import) — same
# spirit as STIX 2.1's own deterministic-ID convention for SCOs, just a
# simpler hash input than the real spec's canonicalization rules.
_NAMESPACE = uuid.UUID("c7b8b1a0-6e4b-4b8a-9b7b-1f2e3d4c5a6b")


def _stix_id(obj_type: str, key: str) -> str:
    return f"{obj_type}--{uuid.uuid5(_NAMESPACE, f'{obj_type}:{key}')}"


def convert(rows: list[dict]) -> dict:
    """Convert parsed CSV rows (dicts with timestamp/src_ip/dst_ip/dst_port/
    protocol keys) into a STIX 2.1 bundle dict.
    """
    objects = []
    ip_ids: dict[str, str] = {}

    def ensure_ip(value: str) -> str:
        if value not in ip_ids:
            oid = _stix_id("ipv4-addr", value)
            ip_ids[value] = oid
            objects.append({"type": "ipv4-addr", "id": oid, "value": value})
        return ip_ids[value]

    for row in rows:
        ts = row["timestamp"].strip()
        src_ip = row["src_ip"].strip()
        dst_ip = row["dst_ip"].strip()
        dst_port = int(row["dst_port"])
        protocol = row["protocol"].strip().lower()

        src_id = ensure_ip(src_ip)
        dst_id = ensure_ip(dst_ip)

        nt_key = f"{ts}|{src_ip}|{dst_ip}|{dst_port}|{protocol}"
        nt_id = _stix_id("network-traffic", nt_key)
        objects.append({
            "type": "network-traffic",
            "id": nt_id,
            "src_ref": src_id,
            "dst_ref": dst_id,
            "dst_port": dst_port,
            "protocols": [protocol],
            "start": ts,
        })

        od_id = _stix_id("observed-data", nt_key)
        objects.append({
            "type": "observed-data",
            "id": od_id,
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [nt_id, src_id, dst_id],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, 'firewall-log-bundle')}",
        "objects": objects,
    }


def convert_file(path: str | Path) -> dict:
    """Read a firewall-log CSV file and return its STIX 2.1 bundle dict."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return convert(rows)
