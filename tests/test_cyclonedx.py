import json
import pytest
from stonework_ingress.parsers.cyclonedx import parse
from stonework_ingress.writers.sparql import to_insert_update
from stonework_ingress.model import CTIENC_BASE

_LOG4J_CPE = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
_BIOS_CPE  = "cpe:2.3:h:dell:precision_490:*:*:*:*:*:*:*:*"

SAMPLE_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "log4j-core", "version": "2.14.1", "cpe": _LOG4J_CPE},
        {"type": "device",  "name": "Precision 490",                   "cpe": _BIOS_CPE},
        {"type": "library", "name": "no-cpe-component"},
    ],
}


def test_parse_extracts_cpe_components():
    assertions = parse(json.dumps(SAMPLE_BOM))
    assert len(assertions) == 2


def test_parse_software_type():
    assertions = parse(json.dumps(SAMPLE_BOM))
    sw = next(a for a in assertions if a.cpe_str == _LOG4J_CPE)
    assert sw.inventory_type == "software"
    assert sw.product_iri.startswith(CTIENC_BASE)


def test_parse_hardware_type():
    assertions = parse(json.dumps(SAMPLE_BOM))
    hw = next(a for a in assertions if a.cpe_str == _BIOS_CPE)
    assert hw.inventory_type == "hardware"


def test_parse_deduplicates():
    bom = {**SAMPLE_BOM, "components": [
        {"type": "library", "cpe": _LOG4J_CPE},
        {"type": "library", "cpe": _LOG4J_CPE},
    ]}
    assertions = parse(json.dumps(bom))
    assert len(assertions) == 1


def test_iri_derivation():
    assertions = parse(json.dumps({"components": [{"cpe": _LOG4J_CPE}]}))
    expected_suffix = "_VersionedProduct_cpe_2-3_a_apache_log4j_2-14-1_X_X_X_X_X_X_X"
    assert assertions[0].product_iri.endswith(expected_suffix)


def test_sparql_writer_produces_insert():
    assertions = parse(json.dumps(SAMPLE_BOM))
    update = to_insert_update(assertions)
    assert update.startswith("INSERT DATA")
    assert "user-inventory/software" in update
    assert "user-inventory/hardware" in update
    assert _LOG4J_CPE in update
