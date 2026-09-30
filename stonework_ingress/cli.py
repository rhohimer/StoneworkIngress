"""sw-ingest CLI — ingest enterprise data sources into the STONEWORK user-data graph."""

try:
    import click
except ImportError:
    raise SystemExit("Install the CLI extra: pip install stonework-ingress[cli]")

import json
import sys
from pathlib import Path
import requests
from stonework_ingress.parsers import cyclonedx
from stonework_ingress.writers.sparql import to_insert_update
from stonework_ingress.converters import firewall_log
from stonework_ingress.model import DEFAULT_INFRA_IRI


@click.group()
def main():
    """StoneworkIngress — transform enterprise data into the user-data graph."""


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--ag-url",   default="http://localhost:10035", show_default=True)
@click.option("--repo",     default="user-data", show_default=True)
@click.option("--user",     envvar="AG_USER", default="admin")
@click.option("--password", envvar="AG_PASS",  default="")
@click.option("--infra",    default=DEFAULT_INFRA_IRI, show_default=True,
              help="Infrastructure IRI to assert hasInstalledProduct from.")
@click.option("--dry-run",  is_flag=True, help="Print SPARQL UPDATE without executing.")
def cyclonedx(file, ag_url, repo, user, password, infra, dry_run):
    """Ingest a CycloneDX JSON SBOM into the user-data inventory graphs."""
    with open(file, "rb") as fh:
        content = fh.read()

    assertions = cyclonedx.parse(content, infra_iri=infra)
    if not assertions:
        click.echo("No CPE-bearing components found.", err=True)
        sys.exit(1)

    click.echo(f"Parsed {len(assertions)} component(s).", err=True)
    update = to_insert_update(assertions)

    if dry_run:
        click.echo(update)
        return

    url = f"{ag_url}/repositories/{repo}"
    resp = requests.post(
        url,
        data={"update": update},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=(user, password),
        timeout=60,
    )
    resp.raise_for_status()
    click.echo(f"Inserted {len(assertions)} assertion(s) into {url}.")


@main.command(name="firewall-log")
@click.argument("file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(),
              help="Write the STIX 2.1 bundle JSON here instead of stdout.")
def firewall_log_cmd(file, output):
    """Convert a firewall-log CSV into a STIX 2.1 bundle (Observed Data).

    Prints the bundle as JSON. This command does not load it into a
    graph itself — feed the output into a STIX 2.1 import pipeline
    (e.g. moai's POST /api/user-graph/import/stix21) to do that.
    """
    bundle = firewall_log.convert_file(file)
    text = json.dumps(bundle, indent=2)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"Wrote {len(bundle['objects'])} STIX object(s) to {output}.", err=True)
    else:
        click.echo(text)
