"""
fuseki_writer.py — EDEN Service Validator
==========================================
Writes batch-validation results back into a Fuseki store as W3C DQV
quality measurements.

Counterpart to fuseki_loader.py: the loader reads harvested service records
from the harmonized graphs (eden://harvester/harmonized/); this writer
annotates the same service nodes with dqv:QualityMeasurement nodes in a
dedicated graph (eden://validator/results/) so metadata and validation
status can be joined in a single SPARQL query. Each validated record yields
a measurement of edenval:endpointValid (always) and edenval:validationScore
(when numeric). The full shape is documented in
docs/fuseki-writeback-schema.md.

Write semantics: the results graph is REPLACED on every run — DROP SILENT +
INSERT DATA are sent as ONE SPARQL Update request, which Fuseki executes as
a single transaction, so stale scores never accumulate and readers never see
a half-written graph. If a run yields zero writable results the graph is
left untouched (an empty run usually means an upstream failure — keep the
last good results).
"""

import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

import requests

logger = logging.getLogger("FusekiWriter")

# Namespace for EDEN-minted terms: the two dqv:Metric definitions, the
# diagnostic properties (which describe the check, not quality, and so have
# no DQV slot), and the run node. https://w3id.org/eden/validator# is the
# intended permanent namespace — the w3id.org registration (PR to
# perma-id/w3id.org, redirecting to docs/fuseki-writeback-schema.md) is
# pending; until it resolves, that schema doc is the authoritative
# definition. Swap it here, nowhere else.
VOCAB_NS = "https://w3id.org/eden/validator#"
DEFAULT_GRAPH = "eden://validator/results/"
RUN_NS = "eden://validator/runs/"

# Conservative IRI check: a scheme, then no whitespace or characters that
# would break out of an inline <IRI> in a SPARQL Update body.
_IRI_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.\-]*:[^\x00-\x20<>"{}|^`\\]*$')

_PROLOGUE = (
    f"PREFIX edenval: <{VOCAB_NS}>\n"
    "PREFIX dqv:  <http://www.w3.org/ns/dqv#>\n"
    "PREFIX prov: <http://www.w3.org/ns/prov#>\n"
    "PREFIX skos: <http://www.w3.org/2004/02/skos/core#>\n"
    "PREFIX ldqd: <http://www.w3.org/2016/05/ldqd#>\n"
    "PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>\n"
)

# Static dqv:Metric definitions. DQV standardizes the measurement *shape*
# but ships no concrete metrics, so these two are minted here. They ride
# along with every run: the graph is replaced wholesale, so they must be
# re-inserted each time.
_METRIC_DEFINITIONS = (
    "edenval:endpointValid a dqv:Metric ;\n"
    '    skos:prefLabel "Endpoint validity"@en ;\n'
    '    skos:definition "Whether the endpoint passed the EDEN service '
    'validator\'s protocol-aware live check."@en ;\n'
    "    dqv:expectedDataType xsd:boolean ;\n"
    "    dqv:inDimension ldqd:availability .\n"
    "edenval:validationScore a dqv:Metric ;\n"
    '    skos:prefLabel "Endpoint validation score"@en ;\n'
    '    skos:definition "0-10 score from the EDEN service validator\'s '
    'protocol-aware endpoint checks."@en ;\n'
    "    dqv:expectedDataType xsd:decimal ;\n"
    "    dqv:inDimension ldqd:availability ."
)


def escape_literal(value) -> str:
    """Escape a value for use inside a double-quoted SPARQL literal."""
    s = str(value)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def is_writable_iri(value) -> bool:
    """True if value can be safely embedded as <value> in a SPARQL Update."""
    return bool(value) and bool(_IRI_RE.match(value))


def derive_update_endpoint(query_endpoint: str) -> str:
    """Map a Fuseki query endpoint to its update endpoint (…/query → …/update)."""
    base = query_endpoint.rstrip("/")
    if base.endswith("/query"):
        return base[: -len("/query")] + "/update"
    return base + "/update"


def _record_triples(row: dict, graph_uri: str, run_uri: str,
                    generated_at: str) -> Optional[str]:
    """
    Serialize one validated record as 1-2 dqv:QualityMeasurement nodes
    (validity always; score only when numeric), or None if the row carries
    no usable service URI (nothing in the graph to annotate).
    """
    service_uri = (row.get("serviceUri") or "").strip()
    if not is_writable_iri(service_uri):
        logger.warning(
            "Write-back: skipping endpoint '%s' — missing or unusable service URI (%r).",
            row.get("endpoint", ""), service_uri,
        )
        return None

    endpoint = (row.get("endpoint") or "").strip()
    digest = hashlib.sha1(
        f"{service_uri}|{endpoint}|{row.get('conforms_to') or ''}".encode("utf-8")
    ).hexdigest()[:16]
    base_uri = f"{graph_uri.rstrip('/')}/m-{digest}"

    # Shared by both measurement nodes. endpointUrl is a literal on purpose:
    # harvested URLs may be malformed IRIs that would make the whole
    # INSERT DATA request fail — and it disambiguates which of a service's
    # several dcat:endpointURLs a measurement refers to.
    common_head = [
        f"    dqv:computedOn <{service_uri}>",
        f'    edenval:endpointUrl "{escape_literal(endpoint)}"',
    ]
    common_tail = [
        f'    prov:generatedAtTime "{generated_at}"^^xsd:dateTime',
        f"    prov:wasGeneratedBy <{run_uri}>",
    ]

    valid_lines = [
        f"<{base_uri}-valid> a dqv:QualityMeasurement",
        *common_head,
        "    dqv:isMeasurementOf edenval:endpointValid",
        f'    dqv:value {"true" if row.get("valid") else "false"}',
    ]

    # Diagnostics describe the check, not quality — they live on the
    # always-present -valid node only.
    service_type = (row.get("mapped_service_type") or "").strip()
    if service_type and service_type != "N/A":
        valid_lines.append(f'    edenval:serviceType "{escape_literal(service_type)}"')

    method = (row.get("resolution_method") or "").strip()
    if method and method != "none":
        valid_lines.append(f'    edenval:resolutionMethod "{escape_literal(method)}"')

    try:
        valid_lines.append(f"    edenval:httpStatus {int(row.get('status_code'))}")
    except (TypeError, ValueError):
        pass

    if row.get("error"):
        valid_lines.append(f'    edenval:error "{escape_literal(row["error"])}"')

    valid_lines.extend(common_tail)
    blocks = [" ;\n".join(valid_lines) + " ."]

    try:
        score = float(row.get("score"))
        score_lines = [
            f"<{base_uri}-score> a dqv:QualityMeasurement",
            *common_head,
            "    dqv:isMeasurementOf edenval:validationScore",
            f'    dqv:value "{score}"^^xsd:decimal',
            *common_tail,
        ]
        blocks.append(" ;\n".join(score_lines) + " .")
    except (TypeError, ValueError):
        pass

    return "\n".join(blocks)


def build_update(results: list, graph_uri: str = DEFAULT_GRAPH,
                 run_id: Optional[str] = None,
                 generated_at: Optional[str] = None) -> Tuple[str, int]:
    """
    Build the full SPARQL Update (DROP + INSERT DATA) for a validation run.

    Args:
        results:      Output rows from batch validation (see module docstring).
        graph_uri:    Named graph to replace.
        run_id:       Optional external (harvest) run identifier for provenance.
        generated_at: Override the run timestamp (tests); xsd:dateTime string.

    Returns:
        (update_string, n_records_included) — a record may serialize to two
        measurement nodes but counts once; rows without a usable service URI
        are excluded from the count. Pure function, no I/O.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_uri = RUN_NS + generated_at.replace("-", "").replace(":", "")

    blocks = [_METRIC_DEFINITIONS]
    n_records = 0
    for row in results:
        triples = _record_triples(row, graph_uri, run_uri, generated_at)
        if triples:
            blocks.append(triples)
            n_records += 1

    run_lines = [
        f"<{run_uri}> a edenval:ValidationRun, prov:Activity",
        f'    prov:endedAtTime "{generated_at}"^^xsd:dateTime',
        f"    edenval:resultCount {n_records}",
    ]
    if run_id:
        run_lines.append(f'    edenval:harvestRunId "{escape_literal(run_id)}"')
    blocks.append(" ;\n".join(run_lines) + " .")

    update = (
        _PROLOGUE
        + f"DROP SILENT GRAPH <{graph_uri}> ;\n"
        + f"INSERT DATA {{ GRAPH <{graph_uri}> {{\n"
        + "\n".join(blocks)
        + "\n} }"
    )
    return update, n_records


class FusekiWriter:
    """POSTs validation results to a Fuseki SPARQL Update endpoint."""

    DEFAULT_ENDPOINT = "http://localhost:3030/service_registry_store/update"

    def __init__(self, update_endpoint: str = DEFAULT_ENDPOINT,
                 graph_uri: str = DEFAULT_GRAPH, timeout: int = 60):
        self.update_endpoint = update_endpoint
        self.graph_uri = graph_uri
        self.timeout = timeout

        # Same env-based Basic Auth convention as FusekiLoader: both vars
        # required, silent no-auth fallback for open Fuseki instances.
        username = os.environ.get("FUSEKI_USERNAME", "").strip()
        password = os.environ.get("FUSEKI_PASSWORD", "").strip()
        self._auth = (username, password) if username and password else None
