"""
fuseki_loader.py — EDEN Service Validator
==========================================
Queries a Fuseki/SPARQL endpoint for harvested, harmonized service metadata
and returns a list of service records ready for validation.

The loader restricts queries to harmonized graphs
(graphs whose URI contains "eden://harvester/harmonized/") to avoid
duplicates from the individual raw harvester passes.
"""

import csv
import logging
import os
from typing import Optional

import requests

logger = logging.getLogger("FusekiLoader")

# ---------------------------------------------------------------------------
# SPARQL query — fixed for Fuseki-compatible graph variable filtering.
#
# Key findings from diagnostic (explore_fuseki_graphs.py):
#   1. FILTER on ?g must be OUTSIDE the GRAPH {} block in Fuseki.
#      Inside the block, the filter on a graph variable is silently ignored.
#   2. Services are top-level named URIs in harmonized graphs (not linked via
#      dcat:service from the catalog). Query directly for dcat:DataService.
#   3. The dcat:Catalog node is a blank node with no dct:title, so repoTitle
#      will always be unbound — kept as OPTIONAL for forward-compatibility.
_SPARQL_QUERY = """
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX dcat: <http://www.w3.org/ns/dcat#>
PREFIX dct:  <http://purl.org/dc/terms/>
PREFIX foaf: <http://xmlns.com/foaf/0.1/>

SELECT DISTINCT ?service ?endpointURL ?conformsTo ?serviceTitle ?repoTitle
WHERE {
  GRAPH ?g {
    ?service rdf:type dcat:DataService ;
             dcat:endpointURL ?endpointURL .
    OPTIONAL { ?service dct:conformsTo ?conformsTo }
    OPTIONAL { ?service dct:title ?serviceTitle }
    OPTIONAL {
      ?catalog rdf:type dcat:Catalog ;
               dct:title ?repoTitle .
    }
  }
  FILTER(CONTAINS(STR(?g), "eden://harvester/harmonized/"))
}
"""


class FusekiLoader:
    """
    Queries a Fuseki SPARQL endpoint for harvested service metadata
    from harmonized graphs and returns a clean list of service records.
    """

    DEFAULT_ENDPOINT = "http://localhost:3030/service_registry_store/query"

    def __init__(self, endpoint_url: str = DEFAULT_ENDPOINT, timeout: int = 30):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

        # Read credentials from environment — set FUSEKI_USERNAME and FUSEKI_PASSWORD.
        # Both must be present for auth to be used; if either is missing the loader
        # continues without auth (works for open/public Fuseki instances).
        username = os.environ.get("FUSEKI_USERNAME", "").strip()
        password = os.environ.get("FUSEKI_PASSWORD", "").strip()
        if username and password:
            self._auth = (username, password)
            logger.info("Fuseki Basic Auth configured from environment variables.")
        else:
            self._auth = None
            logger.debug(
                "FUSEKI_USERNAME / FUSEKI_PASSWORD not set — connecting without auth."
            )

    def query(self) -> list:
        """
        Execute the SPARQL query and return a de-duplicated list of service records.

        Returns:
            List of dicts with keys:
                service_uri   (str|None)  – URI of the dcat:DataService node (for write-back)
                endpoint_url  (str)       – the URL to validate
                conforms_to   (str|None)  – dct:conformsTo value if present
                service_title (str|None)  – dct:title of the service if present
                repo_title    (str|None)  – dct:title of the parent catalog if present

        Raises:
            requests.RequestException  – if the Fuseki endpoint cannot be reached
            ValueError                 – if the SPARQL response cannot be parsed
        """
        logger.info(
            f"Querying Fuseki at {self.endpoint_url} for harmonized service records..."
        )
        try:
            response = requests.post(
                self.endpoint_url,
                data={"query": _SPARQL_QUERY},
                headers={"Accept": "application/sparql-results+json"},
                auth=self._auth,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to connect to Fuseki at {self.endpoint_url}: {e}")
            raise

        try:
            data = response.json()
        except ValueError as e:
            logger.error(f"Failed to parse SPARQL JSON response: {e}")
            raise

        records = []
        seen: set = set()
        bindings = data.get("results", {}).get("bindings", [])
        logger.info(f"SPARQL returned {len(bindings)} raw bindings.")

        for binding in bindings:
            endpoint_url = binding.get("endpointURL", {}).get("value", "").strip()
            if not endpoint_url:
                logger.debug("Skipping binding with empty endpointURL.")
                continue

            service_uri = (
                binding.get("service", {}).get("value", "").strip() or None
            )
            conforms_to = (
                binding.get("conformsTo", {}).get("value", "").strip() or None
            )
            service_title = (
                binding.get("serviceTitle", {}).get("value", "").strip() or None
            )
            repo_title = (
                binding.get("repoTitle", {}).get("value", "").strip() or None
            )

            # De-duplicate on (service_uri, endpoint_url, conforms_to): SELECT DISTINCT
            # handles this against a live Fuseki, but mocked / replayed responses may
            # return duplicate bindings that we must filter here too. The service URI is
            # part of the key: the same endpoint under two distinct service nodes must
            # yield two records, so write-back can annotate each node.
            dedup_key = (service_uri, endpoint_url, conforms_to)
            if dedup_key in seen:
                logger.debug(
                    "Skipping duplicate binding: endpoint=%s conforms_to=%s",
                    endpoint_url, conforms_to,
                )
                continue
            seen.add(dedup_key)

            records.append(
                {
                    "service_uri": service_uri,
                    "endpoint_url": endpoint_url,
                    "conforms_to": conforms_to,
                    "service_title": service_title,
                    "repo_title": repo_title,
                }
            )

        logger.info(f"Returning {len(records)} unique service records.")
        return records

    @staticmethod
    def write_mismatch_report(mismatches: list, output_path: str) -> None:
        """
        Write a CSV report of conformsTo URLs that could not be resolved to
        any known service profile.  Use this file for manual review and
        to decide which profiles need updating.

        Args:
            mismatches:  List of dicts with keys:
                           conformsTo_url, service_title, endpoint_url, repo_title
            output_path: File path for the output CSV.
        """
        if not mismatches:
            logger.info(
                "No conformsTo mismatches to report — all URLs resolved successfully."
            )
            return

        fieldnames = [
            "conformsTo_url",       # URL harvested from the RDF store
            "profile_spec_urls",    # spec_urls from the closest candidate profile (for comparison)
            "candidate_profile_type",  # profile type matched by serviceTitle (if any)
            "service_title",
            "endpoint_url",
            "repo_title",
        ]
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writeheader()
                writer.writerows(mismatches)
            logger.info(
                f"Mismatch report written → '{output_path}' "
                f"({len(mismatches)} unresolved conformsTo URL(s))."
            )
        except IOError as e:
            logger.error(f"Failed to write mismatch report to '{output_path}': {e}")
