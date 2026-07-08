"""
batch.py — EDEN Service Validator
=================================
Batch-validation pipeline, shared by the two entry points:

- controllers/batch_validator.py (standalone CLI, this repo only):
  CSV outputs by default, Fuseki write-back opt-in (--write-back).
- run_batch() (library API, ships in the pip package): the harvester's
  post-harvest call. Fuseki write-back by default, no CSV — the caller
  gets the result rows back. (Added in a later task.)

validate_records() takes loaded records, resolves each record's service
type (conformsTo → serviceTitle → wp2-service-identifier), validates the
endpoint, and returns result rows plus a conformsTo-mismatch list. Where
those rows go — CSV, Fuseki, or the caller — is the entry point's business.
"""

import logging

from eden_validator.type_resolver import resolve_type
from eden_validator.validator import ServiceValidator
from eden_validator.fuseki_loader import FusekiLoader
from eden_validator.fuseki_writer import FusekiWriter, derive_update_endpoint

logger = logging.getLogger("BatchPipeline")

DEFAULT_QUERY_ENDPOINT = "http://localhost:3030/service_registry_store/query"


def validate_records(raw_records, validator, *, force_identifier=False,
                     use_identifier=True):
    """
    Resolve the service type of each record and validate its endpoint.

    Args:
        raw_records:      Record dicts as produced by FusekiLoader.query()
                          (keys: service_uri, endpoint_url, conforms_to,
                          service_title, repo_title) or the CLI's legacy
                          CSV loader (extra key '_original_row' for output
                          column passthrough).
        validator:        A ServiceValidator instance.
        force_identifier: Skip conformsTo/serviceTitle resolution; use the
                          wp2-service-identifier for every record.
        use_identifier:   Allow the wp2-service-identifier fallback.

    Returns:
        (results, mismatches) — results are output-row dicts (one per
        record with a non-empty endpoint URL); mismatches list conformsTo
        URLs that could not be resolved to a profile.
    """
    available_types = list(validator.protocol_configs.keys())
    results = []
    mismatches = []  # conformsTo URLs that couldn't be resolved

    for i, record in enumerate(raw_records):
        endpoint_url = (record.get('endpoint_url') or '').strip()
        conforms_to = record.get('conforms_to')
        service_title = record.get('service_title')
        repo_title = record.get('repo_title')
        original_row = record.get('_original_row', {})

        if not endpoint_url:
            logger.warning(f"Record {i + 1}: No endpoint URL. Skipping.")
            continue

        # ------------------------------------------------------------------
        # Type resolution: conformsTo → serviceTitle → identifier (fallback)
        # ------------------------------------------------------------------
        expected_type = None
        resolution_method = 'none'
        type_inferred = False

        if not force_identifier and conforms_to:
            expected_type = validator.resolve_type_from_conforms_to(
                conforms_to, validator.spec_url_index
            )
            if expected_type:
                resolution_method = 'conforms_to'
            else:
                # Record for mismatch report.
                # Also try a title-based match to find the closest candidate profile,
                # so the CSV shows the harvested conformsTo URL side-by-side with
                # what that profile's spec_urls actually look like — making manual
                # review much easier.
                candidate_type = (
                    validator.map_service_type(service_title, available_types)
                    if service_title else None
                )
                candidate_spec_urls = ''
                if candidate_type:
                    cprofile = validator.protocol_configs.get(candidate_type, {})
                    candidate_spec_urls = ' | '.join(
                        e.get('url', '') for e in cprofile.get('spec_urls', []) if e.get('url')
                    )
                mismatches.append({
                    'conformsTo_url': conforms_to,
                    'service_title': service_title or '',
                    'endpoint_url': endpoint_url,
                    'repo_title': repo_title or '',
                    'candidate_profile_type': candidate_type or '',
                    'profile_spec_urls': candidate_spec_urls,
                })

        if not force_identifier and not expected_type and service_title:
            expected_type = validator.map_service_type(service_title, available_types)
            if expected_type:
                resolution_method = 'service_title'

        # Third fallback (or first when force_identifier): wp2-service-identifier
        if not expected_type and use_identifier:
            try:
                inferred, type_inferred = resolve_type(endpoint_url, mode='batch')
                if inferred:
                    expected_type = inferred
                    resolution_method = 'identifier'
                    logger.info(
                        f"[{i + 1}/{len(raw_records)}] Type inferred by identifier: "
                        f"'{expected_type}' for {endpoint_url}"
                    )
            except RuntimeError as e:
                logger.warning(
                    f"[{i + 1}/{len(raw_records)}] Identifier unavailable for "
                    f"'{endpoint_url}': {e}"
                )

        if not expected_type:
            logger.warning(
                f"[{i + 1}/{len(raw_records)}] Could not resolve type for "
                f"'{service_title}' / conformsTo='{conforms_to}' — will record as error."
            )
        else:
            logger.info(
                f"[{i + 1}/{len(raw_records)}] Validating: {endpoint_url} "
                f"(type: {expected_type}, via: {resolution_method})"
            )

        # ------------------------------------------------------------------
        # Run validation — pass conforms_to and service_title for scoring
        # ------------------------------------------------------------------
        result = validator.validate_url(
            endpoint_url,
            expected_type=expected_type,
            conforms_to=conforms_to,
            service_title=service_title,
        )

        # Build output row: start with original metadata, overlay validation result
        output_row = {
            'repoTitle': repo_title or '',
            'serviceUri': record.get('service_uri') or '',
            'serviceTitle': service_title or '',
            'endpoint': endpoint_url,
            'conforms_to': conforms_to or '',
            'extracted_conforms_to': result.get('extracted_conforms_to', ''),
            'conforms_to_verified': result.get('conforms_to_verified', ''),
            'mapped_service_type': expected_type or 'N/A',
            'resolution_method': resolution_method,
            'inferred_type': type_inferred,
        }
        # Add any extra fields from the original row (CSV mode passthrough)
        for k, v in original_row.items():
            if k not in output_row:
                output_row[k] = v
        # Overlay the validation result (overwrites nothing already keyed above)
        output_row.update(result)
        results.append(output_row)

    return results, mismatches


def run_batch(fuseki_endpoint=DEFAULT_QUERY_ENDPOINT, *, write_back=True,
              fuseki_update_endpoint=None, run_id=None, profiles_path=None,
              use_identifier=True):
    """
    One-call batch validation for library consumers — the harvester's
    post-harvest Model B step. Loads service records from Fuseki, validates
    them, and — BY DEFAULT — writes the results back into the Fuseki results
    graph (eden://validator/results/). This is the write-back-by-default
    counterpart to the CSV-by-default standalone CLI, which the pip package
    does not ship.

    Args:
        fuseki_endpoint:        SPARQL query endpoint of the shared store.
        write_back:             Replace the results graph with this run's
                                results (default True; pass False to only
                                get the result rows back).
        fuseki_update_endpoint: SPARQL Update endpoint; default derived from
                                fuseki_endpoint (…/query → …/update).
        run_id:                 Optional harvest-run identifier stored for
                                provenance (edenval:harvestRunId).
        profiles_path:          Explicit service_profiles.json path (falls
                                back to the EDEN_SERVICE_PROFILES env var,
                                then the repo default).
        use_identifier:         Allow the wp2-service-identifier fallback
                                for records with no resolvable type.

    Returns:
        dict: {"validated": int, "written": int,
               "unresolved_conforms_to": int, "results": list}

    Raises:
        requests.RequestException – Fuseki unreachable (load) or the
            write-back rejected. Unlike the CLI, failures propagate: for
            this entry point the write-back IS the primary output, so the
            caller must see them.
    """
    validator = ServiceValidator(profiles_path=profiles_path)
    loader = FusekiLoader(endpoint_url=fuseki_endpoint)
    records = loader.query()
    logger.info(f"Loaded {len(records)} service record(s) from {fuseki_endpoint}.")

    results, mismatches = validate_records(
        records, validator, use_identifier=use_identifier
    )
    if mismatches:
        logger.info(
            f"{len(mismatches)} conformsTo URL(s) could not be resolved to a profile."
        )

    written = 0
    if write_back:
        update_endpoint = (
            fuseki_update_endpoint or derive_update_endpoint(fuseki_endpoint)
        )
        writer = FusekiWriter(update_endpoint=update_endpoint)
        written = writer.write_results(results, run_id=run_id)

    return {
        "validated": len(results),
        "written": written,
        "unresolved_conforms_to": len(mismatches),
        "results": results,
    }
