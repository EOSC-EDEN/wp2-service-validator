import argparse
import csv
import logging
import os

import requests

from dotenv import load_dotenv
load_dotenv()

from eden_validator.validator import ServiceValidator
from eden_validator.fuseki_loader import FusekiLoader
from eden_validator.fuseki_writer import FusekiWriter, derive_update_endpoint
from eden_validator.batch import validate_records
from controllers._console import enable_utf8_console

enable_utf8_console()  # before basicConfig, so the log StreamHandler uses UTF-8 stderr
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def _load_from_csv(input_csv: str):
    """Legacy CSV loader kept for backward compatibility (--input flag)."""
    rows = []
    with open(input_csv, mode='r', encoding='utf-8') as infile:
        first_line = infile.readline()
        delimiter = ';' if ';' in first_line else ','
        infile.seek(0)
        reader = csv.DictReader(infile, delimiter=delimiter)
        for row in reader:
            rows.append({
                'service_uri': None,
                'endpoint_url': row.get('endpoint', '').strip(),
                'conforms_to': None,
                'service_title': row.get('serviceTitle', '').strip() or None,
                'repo_title': row.get('repoTitle', '').strip() or None,
                '_original_row': row,  # keep for output column passthrough
            })
    return rows, delimiter


def run_batch_validation():
    """
    Validates service endpoints from either:
      - A Fuseki/SPARQL store (default, uses harmonized graphs)
      - A legacy CSV file (--input flag, backward-compatible)

    Results are written to a CSV file. A separate `conformsTo_mismatches.csv`
    is produced for any conformsTo URLs that could not be resolved to a profile.

    When neither conformsTo nor serviceTitle can resolve the service type, the validator
    calls the wp2-service-identifier API to infer the type automatically. Records
    resolved this way are flagged with resolution_method='identifier' and inferred_type=True.
    If the identifier is unavailable, that record is recorded as an error (the batch continues).
    """
    parser = argparse.ArgumentParser(
        description="Run batch validation on service endpoints from Fuseki or a CSV file."
    )
    parser.add_argument(
        '--input', default=None,
        help='Path to a legacy CSV input file. If provided, Fuseki is not queried.'
    )
    parser.add_argument(
        '--fuseki',
        default='http://localhost:3030/service_registry_store/query',
        help='SPARQL endpoint URL for the Fuseki store (default: %(default)s).'
    )
    parser.add_argument(
        '--output', default='output/validation_results.csv',
        help='Path for the validation results CSV (default: %(default)s).'
    )
    parser.add_argument(
        '--mismatches', default='output/conformsTo_mismatches.csv',
        help='Path for the conformsTo mismatch report CSV (default: %(default)s).'
    )
    parser.add_argument(
        '--no-identifier', action='store_true',
        help='Disable automatic type inference via the wp2-service-identifier. '
             'Records with no resolvable type will be recorded as errors.'
    )
    parser.add_argument(
        '--force-identifier', action='store_true',
        help='Skip conformsTo and serviceTitle resolution; use the wp2-service-identifier '
             'for every record. Useful for evaluating identifier accuracy against Fuseki data.'
    )
    parser.add_argument(
        '--write-back', action='store_true',
        help='Write validation results back into Fuseki as DQV RDF '
             '(replaces graph eden://validator/results/). Fuseki mode only.'
    )
    parser.add_argument(
        '--fuseki-update', default=None,
        help='SPARQL Update endpoint for --write-back. '
             'Default: derived from --fuseki by replacing /query with /update.'
    )
    parser.add_argument(
        '--run-id', default=None,
        help='Optional harvest-run identifier stored with written results '
             'for provenance (edenval:harvestRunId).'
    )
    args = parser.parse_args()

    if args.write_back and args.input:
        parser.error('--write-back requires Fuseki mode and cannot be combined '
                     'with --input (CSV rows carry no service node URI).')

    if args.force_identifier:
        base, ext = os.path.splitext(args.output)
        args.output = f"{base}_forced-identifier{ext or '.csv'}"

    validator = ServiceValidator()
    available_types = list(validator.protocol_configs.keys())
    delimiter = ','

    # ------------------------------------------------------------------
    # Load service records
    # ------------------------------------------------------------------
    if args.input:
        if not os.path.exists(args.input):
            logging.error(f"Input file not found: {args.input}")
            return
        logging.info(f"Loading service records from CSV: {args.input}")
        raw_records, delimiter = _load_from_csv(args.input)
    else:
        logging.info(f"Loading service records from Fuseki: {args.fuseki}")
        loader = FusekiLoader(endpoint_url=args.fuseki)
        try:
            fuseki_records = loader.query()
        except Exception as e:
            logging.error(f"Failed to load records from Fuseki: {e}")
            return
        raw_records = [
            {**r, '_original_row': {'repoTitle': r['repo_title'], 'serviceTitle': r['service_title']}}
            for r in fuseki_records
        ]

    logging.info(f"Loaded {len(raw_records)} service record(s) to validate.")
    logging.info(f"Loaded {len(available_types)} service type definition(s).")

    results, mismatches = validate_records(
        raw_records, validator,
        force_identifier=args.force_identifier,
        use_identifier=not args.no_identifier,
    )

    # ------------------------------------------------------------------
    # Write mismatch report
    # ------------------------------------------------------------------
    FusekiLoader.write_mismatch_report(mismatches, args.mismatches)

    # ------------------------------------------------------------------
    # Write validation results CSV
    # ------------------------------------------------------------------
    if not results:
        logging.info("No results to write.")
        return

    ordered_fieldnames = [
        'repoTitle',
        'serviceUri',
        'serviceTitle',
        'endpoint',
        'conforms_to',
        'extracted_conforms_to',
        'conforms_to_verified',
        'mapped_service_type',
        'resolution_method',
        'inferred_type',
        'valid',
        'score',
        'status_code',
        'content_type',
        'expected_content_type',
        'auth_required',
        'constructed_url',
        'redirected_url',
        'had_redirect',
        'redirect_chain',
        'is_doc_page',
        'error',
        'note',
    ]

    all_keys = set(k for r in results for k in r)
    all_keys.discard('redirects')  # not CSV-friendly
    final_fieldnames = ordered_fieldnames + sorted(list(all_keys - set(ordered_fieldnames)))

    try:
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(args.output, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(
                outfile, fieldnames=final_fieldnames,
                extrasaction='ignore', delimiter=delimiter
            )
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Validation complete. Results saved to '{args.output}'.")
    except IOError as e:
        logging.error(f"Failed to write results to '{args.output}': {e}")

    # ------------------------------------------------------------------
    # Optional write-back into Fuseki (CSV outputs above stay the source
    # of truth; a write-back failure must not fail the batch run)
    # ------------------------------------------------------------------
    if args.write_back:
        update_endpoint = args.fuseki_update or derive_update_endpoint(args.fuseki)
        writer_client = FusekiWriter(update_endpoint=update_endpoint)
        try:
            written = writer_client.write_results(results, run_id=args.run_id)
            logging.info(
                f"Write-back: {written} result(s) written to "
                f"graph <{writer_client.graph_uri}> at {update_endpoint}."
            )
        except requests.RequestException as e:
            logging.error(
                f"Write-back to Fuseki failed — CSV outputs are unaffected: {e}"
            )


if __name__ == "__main__":
    run_batch_validation()
