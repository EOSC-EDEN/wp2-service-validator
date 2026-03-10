import argparse
import csv
import logging
import os

from Validator import ServiceValidator
from fuseki_loader import FusekiLoader

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
        '--output', default='validation_results.csv',
        help='Path for the validation results CSV (default: %(default)s).'
    )
    parser.add_argument(
        '--mismatches', default='conformsTo_mismatches.csv',
        help='Path for the conformsTo mismatch report CSV (default: %(default)s).'
    )
    args = parser.parse_args()

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

    results = []
    mismatches = []  # conformsTo URLs that couldn't be resolved

    for i, record in enumerate(raw_records):
        endpoint_url = record.get('endpoint_url', '').strip()
        conforms_to = record.get('conforms_to')
        service_title = record.get('service_title')
        repo_title = record.get('repo_title')
        original_row = record.get('_original_row', {})

        if not endpoint_url:
            logging.warning(f"Record {i + 1}: No endpoint URL. Skipping.")
            continue

        # ------------------------------------------------------------------
        # Type resolution: conformsTo first, then serviceTitle fallback
        # ------------------------------------------------------------------
        expected_type = None
        resolution_method = 'none'

        if conforms_to:
            expected_type = ServiceValidator.resolve_type_from_conforms_to(
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
                    ServiceValidator.map_service_type(service_title, available_types)
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

        if not expected_type and service_title:
            expected_type = ServiceValidator.map_service_type(service_title, available_types)
            if expected_type:
                resolution_method = 'service_title'

        if not expected_type:
            logging.warning(
                f"[{i + 1}/{len(raw_records)}] Could not resolve type for "
                f"'{service_title}' / conformsTo='{conforms_to}' — will record as error."
            )
        else:
            logging.info(
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
            'serviceTitle': service_title or '',
            'endpoint': endpoint_url,
            'conforms_to': conforms_to or '',
            'extracted_conforms_to': result.get('extracted_conforms_to', ''),
            'conforms_to_verified': result.get('conforms_to_verified', ''),
            'mapped_service_type': expected_type or 'N/A',
            'resolution_method': resolution_method,
        }
        # Add any extra fields from the original row (CSV mode passthrough)
        for k, v in original_row.items():
            if k not in output_row:
                output_row[k] = v
        # Overlay the validation result (overwrites nothing already keyed above)
        output_row.update(result)
        results.append(output_row)

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
        'serviceTitle',
        'endpoint',
        'conforms_to',
        'extracted_conforms_to',
        'conforms_to_verified',
        'mapped_service_type',
        'resolution_method',
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

    all_keys = set(k for r in results for k in r.keys())
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


if __name__ == "__main__":
    run_batch_validation()
