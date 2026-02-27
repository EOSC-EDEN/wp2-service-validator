import argparse
import csv
import os
from Validator import ServiceValidator
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def run_batch_validation():
    """Reads service endpoints from a CSV file, validates them, and writes the results to a new CSV.
    """
    parser = argparse.ArgumentParser(description="Run batch validation on a CSV of service endpoints.")
    parser.add_argument("--input", default='repository services.csv', help="Path to the input CSV file.")
    parser.add_argument("--output", default='validation_results.csv', help="Path to the output CSV file.")
    args = parser.parse_args()

    input_csv = args.input
    output_csv = args.output

    if not os.path.exists(input_csv):
        logging.error(f"Input file not found: {input_csv}")
        return

    validator = ServiceValidator()
    available_types = list(validator.protocol_configs.keys())
    
    results = []
    total_rows = 0

    logging.info(f"Starting batch validation for services in '{input_csv}'...")
    logging.info(f"Loaded {len(available_types)} service type definition(s).")

    # Detect delimiter based on the first line
    with open(input_csv, mode='r', encoding='utf-8') as infile:
        first_line = infile.readline()
        delimiter = ';' if ';' in first_line else ','
        infile.seek(0)
        
        reader = csv.DictReader(infile, delimiter=delimiter)
        fieldnames = reader.fieldnames

        # Count total rows for progress indication
        # We need to re-open or seek, but since we are iterating reader above, let's just read all rows into list first?
        # Or just re-open for counting.
        pass

    # Re-open to process
    with open(input_csv, mode='r', encoding='utf-8') as infile:
        # Count lines first
        total_rows = sum(1 for _ in infile) - 1
        infile.seek(0)
        
        reader = csv.DictReader(infile, delimiter=delimiter)
        
        for i, row in enumerate(reader):
            url = row.get('endpoint')
            
            # Strict Validation Logic
            service_title = row.get('serviceTitle', '')
            # Use the shared static method for mapping
            expected_type = ServiceValidator.map_service_type(service_title, available_types)

            if not url:
                logging.warning(f"Row {i + 1}: No URL found. Skipping.")
                continue

            msg = f"[{i + 1}/{total_rows}] Validating: {url} (Strict: {expected_type})"
            logging.info(msg)

            if not expected_type:
                 # Strict Mode Enforcement: Cannot proceed without a known type
                logging.warning(f"Row {i + 1}: Skipping '{url}' - Unknown Service Type for '{service_title}'")
                output_row = row.copy()
                output_row.update({
                    "valid": False, 
                    "error": f"Unknown/Unmapped Service Title: '{service_title}'",
                    "mapped_service_type": "N/A"
                })
                # Add empty placeholders for other fields to match CSV structure?
                # Actually, validate_url returns a structure. Let's call it and let it error?
                # The validator now returns an error dict if expected_type is None.
                # So we can just call it with None and let it handle the error return.
                pass 

            # The validator now returns a complete, final dictionary.
            # If expected_type is None, it will return the "Strict Mode Required" error.
            result = validator.validate_url(url, expected_type=expected_type)

            # Combine original row data with the complete validation result
            output_row = row.copy()
            output_row.update(result)
            output_row['mapped_service_type'] = expected_type if expected_type else 'N/A' # Record what we tried
            results.append(output_row)

    # --- Write results to output file ---
    if not results:
        logging.info("No data to write.")
        return

    # Define the desired order, including the original fieldnames
    # These keys MUST match the keys produced by Validator.py
    base_fieldnames = fieldnames if fieldnames else []
    ordered_fieldnames = base_fieldnames + [
        'valid',
        'status_code',
        'mapped_service_type', # Added this
        'content_type',
        'expected_content_type',
        'constructed_url',
        'redirected_url',
        'error',
        'note',
        'failed_url',
        'auth_required',
        'is_doc_page',
        'had_redirect',
        'redirect_chain'
    ]
    
    # Use the ordered list, but ensure any unexpected keys from the validator are also included
    all_keys = set(k for r in results for k in r.keys())
    # We remove 'redirects' as it's not CSV-friendly
    all_keys.discard('redirects')

    final_fieldnames = ordered_fieldnames + sorted(list(all_keys - set(ordered_fieldnames)))

    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_csv)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(output_csv, mode='w', newline='', encoding='utf-8') as outfile:
            # Use extrasaction='ignore' to avoid errors if a row is missing a key from another row
            writer = csv.DictWriter(outfile, fieldnames=final_fieldnames, extrasaction='ignore', delimiter=delimiter)
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Validation complete. Results saved to '{output_csv}'.")
    except IOError as e:
        logging.error(f"Failed to write to output file: {e}")


if __name__ == "__main__":
    run_batch_validation()
