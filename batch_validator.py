import csv
import os
from Validator import ServiceValidator
import logging

# --- Configuration ---
INPUT_CSV = 'repository services.csv'
OUTPUT_CSV = 'validation_results.csv'
# -------------------

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def run_batch_validation():
    """Reads service endpoints from a CSV file, validates them, and writes the results to a new CSV.
    """
    if not os.path.exists(INPUT_CSV):
        logging.error(f"Input file not found: {INPUT_CSV}")
        return

    validator = ServiceValidator()
    results = []
    total_rows = 0

    logging.info(f"Starting batch validation for services in '{INPUT_CSV}'...")

    with open(INPUT_CSV, mode='r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames

        # Count total rows for progress indication
        with open(INPUT_CSV, mode='r', encoding='utf-8') as f:
            total_rows = sum(1 for row in f) - 1  # Subtract header

        for i, row in enumerate(reader):
            url = row.get('endpoint')

            if not url:
                logging.warning(f"Row {i + 1}: No URL found. Skipping.")
                continue

            logging.info(f"[{i + 1}/{total_rows}] Validating: {url}")

            # The validator returns a complete dictionary with all data points
            result = validator.validate_url(url)

            # --- Prepare for CSV Output ---
            # For CSV output, the flattened 'redirect_chain' string is better than the nested list.
            # We can remove the 'redirects' list to avoid potential issues with the CSV writer.
            csv_row = result.copy()
            csv_row.pop('redirects', None)

            # Combine original row data with the prepared validation result
            output_row = row.copy()
            output_row.update(csv_row)
            results.append(output_row)

    # --- Write results to output file ---
    if not results:
        logging.info("No data to write.")
        return

    # Define the desired order, including the original fieldnames
    ordered_fieldnames = fieldnames + [
        'is_valid',
        'status_code',
        'constructed_url',
        'final_url',
        'error_details',
        'note',
        'detected_api_type',
        'detection_method',
        'auth_required',
        'is_doc_page',
        'had_redirect',
        'redirect_chain'
    ]
    
    # Use the ordered list, but ensure any unexpected keys from the validator are also included
    all_keys = set(k for r in results for k in r.keys())
    final_fieldnames = ordered_fieldnames + sorted(list(all_keys - set(ordered_fieldnames)))


    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as outfile:
            # Use extrasaction='ignore' to avoid errors if a row is missing a key from another row
            writer = csv.DictWriter(outfile, fieldnames=final_fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Validation complete. Results saved to '{OUTPUT_CSV}'.")
    except IOError as e:
        logging.error(f"Failed to write to output file: {e}")


if __name__ == "__main__":
    run_batch_validation()
