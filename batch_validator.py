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

            # Validate the URL (auto-detection only, no user-provided type)
            result = validator.validate_url(url)

            # Extract detected type
            detected_type = result.get('detected_api_type', 'N/A')

            if detected_type != 'N/A':
                logging.info(f"  ✓ DETECTED: '{detected_type}'")
            else:
                logging.info(f"  ℹ️  No API type detected")

            # Combine original row data with validation results
            output_row = row.copy()
            output_row.update({
                'is_valid': result.get('valid'),
                'status_code': result.get('status_code', 'N/A'),
                'final_url': result.get('final_url', url),
                'error_details': result.get('error', ''),
                'detected_api_type': detected_type,
                'auth_required': result.get('auth_required', 'No')
            })
            results.append(output_row)

    # --- Write results to output file ---
    if not results:
        logging.info("No data to write.")
        return

    output_fieldnames = fieldnames + [
        'is_valid',
        'status_code',
        'final_url',
        'error_details',
        'detected_api_type',
        'auth_required'
    ]

    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=output_fieldnames)
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Validation complete. Results saved to '{OUTPUT_CSV}'.")
    except IOError as e:
        logging.error(f"Failed to write to output file: {e}")


if __name__ == "__main__":
    run_batch_validation()
