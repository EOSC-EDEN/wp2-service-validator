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

            # Validate the URL (auto-detection only)
            result = validator.validate_url(url)

            detected_type = result.get('detected_api_type', 'N/A')
            detection_method = result.get('detection_method', 'N/A')

            if detected_type != 'N/A':
                logging.info(f"  ✓ DETECTED: '{detected_type}' (Method: {detection_method})")
            else:
                logging.info(f"  ℹ️  No API type detected")

            # Check for specific cases to report in the CSV
            is_doc_page = 'likely an API documentation page' in result.get('note', '')
            
            # Format the redirect chain for clear output
            redirect_chain_list = result.get('redirects', [])
            had_redirect = bool(redirect_chain_list)
            # Use 'to_url' which is the correct key from Validator.py
            redirect_chain_str = " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list])

            # Check if the URL was modified by the validator
            constructed_url = result.get('url', url)
            was_constructed = constructed_url != url

            # Combine original row data with validation results
            output_row = row.copy()
            output_row.update({
                'is_valid': result.get('valid'),
                'status_code': result.get('status_code', 'N/A'),
                'constructed_url': constructed_url if was_constructed else '',
                'final_url': result.get('final_url', constructed_url),
                'error_details': result.get('error', ''),
                'detected_api_type': detected_type,
                'detection_method': detection_method,
                'auth_required': result.get('auth_required', 'No'),
                'is_doc_page': is_doc_page,
                'had_redirect': had_redirect,
                'redirect_chain': redirect_chain_str
            })
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
        'detected_api_type',
        'detection_method',
        'auth_required',
        'is_doc_page',
        'had_redirect',
        'redirect_chain'
    ]
    
    # Use the ordered list, but ensure any unexpected keys are also included at the end
    all_keys = set(k for r in results for k in r.keys())
    final_fieldnames = ordered_fieldnames + sorted(list(all_keys - set(ordered_fieldnames)))


    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=final_fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Validation complete. Results saved to '{OUTPUT_CSV}'.")
    except IOError as e:
        logging.error(f"Failed to write to output file: {e}")


if __name__ == "__main__":
    run_batch_validation()
