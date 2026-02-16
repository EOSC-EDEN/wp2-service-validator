import argparse
import json
from Validator import ServiceValidator

def main():
    parser = argparse.ArgumentParser(description="Check a single service endpoint.")
    parser.add_argument("--url", help="The URL to validate")
    parser.add_argument("--type", required=False, help="The expected Service Type (Acronym) for strict validation (e.g., 'OAI-PMH')")

    args = parser.parse_args()
    
    url = args.url
    expected_type = args.type

    # If no URL via CLI, ask interactively
    if not url:
        print("--- Manual Service Check ---")
        url = input("Enter Service URL: ").strip()
        if not url:
            print("Error: URL is required.")
            return

    # If no type via CLI, ask interactively (Restored functionality)
    if not expected_type:
        expected_type = input("Enter expected Service Type (e.g., OAI-PMH): ").strip()
        if not expected_type:
             print("Error: Service Type is required for strict validation.")
             return

    validator = ServiceValidator()

    # Attempt to map the user input (e.g., "SWORD API") to a known type (e.g., "SWORD")
    if expected_type:
        available_types = list(validator.protocol_configs.keys())
        mapped_type = ServiceValidator.map_service_type(expected_type, available_types)
        
        if mapped_type:
             if mapped_type != expected_type:
                 print(f"ℹ️  Mapped input '{expected_type}' to '{mapped_type}'")
             expected_type = mapped_type
        # If no mapping found, we keep expected_type as is, 
        # and validate_url will likely return "Unknown Service Type" error, which is correct.

    print(f"\nValidating: {url} (Strict Type: {expected_type})...\n")

    # The validator returns a complete dictionary with all data points
    result = validator.validate_url(url, expected_type=expected_type)

    # --- Prepare for Console Output ---
    # For JSON output, the detailed 'redirects' list is better than the flattened string.
    # We can remove the redundant 'redirect_chain' for cleaner console output.
    console_result = result.copy()
    console_result.pop('redirect_chain', None)


    print("-" * 30)
    print("VALIDATION RESULT:")
    
    # Highlight the detected type from the final result
    # detected_type = result.get('detected_api_type', 'N/A')
    # detection_method = result.get('detection_method', 'N/A')
    print(f"ℹ️  Service Type: {expected_type}")

    print(json.dumps(console_result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
