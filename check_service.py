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

    # If no type via CLI, ask interactively
    if not expected_type:
        expected_type = input("Enter expected Service Type (e.g., OAI-PMH): ").strip()
        if not expected_type:
             print("Error: Service Type is required for strict validation.")
             return

    validator = ServiceValidator()

    # Attempt to map the user's input (e.g., "SWORD API") to a known Acronym (e.g., "SWORD").
    # By this point expected_type is guaranteed non-empty (enforced above).
    # If no mapping is found, validate_url will return an "Unknown Service Type" error.
    available_types = list(validator.protocol_configs.keys())
    mapped_type = ServiceValidator.map_service_type(expected_type, available_types)
    if mapped_type:
        if mapped_type != expected_type:
            print(f"ℹ️  Mapped input '{expected_type}' to '{mapped_type}'")
        expected_type = mapped_type

    print(f"\nValidating: {url} (Strict Type: {expected_type})...\n")

    # The validator returns a complete dictionary with all data points
    result = validator.validate_url(url, expected_type=expected_type)

    # --- Prepare for Console Output ---
    # Remove 'redirect_chain' (the flat string): the structured 'redirects' list
    # is already present and more informative for JSON output.
    console_result = result.copy()
    console_result.pop('redirect_chain', None)

    print("-" * 30)
    print("VALIDATION RESULT:")
    print(f"ℹ️  Service Type: {expected_type}")

    print(json.dumps(console_result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
