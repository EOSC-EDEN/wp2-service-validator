import argparse
import json
from Validator import ServiceValidator

def main():
    parser = argparse.ArgumentParser(description="Check a single service endpoint.")
    parser.add_argument("--url", help="The URL to validate")
    parser.add_argument("--type", help="The expected Service Type (Acronym) for strict validation (e.g., 'OAI-PMH')")

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
            
    # If no type via CLI, optionally ask? 
    # For now, let's keep it optional. Use flags for strictness.
    # If user wants strict checking interactively, they should probably use flags or we could ask.
    # But adhering to the plan: just add the flag.

    if expected_type:
        print(f"\nValidating: {url} (Strict Type: {expected_type})...\n")
    else:
        print(f"\nValidating: {url} (Auto-Detection)...\n")

    validator = ServiceValidator()
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
    detected_type = result.get('detected_api_type', 'N/A')
    detection_method = result.get('detection_method', 'N/A')
    print(f"ℹ️  API Type: {detected_type} (Method: {detection_method})")

    print(json.dumps(console_result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
