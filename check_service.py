import argparse
import json
from Validator import ServiceValidator

def main():
    parser = argparse.ArgumentParser(description="Check a single service endpoint.")
    parser.add_argument("--url", help="The URL to validate")

    args = parser.parse_args()
    
    url = args.url

    # If no URL via CLI, ask interactively
    if not url:
        print("--- Manual Service Check ---")
        url = input("Enter Service URL: ").strip()
        if not url:
            print("Error: URL is required.")
            return

    print(f"\nValidating: {url} (Auto-Detection only)...\n")

    validator = ServiceValidator()
    # The validator returns a complete dictionary with all data points
    result = validator.validate_url(url)

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
    print(f"ℹ️  Auto-Detected API Type: {detected_type} (Method: {detection_method})")

    print(json.dumps(console_result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
