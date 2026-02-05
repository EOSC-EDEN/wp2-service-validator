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
    # No api_type parameter - automatic detection only
    result = validator.validate_url(url)

    print("-" * 30)
    print("VALIDATION RESULT:")
    
    # Highlight the detected type
    detected_type = result.get('detected_api_type', 'N/A')
    print(f"ℹ️  Auto-Detected API Type: {detected_type}")

    print(json.dumps(result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
