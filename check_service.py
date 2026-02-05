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

    # --- Enrich result to match batch_validator output ---
    
    # 1. Detection Info
    detected_type = result.get('detected_api_type', 'N/A')
    detection_method = result.get('detection_method', 'N/A')

    # 2. Documentation Page Flag
    is_doc_page = 'likely an API documentation page' in result.get('note', '')
    result['is_doc_page'] = is_doc_page

    # 3. Redirect Info
    redirect_chain_list = result.get('redirects', [])
    had_redirect = bool(redirect_chain_list)
    
    result['had_redirect'] = had_redirect
    # Note: We do NOT add 'redirect_chain' string here, as the JSON 'redirects' list is sufficient and cleaner for console output.

    # 4. URL Construction Info
    constructed_url = result.get('url', url)
    was_constructed = constructed_url != url
    
    # Add explicit fields for clarity
    result['constructed_url'] = constructed_url if was_constructed else ""
    result['final_url'] = result.get('final_url', constructed_url)
    
    # Ensure auth_required is present (it comes from validator, but good to be explicit)
    if 'auth_required' not in result:
        result['auth_required'] = 'No'


    print("-" * 30)
    print("VALIDATION RESULT:")
    
    # Highlight the detected type
    print(f"ℹ️  Auto-Detected API Type: {detected_type} (Method: {detection_method})")

    print(json.dumps(result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
