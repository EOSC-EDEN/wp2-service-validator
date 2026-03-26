import argparse
import json

from dotenv import load_dotenv
load_dotenv()

from Validator import ServiceValidator
from type_resolver import resolve_type

def main():
    parser = argparse.ArgumentParser(description="Check a single service endpoint.")
    parser.add_argument("--url", help="The URL to validate")
    parser.add_argument("--type", required=False, help="The expected Service Type (Acronym) for strict validation (e.g., 'OAI-PMH'). If omitted, the identifier is queried automatically.")
    parser.add_argument("--conforms-to", dest="conforms_to", default=None, help="Optional dct:conformsTo URL (used for scoring, should match the harvested RDF value)")

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

    # If no type via CLI, try the identifier before asking the user manually.
    # In 'cli' mode, resolve_type will prompt the user interactively when confidence
    # is below the threshold, so the user always has the final say.
    type_inferred = False
    if not expected_type:
        try:
            expected_type, type_inferred = resolve_type(url, mode='cli')
            if expected_type is None:
                print(
                    "Error: The identifier could not suggest a service type for this URL. "
                    "Re-run with --type to supply one manually."
                )
                return
        except RuntimeError as e:
            print(f"Error: {e}")
            return

    validator = ServiceValidator()

    # Attempt to map the user's input (e.g., "SWORD API") to a known Acronym (e.g., "SWORD").
    # If no mapping is found, validate_url will return an "Unknown Service Type" error.
    available_types = list(validator.protocol_configs.keys())
    # Keep the original input as service_title for scoring (mirrors API behaviour).
    # If the type was inferred (not typed by the user), service_title is left None so
    # the title-match scoring criterion is not artificially awarded.
    service_title = expected_type if not type_inferred else None
    mapped_type = ServiceValidator.map_service_type(expected_type, available_types)
    if mapped_type:
        if mapped_type != expected_type:
            print(f"ℹ️  Mapped input '{expected_type}' to '{mapped_type}'")
        expected_type = mapped_type

    # Optionally ask for conforms_to — used for scoring.
    if not args.url:  # only prompt interactively when not using CLI flags
        conforms_to_input = input("Enter dct:conformsTo URL (optional, press Enter to skip): ").strip()
        conforms_to = conforms_to_input if conforms_to_input else None
    else:
        conforms_to = args.conforms_to

    inferred_label = " [inferred by identifier]" if type_inferred else ""
    print(f"\nValidating: {url} (Strict Type: {expected_type}{inferred_label})...\n")

    # The validator returns a complete dictionary with all data points
    result = validator.validate_url(url, expected_type=expected_type,
                                    conforms_to=conforms_to, service_title=service_title)

    # --- Prepare for Console Output ---
    # Remove 'redirect_chain' (the flat string): the structured 'redirects' list
    # is already present and more informative for JSON output.
    console_result = result.copy()
    console_result.pop('redirect_chain', None)

    if type_inferred:
        console_result['inferred_type'] = True
        console_result['inferred_service_type'] = expected_type

    print("-" * 30)
    print("VALIDATION RESULT:")
    print(f"ℹ️  Service Type: {expected_type}")

    print(json.dumps(console_result, indent=4))
    print("-" * 30)

if __name__ == "__main__":
    main()
