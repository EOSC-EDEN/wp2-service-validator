# EDEN Service Validator

This tool validates repository service endpoints (e.g., OAI-PMH, OpenAPI, REST, SPARQL, OGC services) by checking their availability, compliance with expected content types, and matching them against known specifications.

It provides three modes of operation:
1.  **Web Service (FastAPI):** A REST API to validate URLs on demand.
2.  **CLI Tool:** A script to check a single URL from the command line.
3.  **Batch Processor:** A script to natively query the Fuseki SPARQL store for harvested metadata and validate all endpoints at once.

## Features

*   **Fuseki Integration:** Directly queries harmonized graphs in the Fuseki store to validate harvested metadata.
*   **Type Resolution via `dct:conformsTo`:** Intelligently maps specification URLs to known service types, falling back to fuzzy title matching if needed.
*   **Confidence Scoring System:** Calculates a 0.0 to 10.0 score based on multiple criteria (HTTP status codes, `dct:conformsTo` matches, MIME types, body signatures).
*   **Smart Fallbacks:** Automatically attempts POST requests for endpoints throwing 405 errors, and performs documentation page detection to prevent false negatives.
*   **Data-Driven Configuration:** All validation rules, signatures, and match logic are centralized in a single `service_profiles.json` schema.
*   **Unsupported Detection:** Early detection and skipping for unsupported service types (e.g. NetCDF) to save processing time.

## Installation

1.  **Prerequisites:** Python 3.8 or higher.
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Web Service (FastAPI)

Run the web server to expose a validation API.

```bash
uvicorn main:app --reload
```
*   The server will start at `http://127.0.0.1:8000`.
*   **Interactive Docs:** Open `http://127.0.0.1:8000/docs` to test the API in your browser.
*   **Example Request:** `GET /validate?url=https://example.com/oai&conforms_to=http://www.openarchives.org/OAI/2.0/`

### 2. Single URL Check (CLI)

Check a specific URL directly from the terminal.

```bash
python check_service.py --url "https://example.com/oai" --type OAI-PMH
```
*   If you run it without arguments, it will prompt you for the URL and Type interactively.

### 3. Batch Validation (Fuseki)

Validate a list of services queried directly from your Fuseki store.

1.  Set your environment variables if Fuseki is secured:
    ```bash
    export FUSEKI_USERNAME="your_username"
    export FUSEKI_PASSWORD="your_password"
    ```
    *(On Windows PowerShell, use `$env:FUSEKI_USERNAME="your_username"`)*
2.  Run the batch script:
    ```bash
    python batch_validator.py
    ```
    *(Optional: override the endpoint with `--fuseki http://your-url/query`)*
3.  **Outputs:**
    *   `validation_results.csv`: Contains the validation results including the `score` metric.
    *   `conformsTo_mismatches.csv`: A report mapping harvested `dct:conformsTo` URLs that couldn't be automatically resolved. Use this for manual review to update `service_profiles.json`!

**(Legacy CSV Mode):** If you still want to validate from a CSV file instead of Fuseki:
```bash
python batch_validator.py --input "repository services.csv"
```

## Configuration

The file `service_profiles.json` contains the mapping rules for all supported service types. You can edit this file to:
* Add new service profiles or acronyms.
* Define validation criteria like `spec_urls` for matching `dct:conformsTo`.
* Add `body_signatures` for deeper validation.
* Mark profiles as `unsupported`.
