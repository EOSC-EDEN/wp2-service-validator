# EDEN Service Validator

This tool validates repository service endpoints (e.g., OAI-PMH, OpenAPI, REST, SPARQL, OGC services) by checking their availability, compliance with expected content types, and matching them against known specifications.

It provides three modes of operation:
1.  **Web Service (FastAPI):** A REST API to validate URLs on demand.
2.  **CLI Tool:** A script to check a single URL from the command line.
3.  **Batch Processor:** A script to natively query the Fuseki SPARQL store for harvested metadata and validate all endpoints at once.

## Features

*   **Fuseki Integration:** Directly queries harmonized graphs in the Fuseki store to validate harvested metadata.
*   **Auto-Type Inference:** When no service type is provided, the validator calls the `wp2-service-identifier` API to infer the type automatically.
*   **Type Resolution via `dct:conformsTo`:** Intelligently maps specification URLs to known service types, falling back to fuzzy title matching, then the identifier if needed.
*   **Confidence Scoring System:** Calculates a 0.0 to 10.0 score based on multiple criteria (HTTP status codes, `dct:conformsTo` matches, MIME types, body signatures).
*   **Smart Fallbacks:** Automatically attempts POST requests for endpoints throwing 405 errors, and performs documentation page detection to prevent false negatives.
*   **Data-Driven Configuration:** All validation rules, signatures, and match logic are centralized in a single `service_profiles.json` schema.
*   **Unsupported Detection:** Early detection and skipping for unsupported service types (e.g. NetCDF) to save processing time.
*   **SSRF Protection:** The API endpoint rejects non-HTTP/HTTPS URLs (e.g. `file://`, `ftp://`).

## Installation

1.  **Prerequisites:** Python 3.8 or higher.
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure environment:**
    ```bash
    cp .env.example .env
    # Edit .env with your Fuseki credentials and identifier URL
    ```

## Usage

### 1. Web Service (FastAPI)

Run the web server to expose a validation API.

```bash
uvicorn main:app --reload
```
*   The server will start at `http://127.0.0.1:8000`.
*   **Interactive Docs:** Open `http://127.0.0.1:8000/docs` to test the API in your browser.
*   **Example Request (type known):** `GET /validate?url=https://example.com/oai&service_type=OAI-PMH`
*   **Example Request (type inferred):** `GET /validate?url=https://example.com/oai`
    *   Response includes `"inferred_type": true` and `"inferred_service_type": "OAI-PMH"` when auto-inferred.

### 2. Single URL Check (CLI)

Check a specific URL directly from the terminal.

```bash
# With explicit type
python check_service.py --url "https://example.com/oai" --type OAI-PMH

# Without type — identifier is queried automatically
python check_service.py --url "https://example.com/oai"
```

When the identifier's confidence is below the threshold, the CLI will prompt you to confirm or override the suggestion interactively.

### 3. Batch Validation (Fuseki)

Validate all service endpoints queried directly from your Fuseki store.

1.  Copy and fill in your credentials:
    ```bash
    cp .env.example .env
    ```
    Or set environment variables manually:
    ```bash
    export FUSEKI_USERNAME="your_username"
    export FUSEKI_PASSWORD="your_password"
    ```
    *(On Windows PowerShell, use `$env:FUSEKI_USERNAME="your_username"`)*

2.  Run the batch script:
    ```bash
    python batch_validator.py
    ```
    *(Optional: override the Fuseki endpoint with `--fuseki http://your-url/query`)*

3.  **Outputs:**
    *   `validation_results.csv`: Validation results including `score`, `resolution_method`, and `inferred_type` columns.
    *   `conformsTo_mismatches.csv`: A report of harvested `dct:conformsTo` URLs that could not be automatically resolved. Use this for manual review to update `service_profiles.json`.

#### Batch options

| Flag | Effect |
|------|--------|
| *(none)* | Default: resolve via `conformsTo` → `serviceTitle` → identifier fallback |
| `--no-identifier` | Disable identifier fallback; records with no resolvable type are recorded as errors |
| `--force-identifier` | Skip `conformsTo` and `serviceTitle` resolution; use the identifier for every record (output saved to `validation_results_forced-identifier.csv`) |

> **Note on `--force-identifier`:** This mode is useful for evaluating the identifier's accuracy — compare its `mapped_service_type` output against known `conforms_to` values. Because the identifier and validator share overlapping signals (body signatures, content-type), the validation score in this mode is not an independent conformance check.

**(Legacy CSV Mode):** If you still want to validate from a CSV file instead of Fuseki:
```bash
python batch_validator.py --input "repository services.csv"
```

## Type resolution priority

For each record, the validator resolves the service type in this order:

1. **`dct:conformsTo`** (from Fuseki metadata) — matched against known spec URLs in `service_profiles.json`. Most reliable; represents the data provider's own declaration.
2. **`dct:title`** (service title) — fuzzy substring match against known type acronyms.
3. **`wp2-service-identifier`** (auto-inference) — the identifier probes the endpoint and returns its best guess with a confidence score.

The `resolution_method` column in the output CSV records which step succeeded (`conforms_to`, `service_title`, `identifier`, or `none`).

## Configuration

The file `service_profiles.json` contains the mapping rules for all supported service types. You can edit this file to:
* Add new service profiles or acronyms.
* Define validation criteria like `spec_urls` for matching `dct:conformsTo`.
* Add `body_signatures` for deeper validation.
* Mark profiles as `unsupported`.

## Environment variables

See `.env.example` for the full list. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `FUSEKI_USERNAME` | *(empty)* | Fuseki Basic Auth username |
| `FUSEKI_PASSWORD` | *(empty)* | Fuseki Basic Auth password |
| `IDENTIFIER_BASE_URL` | `http://localhost:8001` | Base URL of the `wp2-service-identifier` service |
| `IDENTIFIER_CONFIDENCE_THRESHOLD` | `5.0` | Minimum confidence (0–10) to auto-proceed in CLI mode without prompting |
