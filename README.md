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

## Project Structure

The repository is organized by responsibility. Run all commands from the repository
root so the `controllers` and `core` packages resolve on the import path.

```
service-validator/
├── controllers/          # Entry points — the three modes of operation
│   ├── api.py            #   FastAPI web service (uvicorn controllers.api:app)
│   ├── check_service.py  #   CLI: validate a single URL
│   └── batch_validator.py#   CLI: batch-validate from Fuseki (or a CSV)
├── core/                 # Validation engine and helpers
│   ├── validator.py      #   ServiceValidator — scoring, content checks, fallbacks
│   ├── type_resolver.py  #   Infers service type via the wp2-service-identifier API
│   └── fuseki_loader.py  #   Queries harmonized graphs from the Fuseki SPARQL store
├── config/               # Data-driven configuration
│   ├── service_profiles.json        # Validation rules/signatures (synced in, not edited here)
│   └── service_profiles.schema.json # JSON Schema for the profiles
├── data/                 # Input fixtures (e.g. legacy CSV for --input mode)
├── output/               # Generated results (gitignored)
├── scripts/              # Dev/diagnostic one-offs (gitignored)
└── tests/                # Local test suite (gitignored)
```

| Layer | Holds | Notes |
|-------|-------|-------|
| `controllers/` | The API and two CLIs | Each is a thin entry point that wires together `core` components. |
| `core/` | The reusable validation logic | No CLI/HTTP concerns; imported by every controller. |
| `config/` | Rules and schema | `service_profiles.json` is synced from the source of truth — edit it there, not here. |
| `data/` / `output/` | Inputs vs. generated artifacts | Batch results default to `output/`. |

## Usage

### 1. Web Service (FastAPI)

Run the web server to expose a validation API.

```bash
uvicorn controllers.api:app --reload
```
*(Run from the repository root so the `core` and `controllers` packages resolve.)*
*   The server will start at `http://127.0.0.1:8000`.
*   **Interactive Docs:** Open `http://127.0.0.1:8000/docs` to test the API in your browser.
*   **Example Request (type known):** `GET /validate?url=https://example.com/oai&service_type=OAI-PMH`
*   **Example Request (type inferred):** `GET /validate?url=https://example.com/oai`
    *   Response includes `"inferred_type": true` and `"inferred_service_type": "OAI-PMH"` when auto-inferred.

### 2. Single URL Check (CLI)

Check a specific URL directly from the terminal.

```bash
# With explicit type
python -m controllers.check_service --url "https://example.com/oai" --type OAI-PMH

# Without type — identifier is queried automatically
python -m controllers.check_service --url "https://example.com/oai"
```

You can also run the script with no arguments for an interactive prompt:

```
python -m controllers.check_service
--- Manual Service Check ---
Enter Service URL: https://example.com/oai --type OAI-PMH
```

Inline `--type` is supported in the prompt, so you can paste a URL and append the type in one go.

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
    python -m controllers.batch_validator
    ```
    *(Optional: override the Fuseki endpoint with `--fuseki http://your-url/query`)*

3.  **Outputs** (written to `output/`):
    *   `output/validation_results.csv`: Validation results including `score`, `resolution_method`, and `inferred_type` columns.
    *   `output/conformsTo_mismatches.csv`: A report of harvested `dct:conformsTo` URLs that could not be automatically resolved. Use this for manual review to update `service_profiles.json`.

#### Batch options

| Flag | Effect |
|------|--------|
| *(none)* | Default: resolve via `conformsTo` → `serviceTitle` → identifier fallback |
| `--no-identifier` | Disable identifier fallback; records with no resolvable type are recorded as errors |
| `--force-identifier` | Skip `conformsTo` and `serviceTitle` resolution; use the identifier for every record (output saved to `output/validation_results_forced-identifier.csv`) |

> **Note on `--force-identifier`:** This mode is useful for evaluating the identifier's accuracy — compare its `mapped_service_type` output against known `conforms_to` values. Because the identifier and validator share overlapping signals (body signatures, content-type), the validation score in this mode is not an independent conformance check.

**(Legacy CSV Mode):** If you still want to validate from a CSV file instead of Fuseki:
```bash
python -m controllers.batch_validator --input "data/repository services.csv"
```

## Type resolution priority

For each record, the validator resolves the service type in this order:

1. **`dct:conformsTo`** (from Fuseki metadata) — matched against known spec URLs in `service_profiles.json`. Most reliable; represents the data provider's own declaration.
2. **`dct:title`** (service title) — fuzzy substring match against known type acronyms.
3. **`wp2-service-identifier`** (auto-inference) — the identifier probes the endpoint and returns its best guess with a confidence score.

The `resolution_method` column in the output CSV records which step succeeded (`conforms_to`, `service_title`, `identifier`, or `none`).

## Configuration

> **⚠️ `service_profiles.json` is a synced copy — do not edit it here.**
> The single authoritative copy lives in
> **[weiserjens/service-profiles](https://github.com/weiserjens/service-profiles.git)**
> and is synced automatically into this repo (and the wp2-service-identifier
> repo) via the `sync/service-profiles` branch. Local edits will be
> **overwritten** on the next sync. To change a profile, edit it in the
> authoritative source repo.

The file `service_profiles.json` contains the mapping rules for all supported service types. Edit it **in the authoritative source repo** to:
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
