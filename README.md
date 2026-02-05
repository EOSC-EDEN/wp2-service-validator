# EDEN Service Validator

This tool validates repository service endpoints (e.g., OAI-PMH, OpenAPI, REST, SPARQL, OGC services) by automatically detecting their type and checking their availability and compliance with expected content types.

It provides three modes of operation:
1.  **Web Service (FastAPI):** A REST API to validate URLs on demand.
2.  **CLI Tool:** A script to check a single URL from the command line.
3.  **Batch Processor:** A script to validate a list of URLs from a CSV file.

## Features

*   **Auto-Detection:** Automatically identifies API types (OAI-PMH, OpenAPI, OGC-WMS/CSW, SPARQL, etc.) from the URL structure, response headers, and body content.
*   **Smart Recovery:** Handles cases where an API returns an HTML documentation page (e.g., Swagger UI) instead of the expected machine-readable format, marking them as valid with a note.
*   **Configurable Rules:** Validation rules (default queries, expected MIME types) are defined in `services_default_queries.csv`.

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
python main.py
```
*   The server will start at `http://127.0.0.1:8000`.
*   **Interactive Docs:** Open `http://127.0.0.1:8000/docs` to test the API in your browser.

### 2. Single URL Check (CLI)

Check a specific URL directly from the terminal.

```bash
python check_service.py --url "https://example.com/oai"
```
*   If you run it without arguments, it will prompt you for the URL interactively.

### 3. Batch Validation

Validate a list of services from a CSV file.

1.  Ensure your input file is named `repository services.csv` and contains a column named `endpoint` with the URLs.
2.  Run the batch script:
    ```bash
    python batch_validator.py
    ```
3.  Results will be saved to `validation_results.csv`.

## Configuration

The file `services_default_queries.csv` contains the mapping rules for different API types. You can edit this file to add new service types or change the default validation queries and expected content types.
