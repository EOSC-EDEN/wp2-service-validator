# Usage

## Public demo

A public instance runs at <https://eden-validator.vm.fedcloud.eu/>, with the demo page at the root and the API at `/validate` ([interactive docs](https://eden-validator.vm.fedcloud.eu/docs)). It is not connected to a service identifier, so always pass `service_type`; without it the API returns 503. Requests are rate-limited, so install it locally for anything more than a few checks.

```bash
curl "https://eden-validator.vm.fedcloud.eu/validate?url=https://example.org/oai&service_type=OAI-PMH"
```

## Install

You need Python 3.9 or newer. Run all commands from the repository root, so the `controllers` and `eden_validator` packages resolve.

```bash
git clone https://github.com/EOSC-EDEN/wp2-service-validator.git
cd wp2-service-validator
pip install -r requirements.txt
cp .env.example .env
```

`.env` matters for batch mode (Fuseki credentials) and for type inference (identifier URL). See [Environment variables](reference.md#environment-variables).

## Web API and demo page

```bash
uvicorn controllers.api:app --reload
```

The demo page at <http://127.0.0.1:8000/> takes an endpoint URL, its service type and optionally a `dct:conformsTo` URL, and shows the result as a table and as JSON. The interactive API docs are at <http://127.0.0.1:8000/docs>. From the command line:

```bash
curl "http://127.0.0.1:8000/validate?url=https://example.org/oai&service_type=OAI-PMH"
```

Leave out `service_type` and the API asks the service identifier to infer it. Parameters and responses are in the [REST API reference](reference.md#rest-api).

## Single URL from the command line

```bash
python -m controllers.check_service --url "https://example.org/oai" --type OAI-PMH
```

Without `--type`, the service identifier is asked. If its confidence is below `IDENTIFIER_CONFIDENCE_THRESHOLD`, you are asked to confirm or override its guess. `--conforms-to` passes a `dct:conformsTo` URL for scoring. Run it with no arguments for an interactive prompt.

## Batch validation

Validates every service endpoint in the harmonized graphs of the Fuseki store. Set `FUSEKI_USERNAME` and `FUSEKI_PASSWORD` in `.env`, then:

```bash
python -m controllers.batch_validator
```

It writes two files:

- `output/validation_results.csv`, one row per endpoint, including `score`, `resolution_method` and `inferred_type`,
- `output/conformsTo_mismatches.csv`, the harvested `dct:conformsTo` values that matched no service profile. Use it to extend the profiles.

For each record the type is resolved from `dct:conformsTo` first, then the service title, then the service identifier. `resolution_method` records which one worked.

| Option | Effect |
|--------|--------|
| `--fuseki URL` | SPARQL endpoint to query (default `http://localhost:3030/service_registry_store/query`) |
| `--input FILE` | Read endpoints from a CSV file instead of Fuseki |
| `--output FILE`, `--mismatches FILE` | Change the two output paths |
| `--no-identifier` | Never ask the identifier. Records without a resolvable type are recorded as errors |
| `--force-identifier` | Ask the identifier for every record, skipping `dct:conformsTo` and title. Useful for checking the identifier's accuracy. The identifier and the validator share signals, so the score in this mode says little about conformance |

## As a Python library

The validation core is the package `eden_validator`, which depends only on `requests`:

```bash
pip install "eden-service-validator @ git+https://github.com/EOSC-EDEN/wp2-service-validator.git@v0.1.1"
```

```python
from eden_validator import ServiceValidator

validator = ServiceValidator(profiles_path="/abs/path/to/service_profiles.json")
result = validator.validate_url("https://example.org/oai", expected_type="OAI-PMH")
```

The package does not bundle `service_profiles.json`. Pass an absolute `profiles_path` (a relative one resolves against the working directory, which differs under Docker, systemd or cron) or set `EDEN_SERVICE_PROFILES` and call `ServiceValidator()` without arguments.

The package is GPL-3.0-or-later, which applies to code that imports it.
