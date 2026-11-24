# Reference

## REST API

### `GET /validate`

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `url` | yes | Endpoint to validate. Only `http` and `https` |
| `service_type` | no | Expected type acronym, e.g. `OAI-PMH`. Free text such as `OAI-PMH API` is mapped to the known acronym |
| `conforms_to` | no | `dct:conformsTo` URL from the harvested metadata. Used for scoring, and for the type if `service_type` is missing |

If neither parameter gives a type, the API asks the service identifier at `IDENTIFIER_BASE_URL`.

| Status | When |
|--------|------|
| 200 | Validation ran, whether or not the endpoint passed. Check `valid` |
| 400 | The URL is not `http`/`https`, or its host resolves to a private, loopback or link-local address. Only the submitted URL is checked, not redirect targets |
| 422 | `url` is missing |
| 503 | No type was given and the service identifier could not be reached |

### Other routes

| Route | Purpose |
|-------|---------|
| `/` | Demo page |
| `/docs` | Interactive OpenAPI docs |
| `/healthz` | Liveness check, returns `{"status": "ok"}` |

## Result fields

The API, the CLI and `ServiceValidator.validate_url()` return the same object. A full example is in the [specification](specification.md#example-of-validation-output). Fields are left out when they do not apply, for example when the request failed before a response came back.

| Field | Meaning |
|-------|---------|
| `valid` | `true` if the endpoint answers like the expected service type |
| `score` | Confidence from 0 to 10. The criteria are listed in SV-REQ-012 of the [specification](specification.md#requirement-group-5-scoring-and-reporting) |
| `url` | The URL that was validated, which is the constructed URL if one was used |
| `status_code` | HTTP status of the final response |
| `content_type`, `expected_content_type` | Received `Content-Type` and the types the profile accepts |
| `constructed_url` | The standard protocol request tried when the registered URL was only the base, e.g. `?verb=Identify` |
| `is_doc_page` | `true` if the response is a documentation page rather than the service |
| `auth_required` | `Yes`, `No` or `Unknown` |
| `redirects` | List of `{status_code, from_url, to_url}` |
| `had_redirect`, `redirect_chain`, `redirected_url` | Redirect summary as a flag, a readable string and the final URL |
| `extracted_conforms_to` | Known spec URLs found in the response body, pipe-separated |
| `conforms_to_verified` | `match`, `mismatch` or `not_found`: whether those spec URLs point to the expected type |
| `error` | What went wrong, e.g. `Unknown Service Type: 'X'`, `Unsupported/Cannot be verified`, `Service is decommissioned/migrated.` |
| `note` | Extra context, e.g. for decommissioned services or FTP endpoints |
| `inferred_type`, `inferred_service_type` | API only. Whether the type came from the service identifier, and which type it returned |

## Environment variables

Read from `.env` in the repository root, or from the process environment.

| Variable | Default | Used by |
|----------|---------|---------|
| `FUSEKI_USERNAME`, `FUSEKI_PASSWORD` | empty | Batch mode. Basic auth for Fuseki; leave empty if it needs none |
| `IDENTIFIER_BASE_URL` | `http://localhost:8001` | Type inference. The validator calls `/identify` on it |
| `IDENTIFIER_CONFIDENCE_THRESHOLD` | `5.0` | CLI only. Below this identifier confidence, the CLI asks you to confirm |
| `EDEN_SERVICE_PROFILES` | unset | Library. Path to `service_profiles.json` when `profiles_path` is not passed |
| `EDEN_ALLOW_PRIVATE_TARGETS` | unset | `true` lets the API and demo page check private and loopback hosts. For local development only |

## Service profiles

`config/service_profiles.json` holds the rules for every supported service type: accepted media types, body signatures, spec URLs for matching `dct:conformsTo`, and which types are unsupported. `config/service_profiles.schema.json` is its JSON Schema.

The file is a synced copy. The source is [weiserjens/service-profiles](https://github.com/weiserjens/service-profiles), which also feeds the service identifier. Change profiles there; local edits are overwritten on the next sync.
