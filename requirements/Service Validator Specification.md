# Service Validator Specification

# **Abstract**

This specification defines the functional and technical requirements for the Service Validator (SV), a tool that checks whether a registered repository service endpoint (for example OAI-PMH, SPARQL, OGC or REST APIs) is reachable and behaves like the service type it claims to be. It uses content negotiation, body signature matching and HTML page classification to tell machine-readable endpoints apart from documentation pages and retired services, and it rates each result with a confidence score from 0 to 10. All protocol knowledge lives in a shared set of service profiles, so service types can be added or changed without code changes.

# **Status of This Document**

WIP TRL4, open for review/comments. Describes release v0.1.1 of the reference implementation (Python package `eden-service-validator`, git tag `v0.1.1`, October 2026)

# **Introduction**

The Service Validator checks service endpoints used in research data management. It confirms that a URL leads to a working service that answers the way its protocol prescribes, for example with `text/xml` and an `<OAI-PMH>` root element for OAI-PMH. An HTTP 200 OK with a generic HTML page is not enough. When the registered URL is only the base of a service, the SV tries the protocol's standard request (the "magic URL", such as `?verb=Identify`). It also recognises documentation pages and notices of decommissioned or migrated services.

Currently, the validator is set up to run as part of the the repository harvester (wp2-repo-harvester). The harvstser collects service descriptions into the registry's Fuseki triple store, then validates the harvested endpoints with the SV, which it imports as a library. The scores appear in the registry. When the harvested metadata does not state the service type, the SV asks the service identifier (wp2-service-identifier) to infer it.

## **Rationale**

Automated workflows depend on registered endpoints that work. Registered URLs often point to a human-readable documentation page instead of the machine-readable API endpoint, and services get retired without anyone updating their records in re3data or FAIRsharing. Downstream processes that expect XML, JSON or RDF then fail. The SV marks an endpoint valid only when it is active and answers in the format its protocol prescribes.

A plain valid/invalid flag does not show how sure that verdict is, so the SV also reports a confidence score.

# **Scope**

## **In scope**

*   Validating endpoints against a service type, using content negotiation, the response `Content-Type` and body signatures (e.g. XML namespaces).
*   Resolving the service type from harvested metadata when it is not given.
*   Detecting documentation pages and decommissioned services.
*   Constructing magic URLs from standard protocol suffixes.
*   A confidence score per result.
*   Batch validation of all harvested endpoints.

## **Out of scope**

*   Validating payloads against the protocol's schema. The SV only checks that the response is in the expected format.
*   Performance and load testing.
*   Authentication. The SV reports when an endpoint requires a login (401/403) but does not log in.
*   Writing results back to the registry.

# **Conformance**

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119 (https://www.rfc-editor.org/rfc/rfc2119).

# **Core-Preservation Processes**

This service supports the Data Management and Ingest functional entities of the OAIS model. It checks that the external data sources and services that preservation workflows rely on are active and technically conformant.

# **Normative Requirements**

## **Requirement Group 1 – Service Profiles**

*   {{ SV-REQ-001 }} The Service MUST read all service types and their validation rules (expected media types, probe suffixes, body signatures, spec URLs) from a JSON profile file, so that service types can be added or changed without code changes.
*   {{ SV-REQ-002 }} Service types that cannot be checked over HTTP (e.g. NetCDF) MAY be marked unsupported in the profile file. The Service MUST then skip validation and report them as unsupported.

## **Requirement Group 2 – Service Type**

*   {{ SV-REQ-003 }} The Service MUST validate an endpoint against exactly one known service type. If the type is missing or unknown, it MUST report the endpoint as invalid without validating it.
*   {{ SV-REQ-004 }} If no type is given, the Service SHOULD resolve it in this order: the `dct:conformsTo` value matched against the spec URLs in the profiles, then the service title, then the wp2-service-identifier. The batch output records which of these was used.

## **Requirement Group 3 – Validation Logic**

*   {{ SV-REQ-005 }} The Service MUST send an HTTP `Accept` header for the media type of the expected service type (e.g. `text/xml, application/xml` for OAI-PMH).
*   {{ SV-REQ-006 }} The Service MUST NOT consider an endpoint valid on HTTP status alone. A response is valid if its status is between 200 and 399 and either its `Content-Type` matches the expected media type or its body contains one of the type's signatures.
*   {{ SV-REQ-007 }} A body signature match MUST override a non-matching `Content-Type`, to allow for misconfigured servers.
*   {{ SV-REQ-008 }} Before the content check, the Service MUST scan HTML responses for documentation keywords (e.g. "swagger-ui", "api reference") and decommissioning notices (e.g. "decommissioned", "migrated to") and treat such pages as invalid. Otherwise a documentation page about a protocol would pass the body signature check.
*   {{ SV-REQ-009 }} The Service SHOULD handle protocol-specific cases configured in the profiles, such as POST-only endpoints (DiGIR), a POST retry on HTTP 405, Linked Data Notifications inboxes, search URL templates (schema.org SearchAction) and `ftp://` endpoints.

## **Requirement Group 4 – Recovery**

*   {{ SV-REQ-010 }} If the initial URL fails, the Service SHOULD append the profile's standard suffix (e.g. `?verb=Identify` for OAI-PMH) and validate the resulting magic URL, unless the page announced that the service is decommissioned.
*   {{ SV-REQ-011 }} If the magic URL validates, the Service MUST report it in `constructed_url`. This tells the registry that the registered URL is only the base of the service.

## **Requirement Group 5 – Scoring and Reporting**

*   {{ SV-REQ-012 }} Each result MUST include a confidence score from 0 to 10:

    | Criterion | Points |
    |-----------|--------|
    | HTTP status between 200 and 399 | 3 |
    | `dct:conformsTo` resolves to the validated type | 2 |
    | `Content-Type` matches the expected media type | 2 |
    | Body signatures found (share of the type's signatures) | up to 2 |
    | Service title resolves to the validated type | 1 |
    | Known spec URLs in the response body | +1 if one matches the type, −2 if they only match other types |

*   {{ SV-REQ-013 }} The output MUST be machine-actionable JSON and include at least `valid`, `score`, the HTTP status code, the received and expected `Content-Type`, whether authentication is required (`Yes`/`No`/`Unknown`), the redirect chain and the constructed URL if one was used.
*   {{ SV-REQ-014 }} The Service MUST distinguish valid services from documentation pages, decommissioned services, unsupported types and other errors (4xx/5xx, wrong content, connection failure).

## **Requirement Group 6 – Interfaces**

*   {{ SV-REQ-015 }} The validation core MUST be installable as a Python package (`eden_validator`) so the harvester can call it. It SHOULD also be available as an HTTP API (`GET /validate`) and as a command line tool. The HTTP API MUST accept only `http` and `https` URLs.
*   {{ SV-REQ-016 }} The Service MUST support batch validation of all endpoints in the harmonized graphs of the Fuseki triple store, with a CSV file as alternative input. It MUST write the results to a CSV file, plus a list of `dct:conformsTo` values that matched no profile.

# **Non-normative Guidance**

## **Implementation Considerations**

*   The profile file is maintained in the `service-profiles` repository and synced into the SV, the identifier and the harvester, so edits belong there. v0.1.1 ships 40 service types, from OAI-PMH and OGC services to IVOA protocols and FTP.
*   The package does not bundle the profile file. Pass its path explicitly or set `EDEN_SERVICE_PROFILES`, which is the easier option in Docker.
*   Requests use the User-Agent `EDEN-Endpoint-Validator/1.0` and a 10 second timeout. The [flowchart](Service%20Validator%20Flowchart.md) shows the order of the checks.
*   `valid` and `score` can disagree: a documentation page that answers 200 is invalid but still scores 3.

## **Known Limitations**

*   The keyword lists are heuristic and will misclassify some pages.
*   Pages that render their content with JavaScript are judged on the HTML the server sends.
*   Spec URLs are read from the initial response even when the magic URL decided the result (see the example below).
*   The HTTP API filters only by URL scheme and does not block requests to internal addresses.

## **Example of Validation Output**

An OAI-PMH endpoint registered as `http://example.org/oai`, with `dct:conformsTo` and title given. The base URL redirects to a plain HTML page, so the SV appends `?verb=Identify` and validates that instead. Score: 3 (status) + 2 (`dct:conformsTo`) + 2 (Content-Type) + 0.4 (1 of 5 signatures) + 1 (title) = 8.4.

```json
{
  "valid": true,
  "status_code": 200,
  "content_type": "text/xml;charset=utf-8",
  "url": "http://example.org/oai?verb=Identify",
  "expected_content_type": "text/xml, application/xml",
  "is_doc_page": false,
  "auth_required": "No",
  "redirects": [
    {
      "status_code": 301,
      "from_url": "http://example.org/oai",
      "to_url": "http://example.org/oai/"
    }
  ],
  "had_redirect": true,
  "redirect_chain": "301: http://example.org/oai/",
  "constructed_url": "http://example.org/oai?verb=Identify",
  "redirected_url": "http://example.org/oai/",
  "score": 8.4,
  "extracted_conforms_to": "",
  "conforms_to_verified": "not_found"
}
```

# **References**

1.  EOSC Interoperability Framework.
2.  IETF RFC 2119: Key words for use in RFCs to Indicate Requirement Levels.
3.  Open Archives Initiative Protocol for Metadata Harvesting (OAI-PMH) Specification.
4.  OpenAPI Specification (formerly Swagger).
