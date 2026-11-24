# EDEN Service Validator

The Service Validator checks whether a registered repository service endpoint (OAI-PMH, SPARQL, OGC, REST APIs and others) is reachable and answers the way its service type prescribes. An HTTP 200 with a generic HTML page is not enough. Each result gets a confidence score from 0 to 10.

It supports the Data Management and Ingest functional entities of the OAIS model, because preservation workflows depend on external services that have to work. In the EDEN context, the repository harvester (`wp2-repo-harvester`) imports the validator as a library and validates every harvested endpoint.

What it does:

- compares the HTTP status, `Content-Type` and body signatures (for example the `<OAI-PMH>` root element) with what the service type expects,
- tries the protocol's standard request (such as `?verb=Identify`) when the registered URL is only the base of the service,
- recognises documentation pages and decommissioned services,
- works out the service type from `dct:conformsTo`, the service title or the service identifier (`wp2-service-identifier`) when it is not given.

All protocol knowledge lives in a shared set of service profiles, so service types can be added or changed without code changes.

## Scope

The validator checks that a response has the expected format. It does not validate payloads against the protocol's schema, does not log in to protected endpoints (it reports that a login is needed), and does not write results back to the registry.

## Status

Work in progress, TRL4. The [specification](specification.md) describes release v0.1.1.

## Where to start

| I want to | Go to |
|-----------|-------|
| Try it without installing anything | [Public demo](usage.md#public-demo) |
| Check one endpoint in the browser or with curl | [Web API and demo page](usage.md#web-api-and-demo-page) |
| Validate every endpoint in the registry | [Batch validation](usage.md#batch-validation) |
| Call the validator from Python | [As a Python library](usage.md#as-a-python-library) |
| Look up a parameter, result field or variable | [Reference](reference.md) |
| Read the requirements | [Specification](specification.md) |
