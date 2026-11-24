# EDEN Service Validator

Checks whether a repository service endpoint (OAI-PMH, SPARQL, OGC, REST APIs and others) is reachable and answers the way its service type prescribes, and gives each result a confidence score from 0 to 10. In the EDEN registry, the repository harvester uses it as a library to validate every harvested endpoint. It also runs as a web API with a demo page, a command line tool and a batch job over the Fuseki store.

Documentation: https://eosc-eden.github.io/wp2-service-validator/

The specification is in [`docs/specification.md`](docs/specification.md). Change it through a pull request.
