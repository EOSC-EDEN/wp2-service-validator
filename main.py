from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Query
from Validator import ServiceValidator
from type_resolver import resolve_type
import uvicorn

app = FastAPI(
    title="EDEN Endpoint Validator Service",
    description="A service to validate the status and content type of repository service endpoints.",
    version="2.0.0",
)

# Initialize the validator once when the application starts
validator = ServiceValidator()

@app.get("/validate", summary="Validate a single service endpoint")
def validate_endpoint(
    url: str = Query(..., description="The full URL of the endpoint to validate."),
    service_type: str = Query(None, description="The expected service type acronym (e.g. OAI-PMH). Can be omitted to trigger auto-identification via wp2-service-identifier."),
    conforms_to: str = Query(None, description="The dct:conformsTo URL from harvested RDF metadata. Used for type resolution and scoring."),
):
    """
    Validates a single service endpoint URL against a specific Service Type.

    - **url**: The URL of the service to check.
    - **service_type**: The expected Service Type acronym.  May be omitted — if so, the
      validator will call the wp2-service-identifier to infer the type automatically.
      If the identifier is unavailable, a 503 is returned.
    - **conforms_to**: Optional `dct:conformsTo` URL from harvested RDF metadata. Used
      for type resolution and scoring.

    The response includes a **score** (0–10) reflecting how many validation criteria were
    met, and an **inferred_type** flag (bool) indicating whether the service type was
    inferred by the identifier rather than supplied explicitly.
    """
    # --- SSRF prevention: only http/https are allowed via the API ---
    # ftp:// URLs are handled by the batch validator which runs server-side in a controlled
    # environment; they must not be accepted over the public HTTP API.
    parsed_scheme = urlparse(url).scheme.lower()
    if parsed_scheme not in ('http', 'https'):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid URL scheme '{parsed_scheme}'. "
                "Only http:// and https:// are accepted by this endpoint."
            ),
        )

    # --- Type resolution: conforms_to → explicit service_type → identifier ---
    resolved_type = service_type
    if conforms_to and not resolved_type:
        resolved_type = ServiceValidator.resolve_type_from_conforms_to(
            conforms_to, validator.spec_url_index
        )

    # Map free-text type to known acronym (e.g. "OAI-PMH API" -> "OAI-PMH")
    if resolved_type:
        available_types = list(validator.protocol_configs.keys())
        mapped = ServiceValidator.map_service_type(resolved_type, available_types)
        if mapped:
            resolved_type = mapped

    # If still no type, ask the identifier service
    type_inferred = False
    if not resolved_type:
        try:
            resolved_type, type_inferred = resolve_type(url, mode='api')
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))

    result = validator.validate_url(
        url,
        expected_type=resolved_type,
        conforms_to=conforms_to,
        service_title=service_type,  # original type string used for title-match scoring
    )

    if type_inferred:
        result['inferred_type'] = True
        result['inferred_service_type'] = resolved_type
    else:
        result['inferred_type'] = False

    return result

if __name__ == "__main__":
    # This block allows running the app directly from PyCharm or the command line
    # uvicorn main:app --reload
    uvicorn.run(app, host="127.0.0.1", port=8000)

# To run this service:
# 1. Install dependencies: pip install -r requirements.txt
# 2. Run from your terminal: uvicorn main:app --reload
# 3. Or run this file directly in PyCharm.
# 4. Open your browser to http://127.0.0.1:8000/docs to see the interactive API documentation.
