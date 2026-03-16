from fastapi import FastAPI, Query
from Validator import ServiceValidator
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
    service_type: str = Query(None, description="The expected service type acronym (e.g. OAI-PMH). Can be omitted if conforms_to resolves the type."),
    conforms_to: str = Query(None, description="The dct:conformsTo URL from harvested RDF metadata. Used for type resolution and scoring."),
):
    """
    Validates a single service endpoint URL against a specific Service Type.

    - **url**: The URL of the service to check.
    - **service_type**: The expected Service Type acronym. Can be omitted if **conforms_to** resolves to a known profile.
    - **conforms_to**: Optional `dct:conformsTo` URL from harvested RDF metadata. Used for type resolution and scoring.

    The response includes a **score** (0–10) reflecting how many validation criteria were met.
    """
    # Resolve expected type: conforms_to URL takes priority, then explicit service_type param.
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

    result = validator.validate_url(
        url,
        expected_type=resolved_type,
        conforms_to=conforms_to,
        service_title=service_type,  # original type string used for title-match scoring
    )
    return result

if __name__ == "__main__":
    # This block allows running the app directly from PyCharm or the command line
    # uvicorn main:app --reload
    uvicorn.run(app, host="127.0.0.1", port=8000)

# To run this service:
# 1. Install fastapi and uvicorn: pip install fastapi "uvicorn[standard]"
# 2. Run from your terminal: uvicorn main:app --reload
# 3. Or run this file directly in PyCharm.
# 4. Open your browser to http://127.0.0.1:8000/docs to see the interactive API documentation.