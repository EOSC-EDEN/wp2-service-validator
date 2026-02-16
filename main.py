from fastapi import FastAPI, Query
from Validator import ServiceValidator
import uvicorn

app = FastAPI(
    title="EDEN Endpoint Validator Service",
    description="A service to validate the status and content type of repository service endpoints.",
    version="1.0.0",
)

# Initialize the validator once when the application starts
validator = ServiceValidator()

@app.get("/validate", summary="Validate a single service endpoint")
def validate_endpoint(
    url: str = Query(..., description="The full URL of the endpoint to validate."),
    type: str = Query(None, description="The expected service type (e.g., OAI-PMH, NetCDF). Required for strict validation.")
):
    """
    Validates a single service endpoint URL against a specific Service Type.

    - **url**: The URL of the service to check.
    - **type**: The expected Service Type. Ideally provided by the user.

    The system performs a strict validation based on the provided type.
    """
    # Pass the type to the validator (Validator now enforces strict mode if type is missing)
    result = validator.validate_url(url, expected_type=type)
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