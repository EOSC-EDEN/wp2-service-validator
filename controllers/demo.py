"""The public demo page: one endpoint, one service type, the full validator result."""
import json

# Ordered by how often each type turned up in the 2026-10-22 harvest of 146
# repositories (437 services). Every other profile goes below these, A-Z.
COMMON_TYPES = [
    "OAI-PMH", "RSS", "REST", "Sitemaps", "SearchAction", "FTP", "OpenSearch", "ATOM",
    "SWORD", "SPARQL", "NetCDF", "FAIRiCat", "OGC-WMS", "OGC-WCS", "OpenDAP", "Static OAI", "SOAP",
]

ROW_LABELS = {
    "valid": "Valid",
    "score": "Score",
    "status_code": "HTTP status",
    "content_type": "Content type received",
    "expected_content_type": "Content type expected",
    "auth_required": "Authentication required",
    "is_doc_page": "Documentation page",
    "url": "URL checked",
    "constructed_url": "Constructed URL",
    "redirected_url": "Final URL after redirects",
    "redirect_chain": "Redirects",
    "conforms_to_verified": "conformsTo in response",
    "extracted_conforms_to": "Specification URLs in response",
    "note": "Note",
    "error": "Error",
}

# redirect_chain already spells these out.
HIDDEN_KEYS = {"redirects", "had_redirect"}


def type_options(profiles: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    def label(key):
        title = profiles[key].get("title") or key
        return key if title.lower() == key.lower() else f"{key} ({title})"

    common = [(key, label(key)) for key in COMMON_TYPES if key in profiles]
    other = [(key, label(key)) for key in sorted(profiles, key=str.lower) if key not in COMMON_TYPES]
    return common, other


def _format(key, value):
    if key == "score" and isinstance(value, (int, float)):
        return f"{value:.1f} / 10"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def result_rows(result: dict) -> list[tuple[str, str]]:
    """Known keys first in a fixed order, then whatever else the validator sent.

    Early exits return only a few keys, so nothing here may assume one is present.
    """
    keys = [k for k in ROW_LABELS if k in result]
    keys += [k for k in result if k not in ROW_LABELS and k not in HIDDEN_KEYS]
    return [
        (ROW_LABELS.get(k, k), _format(k, result[k]))
        for k in keys
        if result[k] is not None and result[k] not in ("", [], {})
    ]
