import requests
import os
import csv
import logging
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)


class ServiceValidator:
    logger = logging.getLogger('ServiceValidator')

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'EDEN-Endpoint-Validator/1.0',
                          'Accept': '*/*',  # initially accept any header
        }
        self.protocol_configs = self._load_service_mappings()
        self._load_validation_config()

    def _load_validation_config(self):
        """Loads validation keywords from a JSON configuration file."""
        config_path = os.path.join(os.path.dirname(__file__), 'validation_config.json')

        self.api_doc_keywords = []
        self.decommissioned_keywords = []

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                self.api_doc_keywords = config.get('api_doc_keywords', [])
                self.decommissioned_keywords = config.get('decommissioned_keywords', [])
                self.logger.info(f"Loaded validation configuration from {config_path}")
        except FileNotFoundError:
            self.logger.error(f"Fatal: Validation config file not found at {config_path}. Keyword detection will be disabled.")
        except json.JSONDecodeError:
            self.logger.error(f"Fatal: Error parsing {config_path}. Keyword detection will be disabled.")

    def _load_service_mappings(self):
        """Loads the service mappings from the CSV file."""
        mappings = {}
        csv_path = os.path.join(os.path.dirname(__file__), 'services_default_queries.csv')
        try:
            with open(csv_path, mode='r', encoding='utf-8') as infile:
                # Detect delimiter based on the first line
                first_line = infile.readline()
                delimiter = ';' if ';' in first_line else ','
                infile.seek(0)
                
                reader = csv.DictReader(infile, delimiter=delimiter)
                for row in reader:
                    api_type = row.get('Acronym')
                    if api_type and api_type.strip():
                        suffix = row.get('default query', '')
                        accept = row.get('accept', '')
                        
                        current_config = {
                            'suffix': suffix,
                            'accept': accept
                        }
                        
                        if api_type not in mappings:
                            mappings[api_type] = current_config
                        else:
                            # Conflict resolution for duplicate Acronyms:
                            # 1. Prefer entries with an 'accept' header.
                            # 2. If neither has 'accept', prefer entries with a non-empty 'suffix'.
                            existing = mappings[api_type]
                            
                            if accept:
                                # New entry has accept header -> Overwrite (upgrade or replace)
                                mappings[api_type] = current_config
                            elif existing['accept']:
                                # Existing has accept, new one doesn't -> Keep existing
                                pass
                            elif suffix:
                                # Neither has accept, but new one has suffix -> Overwrite (upgrade)
                                mappings[api_type] = current_config
                            else:
                                # New one has neither -> Keep existing
                                pass

        except FileNotFoundError:
            self.logger.error(f"Fatal: Service mapping file not found at {csv_path}")
        return mappings

    @staticmethod
    def map_service_type(service_title, available_types):
        """
        Maps a service title (e.g., 'SWORD API', 'RSS Feed') to a known Acronym (e.g., 'SWORD', 'RSS').
        Performs case-insensitive substring matching.
        """
        if not service_title:
            return None
        
        title_lower = service_title.lower()
        
        # Sort available types by length (descending) to match specific first (e.g. OGC-WMS before OGC)
        for acr in sorted(available_types, key=len, reverse=True):
            if acr.lower() in title_lower:
                return acr
                
        return None



    def _classify_html_response(self, response, url, is_recovery_attempt=False, expected_mime=None):
        """
        Scans a text/html response for decommissioned or documentation keywords.
        Returns a dict with 'is_valid', 'is_doc_page', 'note', and 'error' overrides if found,
        or None if it's just generic HTML.
        """
        received_mime = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in received_mime:
             return None

        response_text_lower = response.text[:50000].lower()

        # 1. Check for decommissioned/migrated service keywords
        if any(keyword in response_text_lower for keyword in self.decommissioned_keywords):
            self.logger.warning(f"Detected decommissioned service page at {url}.")
            return {
                "valid": False, "is_doc_page": False, 
                "error": "Service is decommissioned/migrated.",
                "note": "Endpoint is a documentation page for a decommissioned/migrated service."
            }

        # 2. Check for API documentation page
        # We check this even if we aren't recovering, as a doc page means it's not the raw endpoint.
        # But if it's a recovery attempt, we might have explicitly sought a doc page, so we skip marking it invalid here
        # or handle it based on the caller's context. Usually, doc pages are invalid service endpoints.
        if not is_recovery_attempt:
             if any(keyword in response_text_lower for keyword in self.api_doc_keywords):
                 self.logger.info(f"Detected API documentation page on {url}. Marking as INVALID (Documentation Page).")
                 
                 # Construct a helpful note based on expectations
                 note = "Invalid endpoint: Received HTML (API documentation page). Status 200 OK suggests service is likely active but URL is not a direct service endpoint."
                 if expected_mime:
                      note = f"Invalid endpoint: Received HTML (API documentation page) instead of expected {expected_mime}. Status 200 OK suggests service is likely active but URL is not a direct service endpoint."
                      
                 return {
                     "valid": False, "is_doc_page": True,
                     "note": note
                 }
                 
        return None

    def _build_redirect_chain_info(self, response):
        """Builds a list of redirect steps with status code and destination URL."""
        chain = []
        if response.history:
            for resp in response.history:
                # The 'url' in resp is the URL *before* the redirect
                # The 'Location' header in resp.headers is the destination of the redirect
                chain.append({
                    "status_code": resp.status_code,
                    "from_url": resp.url,
                    "to_url": resp.headers.get('Location', 'N/A') # Get destination from Location header
                })
        return chain

    def _is_strict_content_match(self, response, expected_type, config):
        """
        Checks if the response strictly matches the expected service type.
        Criteria:
        1. Content-Type matches the config's 'accept' list.
        2. Body contains specific signatures/keywords for the type.
        Returns True if either condition is met (relaxed strictness).
        """
        received_mime = response.headers.get('Content-Type', '').lower()
        expected_mime = config.get('accept', '').lower()

        # 1. Check Content-Type
        ct_match = False
        if expected_mime:
            # expected_mime might be "application/xml, text/xml"
            # We check if ANY of the expected types are present in the received mime
            if any(t.strip() in received_mime for t in expected_mime.split(',')):
                ct_match = True
            else:
                 self.logger.debug(f"Strict Content-Type match failed: '{received_mime}' != '{expected_mime}'")

        # 2. Check Body Patterns (Bonus Confirmation or Fallback)
        body_match = False
        text = response.text[:50000].lower()

        patterns = {
            'OAI-PMH': ['<oai-pmh', 'xmlns:oai', 'oai:identifier', '<oai_dc:dc', 'xmlns:oai_dc'],
            'SPARQL': ['<rdf:rdf', 'sparql-results'],
            'OpenAPI': ['"openapi"', 'swagger', '"paths":'],
            'RSS': ['<rss', '<channel'],
            'ATOM': ['<feed', 'xmlns="http://www.w3.org/2005/atom"'],
            'OGC-WMS': ['wms_capabilities', 'service="wms"'],
            'OGC-CSW': ['csw:capabilities', 'service="csw"'],
            'FTP': ['index of /', 'parent directory', 'name', 'last modified', 'size', 'ftp directory', '[to parent directory]']
        }

        type_patterns = patterns.get(expected_type, [])
        if type_patterns:
            if any(p in text for p in type_patterns):
                body_match = True
                self.logger.info(f"Strict match confirmed via body signature for '{expected_type}'.")
            else:
                self.logger.debug(f"Body signature match failed for '{expected_type}'.")

        # Validation Logic:
        # If body matches, we trust it (overriding potential CT mismatch).
        if body_match:
            return True

        # If CT matches and we didn't explicitly fail a body check (or didn't check), trust CT.
        if ct_match:
            return True

        return False

    def validate_url(self, url, is_recovery_attempt=False, expected_type=None):
        """
        Validates a URL with strict type checking logic:
        1. Initial Check: Request original URL with type-specific Accept header.
           - If strictly matches (Status 200 + Content-Type + Body Pattern) -> VALID.
        2. Fallback: If initial check fails, try constructing service URL (Magic).
        3. Documentation Fallback: If all else fails, check for documentation page.
        """
        if not url:
            return {"valid": False, "error": "Empty URL"}

        # Check Expected Type First
        if not expected_type:
            return {
                "valid": False,
                "error": "Strict Mode Required: No expected service type provided.",
                "url": url,
                "auth_required": "unknown",
                "final_url": url
            }
            
        if expected_type not in self.protocol_configs:
            return {
                "valid": False, 
                "error": f"Unknown Service Type: '{expected_type}'", 
                "url": url, 
                "auth_required": "unknown",
                "final_url": url
            }

        # Prepare Headers with specific Accept if expected_type is provided
        current_headers = self.headers.copy()
        config = self.protocol_configs.get(expected_type)
        # Construct Accept header with q-values
        # e.g., "application/xml;q=1.0, text/html;q=0.9, */*;q=0.8"
        specific_accept = config.get('accept')
        if specific_accept:
            # Ensure we have a valid mime type str
            current_headers['Accept'] = f"{specific_accept};q=1.0, text/html;q=0.9, */*;q=0.8"

        try:
            main_response = requests.get(url, headers=current_headers, timeout=self.timeout, allow_redirects=True)
            
            # Derive Auth Requirement from the request chain
            auth_required = 'No'
            if main_response.status_code in [401, 403]:
                 auth_required = 'required'
            # Note: The requests library might internally negotiate auth challenges (like Digest) 
            # and append the initial 401/403 to the history of a subsequent successful request.
            # While this script never provides credentials so negotiation won't succeed,
            # this check acts as a theoretical safeguard against unexpected server redirects after a 401.
            elif main_response.history and main_response.history[0].status_code in [401, 403]:
                 auth_required = 'required'
                 
        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url, "auth_required": "unknown"}

        final_url = main_response.url
        detected_type = expected_type

        # --- Step 1: Strict Initial Check ---
        # Check if the repository is already giving us what we want on the base URL
        if 200 <= main_response.status_code < 400:
            if self._is_strict_content_match(main_response, expected_type, config):
                self.logger.info(f"Initial URL '{final_url}' strictly matches expected type '{expected_type}'. Skipping construction logic.")

                redirect_chain_list = self._build_redirect_chain_info(main_response)

                return {
                    "valid": True,
                    "status_code": main_response.status_code,
                    "content_type": main_response.headers.get('Content-Type', '').lower(),
                    "url": url, # Original URL was valid
                    "final_url": final_url,
                    "constructed_url": '', # No construction needed
                    "expected_content_type": config.get('accept'),
                    "auth_required": auth_required,
                    "note": "Initial URL validation successful.",
                    "redirects": redirect_chain_list,
                    "had_redirect": bool(redirect_chain_list),
                    "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list]),
                    "is_doc_page": False
                }
                
        # --- Step 1.5: Initial URL Decommissioned / Doc Page Check ---
        # Before trying to build a magic URL, check if the *initial* URL is fundamentally an invalid type
        # (like a decommissioned page or a documentation page).
        # If it is, there's no point in building a magic URL from it.
        initial_html_classification = self._classify_html_response(main_response, final_url, expected_mime=config.get('accept'))
        if initial_html_classification:
            self.logger.info(f"Initial URL '{final_url}' failed strict validation and was classified as an invalid HTML page (e.g. Doc/Decommissioned). Skipping magic URL construction.")
            core_result = {
                 "valid": initial_html_classification.get('valid', False),
                 "status_code": main_response.status_code,
                 "content_type": main_response.headers.get('Content-Type', '').lower(),
                 "url": final_url,
                 "expected_content_type": config.get('accept'),
                 "is_doc_page": initial_html_classification.get('is_doc_page', False)
            }
            if 'error' in initial_html_classification: core_result['error'] = initial_html_classification['error']
            if 'note' in initial_html_classification: core_result['note'] = initial_html_classification['note']
        else:
            # --- Step 2: "Magic" / Construction Fallback ---
            # If initial check didn't satisfy strict requirements AND wasn't a doc/decommissioned page, 
            # try constructing the specific service URL
            self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
            core_result = self._check_specific_http(main_response, final_url, config, detected_type, is_recovery_attempt, current_headers, main_response=main_response)

        # --- Assemble the final, complete result dictionary ---
        final_result = core_result.copy()

        final_result['auth_required'] = auth_required

        redirect_chain_list = self._build_redirect_chain_info(main_response)
        final_result['redirects'] = redirect_chain_list
        final_result['had_redirect'] = bool(redirect_chain_list)
        final_result['redirect_chain'] = " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list])

        # Handle URL keys for consistent output
        constructed_url = final_result.get('url', '')
        # If the core_result didn't set 'url' specifically (it does usually), or if it set it to constructed
        final_result['constructed_url'] = constructed_url if constructed_url and constructed_url != final_url else ''
        final_result['final_url'] = final_url

        # Ensure 'url' in final output matches the logic we want (usually the one that was validated)
        # But for the CSV output we check 'constructed_url' and 'final_url'.
        # Let's ensure 'url' key is consistent or removed if confusing.
        # But 'check_service.py' might rely on 'url'.
        # Actually, let's keep 'url' as the "Validated URL" (endpoint).

        if 'is_doc_page' not in final_result:
            final_result['is_doc_page'] = False

        return final_result

    def _construct_probe_url(self, base_url, suffix):
        """
        Constructs the probe URL by appending the suffix to the base URL.
        Handles query parameters and path separators a little better.
        """
        if not suffix:
            return base_url

        if '{endpointURI}' in suffix:
            suffix = suffix.replace('{endpointURI}', '')

        # If suffix is empty after replacement, return base_url
        if not suffix:
            return base_url

        # Special cases where we don't append
        if 'verb=' in suffix and 'verb=' in base_url:
            return base_url
        if base_url.lower().endswith(('.html', '.htm', '.php', '.jsp', '.aspx')) and suffix.startswith('/'):
            return base_url

        separator = '&' if '?' in base_url else '?'
        # If suffix starts with '?', we use the separator logic.
        # If suffix starts with '/', we append it directly (handling double slashes).

        if suffix.startswith('?'):
             return f"{base_url.rstrip('/')}{separator}{suffix.lstrip('?')}"
        elif suffix.startswith('/'):
             return f"{base_url.rstrip('/')}/{suffix.lstrip('/')}"
        else:
             # Default case: assume it's a query param or path segment depending on context
             # The original logic was: constructed_url = f"{final_url.rstrip('/')}{separator if suffix.startswith('?') else '/'}{suffix.lstrip('?/ ')}"
             # Let's replicate that logic but cleaner
             return f"{base_url.rstrip('/')}{separator if suffix.startswith('?') else '/'}{suffix.lstrip('?/ ')}"

    def _check_specific_http(self, response, final_url, config, api_type, is_recovery_attempt, headers_to_use, main_response=None):
        suffix = config['suffix']
        expected_mime = config['accept']

        constructed_url = self._construct_probe_url(final_url, suffix)
        
        request_failed = False
        if constructed_url != final_url:
            try:
                response = requests.get(constructed_url, headers=headers_to_use, timeout=self.timeout)
            except requests.RequestException as e:
                request_failed = True
                return {"valid": False, "error": str(e), "url": constructed_url}
        
        # If status code indicates failure (e.g. 404, 500)
        # We no longer fall back to checking the original URL because we already checked
        # the original URL in `validate_url` *before* getting here.
        if not (200 <= response.status_code < 400):
             pass # Will just be processed as an invalid result below

        is_valid = 200 <= response.status_code < 400
        received_mime = response.headers.get('Content-Type', '').lower()
        
        # --- HTML Based Fallbacks (Decommissioned / Doc Page) for the Constructed/Final URL ---
        is_doc_page = False
        html_classification = self._classify_html_response(response, constructed_url, is_recovery_attempt, expected_mime)
        
        if html_classification:
             is_valid = html_classification.get('valid', False)
             is_doc_page = html_classification.get('is_doc_page', False)
             
             result = {
                 "valid": is_valid, "status_code": response.status_code, "content_type": received_mime,
                 "url": constructed_url, "expected_content_type": expected_mime,
                 "is_doc_page": is_doc_page
             }
             if 'error' in html_classification: result['error'] = html_classification['error']
             if 'note' in html_classification: result['note'] = html_classification['note']
             return result
             
             
        # --- Strict Signature Checking Fallback ---
        # Instead of just checking expected_mime string inclusion, reuse our robust strict matching parser
        if is_valid:
            if not self._is_strict_content_match(response, api_type, config):
                 is_valid = False
                 return {
                     "valid": is_valid, "status_code": response.status_code, "content_type": received_mime,
                     "url": constructed_url, "expected_content_type": expected_mime,
                     "error": f"Invalid Content-Type or Body Signature: expected '{expected_mime}' format for '{api_type}', got '{received_mime}'",
                     "is_doc_page": is_doc_page # Pass the flag even if invalid
                 }

        return {
            "valid": is_valid, "status_code": response.status_code, "content_type": received_mime,
            "url": constructed_url, "expected_content_type": expected_mime,
            "is_doc_page": is_doc_page # Pass the flag
        }

    def _check_generic_http(self, response, final_url):
        is_valid = 200 <= response.status_code < 400
        note = None
        is_doc_page = False # Default for generic check

        html_classification = self._classify_html_response(response, final_url)
        if html_classification:
             is_valid = html_classification.get('valid', False)
             is_doc_page = html_classification.get('is_doc_page', False)
             if 'note' in html_classification: note = html_classification['note']

        result = {
            "valid": is_valid, "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', 'unknown').lower(),
            "url": final_url,
            "is_doc_page": is_doc_page # Pass the flag
        }
        if note: result["note"] = note
        return result
