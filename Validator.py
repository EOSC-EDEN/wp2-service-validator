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
                          'Accept': '*.*',  # initially accept any header
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
                reader = csv.DictReader(infile)
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



    def _check_auth_requirement(self, url):
        """
        Checks if the endpoint requires authentication for the *initial* URL.
        Returns: 'required' if 401/403, 'unknown' if timeout/error, None if no auth required
        """
        try:
            # Use HEAD request for efficiency, but GET is safer for some servers
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            return 'required' if response.status_code in [401, 403] else 'No'
        except requests.RequestException:
            return 'unknown'

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
        text = response.text[:5000].lower()

        patterns = {
            'OAI-PMH': ['<oai-pmh', 'xmlns:oai', 'oai:identifier', '<oai_dc:dc', 'xmlns:oai_dc'],
            'SPARQL': ['<rdf:rdf', 'sparql-results'],
            'OpenAPI': ['"openapi"', 'swagger', '"paths":'],
            'RSS': ['<rss', '<channel'],
            'ATOM': ['<feed', 'xmlns="http://www.w3.org/2005/atom"'],
            'OGC-WMS': ['wms_capabilities', 'service="wms"'],
            'OGC-CSW': ['csw:capabilities', 'service="csw"']
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
        # But if we checked body and it failed, should we still trust CT?
        # User said "as long as one of them is successful".
        # So yes, trust CT if it matches.
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

        # 1. Check auth requirement for the *initial* URL
        auth_required = self._check_auth_requirement(url)

        # Prepare Headers with specific Accept if expected_type is provided
        current_headers = self.headers.copy()
        config = None
        if expected_type and expected_type in self.protocol_configs:
             config = self.protocol_configs.get(expected_type)
             # Construct Accept header with q-values
             # e.g., "application/xml;q=1.0, text/html;q=0.9, */*;q=0.8"
             specific_accept = config.get('accept')
             if specific_accept:
                 # Ensure we have a valid mime type str
                 current_headers['Accept'] = f"{specific_accept};q=1.0, text/html;q=0.9, */*;q=0.8"

        try:
            main_response = requests.get(url, headers=current_headers, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url, "auth_required": auth_required}

        final_url = main_response.url
        
        detected_type = None

        if expected_type:
             # Strict Mode Flow
            if expected_type in self.protocol_configs:
                detected_type = expected_type
                config = self.protocol_configs.get(detected_type)

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

                # --- Step 2: "Magic" / Construction Fallback ---
                # If initial check didn't satisfy strict requirements, try constructing the specific service URL
                self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
                core_result = self._check_specific_http(main_response, final_url, config, detected_type, is_recovery_attempt, main_response=main_response)
            else:
                 return {
                    "valid": False, 
                    "error": f"Unknown Service Type: '{expected_type}'", 
                    "url": url, 
                    "auth_required": auth_required,
                    "final_url": final_url
                }
        else:
            # Enforce Strict Validation: No Auto-Detection Fallback
            return {
                "valid": False,
                "error": "Strict Mode Required: No expected service type provided.",
                "url": url,
                "auth_required": auth_required,
                "final_url": final_url
            }

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

    def _check_specific_http(self, response, final_url, config, api_type, is_recovery_attempt, main_response=None):
        suffix = config['suffix']
        expected_mime = config['accept']

        constructed_url = self._construct_probe_url(final_url, suffix)
        
        request_failed = False
        if constructed_url != final_url:
            try:
                response = requests.get(constructed_url, headers=self.headers, timeout=self.timeout)
            except requests.RequestException as e:
                request_failed = True
                # Fallback: if we have the main_response (initial URL) and it was successful, check if THAT is a doc page.
                if main_response and 200 <= main_response.status_code < 400:
                    self.logger.info(f"Strict check failed for {constructed_url}. Falling back to check original URL {main_response.url} for documentation.")
                    fallback_result = self._check_generic_http(main_response, main_response.url)
                    # If the fallback says it's valid (e.g. Doc Page), return that.
                    if fallback_result.get('valid') and fallback_result.get('is_doc_page'):
                        fallback_result['note'] = f"Strict check failed on '{constructed_url}' ({e}), but original URL seems to be a valid documentation page."
                        fallback_result['failed_url'] = constructed_url
                        return fallback_result

                return {"valid": False, "error": str(e), "url": constructed_url}
        
        # If status code indicates failure (e.g. 404, 500), try fallback to main_response
        if not (200 <= response.status_code < 400):
             if main_response and 200 <= main_response.status_code < 400:
                self.logger.info(f"Strict check returned {response.status_code} for {constructed_url}. Falling back to check original URL {main_response.url} for documentation.")
                fallback_result = self._check_generic_http(main_response, main_response.url)
                if fallback_result.get('valid') and fallback_result.get('is_doc_page'):
                    fallback_result['note'] = f"Strict check failed on '{constructed_url}' (Status {response.status_code}), but original URL seems to be a valid documentation page."
                    fallback_result['failed_url'] = constructed_url
                    return fallback_result

        is_valid = 200 <= response.status_code < 400
        received_mime = response.headers.get('Content-Type', '').lower()
        
        # --- API Documentation Page Detection (Smart Recovery) for the Constructed/Final URL ---
        is_doc_page = False
        if is_valid and expected_mime and 'application/json' in expected_mime and 'text/html' in received_mime and not is_recovery_attempt:
            self.logger.info(f"Attempting smart recovery for {final_url}: Expected JSON, got HTML.")
            response_text_lower = response.text.lower()
            
            if any(keyword in response_text_lower for keyword in self.api_doc_keywords):
                is_doc_page = True
                self.logger.info(f"Detected API documentation page on {final_url}. Marking as INVALID (Documentation Page).")
                return {
                    "valid": False, "status_code": response.status_code, "content_type": received_mime,
                    "url": constructed_url, "expected_content_type": expected_mime,
                    "note": "Invalid endpoint: Received HTML (API documentation page) instead of JSON. Status 200 OK suggests service is likely active but URL is not a direct service endpoint.",
                    "is_doc_page": True # Explicitly set here
                }
        
        # --- Standard MIME Type Mismatch ---
        if is_valid and expected_mime and not any(t in received_mime for t in expected_mime.split(',')):
            is_valid = False
            return {
                "valid": is_valid, "status_code": response.status_code, "content_type": received_mime,
                "url": constructed_url, "expected_content_type": expected_mime,
                "error": f"Invalid Content-Type: expected '{expected_mime}', got '{received_mime}'",
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

        if is_valid and 'text/html' in response.headers.get('Content-Type', '').lower():
            response_text_lower = response.text.lower()
            if any(keyword in response_text_lower for keyword in self.decommissioned_keywords):
                is_valid = False
                note = "Endpoint is a documentation page for a decommissioned/migrated service."
                self.logger.warning(f"Detected decommissioned service page at {final_url}.")
            else:
                # Also check for general API documentation pages in generic HTML responses
                if any(keyword in response_text_lower for keyword in self.api_doc_keywords):
                    is_doc_page = True
                    is_valid = False # Mark as invalid because it's a doc page, not a service endpoint
                    note = "Invalid endpoint: Received HTML (API documentation page). Status 200 OK suggests service is likely active."
                    self.logger.info(f"Detected API documentation page in generic HTML response at {final_url}.")


        result = {
            "valid": is_valid, "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', 'unknown').lower(),
            "url": final_url,
            "is_doc_page": is_doc_page # Pass the flag
        }
        if note: result["note"] = note
        return result

