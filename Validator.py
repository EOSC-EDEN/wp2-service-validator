import requests
import os
import csv
import logging
import json
import ftplib
import urllib.parse

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
                        suffix = row.get('default query', '').strip()
                        accept = row.get('accept', '').strip()
                        
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



    def _classify_html_response(self, response, url, expected_mime=None):
        """
        Scans a text/html response for decommissioned or documentation keywords.
        Returns a dict with 'valid', 'is_doc_page', and optional 'note' and 'error'
        values that the caller should use to override its default validation results.
        Returns None if it's just generic HTML and standard validation should continue.

        Note: doc-page detection is always active. In earlier designs there was an
        'is_recovery_attempt' flag here that skipped doc-page detection on fallback
        requests, but that concept is no longer used in the current call graph.
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

        # 2. Check for API documentation page (always checked; doc pages are never valid service endpoints)
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

    def _is_http_wrapped_ftp(self, response):
        """
        Returns True if an HTTP response looks like an FTP-style directory listing
        served over HTTP (e.g. Apache mod_autoindex or a web-fronted FTP archive).
        These pages have Content-Type text/html but contain characteristic FTP-index
        markers in the body.  They are NOT valid FTP endpoints.
        """
        received_mime = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in received_mime:
            return False
        text = response.text[:50000].lower()
        ftp_html_markers = [
            'index of /', 'ftp directory', '[to parent directory]', 'parent directory'
        ]
        return any(marker in text for marker in ftp_html_markers)

    def _validate_ftp_url(self, url, expected_type=None):
        """
        Validates a real ftp:// URL using ftplib.

        Note on status codes: FTP uses its own 3-digit reply-code system (e.g. 220
        for service ready, 230 for login OK, 550 for no such file).  These are NOT
        HTTP status codes.  To keep the result dict consistent with the rest of the
        validator we synthesise HTTP-like values: 200 for a successful connection /
        directory listing, and 550 (borrowing the FTP 'file unavailable' reply code
        as the closest meaningful analog) for a failed one.
        """
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 21
        path = parsed.path or '/'

        base_result = {
            "url": url,
            "redirected_url": "",
            "constructed_url": "",
            "content_type": "ftp",
            "expected_content_type": "ftp",
            "is_doc_page": False,
            "had_redirect": False,
            "redirects": [],
            "redirect_chain": "",
        }

        # Determine auth requirement from URL credentials
        if parsed.username and parsed.username.lower() != 'anonymous':
            auth_required = 'Yes'
        else:
            auth_required = 'No'
        base_result['auth_required'] = auth_required

        try:
            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(host, port)
            ftp.login()  # anonymous login; credentials in URL are intentionally ignored for now
            try:
                ftp.nlst(path)  # list the target path to confirm it exists
            except ftplib.error_perm as list_err:
                # 550 = No such file or directory — path doesn't exist but server is up
                self.logger.warning(f"FTP path '{path}' not found on {host}: {list_err}")
                ftp.quit()
                return {
                    **base_result,
                    "valid": False,
                    "status_code": 550,  # synthesised: FTP 'file unavailable' reply code
                    "error": f"FTP path not found: {list_err}",
                }
            ftp.quit()
            self.logger.info(f"FTP connection and directory listing succeeded for {url}")
            return {
                **base_result,
                "valid": True,
                "status_code": 200,  # synthesised: represents a successful FTP connection + listing
                "note": "FTP endpoint validated: anonymous connection and directory listing succeeded.",
            }

        except ftplib.error_perm as e:
            # 530 = login incorrect / authentication required
            code = str(e)[:3]
            if code == '530':
                self.logger.info(f"FTP server at {host} requires authentication.")
                return {
                    **base_result,
                    "valid": False,
                    "status_code": 550,  # synthesised
                    "auth_required": "Yes",
                    "error": f"FTP authentication required: {e}",
                }
            return {
                **base_result,
                "valid": False,
                "status_code": 550,  # synthesised
                "error": f"FTP permission error: {e}",
            }
        except ftplib.all_errors as e:
            self.logger.warning(f"FTP connection failed for {url}: {e}")
            return {
                **base_result,
                "valid": False,
                "status_code": 550,  # synthesised
                "error": f"FTP connection error: {e}",
            }

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
            # FTP and NetCDF use text/html (too generic to trust alone) -- see require_both below.
            # FTP: only FTP-specific phrases; generic terms like 'name'/'size'/'last modified'
            # were removed as they also appear on plain directory listing pages.
            'FTP': ['index of /', 'ftp directory', '[to parent directory]', 'parent directory'],
            # NetCDF/OPeNDAP dataset pages expose these characteristic identifiers:
            'NetCDF': ['opendap', 'thredds', 'netcdf', '.nc"', 'das', 'dds'],
        }

        type_patterns = patterns.get(expected_type, [])
        if type_patterns:
            if any(p in text for p in type_patterns):
                body_match = True
                self.logger.info(f"Strict match confirmed via body signature for '{expected_type}'.")
            else:
                self.logger.debug(f"Body signature match failed for '{expected_type}'.")

        # Validation Logic:
        # Most types: either a CT match OR a body signature match is sufficient.
        # However, some types use a generic accept type (e.g. text/html for FTP and NetCDF)
        # that would match virtually any web page. For these, we require BOTH conditions
        # to be true simultaneously to avoid false positives.
        require_both = {'FTP', 'NetCDF'}

        if expected_type in require_both:
            # Strict: both CT and body must match
            if ct_match and body_match:
                return True
            if ct_match and not body_match:
                self.logger.debug(f"'{expected_type}' requires body signature confirmation (generic accept type), but body check failed.")
            return False

        # Standard "either/or" logic for all other types:
        # If body matches, trust it even if CT is ambiguous (handles misconfigured servers).
        if body_match:
            return True

        # If CT matches and body check wasn't performed or wasn't needed, trust CT.
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

        # Check Expected Type First — abort early to avoid unnecessary network requests (SV-REQ-001)
        if not expected_type:
            return {
                "valid": False,
                "error": "Strict Mode Required: No expected service type provided.",
                "url": url,
                "auth_required": "Unknown",
                "redirected_url": url
            }

        if expected_type not in self.protocol_configs:
            return {
                "valid": False,
                "error": f"Unknown Service Type: '{expected_type}'",
                "url": url,
                "auth_required": "Unknown",
                "redirected_url": url
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

        # Route real ftp:// URLs to the dedicated FTP validator — requests cannot handle them.
        if url.lower().startswith('ftp://'):
            return self._validate_ftp_url(url, expected_type)

        try:
            main_response = requests.get(url, headers=current_headers, timeout=self.timeout, allow_redirects=True)
            
            # Derive Auth Requirement from the request chain.
            # Values follow the spec: 'Yes' | 'No' | 'Unknown'.
            auth_required = 'No'
            if main_response.status_code in [401, 403]:
                auth_required = 'Yes'
            # Note: The requests library may append a 401/403 to the history before
            # following a redirect on certain servers. We check the first history entry
            # as a safeguard, even though we never supply credentials ourselves.
            elif main_response.history and main_response.history[0].status_code in [401, 403]:
                auth_required = 'Yes'
                 
        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url, "auth_required": "Unknown"}

        final_url = main_response.url
        detected_type = expected_type

        # --- Step 0: HTTP-Wrapped FTP Detection ---
        # For FTP-type endpoints, detect the common case where a server exposes its FTP
        # archive as an HTML directory listing over HTTP (e.g. Apache mod_autoindex).
        # This check runs first so the response is never counted as a valid FTP endpoint.
        if expected_type == 'FTP' and self._is_http_wrapped_ftp(main_response):
            self.logger.info(f"URL '{final_url}' is an HTTP-wrapped FTP directory listing. Marking as invalid.")
            return {
                "valid": False,
                "status_code": main_response.status_code,
                "content_type": main_response.headers.get('Content-Type', '').lower(),
                "url": url,
                "redirected_url": final_url,
                "constructed_url": "",
                "expected_content_type": config.get('accept'),
                "auth_required": auth_required,
                "is_doc_page": False,
                "redirects": self._build_redirect_chain_info(main_response),
                "had_redirect": bool(main_response.history),
                "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in self._build_redirect_chain_info(main_response)]),
                "note": (
                    "Invalid FTP endpoint: URL returns an HTTP-wrapped FTP directory listing "
                    "(text/html served over HTTP), not a true FTP endpoint. "
                    "If an ftp:// URL is available, register that instead."
                ),
            }

        # --- Step 1: Doc Page / Decommissioned Check ---
        # This MUST run before the strict content match. A documentation page about a technology
        # (e.g. a page describing NetCDF/OPeNDAP) will naturally contain the same keywords we scan
        # for in body signatures, causing false positives if we check body patterns first.
        # By classifying HTML pages here first, we ensure that any page that looks like a doc or
        # decommissioned notice is rejected immediately, before the body signature check can fire.
        initial_html_classification = self._classify_html_response(main_response, final_url, expected_mime=config.get('accept'))
        if initial_html_classification:
            self.logger.info(f"Initial URL '{final_url}' was classified as an invalid HTML page (Doc/Decommissioned). Skipping strict match and magic URL construction.")
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

        # --- Step 2: Strict Initial Check ---
        # Only reached if the response was NOT identified as a doc/decommissioned page above.
        # Check if the repository is already giving us what we want on the base URL.
        elif 200 <= main_response.status_code < 400:
            if self._is_strict_content_match(main_response, expected_type, config):
                self.logger.info(f"Initial URL '{final_url}' strictly matches expected type '{expected_type}'. Skipping construction logic.")

                redirect_chain_list = self._build_redirect_chain_info(main_response)

                return {
                    "valid": True,
                    "status_code": main_response.status_code,
                    "content_type": main_response.headers.get('Content-Type', '').lower(),
                    "url": url, # Original URL was valid
                    "redirected_url": final_url,
                    "constructed_url": '', # No construction needed
                    "expected_content_type": config.get('accept'),
                    "auth_required": auth_required,
                    "note": "Initial URL validation successful.",
                    "redirects": redirect_chain_list,
                    "had_redirect": bool(redirect_chain_list),
                    "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list]),
                    "is_doc_page": False
                }

            # --- Step 3: "Magic" / Construction Fallback ---
            # Strict match failed and it's not a doc/decommissioned page.
            # Try constructing the specific service URL by appending the known suffix.
            else:
                self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
                core_result = self._check_specific_http(main_response, final_url, config, detected_type, is_recovery_attempt, current_headers, main_response=main_response)

        else:
            # Non-2xx/3xx response and not an HTML doc page — pass through to magic URL construction.
            self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
            core_result = self._check_specific_http(main_response, final_url, config, detected_type, is_recovery_attempt, current_headers, main_response=main_response)

        # --- Assemble the final, complete result dictionary ---
        final_result = core_result.copy()

        final_result['auth_required'] = auth_required

        redirect_chain_list = self._build_redirect_chain_info(main_response)
        final_result['redirects'] = redirect_chain_list
        final_result['had_redirect'] = bool(redirect_chain_list)
        final_result['redirect_chain'] = " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list])

        # Handle URL keys for consistent output.
        # 'constructed_url' is only set when URL construction/magic was used.
        # 'redirected_url' is only set when at least one redirect actually occurred.
        # Both are empty strings when not applicable, making them easy to filter on in the CSV.
        constructed_url = final_result.get('url', '')
        final_result['constructed_url'] = constructed_url if constructed_url and constructed_url != final_url else ''
        final_result['redirected_url'] = final_url if bool(redirect_chain_list) else ''

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

        if constructed_url != final_url:
            # A new, more specific URL was constructed — make a fresh request against it.
            try:
                response = requests.get(constructed_url, headers=headers_to_use, timeout=self.timeout)
            except requests.RequestException as e:
                return {"valid": False, "error": str(e), "url": constructed_url}
        # else: constructed_url == final_url means the suffix was empty and no new URL
        # could be built. We fall through using the `response` object that was passed in
        # (the original response from validate_url). This avoids a redundant request and
        # will naturally produce an invalid result since the initial strict check already failed.

        is_valid = 200 <= response.status_code < 400
        received_mime = response.headers.get('Content-Type', '').lower()

        # --- HTML Based Fallbacks (Decommissioned / Doc Page) for the Constructed/Final URL ---
        is_doc_page = False
        html_classification = self._classify_html_response(response, constructed_url, expected_mime)
        
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
                 # Distinguish between a CT mismatch and a body-signature failure.
                 # For 'require_both' types (FTP, NetCDF) the CT matches but body patterns may not,
                 # which previously produced the confusing message "expected text/html, got text/html".
                 # For FTP specifically, accept is empty (ftp:// URLs use ftplib, not HTTP CT matching),
                 # so a plain "expected '' for 'FTP'" message would be cryptic.
                 ct_actually_matched = (
                     received_mime and expected_mime and
                     any(t.strip() in received_mime for t in expected_mime.split(','))
                 )
                 if ct_actually_matched:
                     err = (f"Body signature check failed for '{api_type}': Content-Type '{received_mime}' matched, "
                            f"but response body did not contain expected service-specific markers.")
                 elif not expected_mime and api_type == 'FTP':
                     err = (f"Invalid FTP endpoint: URL returned '{received_mime}' over HTTP but does not appear to be "
                            f"an HTTP-wrapped FTP directory listing. "
                            f"Use an ftp:// URL for a real FTP server, or verify the URL is correct.")
                 else:
                     err = f"Invalid Content-Type: expected '{expected_mime}' for '{api_type}', got '{received_mime}'."
                 return {
                     "valid": is_valid, "status_code": response.status_code, "content_type": received_mime,
                     "url": constructed_url, "expected_content_type": expected_mime,
                     "error": err,
                     "is_doc_page": is_doc_page
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

        html_classification = self._classify_html_response(response, final_url)  # no expected_mime for generic check
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
