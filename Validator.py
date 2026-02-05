import requests
import ftplib
from urllib.parse import urlparse, urljoin
import os
import csv
from lxml import html
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
            'User-Agent': 'EDEN-Endpoint-Validator/1.0'
        }
        self.protocol_configs = self._load_service_mappings()

    def _load_service_mappings(self):
        """Loads the service mappings from the CSV file."""
        mappings = {}
        csv_path = os.path.join(os.path.dirname(__file__), 'services_default_queries.csv')
        try:
            with open(csv_path, mode='r', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    api_type = row.get('Acronym') # Use Acronym as key, not Type
                    if api_type and api_type.strip():
                        mappings[api_type] = {
                            'suffix': row.get('default query', ''),
                            'accept': row.get('accept', '')
                        }
        except FileNotFoundError:
            self.logger.error(f"Fatal: Service mapping file not found at {csv_path}")
        return mappings

    def _detect_api_type_from_response(self, response, final_url):
        """
        Multi-stage detection. Returns a tuple: (detected_type, detection_method)
        """
        # Stage 1: URL patterns (using the final_url)
        detected = self._detect_from_url_patterns(final_url)
        if detected:
            self.logger.info(f"API type '{detected}' detected from final URL patterns.")
            return detected, 'url_pattern'

        # Stage 2: Response headers
        detected = self._detect_api_type_from_headers(response)
        if detected:
            self.logger.info(f"API type '{detected}' detected from response headers.")
            return detected, 'headers'

        # Stage 3: Response body content
        detected = self._sniff_api_type_from_body(response)
        if detected:
            self.logger.info(f"API type '{detected}' detected from response body content.")
            return detected, 'body_sniffing'

        self.logger.info("No API type detected through any method.")
        return None, None

    def _detect_from_url_patterns(self, url):
        """
        Stage 1: Fast pattern matching based on URL structure.
        """
        url_lower = url.lower()

        if 'oai' in url_lower:
            if 'verb=' in url_lower:
                return 'OAI-PMH'
            if url_lower.endswith('/oai') or '/oai/' in url_lower:
                return 'OAI-PMH'

        if 'service=csw' in url_lower and 'request=getcapabilities' in url_lower:
            return 'OGC-CSW'

        if 'service=wms' in url_lower and 'request=getcapabilities' in url_lower:
            return 'OGC-WMS'

        if '/sparql' in url_lower:
            return 'SPARQL'

        if '/swagger' in url_lower or '/openapi' in url_lower:
            return 'OpenAPI'

        if '/api/' in url_lower or '/rest_api' in url_lower:
            return 'REST'

        if url_lower.endswith(('.rss', '.xml')):
            return 'RSS'

        if url_lower.endswith('/atom') or url_lower.endswith('/atom.xml'):
            return 'ATOM'

        return None

    def _detect_api_type_from_headers(self, response):
        """
        Stage 2: Analyze response headers from a requests.Response object.
        """
        content_type = response.headers.get('Content-Type', '').lower()
        server = response.headers.get('Server', '').lower()

        self.logger.debug(f"Header analysis for {response.url}: Content-Type='{content_type}', Server='{server}'")

        if 'application/xml' in content_type or 'text/xml' in content_type:
            return 'OAI-PMH'

        if 'rdf+xml' in content_type or 'ld+json' in content_type:
            return 'SPARQL'

        if 'application/json' in content_type:
            return 'REST'

        if 'application/rss+xml' in content_type:
            return 'RSS'

        if 'application/atom+xml' in content_type:
            return 'ATOM'
        # NOTE: circular reasoning:
        # For example, when we detect 'REST', ee look up its configuration in services_default_queries.csv.
        # That configuration primarily tells the validator to expect application/json.
        # So, the logic becomes slightly circular: Header says JSON -> We guess REST -> Config for REST says to expect JSON -> We confirm it's JSON.
        # label might be inaccurate, however, the validator's primary goal —to confirm that the endpoint is active and
        # serves machine-readable data—has been successfully met. The harm is minimal, but this should be improved

        return None

    def _sniff_api_type_from_body(self, response):
        """
        Stage 3: Inspect response body for distinctive patterns and markers.
        """
        try:
            # Only read a portion of the text to avoid memory issues with large responses
            text = response.text[:5000].lower()

            self.logger.debug(f"Body sniffing for {response.url}: checking content patterns...")

            patterns = {
                'OAI-PMH': ['<oai-pmh>', 'oai:identifier', 'oai:metadata'],
                'SPARQL': ['<rdf:rdf', 'sparql', 'rdf+xml'],
                'OpenAPI': ['"openapi"'],
                'RSS': ['<rss', '<channel', '<item'],
                'ATOM': ['<feed', 'xmlns="http://www.w3.org/2005/atom"']
            }

            for api_type, markers in patterns.items():
                if any(marker in text for marker in markers):
                    return api_type

            return None

        except Exception as e: # Catch any error during text processing
            self.logger.debug(f"Error during body sniffing for {response.url}: {e}")
            return None

    def _check_auth_requirement(self, url):
        """
        Checks if the endpoint requires authentication for the *initial* URL.
        Returns: 'required' if 401/403, 'unknown' if timeout/error, None if no auth required
        """
        try:
            # Use HEAD request for efficiency, but GET is safer for some servers
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 401:
                return 'required'
            elif response.status_code == 403:
                return 'required'
            return None
        except requests.RequestException as e:
            self.logger.debug(f"Could not determine auth requirement for {url}: {e}")
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

    def validate_url(self, url, is_recovery_attempt=False):
        """
        Validates a URL using automatic API type detection only.
        """
        if not url:
            return {"valid": False, "error": "Empty URL"}

        # 1. Check auth requirement for the *initial* URL (without following redirects)
        auth_required = self._check_auth_requirement(url)

        # 2. Make the primary HTTP request, allowing redirects
        try:
            main_response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            final_url = main_response.url
            status_code = main_response.status_code
            content_type = main_response.headers.get('Content-Type', '').lower()
        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url} # Return early on request failure

        # 3. Perform API type detection on the *final_url* and its response content
        detected_type, detection_method = self._detect_api_type_from_response(main_response, final_url)
        api_type = detected_type # Use detected type for subsequent config lookup

        # 4. Determine validation path based on detected API type
        if (api_type and api_type.upper() == 'FTP') or final_url.startswith('ftp://'):
            # FTP check needs to be adapted for final_url, or handled separately if initial was FTP
            # For now, if final_url is FTP, we'll treat it as such.
            result = self._check_ftp(final_url)
        else:
            config = self.protocol_configs.get(api_type)
            if config:
                result = self._check_specific_http_from_response(main_response, final_url, config, api_type, is_recovery_attempt)
            else:
                result = self._check_generic_http_from_response(main_response, final_url)

        # 5. Populate the final result dictionary
        result['detected_api_type'] = detected_type if detected_type else 'N/A'
        if detection_method:
            result['detection_method'] = detection_method
        if auth_required:
            result['auth_required'] = auth_required
        
        # Ensure final_url and redirect chain are correctly added
        result['final_url'] = final_url
        result['redirects'] = self._build_redirect_chain_info(main_response) # This needs to be called here

        return result

    def _check_specific_http_from_response(self, response, final_url, config, api_type, is_recovery_attempt):
        """
        Handles validation using the extracted default queries, given a pre-fetched response.
        """
        suffix = config['suffix']
        expected_mime = config['accept']

        if suffix and '{endpointURI}' in suffix:
            suffix = suffix.replace('{endpointURI}', '')

        target_url = final_url # Start with the final URL from the initial request

        # If a suffix is defined, we might need to construct a *new* target_url for the specific check
        # This means we might make a *second* request if the suffix needs to be applied.
        # This is a complex interaction. Let's simplify: if a suffix is defined, we assume the initial request was to the base.
        # If the initial request already redirected, and we have a suffix, we should apply the suffix to the final_url.
        
        # Re-evaluate target_url construction based on final_url and suffix
        constructed_url_for_check = final_url # Default to final_url if no suffix applied
        if suffix:
            # Heuristic: If the suffix adds a 'verb=' param (common in OAI), 
            # and the final_url already has one, assume the user provided a full query.
            if 'verb=' in suffix and 'verb=' in final_url:
                constructed_url_for_check = final_url
            # Avoid appending path suffixes to file-like URLs (e.g. index.html)
            elif final_url.lower().endswith(('.html', '.htm', '.php', '.jsp', '.aspx')) and suffix.startswith('/'):
                constructed_url_for_check = final_url
            else:
                if suffix.startswith('?'):
                    separator = '&' if '?' in final_url else '?'
                    constructed_url_for_check = f"{final_url}{separator}{suffix.lstrip('?')}"
                elif suffix.startswith('/'):
                    constructed_url_for_check = urljoin(final_url, suffix)
                else:
                    constructed_url_for_check = f"{final_url.rstrip('/')}/{suffix.lstrip('/')}"
        
        # If the constructed_url_for_check is different from the final_url, we need to make another request
        if constructed_url_for_check != final_url:
            try:
                response = requests.get(constructed_url_for_check, headers=self.headers, timeout=self.timeout)
            except requests.RequestException as e:
                return {"valid": False, "error": str(e), "url": constructed_url_for_check}
        else:
            # Otherwise, use the response we already have
            response = response

        is_valid = 200 <= response.status_code < 400
        received_mime = response.headers.get('Content-Type', '').lower()
        mime_warning = None
        match_found = True

        if is_valid and expected_mime:
            accepted_types = [t.strip().lower() for t in expected_mime.split(',')]
            match_found = any(t in received_mime for t in accepted_types)

            if not match_found:
                if 'application/json' in expected_mime and 'text/html' in received_mime and not is_recovery_attempt:
                    self.logger.info(f"Attempting smart recovery for {final_url}: Expected JSON, got HTML.")
                    try:
                        self.logger.info(f"HTML Snippet (first 500 chars): {response.text[:500]}")
                        doc = html.fromstring(response.text)
                        all_links = doc.xpath('//a/@href')
                        self.logger.info(f"All links found on page: {all_links}")
                        json_links = doc.xpath('//a[contains(@href, ".json")]/@href')
                        self.logger.info(f"Found potential JSON links: {json_links}")

                        if json_links:
                            recovery_url = urljoin(response.url, json_links[0])
                            self.logger.info(f"Attempting to validate recovery URL: {recovery_url}")
                            # Recursive call to validate_url with the new recovery URL
                            recovery_result = self.validate_url(recovery_url, is_recovery_attempt=True)
                            if recovery_result.get('valid'):
                                recovery_result['note'] = f"Recovered from HTML page; original URL was {final_url}"
                                self.logger.info(f"Smart recovery SUCCESS for {final_url} via {recovery_url}")
                                return recovery_result
                            else:
                                self.logger.warning(
                                    f"Smart recovery FAILED for {final_url} via {recovery_url}: {recovery_result.get('error', 'Unknown error')}")
                        else:
                            self.logger.info(f"No JSON links found on HTML page for {final_url}.")
                            response_text_lower = response.text.lower()
                            if 'swagger-ui' in response_text_lower or 'id="swagger-ui"' in response_text_lower or 'rest api' in response_text_lower:
                                self.logger.info(
                                    f"Detected API documentation page on {final_url}. Marking as valid (content unverified).")
                                return {
                                    "valid": True, "status_code": response.status_code, "content_type": received_mime,
                                    "url": constructed_url_for_check, "expected_content_type": expected_mime,
                                    "note": "Received HTML (likely an API documentation page) instead of JSON. Status 200 OK suggests service is active."
                                }
                    except Exception as e:
                        self.logger.error(f"Error during smart recovery for {final_url}: {e}")

                is_valid = False
                mime_warning = f"Invalid Content-Type: expected '{expected_mime}', got '{received_mime}'"

        result = {
            "valid": is_valid,
            "status_code": response.status_code,
            "content_type": received_mime,
            "url": constructed_url_for_check, # This is the URL that was actually requested for this specific check
            "expected_content_type": expected_mime if expected_mime else None
        }

        if mime_warning:
            result["error"] = mime_warning

        return result

    def _check_generic_http_from_response(self, response, final_url):
        """
        Standard GET for types without specific path requirements, given a pre-fetched response.
        """
        is_valid = 200 <= response.status_code < 400
        note = None

        if is_valid and 'text/html' in response.headers.get('Content-Type', '').lower():
            decommissioned_keywords = ['no longer accessible', 'migrated to', 'decommissioned']
            response_text_lower = response.text.lower()
            if any(keyword in response_text_lower for keyword in decommissioned_keywords):
                is_valid = False
                note = "Endpoint is a documentation page for a decommissioned/migrated service."
                self.logger.warning(f"Detected decommissioned service page at {final_url}.")

        result = {
            "valid": is_valid,
            "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', 'unknown').lower(),
            "url": final_url # For generic, the URL is the final_url
        }
        
        if note:
            result["note"] = note

        return result

    def _check_ftp(self, url):
        """
        Validates FTP endpoints.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port if parsed.port else 21

        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login()
            ftp.quit()
            return {"valid": True, "status_code": 220}
        except Exception as e:
            return {"valid": False, "error": str(e)}