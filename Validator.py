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
        if 'oai' in url_lower and ('verb=' in url_lower or url_lower.endswith('/oai') or '/oai/' in url_lower):
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
        if 'application/xml' in content_type or 'text/xml' in content_type: return 'OAI-PMH'
        if 'rdf+xml' in content_type or 'ld+json' in content_type: return 'SPARQL'
        if 'application/json' in content_type: return 'REST'
        if 'application/rss+xml' in content_type: return 'RSS'
        if 'application/atom+xml' in content_type: return 'ATOM'
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
                'OAI-PMH': ['<oai-pmh>', 'oai:identifier'],
                'SPARQL': ['<rdf:rdf', 'sparql'],
                'OpenAPI': ['"openapi"'],
                'RSS': ['<rss', '<channel'],
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

    def validate_url(self, url, is_recovery_attempt=False, expected_type=None):
        """
        Validates a URL.
        If expected_type is provided, it strictly checks against that type.
        Otherwise, it attempts automatic API type detection.
        """
        if not url:
            return {"valid": False, "error": "Empty URL"}

        # 1. Check auth requirement for the *initial* URL (without following redirects)
        auth_required = self._check_auth_requirement(url)

        try:
            main_response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url, "auth_required": auth_required}

        final_url = main_response.url
        
        detected_type = None
        detection_method = None
        
        if expected_type:
             # Strict Mode: Use the provided type directly
            if expected_type in self.protocol_configs:
                detected_type = expected_type
                detection_method = 'manual_strict'
                config = self.protocol_configs.get(detected_type)
                core_result = self._check_specific_http(main_response, final_url, config, detected_type, is_recovery_attempt)
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
        
        # final_result['detected_api_type'] = detected_type if detected_type else 'N/A'
        # final_result['detection_method'] = detection_method if detection_method else 'N/A'
        final_result['auth_required'] = auth_required

        redirect_chain_list = self._build_redirect_chain_info(main_response)
        final_result['redirects'] = redirect_chain_list
        final_result['had_redirect'] = bool(redirect_chain_list)
        final_result['redirect_chain'] = " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list])

        constructed_url = final_result.pop('url', url) # Pop ambiguous 'url' key
        final_result['constructed_url'] = constructed_url if constructed_url != url else ''
        final_result['final_url'] = final_url

        # This flag is set within _check_specific_http or _check_generic_http
        # We ensure it's always present
        if 'is_doc_page' not in final_result:
            final_result['is_doc_page'] = False

        return final_result

    def _check_specific_http(self, response, final_url, config, api_type, is_recovery_attempt):
        suffix = config['suffix']
        expected_mime = config['accept']

        if suffix and '{endpointURI}' in suffix:
            suffix = suffix.replace('{endpointURI}', '')

        constructed_url = final_url
        if suffix:
            if 'verb=' in suffix and 'verb=' in final_url:
                pass
            elif final_url.lower().endswith(('.html', '.htm', '.php', '.jsp', '.aspx')) and suffix.startswith('/'):
                pass
            else:
                separator = '&' if '?' in final_url else '?'
                constructed_url = f"{final_url.rstrip('/')}{separator if suffix.startswith('?') else '/'}{suffix.lstrip('?/ ')}"
        
        if constructed_url != final_url:
            try:
                response = requests.get(constructed_url, headers=self.headers, timeout=self.timeout)
            except requests.RequestException as e:
                return {"valid": False, "error": str(e), "url": constructed_url}
        
        is_valid = 200 <= response.status_code < 400
        received_mime = response.headers.get('Content-Type', '').lower()
        
        # --- API Documentation Page Detection (Smart Recovery) ---
        is_doc_page = False
        if is_valid and expected_mime and 'application/json' in expected_mime and 'text/html' in received_mime and not is_recovery_attempt:
            self.logger.info(f"Attempting smart recovery for {final_url}: Expected JSON, got HTML.")
            response_text_lower = response.text.lower()
            
            # Expanded list of keywords for API documentation pages
            api_doc_keywords = [
                'swagger-ui', 'id="swagger-ui"', 'rest api', 'api documentation', 'api reference',
                'developer guide', 'endpoints', 'usage guide', 'how to use', 'getting started',
                'authentication', 'rate limits', 'data formats', 'query parameters', 'response codes',
                'error handling', 'sdk', 'client library', 'restful api', 'soap api', 'graphql api',
                'openapi specification', 'wsdl', 'asyncapi', 'raml', 'api console', 'postman',
                'curl', 'example request', 'example response'
            ]
            
            if any(keyword in response_text_lower for keyword in api_doc_keywords):
                is_doc_page = True
                self.logger.info(f"Detected API documentation page on {final_url}. Marking as valid (content unverified).")
                return {
                    "valid": True, "status_code": response.status_code, "content_type": received_mime,
                    "url": constructed_url, "expected_content_type": expected_mime,
                    "note": "Received HTML (likely an API documentation page) instead of JSON. Status 200 OK suggests service is active.",
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
            decommissioned_keywords = [
                'no longer accessible', 'migrated to', 'decommissioned', 'service unavailable',
                'discontinued', 'retired', 'deprecated', 'shut down', 'end of life',
                'not available', 'moved to', 'new location'
            ]
            response_text_lower = response.text.lower()
            if any(keyword in response_text_lower for keyword in decommissioned_keywords):
                is_valid = False
                note = "Endpoint is a documentation page for a decommissioned/migrated service."
                self.logger.warning(f"Detected decommissioned service page at {final_url}.")
            else:
                # Also check for general API documentation pages in generic HTML responses
                api_doc_keywords = [
                    'swagger-ui', 'id="swagger-ui"', 'rest api', 'api documentation', 'api reference',
                    'developer guide', 'endpoints', 'usage guide', 'how to use', 'getting started',
                    'authentication', 'rate limits', 'data formats', 'query parameters', 'response codes',
                    'error handling', 'sdk', 'client library', 'restful api', 'soap api', 'graphql api',
                    'openapi specification', 'wsdl', 'asyncapi', 'raml', 'api console', 'postman',
                    'curl', 'example request', 'example response'
                ]
                if any(keyword in response_text_lower for keyword in api_doc_keywords):
                    is_doc_page = True
                    note = "Received HTML (likely an API documentation page). Status 200 OK suggests service is active."
                    self.logger.info(f"Detected API documentation page in generic HTML response at {final_url}.")


        result = {
            "valid": is_valid, "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', 'unknown').lower(),
            "url": final_url,
            "is_doc_page": is_doc_page # Pass the flag
        }
        if note: result["note"] = note
        return result

    def _check_ftp(self, url):
        parsed = urlparse(url)
        try:
            with ftplib.FTP(host=parsed.hostname, timeout=self.timeout) as ftp:
                ftp.login()
                return {"valid": True, "status_code": 220, "url": url, "is_doc_page": False}
        except Exception as e:
            return {"valid": False, "error": str(e), "url": url, "is_doc_page": False}