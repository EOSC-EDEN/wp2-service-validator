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
                    api_type = row.get('Type')
                    if api_type and api_type.strip():
                        mappings[api_type] = {
                            'suffix': row.get('default query', ''),
                            'accept': row.get('accept', '')
                        }
        except FileNotFoundError:
            self.logger.error(f"Fatal: Service mapping file not found at {csv_path}")
        return mappings

    def _detect_api_type(self, url):
        """
        Multi-stage detection: URL patterns → Response headers → Body content → None
        """
        detected = self._detect_from_url_patterns(url)
        if detected:
            self.logger.info(f"API type '{detected}' detected from URL patterns.")
            return detected

        detected = self._detect_api_type_from_headers(url)
        if detected:
            self.logger.info(f"API type '{detected}' detected from response headers.")
            return detected

        detected = self._sniff_api_type_from_body(url)
        if detected:
            self.logger.info(f"API type '{detected}' detected from response body content.")
            return detected

        self.logger.info("No API type detected through any method.")
        return None

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

    def _detect_api_type_from_headers(self, url):
        """
        Stage 2: Analyze response headers from a HEAD request.
        """
        try:
            response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '').lower()
            server = response.headers.get('Server', '').lower()

            self.logger.debug(f"Header analysis for {url}: Content-Type='{content_type}', Server='{server}'")

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

            return None

        except requests.RequestException as e:
            self.logger.debug(f"HEAD request failed for {url}: {e}")
            return None

    def _sniff_api_type_from_body(self, url):
        """
        Stage 3: Inspect response body for distinctive patterns and markers.
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            text = response.text[:5000].lower()

            self.logger.debug(f"Body sniffing for {url}: checking content patterns...")

            patterns = {
                'OAI-PMH': ['<oai-pmh>', 'oai:identifier', 'oai:metadata'],
                'SPARQL': ['<rdf:rdf', 'sparql', 'rdf+xml'],
                'OpenAPI': ['"openapi"'],
                'REST': ['"', '{}', '[]'],
                'RSS': ['<rss', '<channel', '<item'],
                'ATOM': ['<feed', 'xmlns="http://www.w3.org/2005/atom"']
            }

            for api_type, markers in patterns.items():
                if any(marker in text for marker in markers):
                    return api_type

            return None

        except requests.RequestException as e:
            self.logger.debug(f"GET request failed for body sniffing at {url}: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Error during body sniffing for {url}: {e}")
            return None

    def _check_auth_requirement(self, url):
        """
        Checks if the endpoint requires authentication.
        Returns: 'required' if 401/403, 'unknown' if timeout/error, None if no auth required
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 401:
                return 'required'
            elif response.status_code == 403:
                return 'required'
            return None
        except requests.RequestException as e:
            self.logger.debug(f"Could not determine auth requirement for {url}: {e}")
            return 'unknown'

    def validate_url(self, url, is_recovery_attempt=False):
        """
        Validates a URL using automatic API type detection only.
        """
        if not url:
            return {"valid": False, "error": "Empty URL"}

        auth_required = self._check_auth_requirement(url)

        detected_type = self._detect_api_type(url)
        api_type = detected_type

        if (api_type and api_type.upper() == 'FTP') or url.startswith('ftp://'):
            result = self._check_ftp(url)
        else:
            config = self.protocol_configs.get(api_type)
            if config:
                result = self._check_specific_http(url, config, api_type, is_recovery_attempt)
            else:
                result = self._check_generic_http(url)

        result['detected_api_type'] = detected_type if detected_type else 'N/A'
        if auth_required:
            result['auth_required'] = auth_required

        return result

    def _check_specific_http(self, url, config, api_type, is_recovery_attempt):
        """
        Handles validation using the extracted default queries.
        """
        suffix = config['suffix']
        expected_mime = config['accept']

        if suffix and '{endpointURI}' in suffix:
            suffix = suffix.replace('{endpointURI}', '')

        target_url = url

        if suffix:
            if 'verb=' in suffix and 'verb=' in url:
                target_url = url
            elif url.lower().endswith(('.html', '.htm', '.php', '.jsp', '.aspx')) and suffix.startswith('/'):
                target_url = url
            else:
                if suffix.startswith('?'):
                    target_url = url + suffix
                elif suffix.startswith('/'):
                    target_url = urljoin(url, suffix)
                else:
                    target_url = url + '/' + suffix

        req_headers = self.headers.copy()
        if expected_mime:
            req_headers['Accept'] = expected_mime

        try:
            response = requests.get(target_url, headers=req_headers, timeout=self.timeout)

            if 'SPARQL' in (expected_mime or '') and response.status_code == 400:
                return {"valid": True, "status_code": 400, "note": "Active (Missing Query params)", "url": target_url}

            is_valid = 200 <= response.status_code < 400
            received_mime = response.headers.get('Content-Type', '').lower()
            mime_warning = None
            match_found = True

            if is_valid and expected_mime:
                accepted_types = [t.strip().lower() for t in expected_mime.split(',')]
                match_found = any(t in received_mime for t in accepted_types)

                if not match_found:
                    if 'application/json' in expected_mime and 'text/html' in received_mime and not is_recovery_attempt:
                        self.logger.info(f"Attempting smart recovery for {url}: Expected JSON, got HTML.")
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
                                # Recursively call validate_url, but we must ensure we don't loop.
                                # Since validate_url re-detects, we rely on the recovery URL being different/better.
                                recovery_result = self.validate_url(recovery_url, is_recovery_attempt=True)
                                if recovery_result.get('valid'):
                                    recovery_result['note'] = f"Recovered from HTML page; original URL was {url}"
                                    self.logger.info(f"Smart recovery SUCCESS for {url} via {recovery_url}")
                                    return recovery_result
                                else:
                                    self.logger.warning(
                                        f"Smart recovery FAILED for {url} via {recovery_url}: {recovery_result.get('error', 'Unknown error')}")
                            else:
                                self.logger.info(f"No JSON links found on HTML page for {url}.")
                                # Fallback for human-readable documentation pages
                                response_text_lower = response.text.lower()
                                if 'swagger-ui' in response_text_lower or 'id="swagger-ui"' in response_text_lower or 'rest api' in response_text_lower:
                                    self.logger.info(
                                        f"Detected API documentation page on {url}. Marking as valid (content unverified).")
                                    return {
                                        "valid": True, "status_code": response.status_code, "content_type": received_mime,
                                        "url": target_url, "expected_content_type": expected_mime,
                                        "note": "Received HTML (likely an API documentation page) instead of JSON. Status 200 OK suggests service is active."
                                    }
                        except Exception as e:
                            self.logger.error(f"Error during smart recovery for {url}: {e}")

                    is_valid = False
                    mime_warning = f"Invalid Content-Type: expected '{expected_mime}', got '{received_mime}'"

            redirect_chain = [{"status_code": r.status_code, "url": r.url} for r in response.history]

            result = {
                "valid": is_valid,
                "status_code": response.status_code,
                "content_type": received_mime,
                "url": target_url,
                "expected_content_type": expected_mime if expected_mime else None
            }

            if redirect_chain:
                result["redirects"] = redirect_chain
                result["final_url"] = response.url

            if mime_warning:
                result["error"] = mime_warning

            return result

        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": target_url}

    def _check_generic_http(self, url):
        """
        Standard GET for types without specific path requirements.
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            redirect_chain = [{"status_code": r.status_code, "url": r.url} for r in response.history]

            result = {
                "valid": 200 <= response.status_code < 400,
                "status_code": response.status_code,
                "content_type": response.headers.get('Content-Type', '').lower(),
                "url": url
            }

            if redirect_chain:
                result["redirects"] = redirect_chain
                result["final_url"] = response.url

            return result

        except requests.RequestException as e:
            return {"valid": False, "error": str(e), "url": url}

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