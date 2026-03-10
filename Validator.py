import re
import requests
import os
import logging
import json
import ftplib
import urllib.parse
from urllib.parse import urljoin

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
        self.api_doc_keywords = []
        self.decommissioned_keywords = []
        self.protocol_configs = self._load_profiles()

    def _load_profiles(self):
        """
        Single loader for service_profiles.json — the unified source of truth.
        Populates:
          - self.protocol_configs     : dict of acronym -> full profile object
          - self.spec_url_index       : dict of spec URL -> acronym (for conformsTo resolution)
          - self.api_doc_keywords     : list of HTML keyword strings
          - self.decommissioned_keywords : list of HTML keyword strings
        """
        profiles = {}
        profile_path = os.path.join(os.path.dirname(__file__), 'service_profiles.json')
        try:
            with open(profile_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            g = data.get('global', {})
            self.api_doc_keywords = g.get('api_doc_keywords', [])
            self.decommissioned_keywords = g.get('decommissioned_keywords', [])
            profiles = data.get('service_profiles', {})
            self.logger.info(f"Loaded {len(profiles)} service profiles from {profile_path}")
        except FileNotFoundError:
            self.logger.error(
                f"Fatal: service_profiles.json not found at {profile_path}. "
                "Validation will not function correctly."
            )
        except json.JSONDecodeError as e:
            self.logger.error(
                f"Fatal: Error parsing {profile_path}: {e}. "
                "Validation will not function correctly."
            )

        # Build reverse-lookup index: spec URL (normalised, no trailing slash) -> acronym.
        # Covers both 'doc' and 'namespace' roles so either kind of conformsTo URL resolves.
        self.spec_url_index = {}
        for acronym, profile in profiles.items():
            for entry in profile.get('spec_urls', []):
                url = entry.get('url', '').rstrip('/')
                if url:
                    self.spec_url_index[url] = acronym

        return profiles

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

    @staticmethod
    def resolve_type_from_conforms_to(conforms_to_url, spec_url_index):
        """
        Resolves a dct:conformsTo URL to a known service-type acronym by looking it
        up in the pre-built spec_url_index (built from service_profiles.json spec_urls).

        Both 'doc' and 'namespace' role URLs are indexed, so either kind can match.
        Trailing slashes are stripped before comparison.

        Args:
            conforms_to_url : str|None  – the raw dct:conformsTo value from the RDF store
            spec_url_index  : dict      – maps normalised spec URL -> acronym

        Returns:
            str|None – acronym (e.g. 'OAI-PMH') or None if not resolved
        """
        if not conforms_to_url or not spec_url_index:
            return None
        normalised = conforms_to_url.rstrip('/')
        return spec_url_index.get(normalised)

    def _count_body_sigs_in_text(self, text, config):
        """
        Count how many body signatures defined in a profile match the given text.

        Returns:
            (hit: int, total: int)  – number matched and total signatures defined.
            Returns (0, 0) if no signatures are defined for this profile.
        """
        signatures = config.get('validation', {}).get('body_signatures', [])
        total = len(signatures)
        if total == 0:
            return 0, 0

        text_lower = text[:50000].lower()
        text_full = text[:50000]
        hit = 0
        for sig in signatures:
            pattern = sig.get('pattern', '')
            mode = sig.get('mode', 'substring')
            if not pattern:
                continue
            if mode == 'regex':
                if re.search(pattern, text_full, re.IGNORECASE):
                    hit += 1
            else:
                if pattern.lower() in text_lower:
                    hit += 1
        return hit, total

    def _calculate_score(
        self,
        status_code,
        expected_mime,
        received_mime,
        conforms_to_matched,
        service_title_matched,
        body_sig_hit,
        body_sig_total,
        extracted_conforms_to_delta=0,
    ):
        """
        Calculate a 0.0–10.0 confidence score for a validation result.

        Scoring breakdown (max 10 pts):
          3 pts – HTTP status code 200–399
          2 pts – dct:conformsTo resolved to this profile
          2 pts – returned MIME matches expected MIME
          2 pts – body signatures matched (partial credit: hit/total × 2)
          1 pt  – serviceTitle present and matches this profile
          +1/−2 – extracted spec URL bonus/penalty (match/mismatch/not_found)

        Args:
            status_code                   : int|None
            expected_mime                 : str  – from profile probe.accept
            received_mime                 : str  – from response Content-Type
            conforms_to_matched           : bool – was conformsTo resolved to this profile?
            service_title_matched         : bool – did serviceTitle map to this profile?
            body_sig_hit                  : int  – number of signatures matched
            body_sig_total                : int  – total signatures defined
            extracted_conforms_to_delta   : int  – +1 (match), -2 (mismatch), 0 (not found)

        Returns:
            float rounded to 2 decimal places, range 0.0–10.0
        """
        score = 0.0

        # 1. Status code (3 pts)
        if status_code is not None and 200 <= status_code < 400:
            score += 3.0

        # 2. conformsTo resolved (2 pts)
        if conforms_to_matched:
            score += 2.0

        # 3. MIME match (2 pts)
        if expected_mime and received_mime:
            expected_parts = [t.strip() for t in expected_mime.split(',')]
            if any(part in received_mime for part in expected_parts):
                score += 2.0

        # 4. Body signatures partial credit (2 pts)
        if body_sig_total > 0:
            score += round((body_sig_hit / body_sig_total) * 2.0, 2)

        # 5. serviceTitle matched (1 pt)
        if service_title_matched:
            score += 1.0

        # 6. Extracted spec URL bonus/penalty (+1 / -2 / 0)
        score += extracted_conforms_to_delta

        return round(min(max(score, 0.0), 10.0), 2)



    def _classify_html_response(self, response, url, expected_mime=None):
        """
        Scans a text/html response for decommissioned or documentation keywords.
        Returns a dict with 'valid', 'is_doc_page', and optional 'note' and 'error'
        values that the caller should use to override its default validation results.
        Returns None if it's just generic HTML and standard validation should continue.

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
        expected_mime = config.get('probe', {}).get('accept', '').lower()

        # 1. Check Content-Type
        ct_match = False
        if expected_mime:
            # expected_mime might be "application/xml, text/xml"
            # We check if ANY of the expected types are present in the received mime
            if any(t.strip() in received_mime for t in expected_mime.split(',')):
                ct_match = True
            else:
                self.logger.debug(f"Strict Content-Type match failed: '{received_mime}' != '{expected_mime}'")

        # 2. Check Body Signatures (loaded from service_profiles.json: validation.body_signatures).
        # Each signature has a 'pattern' and a 'mode' ('substring' or 'regex').
        # A single match is sufficient to set body_match = True.
        body_match = False
        text_full = response.text[:50000]
        text_lower = text_full.lower()

        signatures = config.get('validation', {}).get('body_signatures', [])
        if signatures:
            for sig in signatures:
                pattern = sig.get('pattern', '')
                mode = sig.get('mode', 'substring')
                if not pattern:
                    continue
                if mode == 'regex':
                    if re.search(pattern, text_full, re.IGNORECASE):
                        body_match = True
                        break
                else:  # 'substring' — case-insensitive via pre-lowercased text
                    if pattern.lower() in text_lower:
                        body_match = True
                        break
            if body_match:
                self.logger.info(f"Strict match confirmed via body signature for '{expected_type}'.")
            else:
                self.logger.debug(f"Body signature match failed for '{expected_type}'.")

        # Validation Logic:
        # Most types: either a CT match OR a body signature match is sufficient.
        # When require_body_and_ct is true in the profile (e.g. NetCDF uses text/html —
        # too generic to trust alone), BOTH must match to avoid false positives.
        require_both = config.get('validation', {}).get('require_body_and_ct', False)

        if require_both:
            # Strict: both CT and body must match
            if ct_match and body_match:
                return True
            if ct_match and not body_match:
                self.logger.debug(
                    f"'{expected_type}' requires body signature confirmation "
                    f"(require_body_and_ct: true), but body check failed."
                )
            return False

        # Standard "either/or" logic for all other types:
        # If body matches, trust it even if CT is ambiguous (handles misconfigured servers).
        if body_match:
            return True

        # If CT matches and body check wasn't performed or wasn't needed, trust CT.
        if ct_match:
            return True

        return False

    def validate_url(self, url, expected_type=None, conforms_to=None, service_title=None):
        """
        Validates a URL with strict type checking logic:
        1. Unsupported check: immediately return for profiles marked unsupported.
        2. Initial GET: type-specific Accept header.
           - If strictly matches (Status 200 + Content-Type + Body Pattern) -> VALID.
           - If 405, retry with POST (empty body) before other checks.
        3. Fallback: construct the specific service URL (Magic URL).

        Args:
            url           : str       – endpoint URL to validate
            expected_type : str|None  – service type acronym (required for strict mode)
            conforms_to   : str|None  – raw dct:conformsTo URL (used only for scoring)
            service_title : str|None  – original service title (used only for scoring)
        """
        if not url:
            return {"valid": False, "error": "Empty URL", "score": 0.0, "extracted_conforms_to": ""}

        # Check Expected Type First — abort early to avoid unnecessary network requests
        if not expected_type:
            extracted = ""
            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                extracted = self._extract_conforms_to_from_response(resp.text)
            except Exception:
                pass
            return {
                "valid": False,
                "error": "No expected service type provided.",
                "url": url,
                "auth_required": "Unknown",
                "redirected_url": url,
                "score": 0.0,
                "extracted_conforms_to": extracted,
            }

        if expected_type not in self.protocol_configs:
            extracted = ""
            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                extracted = self._extract_conforms_to_from_response(resp.text)
            except Exception:
                pass
            return {
                "valid": False,
                "error": f"Unknown Service Type: '{expected_type}'",
                "url": url,
                "auth_required": "Unknown",
                "redirected_url": url,
                "score": 0.0,
                "extracted_conforms_to": extracted,
            }

        config = self.protocol_configs.get(expected_type)

        # --- Unsupported profile early exit ---
        if config.get('special', {}).get('unsupported'):
            self.logger.info(
                f"Service type '{expected_type}' is marked unsupported. Skipping validation."
            )
            result = {
                "valid": False,
                "url": url,
                "status_code": None,
                "content_type": None,
                "expected_content_type": config.get('probe', {}).get('accept', ''),
                "auth_required": "Unknown",
                "is_doc_page": False,
                "had_redirect": False,
                "redirects": [],
                "redirect_chain": "",
                "redirected_url": "",
                "constructed_url": "",
                "error": "Unsupported/Cannot be verified",
                "note": (
                    f"Service type '{expected_type}' is a file format or protocol that "
                    "cannot be verified via HTTP requests."
                ),
                "score": 0.0,
                "extracted_conforms_to": "",
            }
            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                result["extracted_conforms_to"] = self._extract_conforms_to_from_response(resp.text)
                if resp.history:
                    result["redirected_url"] = resp.url
            except Exception as e:
                self.logger.warning(f"Failed to fetch {url} for URL extraction: {e}")
            return result

        # --- Pre-compute scoring context flags ---
        # conforms_to_matched: True if caller supplied a conformsTo URL that resolves to this type
        conforms_to_matched = (
            conforms_to is not None
            and self.resolve_type_from_conforms_to(conforms_to, self.spec_url_index) == expected_type
        )
        # service_title_matched: True if caller supplied a title that maps to this type
        service_title_matched = (
            service_title is not None
            and self.map_service_type(service_title, list(self.protocol_configs.keys())) == expected_type
        )

        # Prepare Headers with specific Accept if expected_type is provided
        current_headers = self.headers.copy()
        # Construct Accept header with q-values e.g. "application/xml;q=1.0, */*;q=0.8"
        specific_accept = config.get('probe', {}).get('accept', '')
        if specific_accept:
            current_headers['Accept'] = f"{specific_accept};q=1.0, text/html;q=0.9, */*;q=0.8"

        # Route real ftp:// URLs to the dedicated FTP validator — requests cannot handle them.
        if url.lower().startswith('ftp://'):
            result = self._validate_ftp_url(url, expected_type)
            result['score'] = 0.0  # FTP scoring not implemented via HTTP criteria
            return result

        try:
            main_response = requests.get(url, headers=current_headers, timeout=self.timeout, allow_redirects=True)

            # --- Universal POST retry on 405 Method Not Allowed ---
            # If GET is blocked, try a POST with an empty body before any further checks.
            # This is intentionally universal: 405 on GET is rare, and a POST probe tells
            # us whether the endpoint is alive and processing requests at all.
            if main_response.status_code == 405:
                self.logger.info(
                    f"GET returned 405 for '{url}'. Retrying with POST (empty body)."
                )
                try:
                    post_response = requests.post(
                        url,
                        headers=current_headers,
                        data='',
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                    # Only replace main_response if POST gave us something useful
                    if post_response.status_code != 405:
                        self.logger.info(
                            f"POST to '{url}' returned {post_response.status_code} "
                            "— using POST response for validation."
                        )
                        main_response = post_response
                    else:
                        self.logger.info(
                            f"POST also returned 405 for '{url}'. Keeping GET response."
                        )
                except requests.RequestException as post_err:
                    self.logger.warning(
                        f"POST retry failed for '{url}': {post_err}. Keeping GET response."
                    )

            # Derive Auth Requirement from the request chain.
            auth_required = 'No'
            if main_response.status_code in [401, 403]:
                auth_required = 'Yes'
            elif main_response.history and main_response.history[0].status_code in [401, 403]:
                auth_required = 'Yes'

        except requests.RequestException as e:
            return {
                "valid": False,
                "error": str(e),
                "url": url,
                "auth_required": "Unknown",
                "score": 0.0,
                "extracted_conforms_to": "",
            }

        final_url = main_response.url

        # --- Evaluate extracted spec URLs early ---
        # Compute once, use everywhere — available for all return paths below.
        ect_eval = self._evaluate_extracted_conforms_to(main_response.text, expected_type)

        # --- Step 0a: LDN Inbox — 405 Method Not Allowed ---
        # POST retry above already ran; if we're still at 405 here, both GET and POST
        # are rejected with 405 (Method Not Allowed). For LDN this still confirms the
        # inbox exists — the server is responding, just not accepting these methods.
        if config.get('special', {}).get('accept_405_as_valid') and main_response.status_code == 405:
            self.logger.info(f"Endpoint at '{final_url}' returned 405 — inbox/endpoint confirmed (Method Not Allowed).")
            redirect_chain_list = self._build_redirect_chain_info(main_response)
            sig_hit, sig_total = self._count_body_sigs_in_text(main_response.text, config)
            score = self._calculate_score(
                status_code=405,
                expected_mime=config.get('probe', {}).get('accept', ''),
                received_mime=main_response.headers.get('Content-Type', '').lower(),
                conforms_to_matched=conforms_to_matched,
                service_title_matched=service_title_matched,
                body_sig_hit=sig_hit,
                body_sig_total=sig_total,
                extracted_conforms_to_delta=ect_eval['score_delta'],
            )
            return {
                "valid": True,
                "status_code": 405,
                "content_type": main_response.headers.get('Content-Type', '').lower(),
                "url": url,
                "redirected_url": final_url if bool(redirect_chain_list) else '',
                "constructed_url": '',
                "expected_content_type": config.get('probe', {}).get('accept', ''),
                "auth_required": 'Unknown',  # 405 = Method Not Allowed, not an auth error
                "is_doc_page": False,
                "redirects": redirect_chain_list,
                "had_redirect": bool(redirect_chain_list),
                "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list]),
                "score": score,
                "note": (
                    "LDN Inbox confirmed (405 Method Not Allowed): the inbox endpoint exists "
                    "but does not accept GET or POST on this URL (method not allowed by server)."
                ),
                "extracted_conforms_to": ect_eval['extracted_urls'],
                "conforms_to_verified": ect_eval['status'],
            }

        # --- Step 0: HTTP-Wrapped FTP Detection ---
        # For FTP-type endpoints, detect the common case where a server exposes its FTP
        # archive as an HTML directory listing over HTTP (e.g. Apache mod_autoindex).
        # This check runs first so the response is never counted as a valid FTP endpoint.
        if config.get('special', {}).get('detect_http_wrapped_ftp') and self._is_http_wrapped_ftp(main_response):
            self.logger.info(f"URL '{final_url}' is an HTTP-wrapped FTP directory listing. Marking as invalid.")
            redirect_chain_list = self._build_redirect_chain_info(main_response)
            return {
                "valid": False,
                "status_code": main_response.status_code,
                "content_type": main_response.headers.get('Content-Type', '').lower(),
                "url": url,
                "redirected_url": final_url,
                "constructed_url": "",
                "expected_content_type": config.get('probe', {}).get('accept', ''),
                "auth_required": auth_required,
                "is_doc_page": False,
                "redirects": redirect_chain_list,
                "had_redirect": bool(redirect_chain_list),
                "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list]),
                "note": (
                    "Invalid FTP endpoint: URL returns an HTTP-wrapped FTP directory listing "
                    "(text/html served over HTTP), not a true FTP endpoint. "
                    "If an ftp:// URL is available, register that instead."
                ),
                "extracted_conforms_to": ect_eval['extracted_urls'],
                "conforms_to_verified": ect_eval['status'],
            }

        # --- Step 1: Doc Page / Decommissioned Check ---
        # This MUST run before the strict content match. A documentation page about a technology
        # (e.g. a page describing NetCDF/OPeNDAP) will naturally contain the same keywords we scan
        # for in body signatures, causing false positives if we check body patterns first.
        # By classifying HTML pages here first, we ensure that any page that looks like a doc or
        # decommissioned notice is rejected immediately, before the body signature check can fire.
        initial_html_classification = self._classify_html_response(main_response, final_url, expected_mime=config.get('probe', {}).get('accept', ''))
        if initial_html_classification:
            self.logger.info(f"Initial URL '{final_url}' was classified as an invalid HTML page (Doc/Decommissioned). Skipping strict match and magic URL construction.")

            # Override ect_eval: HTML pages naturally contain spec URLs in their content
            # (e.g. a SWORD documentation page will mention 'http://swordapp.org/'), so the
            # normal extraction logic would produce a false 'match'. We neutralise this by
            # marking conformsTo verification as not_applicable on any doc/decommissioned page.
            ect_eval = {
                "extracted_urls": "",
                "status": "not_applicable",
                "score_delta": 0,
            }

            core_result = {
                 "valid": initial_html_classification.get('valid', False),
                 "status_code": main_response.status_code,
                 "content_type": main_response.headers.get('Content-Type', '').lower(),
                 "url": final_url,
                 "expected_content_type": config.get('probe', {}).get('accept', ''),
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
                sig_hit, sig_total = self._count_body_sigs_in_text(main_response.text, config)
                score = self._calculate_score(
                    status_code=main_response.status_code,
                    expected_mime=config.get('probe', {}).get('accept', ''),
                    received_mime=main_response.headers.get('Content-Type', '').lower(),
                    conforms_to_matched=conforms_to_matched,
                    service_title_matched=service_title_matched,
                    body_sig_hit=sig_hit,
                    body_sig_total=sig_total,
                    extracted_conforms_to_delta=ect_eval['score_delta'],
                )
                return {
                    "valid": True,
                    "status_code": main_response.status_code,
                    "content_type": main_response.headers.get('Content-Type', '').lower(),
                    "url": url,
                    "redirected_url": final_url,
                    "constructed_url": '',
                    "expected_content_type": config.get('probe', {}).get('accept', ''),
                    "auth_required": auth_required,
                    "note": "Initial URL validation successful.",
                    "redirects": redirect_chain_list,
                    "had_redirect": bool(redirect_chain_list),
                    "redirect_chain": " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list]),
                    "is_doc_page": False,
                    "score": score,
                    "extracted_conforms_to": ect_eval['extracted_urls'],
                    "conforms_to_verified": ect_eval['status'],
                }

            # --- Step 3: "Magic" / Construction Fallback ---
            # Strict match failed and it's not a doc/decommissioned page.
            # Try constructing the specific service URL by appending the known suffix.
            else:
                self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
                core_result = self._check_specific_http(main_response, final_url, config, expected_type, current_headers)

        else:
            # Non-2xx/3xx response and not an HTML doc page — pass through to magic URL construction.
            self.logger.info(f"Initial check did not strictly match '{expected_type}'. Proceeding to URL construction/magic.")
            core_result = self._check_specific_http(main_response, final_url, config, expected_type, current_headers)

        # --- Assemble the final, complete result dictionary ---
        final_result = core_result.copy()

        final_result['auth_required'] = auth_required

        redirect_chain_list = self._build_redirect_chain_info(main_response)
        final_result['redirects'] = redirect_chain_list
        final_result['had_redirect'] = bool(redirect_chain_list)
        final_result['redirect_chain'] = " -> ".join([f"{r['status_code']}: {r.get('to_url', 'N/A')}" for r in redirect_chain_list])

        # Handle URL keys for consistent output.
        constructed_url = final_result.get('url', '')
        final_result['constructed_url'] = constructed_url if constructed_url and constructed_url != final_url else ''
        final_result['redirected_url'] = final_url if bool(redirect_chain_list) else ''

        if 'is_doc_page' not in final_result:
            final_result['is_doc_page'] = False

        # --- Compute score if not already set (magic-URL / fallback paths) ---
        if 'score' not in final_result:
            # Use main_response text for body sig counting on the fallback paths.
            # This is an approximation when a constructed URL was used, but keeps
            # scoring logic simple and avoids threading response objects through
            # the entire call stack.
            resp_text_for_score = main_response.text
            sig_hit, sig_total = self._count_body_sigs_in_text(resp_text_for_score, config)
            final_result['score'] = self._calculate_score(
                status_code=final_result.get('status_code'),
                expected_mime=config.get('probe', {}).get('accept', ''),
                received_mime=final_result.get('content_type', ''),
                conforms_to_matched=conforms_to_matched,
                service_title_matched=service_title_matched,
                body_sig_hit=sig_hit,
                body_sig_total=sig_total,
                extracted_conforms_to_delta=ect_eval['score_delta'],
            )

        if 'extracted_conforms_to' not in final_result:
            final_result['extracted_conforms_to'] = ect_eval['extracted_urls']
        if 'conforms_to_verified' not in final_result:
            final_result['conforms_to_verified'] = ect_eval['status']

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

    def _extract_ldn_inbox_url(self, response):
        """
        Attempts to discover an LDN Inbox URL from a response by inspecting:
        1. The HTTP Link header for rel="http://www.w3.org/ns/ldp#inbox".
        2. The response body for an RDF/HTML ldp:inbox relation (basic pattern match).
        Returns the discovered inbox URL string, or None if not found.
        """


        # 1. Check Link header — most common and most reliable discovery mechanism.
        # Example: Link: <https://example.org/inbox/>; rel="http://www.w3.org/ns/ldp#inbox"
        link_header = response.headers.get('Link', '')
        if link_header:
            for part in link_header.split(','):
                part = part.strip()
                if 'ldp#inbox' in part.lower():
                    url_part = part.split(';')[0].strip()
                    if url_part.startswith('<') and url_part.endswith('>'):
                        candidate = url_part[1:-1].strip()
                        return urljoin(response.url, candidate)

        # 2. Scan body for ldp:inbox (JSON-LD compact, Turtle, or HTML/RDFa).
        text = response.text[:50000]

        # JSON-LD compact form: "inbox": "<url>"
        jld_match = re.search(r'"inbox"\s*:\s*"([^"]+)"', text)
        if jld_match:
            return urljoin(response.url, jld_match.group(1))

        # Turtle / expanded IRI form: ldp:inbox <url> or <ldp:inbox> <url>
        ttl_match = re.search(r'ldp:inbox\s+<([^>]+)>', text)
        if ttl_match:
            return urljoin(response.url, ttl_match.group(1))

        # HTML/RDFa: href="..." rel="http://www.w3.org/ns/ldp#inbox"
        html_match = re.search(
            r'href=["\']([^"\']+)["\'][^>]*rel=["\']http://www\.w3\.org/ns/ldp#inbox["\']',
            text, re.IGNORECASE
        )
        if not html_match:
            html_match = re.search(
                r'rel=["\']http://www\.w3\.org/ns/ldp#inbox["\'][^>]*href=["\']([^"\']+)["\']',
                text, re.IGNORECASE
            )
        if html_match:
            return urljoin(response.url, html_match.group(1))

        return None

    def _extract_conforms_to_from_response(self, text):
        """
        Scans the response text for any of the known spec URLs defined in service_profiles.json.
        Returns a pipe-separated string of matched URLs (original casing preserved).
        Only URLs that are in self.spec_url_index (indexed from service_profiles.json spec_urls)
        are searched for; unknown/unlisted conformsTo URL values will not appear here.
        """
        if not text:
            return ""
        text_lower = text[:50000].lower()
        found_urls = []
        # Sort by length descending to match longer, more specific URLs first
        for url in sorted(self.spec_url_index.keys(), key=len, reverse=True):
            if url.lower() in text_lower:
                found_urls.append(url)
        return " | ".join(found_urls)

    def _evaluate_extracted_conforms_to(self, text, expected_type):
        """
        Three-state evaluation of spec URLs found in the response body.

        1. Extracts known spec URLs from the response text.
        2. Resolves each to a service profile acronym.
        3. Compares against expected_type:
           - match     → {"status": "match",     "score_delta": +1}
           - mismatch  → {"status": "mismatch",  "score_delta": -2}
           - not_found → {"status": "not_found", "score_delta":  0}

        Returns:
            dict with keys: extracted_urls (str), status (str), score_delta (int)
        """
        extracted_str = self._extract_conforms_to_from_response(text)

        if not extracted_str:
            return {
                "extracted_urls": "",
                "status": "not_found",
                "score_delta": 0,
            }

        # Resolve each found URL to its profile acronym
        found_urls = [u.strip() for u in extracted_str.split(" | ")]
        resolved_types = set()
        for url in found_urls:
            resolved = self.resolve_type_from_conforms_to(url, self.spec_url_index)
            if resolved:
                resolved_types.add(resolved)

        if not resolved_types:
            # Found URLs but none resolved to a known profile
            return {
                "extracted_urls": extracted_str,
                "status": "not_found",
                "score_delta": 0,
            }

        if expected_type in resolved_types:
            return {
                "extracted_urls": extracted_str,
                "status": "match",
                "score_delta": 1,
            }
        else:
            return {
                "extracted_urls": extracted_str,
                "status": "mismatch",
                "score_delta": -2,
            }


    def _check_specific_http(self, response, final_url, config, api_type, headers_to_use):

        suffix = config.get('probe', {}).get('suffix', '')
        expected_mime = config.get('probe', {}).get('accept', '')

        # --- LDN Discovery Fallback ---
        # If type is LDN and the initial request did not return a JSON-LD inbox, attempt to
        # discover the Inbox URL via the Link header or body of the response. This handles
        # the case where the user provides a "target resource" URL (e.g. a profile page or
        # article) rather than a direct inbox URL.
        if config.get('special', {}).get('ldn_inbox_discovery'):
            inbox_url = self._extract_ldn_inbox_url(response)
            if inbox_url:
                self.logger.info(f"LDN Inbox discovered via Link header/body from '{final_url}': '{inbox_url}'")
                try:
                    inbox_response = requests.get(inbox_url, headers=headers_to_use, timeout=self.timeout)
                except requests.RequestException as e:
                    return {"valid": False,
                            "error": f"LDN inbox discovered at '{inbox_url}' but GET failed: {e}",
                            "url": inbox_url, "expected_content_type": expected_mime, "is_doc_page": False}

                # A 405 on the discovered inbox still confirms the inbox exists
                if inbox_response.status_code == 405:
                    return {
                        "valid": True,
                        "status_code": 405,
                        "content_type": inbox_response.headers.get('Content-Type', '').lower(),
                        "url": inbox_url,
                        "expected_content_type": expected_mime,
                        "is_doc_page": False,
                        "note": (
                            f"LDN Inbox discovered via Link header/body from '{final_url}' \u2192 '{inbox_url}'. "
                            "Inbox confirmed (405): exists but GET listing requires authentication."
                        ),
                    }

                if self._is_strict_content_match(inbox_response, api_type, config):
                    return {
                        "valid": True,
                        "status_code": inbox_response.status_code,
                        "content_type": inbox_response.headers.get('Content-Type', '').lower(),
                        "url": inbox_url,
                        "expected_content_type": expected_mime,
                        "is_doc_page": False,
                        "note": (
                            f"LDN Inbox discovered via Link header/body from target "
                            f"resource '{final_url}' \u2192 '{inbox_url}'."
                        ),
                    }
                else:
                    discovered_mime = inbox_response.headers.get('Content-Type', '').lower()
                    return {
                        "valid": False,
                        "status_code": inbox_response.status_code,
                        "content_type": discovered_mime,
                        "url": inbox_url,
                        "expected_content_type": expected_mime,
                        "is_doc_page": False,
                        "error": (
                            f"LDN Inbox discovered at '{inbox_url}' but response did not match "
                            f"expected content or LDN body signatures (got '{discovered_mime}')."
                        ),
                    }
            else:
                self.logger.info(f"LDN discovery: no inbox link found in response from '{final_url}'.")

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


