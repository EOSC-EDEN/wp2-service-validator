"""
type_resolver.py — Infers a service type by calling the wp2-service-identifier API.

Used when --type / service_type is not supplied to any of the three entry points
(check_service.py, main.py, batch_validator.py).

Configuration (environment variables):
  IDENTIFIER_BASE_URL             – base URL of the identifier service
                                    (default: http://localhost:8001)
  IDENTIFIER_CONFIDENCE_THRESHOLD – minimum confidence score to auto-proceed
                                    without prompting in CLI mode
                                    (default: 5.0, range 0.0–10.0)
"""

import os
import logging
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)

_IDENTIFIER_BASE_URL: str = os.getenv('IDENTIFIER_BASE_URL', 'http://localhost:8001')
_CONFIDENCE_THRESHOLD: float = float(os.getenv('IDENTIFIER_CONFIDENCE_THRESHOLD', '5.0'))


def resolve_type(url: str, mode: str = 'api') -> Tuple[Optional[str], bool]:
    """
    Infers the service type for *url* by calling the wp2-service-identifier /identify endpoint.

    Behaviour by mode when confidence is below the threshold or the result is ambiguous:
      • 'cli'   – interactive prompt; user may confirm the suggestion or supply a different type
      • 'api'   – auto-proceed with the best guess; caller adds inferred_type flag to the response
      • 'batch' – auto-proceed with the best guess; caller adds inferred_type flag to CSV output

    When confidence is at or above the threshold and the result is unambiguous, all three modes
    auto-proceed without prompting.

    Args:
        url  : str – the service endpoint URL to identify
        mode : str – one of 'cli', 'api', 'batch' (default: 'api')

    Returns:
        (resolved_type, inferred) where:
            resolved_type : str | None – inferred service-type acronym (e.g. 'OAI-PMH'),
                                         or None if the identifier could not suggest anything
            inferred      : bool       – True if the type came from the identifier;
                                         False only when a CLI user typed a manual override

    Raises:
        RuntimeError – identifier is unreachable OR returned a hard-error field.
                       Callers must surface this to the user or record it per-item.
    """
    identifier_url = f"{_IDENTIFIER_BASE_URL.rstrip('/')}/identify"

    try:
        resp = requests.get(identifier_url, params={'url': url}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.ConnectionError:
        raise RuntimeError(
            f"Identifier service unreachable at '{_IDENTIFIER_BASE_URL}'. "
            "Supply --type manually, or set IDENTIFIER_BASE_URL to the correct address."
        )
    except requests.RequestException as e:
        raise RuntimeError(
            f"Identifier request failed: {e}. "
            "Supply --type manually, or check IDENTIFIER_BASE_URL."
        )

    # Hard identification failure — the identifier itself signals that identification was
    # impossible (e.g. 'unreachable', 'unsupported_scheme', 'no_match').  This is distinct
    # from a low-confidence result: the service was queried successfully but couldn't help.
    error = data.get('error')
    if error:
        raise RuntimeError(
            f"Identifier could not identify '{url}': {error}. "
            "Supply --type manually."
        )

    identified_type: Optional[str] = data.get('identified_type')
    confidence: float = float(data.get('confidence') or 0.0)
    ambiguous: bool = bool(data.get('ambiguous', False))
    runners_up: list = data.get('runners_up', [])

    if not identified_type:
        logger.debug("Identifier returned no identified_type for '%s'.", url)
        return None, True

    high_confidence = confidence >= _CONFIDENCE_THRESHOLD and not ambiguous

    if mode == 'cli' and not high_confidence:
        # Interactive prompt — let the user confirm the suggestion or supply a different type.
        ambiguous_label = ", ambiguous" if ambiguous else ""
        print(
            f"\n[Identifier] Suggested type: '{identified_type}' "
            f"(confidence: {confidence:.1f}/10{ambiguous_label})"
        )
        if runners_up:
            ru_labels = [
                r.get('type', str(r)) if isinstance(r, dict) else str(r)
                for r in runners_up
            ]
            print(f"[Identifier] Alternatives considered: {', '.join(ru_labels)}")

        user_input = input(
            f"Confirm service type [{identified_type}] or enter a different type: "
        ).strip()

        if not user_input or user_input == identified_type:
            logger.info("CLI: user confirmed inferred type '%s' for '%s'.", identified_type, url)
            return identified_type, True

        logger.info("CLI: user overrode inferred type to '%s' for '%s'.", user_input, url)
        return user_input, False  # user-supplied override; inferred=False

    # All other cases (API/batch, or CLI with high confidence): auto-proceed.
    logger.info(
        "Type resolved via identifier: '%s' (confidence: %.1f) for '%s'.",
        identified_type, confidence, url,
    )
    return identified_type, True
