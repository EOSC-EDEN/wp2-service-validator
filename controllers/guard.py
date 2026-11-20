"""Keep the public endpoints from probing hosts that are not on the public internet.

On the EU node the validator shares a private network with the harvester, the
entry VM and Fuseki, so without this anyone could make it report what answers
on those addresses.

Known ceiling: only the submitted URL is checked. An endpoint that redirects to
a private address, or a DNS record that changes between this check and the
request, still gets through. Closing that means routing every request in
ServiceValidator through a guarded session, as the harvester's HarvestSession
does.
"""
import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

import requests

logger = logging.getLogger('TargetGuard')

# Same switch and values as the harvester's HarvestSession, for local
# development against private hosts. Off unless set.
ALLOW_PRIVATE_TARGETS_ENV = 'EDEN_ALLOW_PRIVATE_TARGETS'
_TRUE_VALUES = ('1', 'true', 'yes', 'on')


class BlockedTargetError(ValueError):
    """The URL must not be fetched. str() is safe to show a visitor."""


def _private_targets_allowed():
    # Read per call: tests and operators change it at runtime.
    return os.environ.get(ALLOW_PRIVATE_TARGETS_ENV, '').strip().lower() in _TRUE_VALUES


def check_target(url: str) -> None:
    try:
        # Parse the URL requests will send, not the raw input: urlparse and
        # urllib3 disagree on a backslash in the authority, and only urllib3's
        # reading decides where the connection goes.
        parsed = urlparse(requests.Request('GET', url).prepare().url)
        host = parsed.hostname
        port = parsed.port
    except (requests.RequestException, ValueError):
        parsed, host, port = None, None, None
    if parsed is None or parsed.scheme.lower() not in ('http', 'https') or not host:
        logger.warning("Refused %s: not an http(s) URL with a host", url)
        raise BlockedTargetError("Only http:// and https:// URLs can be checked here.")

    if _private_targets_allowed():
        return

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # Nothing to protect: the validator cannot reach it either, and its own
        # connection error is the more useful thing to show.
        return
    except UnicodeError:
        # An empty or over-long label (example..org); the idna codec rejects it
        # before any lookup, and the validator would only crash on it later.
        logger.warning("Refused %s: invalid host name", url)
        raise BlockedTargetError("That URL's host name is not valid.")

    for info in infos:
        # Link-local IPv6 can carry a %scope suffix that ip_address rejects.
        address = ipaddress.ip_address(info[4][0].split('%')[0])
        if not address.is_global:
            # The address goes to the log only; telling a visitor what an
            # internal name resolves to would leak the network layout.
            logger.warning("Refused %s: %s resolves to %s", url, host, address)
            raise BlockedTargetError(
                "That host is not on the public internet, so it is not checked here."
            )
