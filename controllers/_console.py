"""Console helpers for the CLI entry points."""

import sys


def enable_utf8_console() -> None:
    """
    Force stdout/stderr to UTF-8 so non-ASCII output (arrows, em-dashes, the info
    glyph, unicode in harvested service metadata) doesn't raise UnicodeEncodeError
    on legacy Windows consoles that default to cp1252.

    Reconfigures the existing stream objects in place, so logging StreamHandlers
    that already hold a reference to sys.stderr benefit too. No-op where the streams
    cannot be reconfigured (e.g. captured/replaced streams under pytest).
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
