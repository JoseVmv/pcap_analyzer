"""Central logging configuration.

Only the CLI installs handlers; library modules just call
``logging.getLogger(__name__)`` and emit records.  This keeps the package
usable as a library, where the host application decides what to do with
log output.
"""

from __future__ import annotations

import logging
import sys

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATE_FORMAT = "%H:%M:%S"


def configure_logging(verbosity: int = 0) -> None:
    """Configure root logging for CLI usage.

    verbosity 0 -> WARNING, 1 -> INFO, 2 -> DEBUG.
    At 3+ Scapy's own loggers are unmuted as well.
    """
    if verbosity <= 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format=_FORMAT,
        datefmt=_DATE_FORMAT,
        stream=sys.stderr,
        force=True,  # idempotent: safe to call again (tests, REPL)
    )

    # Scapy is chatty at import/dissection time (e.g. "no libpcap" warnings
    # that only matter for live capture, which this project never does).
    # Keep it quiet unless the user explicitly asked for full debug output.
    scapy_level = logging.DEBUG if verbosity >= 3 else logging.ERROR
    for name in ("scapy", "scapy.runtime", "scapy.loading"):
        logging.getLogger(name).setLevel(scapy_level)
