"""Exception hierarchy for the investigator.

Every error raised on purpose by this project derives from
:class:`InvestigatorError`, so callers (the CLI in particular) can catch a
single type and translate it into a friendly message and a stable exit code,
while genuine bugs still surface as regular tracebacks.
"""

from __future__ import annotations

from pathlib import Path


class InvestigatorError(Exception):
    """Base class for all errors raised by this project."""


class CaptureFileError(InvestigatorError):
    """A problem with the capture file supplied by the user."""

    def __init__(self, path: Path | str, reason: str) -> None:
        self.path = Path(path)
        self.reason = reason
        super().__init__(f"{self.path}: {reason}")


class CaptureFileNotFoundError(CaptureFileError):
    """The path does not exist or is not a regular file."""


class UnsupportedCaptureFormatError(CaptureFileError):
    """The file exists but is not a pcap/pcapng capture."""


class CorruptCaptureFileError(CaptureFileError):
    """The file looks like a capture but cannot be read."""
