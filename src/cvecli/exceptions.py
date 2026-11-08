"""Operational errors for database updates."""

from typing import Optional


class CVECliError(Exception):
    """Base exception for all cvecli errors.

    All cvecli-specific exceptions inherit from this class,
    allowing users to catch all cvecli errors with a single except clause.
    """

    def __init__(self, message: str, details: Optional[str] = None):
        self.message = message
        self.details = details
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}\n  Details: {self.details}"
        return self.message


class ChecksumMismatchError(CVECliError):
    """Raised when a downloaded file's checksum doesn't match expected value."""

    def __init__(
        self,
        filename: str,
        expected: str,
        actual: str,
    ):
        self.filename = filename
        self.expected = expected
        self.actual = actual
        msg = f"Checksum mismatch for {filename}"
        details = f"Expected: {expected}, Got: {actual}"
        super().__init__(msg, details)


class ManifestIncompatibleError(CVECliError):
    """Raised when the manifest schema version is incompatible."""

    def __init__(self, remote_version: int, supported_version: int):
        self.remote_version = remote_version
        self.supported_version = supported_version
        msg = (
            f"Incompatible parquet schema: remote version {remote_version}, "
            f"supported version {supported_version}"
        )
        hint = "Please update cvecli to the latest version."
        super().__init__(msg, hint)
