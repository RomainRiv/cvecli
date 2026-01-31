"""Custom exceptions for cvecli.

This module defines a hierarchy of exceptions used throughout the cvecli
package. Using specific exception types improves error handling, debugging,
and provides better user feedback.

Exception Hierarchy:
    CVECliError
    ├── ConfigurationError
    ├── DataError
    │   ├── DataNotFoundError
    │   ├── DataCorruptedError
    │   └── SchemaVersionError
    ├── SearchError
    │   ├── InvalidQueryError
    │   ├── InvalidCPEError
    │   ├── InvalidPURLError
    │   └── SemanticSearchError
    ├── DownloadError
    │   ├── NetworkError
    │   ├── ChecksumMismatchError
    │   └── ManifestError
    └── ExtractionError
"""

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


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(CVECliError):
    """Raised when there's a configuration problem.

    Examples:
        - Invalid environment variable value
        - Missing required configuration
        - Invalid path configuration
    """

    pass


# =============================================================================
# Data Errors
# =============================================================================


class DataError(CVECliError):
    """Base class for data-related errors."""

    pass


class DataNotFoundError(DataError):
    """Raised when required CVE data files are not found.

    This typically means the user needs to run 'cvecli db update' first.
    """

    def __init__(
        self,
        message: str = "CVE data not found",
        path: Optional[str] = None,
        hint: str = "Run 'cvecli db update' to download the CVE database.",
    ):
        self.path = path
        self.hint = hint
        details = f"Path: {path}" if path else None
        super().__init__(message, details)


class DataCorruptedError(DataError):
    """Raised when CVE data appears to be corrupted or invalid."""

    pass


class SchemaVersionError(DataError):
    """Raised when the data schema version is incompatible.

    This happens when the local cvecli version doesn't support
    the schema version of the downloaded data.
    """

    def __init__(
        self,
        remote_version: int,
        supported_version: int,
        message: Optional[str] = None,
    ):
        self.remote_version = remote_version
        self.supported_version = supported_version
        msg = message or (
            f"Incompatible schema version: remote={remote_version}, "
            f"supported={supported_version}"
        )
        hint = (
            "Please update cvecli to the latest version: pip install --upgrade cvecli"
        )
        super().__init__(msg, hint)


# =============================================================================
# Search Errors
# =============================================================================


class SearchError(CVECliError):
    """Base class for search-related errors."""

    pass


class InvalidQueryError(SearchError):
    """Raised when a search query is invalid.

    Examples:
        - Empty query string
        - Invalid regex pattern
        - Malformed search syntax
    """

    def __init__(self, query: str, reason: str):
        self.query = query
        self.reason = reason
        super().__init__(f"Invalid query '{query}': {reason}")


class InvalidCPEError(SearchError):
    """Raised when a CPE string is invalid or malformed.

    CPE strings should follow the format:
        cpe:2.3:<part>:<vendor>:<product>:...
    or:
        cpe:/<part>:<vendor>:<product>:...
    """

    def __init__(self, cpe_string: str, reason: Optional[str] = None):
        self.cpe_string = cpe_string
        msg = f"Invalid CPE string: {cpe_string}"
        details = reason or (
            "Expected format: cpe:2.3:<part>:<vendor>:<product>:... "
            "or cpe:/<part>:<vendor>:<product>:..."
        )
        super().__init__(msg, details)


class InvalidPURLError(SearchError):
    """Raised when a Package URL (PURL) is invalid or malformed.

    PURL strings should follow the format:
        pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    """

    def __init__(self, purl_string: str, reason: Optional[str] = None):
        self.purl_string = purl_string
        msg = f"Invalid PURL: {purl_string}"
        details = reason or (
            "Expected format: pkg:<type>/<namespace>/<name> "
            "(e.g., pkg:npm/lodash, pkg:pypi/django)"
        )
        super().__init__(msg, details)


class SemanticSearchError(SearchError):
    """Raised when semantic search fails.

    This can happen when:
        - Embeddings are not available
        - fastembed is not installed
        - Model loading fails
    """

    pass


class EmbeddingsNotFoundError(SemanticSearchError):
    """Raised when embeddings file is not found."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        msg = "Embeddings not found for semantic search"
        hint = (
            "Download embeddings with: cvecli db update --embeddings\n"
            "Or generate them locally with: cvecli db build extract-embeddings"
        )
        super().__init__(msg, hint)


class SemanticDependencyError(SemanticSearchError):
    """Raised when semantic search dependencies are not installed."""

    def __init__(self, operation: str = "semantic search"):
        self.operation = operation
        msg = f"Cannot perform {operation}: fastembed is not installed"
        hint = (
            "Install with: pip install cvecli[semantic]\n"
            "Or with uv: uv pip install cvecli[semantic]"
        )
        super().__init__(msg, hint)


# =============================================================================
# Download Errors
# =============================================================================


class DownloadError(CVECliError):
    """Base class for download-related errors."""

    pass


class NetworkError(DownloadError):
    """Raised when a network operation fails.

    Examples:
        - Connection timeout
        - DNS resolution failure
        - HTTP errors
    """

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Network error accessing {url}: {reason}")


class ChecksumMismatchError(DownloadError):
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


class ManifestError(DownloadError):
    """Raised when there's a problem with the release manifest."""

    pass


class ManifestNotFoundError(ManifestError):
    """Raised when manifest.json is not found in a release."""

    def __init__(self, release_tag: str):
        self.release_tag = release_tag
        super().__init__(f"No manifest.json found in release {release_tag}")


class ManifestIncompatibleError(ManifestError):
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


# =============================================================================
# Extraction Errors
# =============================================================================


class ExtractionError(CVECliError):
    """Raised when CVE data extraction fails."""

    pass


class JSONParseError(ExtractionError):
    """Raised when a CVE JSON file cannot be parsed."""

    def __init__(self, filepath: str, reason: str):
        self.filepath = filepath
        self.reason = reason
        super().__init__(f"Failed to parse {filepath}: {reason}")
