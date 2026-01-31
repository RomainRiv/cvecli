"""Unit tests for custom exceptions.

These tests verify that all exception classes in the hierarchy work correctly.
"""

import pytest

from cvecli.exceptions import (
    ChecksumMismatchError,
    # Configuration
    ConfigurationError,
    # Base
    CVECliError,
    DataCorruptedError,
    # Data errors
    DataError,
    DataNotFoundError,
    # Download errors
    DownloadError,
    EmbeddingsNotFoundError,
    # Extraction errors
    ExtractionError,
    InvalidCPEError,
    InvalidPURLError,
    InvalidQueryError,
    JSONParseError,
    ManifestError,
    ManifestIncompatibleError,
    ManifestNotFoundError,
    NetworkError,
    SchemaVersionError,
    # Search errors
    SearchError,
    SemanticDependencyError,
    SemanticSearchError,
)

# =============================================================================
# Base Exception Tests
# =============================================================================


class TestCVECliError:
    """Tests for the base CVECliError class."""

    def test_basic_message(self):
        """Error should store and display message."""
        error = CVECliError("Test error message")
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details is None

    def test_message_with_details(self):
        """Error should include details when provided."""
        error = CVECliError("Main message", details="Additional info")
        assert "Main message" in str(error)
        assert "Additional info" in str(error)
        assert error.details == "Additional info"

    def test_is_exception(self):
        """CVECliError should be an Exception."""
        error = CVECliError("Test")
        assert isinstance(error, Exception)

    def test_can_be_raised_and_caught(self):
        """Error can be raised and caught."""
        with pytest.raises(CVECliError) as exc_info:
            raise CVECliError("Raised error")
        assert "Raised error" in str(exc_info.value)


# =============================================================================
# Configuration Errors
# =============================================================================


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_inherits_from_cvecli_error(self):
        """Should inherit from CVECliError."""
        error = ConfigurationError("Config problem")
        assert isinstance(error, CVECliError)

    def test_message_formatting(self):
        """Should format message correctly."""
        error = ConfigurationError("Invalid path", details="/bad/path")
        assert "Invalid path" in str(error)
        assert "/bad/path" in str(error)


# =============================================================================
# Data Errors
# =============================================================================


class TestDataError:
    """Tests for DataError base class."""

    def test_inherits_from_cvecli_error(self):
        """Should inherit from CVECliError."""
        error = DataError("Data problem")
        assert isinstance(error, CVECliError)


class TestDataNotFoundError:
    """Tests for DataNotFoundError."""

    def test_default_message(self):
        """Should have default message."""
        error = DataNotFoundError()
        assert "not found" in str(error).lower()

    def test_with_path(self):
        """Should include path in details."""
        error = DataNotFoundError(path="/data/cves.parquet")
        assert error.path == "/data/cves.parquet"

    def test_has_hint(self):
        """Should have helpful hint."""
        error = DataNotFoundError()
        assert "cvecli db update" in error.hint

    def test_inherits_from_data_error(self):
        """Should inherit from DataError."""
        error = DataNotFoundError()
        assert isinstance(error, DataError)


class TestDataCorruptedError:
    """Tests for DataCorruptedError."""

    def test_inherits_from_data_error(self):
        """Should inherit from DataError."""
        error = DataCorruptedError("Corrupted file")
        assert isinstance(error, DataError)


class TestSchemaVersionError:
    """Tests for SchemaVersionError."""

    def test_version_attributes(self):
        """Should store version numbers."""
        error = SchemaVersionError(remote_version=5, supported_version=3)
        assert error.remote_version == 5
        assert error.supported_version == 3

    def test_default_message(self):
        """Should include version info in message."""
        error = SchemaVersionError(remote_version=5, supported_version=3)
        assert "5" in str(error)
        assert "3" in str(error)

    def test_custom_message(self):
        """Should accept custom message."""
        error = SchemaVersionError(
            remote_version=5,
            supported_version=3,
            message="Custom schema error",
        )
        assert "Custom schema error" in str(error)

    def test_inherits_from_data_error(self):
        """Should inherit from DataError."""
        error = SchemaVersionError(remote_version=1, supported_version=1)
        assert isinstance(error, DataError)


# =============================================================================
# Search Errors
# =============================================================================


class TestSearchError:
    """Tests for SearchError base class."""

    def test_inherits_from_cvecli_error(self):
        """Should inherit from CVECliError."""
        error = SearchError("Search failed")
        assert isinstance(error, CVECliError)


class TestInvalidQueryError:
    """Tests for InvalidQueryError."""

    def test_stores_query_and_reason(self):
        """Should store query and reason."""
        error = InvalidQueryError(query="[invalid regex", reason="unclosed bracket")
        assert error.query == "[invalid regex"
        assert error.reason == "unclosed bracket"

    def test_message_includes_query(self):
        """Message should include the query."""
        error = InvalidQueryError(query="bad query", reason="syntax error")
        assert "bad query" in str(error)
        assert "syntax error" in str(error)

    def test_inherits_from_search_error(self):
        """Should inherit from SearchError."""
        error = InvalidQueryError("q", "r")
        assert isinstance(error, SearchError)


class TestInvalidCPEError:
    """Tests for InvalidCPEError."""

    def test_stores_cpe_string(self):
        """Should store the invalid CPE string."""
        error = InvalidCPEError(cpe_string="cpe:invalid")
        assert error.cpe_string == "cpe:invalid"

    def test_message_includes_cpe(self):
        """Message should include the CPE string."""
        error = InvalidCPEError(cpe_string="cpe:bad")
        assert "cpe:bad" in str(error)

    def test_with_reason(self):
        """Should include reason in details."""
        error = InvalidCPEError(cpe_string="cpe:bad", reason="wrong format")
        assert "wrong format" in str(error)

    def test_inherits_from_search_error(self):
        """Should inherit from SearchError."""
        error = InvalidCPEError("cpe:")
        assert isinstance(error, SearchError)


class TestInvalidPURLError:
    """Tests for InvalidPURLError."""

    def test_stores_purl_string(self):
        """Should store the invalid PURL string."""
        error = InvalidPURLError(purl_string="not-a-purl")
        assert error.purl_string == "not-a-purl"

    def test_message_includes_purl(self):
        """Message should include the PURL string."""
        error = InvalidPURLError(purl_string="invalid:purl")
        assert "invalid:purl" in str(error)

    def test_with_reason(self):
        """Should include reason in details."""
        error = InvalidPURLError(purl_string="bad", reason="missing pkg: prefix")
        assert "missing pkg: prefix" in str(error)

    def test_inherits_from_search_error(self):
        """Should inherit from SearchError."""
        error = InvalidPURLError("p")
        assert isinstance(error, SearchError)


class TestSemanticSearchError:
    """Tests for SemanticSearchError."""

    def test_inherits_from_search_error(self):
        """Should inherit from SearchError."""
        error = SemanticSearchError("Semantic search failed")
        assert isinstance(error, SearchError)


class TestEmbeddingsNotFoundError:
    """Tests for EmbeddingsNotFoundError."""

    def test_default_message(self):
        """Should have helpful default message."""
        error = EmbeddingsNotFoundError()
        assert "embeddings" in str(error).lower()

    def test_stores_path(self):
        """Should store the path."""
        error = EmbeddingsNotFoundError(path="/data/embeddings.parquet")
        assert error.path == "/data/embeddings.parquet"

    def test_inherits_from_semantic_search_error(self):
        """Should inherit from SemanticSearchError."""
        error = EmbeddingsNotFoundError()
        assert isinstance(error, SemanticSearchError)


class TestSemanticDependencyError:
    """Tests for SemanticDependencyError."""

    def test_default_operation(self):
        """Should have default operation in message."""
        error = SemanticDependencyError()
        assert "semantic search" in str(error)
        assert "fastembed" in str(error)

    def test_custom_operation(self):
        """Should use custom operation."""
        error = SemanticDependencyError(operation="embedding generation")
        assert error.operation == "embedding generation"
        assert "embedding generation" in str(error)

    def test_has_install_hint(self):
        """Should have installation hint."""
        error = SemanticDependencyError()
        assert "cvecli[semantic]" in str(error) or "semantic" in str(error)

    def test_inherits_from_semantic_search_error(self):
        """Should inherit from SemanticSearchError."""
        error = SemanticDependencyError()
        assert isinstance(error, SemanticSearchError)


# =============================================================================
# Download Errors
# =============================================================================


class TestDownloadError:
    """Tests for DownloadError base class."""

    def test_inherits_from_cvecli_error(self):
        """Should inherit from CVECliError."""
        error = DownloadError("Download failed")
        assert isinstance(error, CVECliError)


class TestNetworkError:
    """Tests for NetworkError."""

    def test_stores_url_and_reason(self):
        """Should store URL and reason."""
        error = NetworkError(url="https://example.com", reason="timeout")
        assert error.url == "https://example.com"
        assert error.reason == "timeout"

    def test_message_includes_url(self):
        """Message should include URL."""
        error = NetworkError(url="https://example.com/file", reason="404")
        assert "https://example.com/file" in str(error)
        assert "404" in str(error)

    def test_inherits_from_download_error(self):
        """Should inherit from DownloadError."""
        error = NetworkError("url", "reason")
        assert isinstance(error, DownloadError)


class TestChecksumMismatchError:
    """Tests for ChecksumMismatchError."""

    def test_stores_checksum_info(self):
        """Should store filename and checksums."""
        error = ChecksumMismatchError(
            filename="cves.parquet",
            expected="abc123",
            actual="def456",
        )
        assert error.filename == "cves.parquet"
        assert error.expected == "abc123"
        assert error.actual == "def456"

    def test_message_includes_filename(self):
        """Message should include filename."""
        error = ChecksumMismatchError("test.parquet", "a", "b")
        assert "test.parquet" in str(error)

    def test_inherits_from_download_error(self):
        """Should inherit from DownloadError."""
        error = ChecksumMismatchError("f", "e", "a")
        assert isinstance(error, DownloadError)


class TestManifestError:
    """Tests for ManifestError base class."""

    def test_inherits_from_download_error(self):
        """Should inherit from DownloadError."""
        error = ManifestError("Manifest problem")
        assert isinstance(error, DownloadError)


class TestManifestNotFoundError:
    """Tests for ManifestNotFoundError."""

    def test_stores_release_tag(self):
        """Should store release tag."""
        error = ManifestNotFoundError(release_tag="v20260101")
        assert error.release_tag == "v20260101"

    def test_message_includes_release(self):
        """Message should include release tag."""
        error = ManifestNotFoundError(release_tag="v20260101")
        assert "v20260101" in str(error)

    def test_inherits_from_manifest_error(self):
        """Should inherit from ManifestError."""
        error = ManifestNotFoundError("v1")
        assert isinstance(error, ManifestError)


class TestManifestIncompatibleError:
    """Tests for ManifestIncompatibleError."""

    def test_stores_version_info(self):
        """Should store version information."""
        error = ManifestIncompatibleError(remote_version=5, supported_version=3)
        assert error.remote_version == 5
        assert error.supported_version == 3

    def test_message_includes_versions(self):
        """Message should include both versions."""
        error = ManifestIncompatibleError(remote_version=5, supported_version=3)
        assert "5" in str(error)
        assert "3" in str(error)

    def test_inherits_from_manifest_error(self):
        """Should inherit from ManifestError."""
        error = ManifestIncompatibleError(1, 1)
        assert isinstance(error, ManifestError)


# =============================================================================
# Extraction Errors
# =============================================================================


class TestExtractionError:
    """Tests for ExtractionError base class."""

    def test_inherits_from_cvecli_error(self):
        """Should inherit from CVECliError."""
        error = ExtractionError("Extraction failed")
        assert isinstance(error, CVECliError)


class TestJSONParseError:
    """Tests for JSONParseError."""

    def test_stores_filepath_and_reason(self):
        """Should store filepath and reason."""
        error = JSONParseError(
            filepath="/data/CVE-2024-1234.json",
            reason="invalid JSON syntax",
        )
        assert error.filepath == "/data/CVE-2024-1234.json"
        assert error.reason == "invalid JSON syntax"

    def test_message_includes_filepath(self):
        """Message should include filepath."""
        error = JSONParseError(filepath="/path/file.json", reason="bad syntax")
        assert "/path/file.json" in str(error)
        assert "bad syntax" in str(error)

    def test_inherits_from_extraction_error(self):
        """Should inherit from ExtractionError."""
        error = JSONParseError("f", "r")
        assert isinstance(error, ExtractionError)


# =============================================================================
# Exception Hierarchy Tests
# =============================================================================


class TestExceptionHierarchy:
    """Tests verifying the complete exception hierarchy."""

    def test_all_inherit_from_base(self):
        """All exceptions should inherit from CVECliError."""
        exceptions = [
            ConfigurationError("test"),
            DataError("test"),
            DataNotFoundError(),
            DataCorruptedError("test"),
            SchemaVersionError(1, 1),
            SearchError("test"),
            InvalidQueryError("q", "r"),
            InvalidCPEError("cpe"),
            InvalidPURLError("purl"),
            SemanticSearchError("test"),
            EmbeddingsNotFoundError(),
            SemanticDependencyError(),
            DownloadError("test"),
            NetworkError("url", "reason"),
            ChecksumMismatchError("f", "e", "a"),
            ManifestError("test"),
            ManifestNotFoundError("v1"),
            ManifestIncompatibleError(1, 1),
            ExtractionError("test"),
            JSONParseError("f", "r"),
        ]

        for exc in exceptions:
            assert isinstance(
                exc, CVECliError
            ), f"{type(exc).__name__} should inherit from CVECliError"

    def test_can_catch_by_category(self):
        """Should be able to catch errors by category."""
        # Catch all data errors
        with pytest.raises(DataError):
            raise DataNotFoundError()

        with pytest.raises(DataError):
            raise SchemaVersionError(1, 1)

        # Catch all search errors
        with pytest.raises(SearchError):
            raise InvalidQueryError("q", "r")

        with pytest.raises(SearchError):
            raise InvalidPURLError("p")

        # Catch all download errors
        with pytest.raises(DownloadError):
            raise NetworkError("url", "reason")

        with pytest.raises(DownloadError):
            raise ChecksumMismatchError("f", "e", "a")
