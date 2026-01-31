"""Unit tests for the artifact fetcher service.

These tests use mocked HTTP responses to avoid network dependencies.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvecli.core.config import Config
from cvecli.exceptions import ChecksumMismatchError, ManifestIncompatibleError
from cvecli.services.artifact_fetcher import (
    SUPPORTED_SCHEMA_VERSION,
    ArtifactFetcher,
)


@pytest.fixture
def temp_fetcher_config():
    """Create a config with temporary directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(data_dir=Path(tmpdir))
        config.ensure_directories()
        yield config


@pytest.fixture
def fetcher(temp_fetcher_config):
    """Create an ArtifactFetcher with temp config in quiet mode."""
    return ArtifactFetcher(config=temp_fetcher_config, quiet=True)


@pytest.fixture
def mock_release():
    """Sample GitHub release data."""
    return {
        "tag_name": "v20260108",
        "assets": [
            {
                "name": "manifest.json",
                "browser_download_url": "https://example.com/manifest.json",
            },
            {
                "name": "cves.parquet",
                "browser_download_url": "https://example.com/cves.parquet",
            },
        ],
    }


@pytest.fixture
def mock_manifest():
    """Sample manifest data."""
    return {
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "generated_at": "2026-01-08T12:00:00Z",
        "release_status": "official",
        "files": [
            {"name": "cves.parquet", "sha256": "abc123"},
        ],
        "stats": {"total_cves": 1000},
    }


class TestManifestIncompatibleError:
    """Test ManifestIncompatibleError exception."""

    def test_error_message(self):
        """Test error message contains version info."""
        error = ManifestIncompatibleError(2, 1)
        assert "remote version 2" in str(error)
        assert "supported version 1" in str(error)
        assert error.remote_version == 2
        assert error.supported_version == 1

    def test_error_attributes(self):
        """Test error attributes are set correctly."""
        error = ManifestIncompatibleError(5, 3)
        assert error.remote_version == 5
        assert error.supported_version == 3


class TestChecksumMismatchError:
    """Test ChecksumMismatchError exception."""

    def test_error_message(self):
        """Test error message contains filename."""
        error = ChecksumMismatchError("test.parquet", "abc123", "def456")
        assert "test.parquet" in str(error)
        assert error.filename == "test.parquet"
        assert error.expected == "abc123"
        assert error.actual == "def456"

    def test_inherits_from_exception(self):
        """Should inherit from Exception."""
        error = ChecksumMismatchError("test.parquet", "abc", "def")
        assert isinstance(error, Exception)


class TestArtifactFetcherInit:
    """Test ArtifactFetcher initialization."""

    def test_quiet_mode(self, temp_fetcher_config):
        """Test quiet mode can be enabled."""
        fetcher = ArtifactFetcher(config=temp_fetcher_config, quiet=True)
        assert fetcher.quiet is True

    def test_default_not_quiet(self, temp_fetcher_config):
        """Test default is not quiet."""
        fetcher = ArtifactFetcher(config=temp_fetcher_config)
        assert fetcher.quiet is False


class TestGetLatestRelease:
    """Test _get_latest_release method."""

    def test_get_latest_release_success(self, fetcher, mock_release):
        """Test successful release fetch."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.ok = True
            mock_response.json.return_value = mock_release
            mock_get.return_value = mock_response

            release = fetcher._get_latest_release()

            assert release["tag_name"] == "v20260108"
            assert len(release["assets"]) == 2

    def test_get_latest_release_failure(self, fetcher):
        """Test handling of failed release fetch - raises HTTPError."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = Exception("404 Not Found")
            mock_get.return_value = mock_response

            with pytest.raises(Exception):
                fetcher._get_latest_release()


class TestCheckCompatibility:
    """Test manifest compatibility checking."""

    def test_check_compatible_manifest(self, fetcher, mock_manifest):
        """Test validation of compatible manifest."""
        # Should return True and not raise
        assert fetcher.check_compatibility(mock_manifest) is True

    def test_check_incompatible_manifest(self, fetcher):
        """Test validation of incompatible manifest."""
        incompatible_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION + 1,
        }

        with pytest.raises(ManifestIncompatibleError) as exc_info:
            fetcher.check_compatibility(incompatible_manifest)

        assert exc_info.value.remote_version == SUPPORTED_SCHEMA_VERSION + 1
        assert exc_info.value.supported_version == SUPPORTED_SCHEMA_VERSION


class TestSupportedSchemaVersion:
    """Test schema version constant."""

    def test_schema_version_positive(self):
        """Schema version should be positive."""
        assert SUPPORTED_SCHEMA_VERSION > 0

    def test_schema_version_integer(self):
        """Schema version should be an integer."""
        assert isinstance(SUPPORTED_SCHEMA_VERSION, int)
