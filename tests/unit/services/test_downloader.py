"""Unit tests for the downloader service.

These tests use mocked HTTP responses to avoid network dependencies.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvecli.core.config import Config
from cvecli.services.downloader import (
    DownloadService,
    CAPEC_URL,
    CWE_URL,
    CVE_GITHUB_URL,
)


@pytest.fixture
def temp_download_config():
    """Create a config with temporary directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(
            data_dir=Path(tmpdir) / "data",
            download_dir=Path(tmpdir) / "download",
        )
        config.ensure_directories()
        yield config


@pytest.fixture
def download_service(temp_download_config):
    """Create a DownloadService with temp config in quiet mode."""
    return DownloadService(config=temp_download_config, quiet=True)


class TestDownloadServiceInit:
    """Test DownloadService initialization."""

    def test_default_config(self):
        """Test that default config is used when not provided."""
        with patch("cvecli.services.downloader.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.data_dir = Path(tempfile.gettempdir())
            mock_get_config.return_value = mock_config
            service = DownloadService()
            assert service.config == mock_config

    def test_quiet_mode(self, temp_download_config):
        """Test quiet mode can be enabled."""
        service = DownloadService(config=temp_download_config, quiet=True)
        assert service.quiet is True

    def test_verbose_mode(self, temp_download_config):
        """Test default is not quiet."""
        service = DownloadService(config=temp_download_config)
        assert service.quiet is False


class TestDownloadWithProgress:
    """Test _download_with_progress method."""

    def test_download_with_progress_success_quiet(self, download_service):
        """Test successful file download in quiet mode."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test content"]
            mock_get.return_value = mock_response

            dest_path = download_service.config.data_dir / "test.txt"
            download_service._download_with_progress(
                "https://example.com/test.txt", dest_path
            )

            assert dest_path.exists()
            assert dest_path.read_bytes() == b"test content"

    def test_download_creates_parent_dirs(self, download_service):
        """Test that parent directories are created if they don't exist."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test"]
            mock_get.return_value = mock_response

            dest_path = download_service.config.data_dir / "nested" / "dir" / "test.txt"
            download_service._download_with_progress(
                "https://example.com/test.txt", dest_path
            )

            assert dest_path.exists()

    def test_download_no_content_length(self, download_service):
        """Test download when content-length header is missing."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {}  # No content-length
            mock_response.iter_content.return_value = [b"test content"]
            mock_get.return_value = mock_response

            dest_path = download_service.config.data_dir / "test.txt"
            download_service._download_with_progress(
                "https://example.com/test.txt", dest_path
            )

            assert dest_path.exists()


class TestDownloadURLs:
    """Test URL constants."""

    def test_cve_github_url(self):
        """CVE GitHub URL should be properly formatted."""
        assert "github.com" in CVE_GITHUB_URL.lower()

    def test_capec_url(self):
        """CAPEC URL should be properly formatted."""
        assert "capec" in CAPEC_URL.lower()

    def test_cwe_url(self):
        """CWE URL should be properly formatted."""
        assert "cwe" in CWE_URL.lower()
