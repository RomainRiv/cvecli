"""Unit tests for configuration module.

These tests verify that the Config class handles paths, environment variables,
and directory management correctly.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from cvecli.core.config import (
    CURRENT_YEAR,
    DEFAULT_DATA_DIR,
    DEFAULT_DOWNLOAD_DIR,
    DEFAULT_YEARS,
    Config,
    get_config,
    reset_config,
)

# =============================================================================
# Config Initialization Tests
# =============================================================================


class TestConfigInit:
    """Tests for Config initialization."""

    def test_default_paths(self):
        """Config should use default paths when none provided."""
        config = Config()
        # Should have data_dir and download_dir set
        assert config.data_dir is not None
        assert config.download_dir is not None
        assert isinstance(config.data_dir, Path)
        assert isinstance(config.download_dir, Path)

    def test_custom_data_dir(self):
        """Config should accept custom data directory."""
        custom_path = Path("/custom/data")
        config = Config(data_dir=custom_path)
        assert config.data_dir == custom_path

    def test_custom_download_dir(self):
        """Config should accept custom download directory."""
        custom_path = Path("/custom/download")
        config = Config(download_dir=custom_path)
        assert config.download_dir == custom_path

    def test_custom_default_years(self):
        """Config should accept custom default years."""
        config = Config(default_years=5)
        assert config.default_years == 5

    def test_all_custom_values(self):
        """Config should accept all custom values at once."""
        config = Config(
            data_dir=Path("/data"),
            download_dir=Path("/download"),
            default_years=3,
        )
        assert config.data_dir == Path("/data")
        assert config.download_dir == Path("/download")
        assert config.default_years == 3


class TestConfigEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_data_dir_from_env(self):
        """Config should read CVE_DATA_DIR from environment."""
        with patch.dict(os.environ, {"CVE_DATA_DIR": "/env/data"}):
            reset_config()  # Clear cached config
            config = Config()
            assert config.data_dir == Path("/env/data")

    def test_download_dir_from_env(self):
        """Config should read CVE_DOWNLOAD_DIR from environment."""
        with patch.dict(os.environ, {"CVE_DOWNLOAD_DIR": "/env/download"}):
            reset_config()
            config = Config()
            assert config.download_dir == Path("/env/download")

    def test_default_years_from_env(self):
        """Config should read CVE_DEFAULT_YEARS from environment."""
        with patch.dict(os.environ, {"CVE_DEFAULT_YEARS": "7"}):
            reset_config()
            config = Config()
            assert config.default_years == 7

    def test_explicit_values_override_env(self):
        """Explicit values should override environment variables."""
        with patch.dict(os.environ, {"CVE_DATA_DIR": "/env/data"}):
            config = Config(data_dir=Path("/explicit/data"))
            assert config.data_dir == Path("/explicit/data")


# =============================================================================
# Path Properties Tests
# =============================================================================


class TestConfigPathProperties:
    """Tests for Config path properties."""

    @pytest.fixture
    def config(self):
        """Create a config with known paths for testing."""
        return Config(
            data_dir=Path("/test/data"),
            download_dir=Path("/test/download"),
        )

    def test_cve_dir(self, config):
        """cve_dir should be under download_dir."""
        assert config.cve_dir.is_relative_to(config.download_dir)
        assert "cve_github" in str(config.cve_dir)

    def test_cves_parquet(self, config):
        """cves_parquet should be in data_dir."""
        assert config.cves_parquet.parent == config.data_dir
        assert config.cves_parquet.name == "cves.parquet"

    def test_cve_descriptions_parquet(self, config):
        """cve_descriptions_parquet should be in data_dir."""
        assert config.cve_descriptions_parquet.parent == config.data_dir
        assert config.cve_descriptions_parquet.name == "cve_descriptions.parquet"

    def test_cve_metrics_parquet(self, config):
        """cve_metrics_parquet should be in data_dir."""
        assert config.cve_metrics_parquet.parent == config.data_dir
        assert config.cve_metrics_parquet.name == "cve_metrics.parquet"

    def test_cve_products_parquet(self, config):
        """cve_products_parquet should be in data_dir."""
        assert config.cve_products_parquet.parent == config.data_dir
        assert config.cve_products_parquet.name == "cve_products.parquet"

    def test_cve_versions_parquet(self, config):
        """cve_versions_parquet should be in data_dir."""
        assert config.cve_versions_parquet.parent == config.data_dir
        assert config.cve_versions_parquet.name == "cve_versions.parquet"

    def test_cve_cwes_parquet(self, config):
        """cve_cwes_parquet should be in data_dir."""
        assert config.cve_cwes_parquet.parent == config.data_dir
        assert config.cve_cwes_parquet.name == "cve_cwes.parquet"

    def test_cve_references_parquet(self, config):
        """cve_references_parquet should be in data_dir."""
        assert config.cve_references_parquet.parent == config.data_dir
        assert config.cve_references_parquet.name == "cve_references.parquet"

    def test_cve_credits_parquet(self, config):
        """cve_credits_parquet should be in data_dir."""
        assert config.cve_credits_parquet.parent == config.data_dir
        assert config.cve_credits_parquet.name == "cve_credits.parquet"

    def test_cve_tags_parquet(self, config):
        """cve_tags_parquet should be in data_dir."""
        assert config.cve_tags_parquet.parent == config.data_dir
        assert config.cve_tags_parquet.name == "cve_tags.parquet"

    def test_cve_embeddings_parquet(self, config):
        """cve_embeddings_parquet should be in data_dir."""
        assert config.cve_embeddings_parquet.parent == config.data_dir
        assert config.cve_embeddings_parquet.name == "cve_embeddings.parquet"

    def test_capec_json(self, config):
        """capec_json should be in data_dir."""
        assert config.capec_json.parent == config.data_dir
        assert config.capec_json.name == "capec.json"

    def test_cwe_json(self, config):
        """cwe_json should be in data_dir."""
        assert config.cwe_json.parent == config.data_dir
        assert config.cwe_json.name == "cwe.json"

    def test_capec_xml(self, config):
        """capec_xml should be in download_dir."""
        assert config.capec_xml.is_relative_to(config.download_dir)
        assert "capec" in str(config.capec_xml)

    def test_cwe_xml(self, config):
        """cwe_xml should be in download_dir."""
        assert config.cwe_xml.is_relative_to(config.download_dir)
        assert "cwe" in str(config.cwe_xml)

    def test_cve_zip(self, config):
        """cve_zip should be in download_dir."""
        assert config.cve_zip.is_relative_to(config.download_dir)
        assert ".zip" in config.cve_zip.name


# =============================================================================
# Year Range Tests
# =============================================================================


class TestConfigYearRange:
    """Tests for get_year_range method."""

    def test_default_year_range(self):
        """Default year range should use default_years."""
        config = Config(default_years=10)
        start, end = config.get_year_range()

        assert end == CURRENT_YEAR
        assert start == CURRENT_YEAR - 10 + 1

    def test_custom_year_range(self):
        """Custom years parameter should override default."""
        config = Config(default_years=10)
        start, end = config.get_year_range(years=5)

        assert end == CURRENT_YEAR
        assert start == CURRENT_YEAR - 5 + 1

    def test_year_range_single_year(self):
        """Year range with 1 year should return same start and end."""
        config = Config()
        start, end = config.get_year_range(years=1)

        assert start == end == CURRENT_YEAR

    def test_year_range_returns_tuple(self):
        """get_year_range should return a tuple."""
        config = Config()
        result = config.get_year_range()

        assert isinstance(result, tuple)
        assert len(result) == 2


# =============================================================================
# Directory Management Tests
# =============================================================================


class TestConfigDirectoryManagement:
    """Tests for ensure_directories method."""

    def test_ensure_directories_creates_data_dir(self):
        """ensure_directories should create data directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(
                data_dir=Path(tmpdir) / "data",
                download_dir=Path(tmpdir) / "download",
            )
            assert not config.data_dir.exists()

            config.ensure_directories()

            assert config.data_dir.exists()
            assert config.data_dir.is_dir()

    def test_ensure_directories_creates_download_dir(self):
        """ensure_directories should create download directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(
                data_dir=Path(tmpdir) / "data",
                download_dir=Path(tmpdir) / "download",
            )
            assert not config.download_dir.exists()

            config.ensure_directories()

            assert config.download_dir.exists()
            assert config.download_dir.is_dir()

    def test_ensure_directories_creates_subdirs(self):
        """ensure_directories should create necessary subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(
                data_dir=Path(tmpdir) / "data",
                download_dir=Path(tmpdir) / "download",
            )

            config.ensure_directories()

            # Should create capec, cwe, cve_github subdirs
            assert (config.download_dir / "capec").exists()
            assert (config.download_dir / "cwe").exists()
            assert (config.download_dir / "cve_github").exists()

    def test_ensure_directories_idempotent(self):
        """ensure_directories should be safe to call multiple times."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config(
                data_dir=Path(tmpdir) / "data",
                download_dir=Path(tmpdir) / "download",
            )

            # Call twice - should not raise
            config.ensure_directories()
            config.ensure_directories()

            assert config.data_dir.exists()


# =============================================================================
# Global Config Tests
# =============================================================================


class TestGlobalConfig:
    """Tests for global config functions."""

    def teardown_method(self):
        """Reset global config after each test."""
        reset_config()

    def test_get_config_returns_config(self):
        """get_config should return a Config instance."""
        config = get_config()
        assert isinstance(config, Config)

    def test_get_config_is_cached(self):
        """get_config should return the same instance on repeated calls."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_reset_config_clears_cache(self):
        """reset_config should clear the cached config."""
        config1 = get_config()
        reset_config()
        config2 = get_config()
        assert config1 is not config2

    def test_reset_config_allows_env_changes(self):
        """After reset, config should pick up new environment values."""
        _ = get_config()  # Cache initial config
        reset_config()

        with patch.dict(os.environ, {"CVE_DATA_DIR": "/new/path"}):
            config = get_config()
            assert config.data_dir == Path("/new/path")


# =============================================================================
# Constants Tests
# =============================================================================


class TestConfigConstants:
    """Tests for configuration constants."""

    def test_default_data_dir_is_path(self):
        """DEFAULT_DATA_DIR should be a Path."""
        assert isinstance(DEFAULT_DATA_DIR, Path)

    def test_default_download_dir_is_path(self):
        """DEFAULT_DOWNLOAD_DIR should be a Path."""
        assert isinstance(DEFAULT_DOWNLOAD_DIR, Path)

    def test_default_years_is_positive(self):
        """DEFAULT_YEARS should be a positive integer."""
        assert isinstance(DEFAULT_YEARS, int)
        assert DEFAULT_YEARS > 0

    def test_current_year_is_reasonable(self):
        """CURRENT_YEAR should be a reasonable year."""
        assert isinstance(CURRENT_YEAR, int)
        assert 2020 <= CURRENT_YEAR <= 2100
