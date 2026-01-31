"""Tests to verify that example files run without errors.

These tests import and run each example's main() function to ensure
the examples work correctly and don't crash when the API changes.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import polars as pl
import pytest

from cvecli.core.config import Config

# Add examples directory to path for imports
EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


class TestExamples:
    """Test that all example files run without errors.

    These tests require real CVE data to be present.
    Run 'cvecli db update' first to download the database.
    """

    @pytest.fixture(autouse=True)
    def setup_examples_path(self):
        """Add examples directory to sys.path for imports."""
        sys.path.insert(0, str(EXAMPLES_DIR))
        yield
        sys.path.remove(str(EXAMPLES_DIR))

    @pytest.fixture
    def real_data_available(self):
        """Skip tests if real CVE data is not available."""
        config = Config()
        if not config.cves_parquet.exists():
            pytest.skip("Real CVE data not available - run 'cvecli db update' first")

        # Check schema
        try:
            df = pl.read_parquet(config.cves_parquet)
            if "cve_id" not in df.columns:
                pytest.skip("CVE data is in old schema format")
        except Exception:
            pytest.skip("Error reading parquet file")

    @pytest.fixture
    def suppress_output(self):
        """Suppress print output during tests."""
        with patch("builtins.print"):
            yield

    def test_basic_search_example(self, real_data_available, suppress_output):
        """Test basic_search.py runs without errors."""
        import basic_search

        # Run the example - should not raise any exceptions
        basic_search.main()

    def test_purl_search_example(self, real_data_available, suppress_output):
        """Test purl_search.py runs without errors."""
        import purl_search

        purl_search.main()

    def test_cpe_version_search_example(self, real_data_available, suppress_output):
        """Test cpe_version_search.py runs without errors."""
        import cpe_version_search

        cpe_version_search.main()

    def test_severity_date_filter_example(self, real_data_available, suppress_output):
        """Test severity_date_filter.py runs without errors."""
        import severity_date_filter

        severity_date_filter.main()

    def test_export_data_example(
        self, real_data_available, suppress_output, tmp_path, monkeypatch
    ):
        """Test export_data.py runs without errors."""
        import export_data

        # Patch OUTPUT_DIR to use tmp_path
        test_output_dir = tmp_path / "output"
        monkeypatch.setattr(export_data, "OUTPUT_DIR", test_output_dir)

        export_data.main()

        # Verify output files were created
        assert test_output_dir.exists()
        assert (test_output_dir / "django_cves.json").exists()
        assert (test_output_dir / "django_cves.csv").exists()
        assert (test_output_dir / "django_cves.parquet").exists()
