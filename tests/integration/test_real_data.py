"""Integration tests with real CVE data.

These tests require the real CVE database to be present.
Run 'cvecli db update' first to download the database.

These tests are marked with @pytest.mark.requires_real_data and are
skipped if the database is not available.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from cvecli.constants import SeverityLevel
from cvecli.services.search import CVESearchService


class TestSearchWithRealData:
    """Tests using real CVE data from the repository (if available)."""

    def test_search_known_cve(self, real_data_config):
        """Test searching for a known CVE in real data."""
        search = CVESearchService(config=real_data_config)
        result = search.query().by_id("CVE-2024-6387").execute()  # regreSSHion

        if result.count == 0:
            pytest.skip("CVE-2024-6387 not in extracted data")

        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2024-6387"
        assert cve["state"] == "PUBLISHED"

    def test_search_openssl_cves(self, real_data_config):
        """Test searching for OpenSSL CVEs in real data."""
        search = CVESearchService(config=real_data_config)
        result = search.query().by_product("openssl", fuzzy=True).execute()

        # There should be many OpenSSL CVEs
        assert result.count > 0

    def test_search_critical_severity(self, real_data_config):
        """Test searching for critical CVEs in real data."""
        search = CVESearchService(config=real_data_config)
        result = search.query().by_severity(SeverityLevel.CRITICAL).execute()

        # There should be many critical CVEs
        assert result.count > 0

        # All should have high CVSS - check via get_best_metric
        for cve in result.to_dicts()[:10]:  # Check first 10
            metric = search.get_best_metric(cve["cve_id"])
            if metric is not None and metric.get("base_score") is not None:
                score = metric["base_score"]
                assert (
                    score >= 9.0
                ), f"CVE {cve['cve_id']} has score {score}, expected >= 9.0"

    def test_search_log4shell(self, real_data_config):
        """Test searching for Log4Shell vulnerability."""
        search = CVESearchService(config=real_data_config)
        result = search.query().by_id("CVE-2021-44228").execute()

        if result.count == 0:
            pytest.skip("CVE-2021-44228 not in extracted data")

        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2021-44228"

        # Check it's critical severity
        metric = search.get_best_metric("CVE-2021-44228")
        if metric and metric.get("base_score"):
            assert metric["base_score"] >= 9.0

    def test_search_by_cwe_in_real_data(self, real_data_config):
        """Test searching by CWE in real data."""
        search = CVESearchService(config=real_data_config)

        # CWE-79: Cross-site Scripting (XSS) - very common
        result = search.query().by_cwe("CWE-79").execute()

        assert result.count > 0, "Should find CVEs with CWE-79"


# =============================================================================
# Example Script Tests
# =============================================================================


EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


class TestExamples:
    """Test that all example files run without errors.

    These tests require real CVE data to be present.
    """

    @pytest.fixture(autouse=True)
    def setup_examples_path(self):
        """Add examples directory to sys.path for imports."""
        sys.path.insert(0, str(EXAMPLES_DIR))
        yield
        if str(EXAMPLES_DIR) in sys.path:
            sys.path.remove(str(EXAMPLES_DIR))

    @pytest.fixture
    def suppress_output(self):
        """Suppress print output during tests."""
        with patch("builtins.print"):
            yield

    def test_basic_search_example(self, real_data_config, suppress_output):
        """Test basic_search.py runs without errors."""
        import basic_search

        basic_search.main()

    def test_purl_search_example(self, real_data_config, suppress_output):
        """Test purl_search.py runs without errors."""
        import purl_search

        purl_search.main()

    def test_cpe_version_search_example(self, real_data_config, suppress_output):
        """Test cpe_version_search.py runs without errors."""
        import cpe_version_search

        cpe_version_search.main()

    def test_severity_date_filter_example(self, real_data_config, suppress_output):
        """Test severity_date_filter.py runs without errors."""
        import severity_date_filter

        severity_date_filter.main()

    def test_export_data_example(
        self, real_data_config, suppress_output, tmp_path, monkeypatch
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
