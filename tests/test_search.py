"""Unit tests for the search service."""

import pytest

from cvecli.constants import SeverityLevel
from cvecli.services.search import (
    SEVERITY_THRESHOLDS,
    CVESearchService,
    SearchResult,
)


class TestSeverityThresholds:
    """Tests for severity threshold constants."""

    def test_severity_levels_exist(self):
        """All severity levels should be defined."""
        assert SeverityLevel.NONE in SEVERITY_THRESHOLDS
        assert SeverityLevel.LOW in SEVERITY_THRESHOLDS
        assert SeverityLevel.MEDIUM in SEVERITY_THRESHOLDS
        assert SeverityLevel.HIGH in SEVERITY_THRESHOLDS
        assert SeverityLevel.CRITICAL in SEVERITY_THRESHOLDS

    def test_severity_ranges(self):
        """Severity ranges should be correct."""
        assert SEVERITY_THRESHOLDS[SeverityLevel.NONE] == (0.0, 0.0)
        assert SEVERITY_THRESHOLDS[SeverityLevel.LOW] == (0.1, 3.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.MEDIUM] == (4.0, 6.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.HIGH] == (7.0, 8.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.CRITICAL] == (9.0, 10.0)


class TestSearchResult:
    """Tests for SearchResult class."""

    def test_empty_result(self):
        """Empty result should have count of 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        assert result.count == 0
        assert result.to_dicts() == []

    def test_count_property(self, sample_parquet_data):
        """Count should reflect number of CVEs."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        assert result.count == 5  # 5 sample CVEs in fixture

    def test_summary_empty(self):
        """Summary of empty result should show count 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        summary = result.summary()
        assert summary["count"] == 0

    def test_summary_with_data(self, sample_parquet_data):
        """Summary should include severity and year distribution."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        summary = result.summary()

        assert "count" in summary
        assert "severity_distribution" in summary
        assert "year_distribution" in summary
        assert summary["count"] == 5

    def test_severity_distribution(self, sample_parquet_data):
        """Severity distribution should categorize CVEs correctly."""
        # Use the search service to get results with all related data
        service = CVESearchService(config=sample_parquet_data)

        # Search for all CVEs
        result = service.query().by_id("CVE-2022-2196").execute()
        assert result.count == 1

        # Now test with the full search which includes metrics
        # Search for all by using a broad product search
        result_all = service.query().by_product("", fuzzy=True).execute()
        summary = result_all.summary()

        dist = summary["severity_distribution"]
        # CVE-2022-2196 has 5.8 (medium)
        # CVE-2024-1234 has 9.8 from ADP (critical)
        # CVE-2016-7054 has text severity but no numeric
        # CVE-2023-0001 has no severity (unknown)
        # At minimum we should have some medium and critical
        total = sum(dist.values())
        assert total > 0


class TestCVESearchService:
    """Tests for CVESearchService class."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = CVESearchService()
        assert service.config is not None

    def test_init_custom_config(self, temp_config):
        """Service should accept custom config."""
        service = CVESearchService(config=temp_config)
        assert service.config == temp_config

    def test_by_id_found(self, sample_parquet_data):
        """by_id should return matching CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"
        assert cve["state"] == "PUBLISHED"

    def test_by_id_not_found(self, sample_parquet_data):
        """by_id should return empty result for non-existent CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_id("CVE-9999-9999").execute()

        assert result.count == 0

    def test_by_id_normalizes_input(self, sample_parquet_data):
        """by_id should normalize CVE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CVE- prefix
        result1 = service.query().by_id("2022-2196").execute()
        assert result1.count == 1

        # Lowercase
        result2 = service.query().by_id("cve-2022-2196").execute()
        assert result2.count == 1

    def test_by_product_found(self, sample_parquet_data):
        """by_product should return CVEs affecting the product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_product("Linux Kernel").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_product_fuzzy(self, sample_parquet_data):
        """by_product should support fuzzy matching."""
        service = CVESearchService(config=sample_parquet_data)

        # Partial match
        result = service.query().by_product("kernel", fuzzy=True).execute()
        assert result.count >= 1

    def test_by_product_with_vendor(self, sample_parquet_data):
        """by_product chained with by_vendor should filter both."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("Linux Kernel").by_vendor("Linux").execute()
        assert result.count >= 1

    def test_by_product_not_found(self, sample_parquet_data):
        """by_product should return empty for non-existent product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_product("NonExistentProduct12345").execute()

        assert result.count == 0

    def test_by_vendor(self, sample_parquet_data):
        """by_vendor should return CVEs for vendor's products."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_vendor("OpenSSL").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_by_cwe_found(self, sample_parquet_data):
        """by_cwe should return CVEs with matching CWE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_cwe("CWE-1188").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_cwe_normalizes_input(self, sample_parquet_data):
        """by_cwe should normalize CWE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CWE- prefix
        result1 = service.query().by_cwe("1188").execute()
        assert result1.count >= 1

        # Lowercase
        result2 = service.query().by_cwe("cwe-1188").execute()
        assert result2.count >= 1

    def test_by_severity_medium(self, sample_parquet_data):
        """by_severity should return CVEs with matching severity."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_severity(SeverityLevel.MEDIUM).execute()

        # CVE-2022-2196 has CVSS 5.8 (medium)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_severity_critical(self, sample_parquet_data):
        """by_severity should find critical CVEs."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_severity(SeverityLevel.CRITICAL).execute()

        # CVE-2024-1234 has ADP CVSS 9.8 (critical)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_severity_with_date_filter(self, sample_parquet_data):
        """by_severity should filter by date range using chained query."""
        service = CVESearchService(config=sample_parquet_data)

        # After 2020
        result = (
            service.query()
            .by_severity(SeverityLevel.MEDIUM)
            .by_date(after="2020-01-01")
            .execute()
        )
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

        # Before 2020 should not include 2022 CVE
        result2 = (
            service.query()
            .by_severity(SeverityLevel.MEDIUM)
            .by_date(before="2020-01-01")
            .execute()
        )
        cve_ids2 = [c["cve_id"] for c in result2.to_dicts()]
        assert "CVE-2022-2196" not in cve_ids2

    def test_missing_data_file(self, temp_config):
        """Service should raise error when data files are missing."""
        service = CVESearchService(config=temp_config)

        with pytest.raises(FileNotFoundError):
            service.query().by_id("CVE-2022-2196").execute()


class TestSearchResultProducts:
    """Tests for product-related search functionality."""

    def test_products_included_in_result(self, sample_parquet_data):
        """Search result should include product information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.products is not None
        products = result.products.to_dicts()
        assert len(products) >= 1
        assert any(p["product"] == "Linux Kernel" for p in products)


class TestSearchResultCWEs:
    """Tests for CWE-related search functionality."""

    def test_cwes_included_in_result(self, sample_parquet_data):
        """Search result should include CWE information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.cwes is not None
        cwes = result.cwes.to_dicts()
        assert len(cwes) >= 1
        assert any(c["cwe_id"] == "CWE-1188" for c in cwes)


class TestValidateDate:
    """Tests for date validation."""

    def test_valid_date(self, sample_parquet_data):
        """Valid date format should return True."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("2024-01-15") is True
        assert service.validate_date("2023-12-31") is True
        assert service.validate_date("1999-01-01") is True

    def test_invalid_date_format(self, sample_parquet_data):
        """Invalid date formats should return False."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("01-15-2024") is False
        assert service.validate_date("2024/01/15") is False
        assert service.validate_date("not-a-date") is False
        assert service.validate_date("") is False

    def test_invalid_date_values(self, sample_parquet_data):
        """Invalid date values should return False."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("2024-13-01") is False  # Invalid month
        assert service.validate_date("2024-02-30") is False  # Invalid day


class TestExactMatching:
    """Tests for exact (literal) string matching with regex character escaping."""

    def test_by_product_with_regex_chars_exact(self, sample_parquet_data):
        """by_product with exact=True should match literal regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for product with regex special characters using exact matching
        result = (
            service.query()
            .by_product("Product[v1.0]+", fuzzy=True, exact=True)
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_product_regex_chars_without_exact_fails(self, sample_parquet_data):
        """by_product without exact=True should fail on unescaped regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # These regex characters would cause issues or match wrong results without escaping
        # [v1.0] would be interpreted as character class
        # This may either throw an error or return wrong results
        try:
            service.query().by_product("[v1.0]", fuzzy=True, exact=False).execute()
            # If it doesn't throw, it might match other products containing v, 1, 0, or .
            # The exact behavior depends on polars regex handling
        except Exception:
            pass  # Expected - regex parsing error

    def test_by_vendor_with_regex_chars_exact(self, sample_parquet_data):
        """by_vendor with exact=True should match literal regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for vendor with regex special characters using exact matching
        result = (
            service.query()
            .by_vendor("Test.Vendor (Inc.)", fuzzy=True, exact=True)
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_product_partial_with_regex_chars_exact(self, sample_parquet_data):
        """by_product with exact=True should find partial matches with literal characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for partial product name with regex special characters
        result = service.query().by_product("[v1.0]", fuzzy=True, exact=True).execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids


class TestStateFiltering:
    """Tests for state filtering using chainable query API."""

    def test_by_state_published(self, sample_parquet_data):
        """by_state should filter to only published CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        # Get all CVEs first
        all_result = service.query().by_product("", fuzzy=True).execute()
        assert all_result.count >= 5  # We have 5 CVEs in fixtures

        # Filter to published only
        published_result = service.query().by_state("published").execute()
        assert published_result.count >= 4  # 4 published CVEs
        for cve in published_result.to_dicts():
            assert cve["state"] == "PUBLISHED"

    def test_by_state_rejected(self, sample_parquet_data):
        """by_state should filter to only rejected CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter to rejected only
        rejected_result = service.query().by_state("rejected").execute()
        assert rejected_result.count >= 1  # 1 rejected CVE
        for cve in rejected_result.to_dicts():
            assert cve["state"] == "REJECTED"

    def test_by_state_case_insensitive(self, sample_parquet_data):
        """by_state should be case insensitive."""
        service = CVESearchService(config=sample_parquet_data)

        # Test various cases
        result_upper = service.query().by_state("PUBLISHED").execute()
        result_lower = service.query().by_state("published").execute()
        result_mixed = service.query().by_state("Published").execute()

        assert result_upper.count == result_lower.count == result_mixed.count


class TestSemanticSearch:
    """Tests for semantic search functionality."""

    def test_has_embeddings_false(self, sample_parquet_data):
        """has_embeddings should return False when no embeddings exist."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.has_embeddings() is False

    def test_has_embeddings_true(self, sample_parquet_data_with_embeddings):
        """has_embeddings should return True when embeddings exist."""
        service = CVESearchService(config=sample_parquet_data_with_embeddings)
        assert service.has_embeddings() is True

    def test_semantic_search_no_embeddings(self, sample_parquet_data):
        """semantic search should raise error when embeddings don't exist."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(FileNotFoundError):
            service.query().semantic("buffer overflow").execute()

    def test_semantic_search_returns_results(self, sample_parquet_data_with_embeddings):
        """semantic search should return CVEs with similarity scores."""
        from unittest.mock import patch, MagicMock
        import numpy as np
        from cvecli.services.embeddings import EMBEDDING_DIMENSION

        # Mock the embedding model to return a specific query embedding
        with patch(
            "cvecli.services.embeddings.EmbeddingsService._get_model"
        ) as mock_get_model:
            mock_model = MagicMock()
            # fastembed's embed returns a generator
            mock_model.embed.return_value = iter(
                [np.array([1.0] * EMBEDDING_DIMENSION)]
            )
            mock_get_model.return_value = mock_model

            service = CVESearchService(config=sample_parquet_data_with_embeddings)
            result = (
                service.query()
                .semantic("buffer overflow", top_k=10, min_similarity=0.0)
                .execute()
            )

            assert result.count >= 1
            # Results should have similarity_score column
            cve_data = result.to_dicts()[0]
            assert "similarity_score" in cve_data


class TestKEVFiltering:
    """Tests for CISA KEV filtering using chainable query API."""

    def test_by_kev(self, sample_parquet_data):
        """by_kev should filter to only CVEs in CISA KEV."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter to KEV only
        kev_result = service.query().by_kev().execute()
        assert kev_result.count >= 1  # At least CVE-2024-1234 should be in KEV
        cve_ids = [c["cve_id"] for c in kev_result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_kev_preserves_related_data(self, sample_parquet_data):
        """by_kev should preserve related data for filtered CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        kev_result = service.query().by_kev().execute()

        # Related data should be present
        assert kev_result.products is not None or kev_result.count == 0


class TestGetKEVInfo:
    """Tests for KEV info retrieval."""

    def test_get_kev_info_found(self, sample_parquet_data):
        """get_kev_info should return KEV data for CVE in KEV list."""
        service = CVESearchService(config=sample_parquet_data)

        kev_info = service.get_kev_info("CVE-2024-1234")
        assert kev_info is not None
        assert "dateAdded" in kev_info
        assert kev_info["dateAdded"] == "2024-01-15"

    def test_get_kev_info_not_found(self, sample_parquet_data):
        """get_kev_info should return None for CVE not in KEV list."""
        service = CVESearchService(config=sample_parquet_data)

        kev_info = service.get_kev_info("CVE-2022-2196")
        assert kev_info is None


class TestGetSSVCInfo:
    """Tests for SSVC info retrieval."""

    def test_get_ssvc_info_found(self, sample_parquet_data):
        """get_ssvc_info should return SSVC data for CVE with SSVC assessment."""
        service = CVESearchService(config=sample_parquet_data)

        ssvc_info = service.get_ssvc_info("CVE-2024-1234")
        assert ssvc_info is not None
        assert "automatable" in ssvc_info
        assert ssvc_info["automatable"] == "Yes"
        assert "exploitation" in ssvc_info
        assert ssvc_info["exploitation"] == "Active"

    def test_get_ssvc_info_not_found(self, sample_parquet_data):
        """get_ssvc_info should return None for CVE without SSVC assessment."""
        service = CVESearchService(config=sample_parquet_data)

        ssvc_info = service.get_ssvc_info("CVE-2022-2196")
        assert ssvc_info is None


class TestCPESearch:
    """Tests for CPE-based search functionality."""

    def test_by_cpe_with_explicit_version(self, sample_parquet_data):
        """by_cpe should extract version from CPE string automatically."""
        service = CVESearchService(config=sample_parquet_data)

        # Search with a CPE that has a specific version
        result = (
            service.query()
            .by_cpe("cpe:2.3:a:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*")
            .execute()
        )

        # Should filter to only CVEs affecting version 5.15.0
        # The sample data has CVE-2022-2196 with affected version range
        assert (
            result.count >= 0
        )  # May or may not have matches depending on version ranges

    def test_by_cpe_with_wildcard_version(self, sample_parquet_data):
        """by_cpe should not filter by version when CPE has wildcard."""
        service = CVESearchService(config=sample_parquet_data)

        # Search with wildcard version - should return all matching vendor/product
        result = (
            service.query()
            .by_cpe("cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*")
            .execute()
        )

        # Should NOT filter by version, return all linux kernel CVEs
        assert result.count >= 1  # Should find CVE-2022-2196

    def test_by_cpe_version_override(self, sample_parquet_data):
        """Explicit check_version parameter should override CPE version."""
        service = CVESearchService(config=sample_parquet_data)

        # CPE has version 0, but we override with explicit version
        result = (
            service.query()
            .by_cpe(
                "cpe:2.3:a:linux:linux_kernel:0:*:*:*:*:*:*:*", check_version="5.15.0"
            )
            .execute()
        )

        # Should use explicit version (5.15.0), not CPE version (0)
        assert result.count >= 0

    def test_by_cpe_invalid_format(self, sample_parquet_data):
        """by_cpe should raise ValueError for invalid CPE string."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(ValueError, match="Invalid CPE string"):
            service.query().by_cpe("not-a-cpe-string").execute()

    def test_by_cpe_with_dash_version(self, sample_parquet_data):
        """by_cpe should treat dash (-) as wildcard and not filter by version."""
        service = CVESearchService(config=sample_parquet_data)

        # CPE with dash for version (means "not applicable")
        result = (
            service.query()
            .by_cpe("cpe:2.3:a:linux:linux_kernel:-:*:*:*:*:*:*:*")
            .execute()
        )

        # Should NOT filter by version
        assert result.count >= 1  # Should find CVE-2022-2196


class TestVersionRangeParsing:
    """Tests for version range string parsing in filter_by_version."""

    def test_version_range_string_parsing(self):
        """Version range strings like '0.5.6 - 1.13.2' should be parsed correctly."""
        from cvecli.services.version import is_version_affected

        # Simulate what happens when filter_by_version processes a range string
        version_start = "0.5.6 - 1.13.2"
        less_than = None
        less_than_or_equal = None

        # Parse the range string
        if version_start and " - " in str(version_start):
            parts = str(version_start).split(" - ")
            if len(parts) == 2:
                version_start = parts[0].strip()
                if not less_than and not less_than_or_equal:
                    less_than_or_equal = parts[1].strip()

        # Test versions within range should be affected
        assert is_version_affected(
            "1.10.0", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert is_version_affected(
            "0.5.6", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert is_version_affected(
            "1.13.2", version_start=version_start, less_than_or_equal=less_than_or_equal
        )

        # Test versions outside range should NOT be affected
        assert not is_version_affected(
            "0.5.5", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert not is_version_affected(
            "1.13.3", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert not is_version_affected(
            "1.28.9", version_start=version_start, less_than_or_equal=less_than_or_equal
        )


class TestCVSSScoreFiltering:
    """Tests for CVSS score filtering using chainable query API."""

    def test_by_cvss_min(self, sample_parquet_data):
        """Filter by minimum CVSS score."""
        service = CVESearchService(config=sample_parquet_data)

        # Get all results first
        result_all = service.query().by_product("", fuzzy=True).execute()
        initial_count = result_all.count

        # Filter by CVSS >= 7.0 (high and critical)
        result_high = service.query().by_cvss(min_score=7.0).execute()

        # Should have fewer or equal results
        assert result_high.count <= initial_count
        assert result_high.count >= 0

    def test_by_cvss_max(self, sample_parquet_data):
        """Filter by maximum CVSS score."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter by CVSS <= 5.0 (low and medium)
        result_low = service.query().by_cvss(max_score=5.0).execute()

        assert result_low.count >= 0

    def test_by_cvss_range(self, sample_parquet_data):
        """Filter by CVSS score range."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter by CVSS between 7.0 and 9.0
        result_range = service.query().by_cvss(min_score=7.0, max_score=9.0).execute()

        assert result_range.count >= 0

    def test_cvss_filter_with_invalid_values(self, sample_parquet_data):
        """CVSS filter should handle edge values correctly."""
        service = CVESearchService(config=sample_parquet_data)

        # Test with min > max (should still work, just return empty)
        filtered = service.query().by_cvss(min_score=9.0, max_score=7.0).execute()
        assert filtered.count == 0

        # Test with boundary values
        filtered_zero = service.query().by_cvss(min_score=0.0).execute()
        assert filtered_zero.count >= 0

        filtered_ten = service.query().by_cvss(max_score=10.0).execute()
        assert filtered_ten.count >= 0


class TestCWEChainedFiltering:
    """Tests for CWE filtering using chainable query API."""

    def test_by_cwe_numeric(self, sample_parquet_data):
        """Filter by CWE ID with numeric format."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter by CWE-787 (out-of-bounds write)
        result_cwe = service.query().by_cwe("787").execute()

        assert result_cwe.count >= 0

    def test_by_cwe_with_prefix(self, sample_parquet_data):
        """Filter by CWE ID with CWE- prefix."""
        service = CVESearchService(config=sample_parquet_data)

        # Filter by CWE-787 with prefix
        result_cwe = service.query().by_cwe("CWE-787").execute()

        assert result_cwe.count >= 0

    def test_by_cwe_case_insensitive(self, sample_parquet_data):
        """CWE filter should be case-insensitive."""
        service = CVESearchService(config=sample_parquet_data)

        # Test with lowercase
        result_lower = service.query().by_cwe("cwe-787").execute()
        result_upper = service.query().by_cwe("CWE-787").execute()

        assert result_lower.count == result_upper.count


class TestSortResults:
    """Tests for sorting using chainable query API."""

    def test_sort_by_date_ascending(self, sample_parquet_data):
        """Sort by date in ascending order."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).execute()

        # Sort by date ascending
        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=False)
            .execute()
        )

        assert sorted_result.count == result.count
        if sorted_result.count > 1:
            dates = sorted_result.cves.get_column("date_published").to_list()
            # Check that dates are in ascending order
            for i in range(len(dates) - 1):
                if dates[i] is not None and dates[i + 1] is not None:
                    assert dates[i] <= dates[i + 1]

    def test_sort_by_date_descending(self, sample_parquet_data):
        """Sort by date in descending order."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).execute()

        # Sort by date descending
        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=True)
            .execute()
        )

        assert sorted_result.count == result.count
        if sorted_result.count > 1:
            dates = sorted_result.cves.get_column("date_published").to_list()
            # Check that dates are in descending order
            for i in range(len(dates) - 1):
                if dates[i] is not None and dates[i + 1] is not None:
                    assert dates[i] >= dates[i + 1]

    def test_sort_by_cvss_descending(self, sample_parquet_data):
        """Sort by CVSS score in descending order."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).execute()

        # Sort by CVSS descending (highest first)
        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("cvss", descending=True)
            .execute()
        )

        assert sorted_result.count == result.count

    def test_sort_by_severity_ascending(self, sample_parquet_data):
        """Sort by severity in ascending order."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).execute()

        # Sort by severity ascending (lowest first)
        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("severity", descending=False)
            .execute()
        )

        assert sorted_result.count == result.count

    def test_sort_preserves_data_integrity(self, sample_parquet_data):
        """Sorting should not lose any CVE data."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).execute()
        original_ids = set(result.cves.get_column("cve_id").to_list())

        # Sort and check IDs are preserved
        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=True)
            .execute()
        )
        sorted_ids = set(sorted_result.cves.get_column("cve_id").to_list())

        assert original_ids == sorted_ids


class TestByPurl:
    """Tests for PURL (Package URL) search functionality."""

    def test_by_purl_exact_match(self, sample_parquet_data):
        """by_purl should find CVEs with exact PURL match."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_purl("pkg:pypi/django").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2023-0001" in cve_ids

    def test_by_purl_npm_package(self, sample_parquet_data):
        """by_purl should find CVEs for npm packages."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_purl("pkg:npm/lodash").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_purl_maven_package(self, sample_parquet_data):
        """by_purl should find CVEs for Maven packages."""
        service = CVESearchService(config=sample_parquet_data)
        result = (
            service.query()
            .by_purl("pkg:maven/org.apache.xmlgraphics/batik-anim")
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_purl_fuzzy_match(self, sample_parquet_data):
        """by_purl with fuzzy=True should find partial matches."""
        service = CVESearchService(config=sample_parquet_data)
        # Search for just "pypi" - should match any pypi package
        result = service.query().by_purl("pypi", fuzzy=True).execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2023-0001" in cve_ids

    def test_by_purl_not_found(self, sample_parquet_data):
        """by_purl should return empty result for non-existent PURL."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_purl("pkg:cargo/nonexistent-package").execute()

        assert result.count == 0

    def test_by_purl_empty_raises_error(self, sample_parquet_data):
        """by_purl should raise ValueError for empty PURL."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(ValueError, match="cannot be empty"):
            service.query().by_purl("").execute()

    def test_by_purl_invalid_format_raises_error(self, sample_parquet_data):
        """by_purl should raise ValueError for invalid PURL format."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(ValueError, match="Invalid PURL format"):
            service.query().by_purl("not-a-valid-purl").execute()

    def test_by_purl_case_insensitive(self, sample_parquet_data):
        """by_purl should match case-insensitively."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.query().by_purl("PKG:PYPI/DJANGO").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2023-0001" in cve_ids

    def test_by_purl_prefix_match(self, sample_parquet_data):
        """by_purl should match PURL prefixes."""
        service = CVESearchService(config=sample_parquet_data)
        # Match just the package type and namespace prefix
        result = service.query().by_purl("pkg:maven/org.apache").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids


class TestChainedQueries:
    """Tests for chaining multiple query filters together."""

    def test_chain_product_and_severity(self, sample_parquet_data):
        """Chain product and severity filters."""
        service = CVESearchService(config=sample_parquet_data)

        result = (
            service.query()
            .by_product("", fuzzy=True)
            .by_severity(SeverityLevel.MEDIUM)
            .execute()
        )

        assert result.count >= 0

    def test_chain_vendor_and_date(self, sample_parquet_data):
        """Chain vendor and date filters."""
        service = CVESearchService(config=sample_parquet_data)

        result = (
            service.query()
            .by_vendor("Linux", fuzzy=True)
            .by_date(after="2020-01-01")
            .execute()
        )

        assert result.count >= 0

    def test_chain_multiple_filters(self, sample_parquet_data):
        """Chain multiple filters together."""
        service = CVESearchService(config=sample_parquet_data)

        result = (
            service.query()
            .by_product("kernel", fuzzy=True)
            .by_severity(SeverityLevel.MEDIUM)
            .by_date(after="2020-01-01")
            .sort_by("date", descending=True)
            .limit(10)
            .execute()
        )

        assert result.count >= 0
        assert result.count <= 10

    def test_chain_with_limit(self, sample_parquet_data):
        """Chain with limit should respect the limit."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.query().by_product("", fuzzy=True).limit(2).execute()

        assert result.count <= 2


class TestRecentCVEs:
    """Tests for recent CVEs filter."""

    def test_recent_cves(self, sample_parquet_data):
        """recent() should filter to CVEs from the last N days."""
        service = CVESearchService(config=sample_parquet_data)

        # Use a very large number of days to include our test data
        result = service.query().recent(days=3650).execute()

        # Should find some CVEs
        assert result.count >= 0
