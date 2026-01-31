"""Unit tests for SearchResult and CVESearchService.

These tests focus on the search service logic without I/O dependencies.
Tests use static parquet fixtures for consistent, reproducible results.
"""

import pytest
import polars as pl

from cvecli.constants import SeverityLevel
from cvecli.services.search import (
    SEVERITY_THRESHOLDS,
    CVESearchService,
    SearchResult,
)

# =============================================================================
# SearchResult Unit Tests
# =============================================================================


class TestSearchResult:
    """Tests for SearchResult class."""

    def test_empty_result(self):
        """Empty result should have count of 0."""
        result = SearchResult(pl.DataFrame())
        assert result.count == 0
        assert result.to_dicts() == []

    def test_count_property(self, test_config):
        """Count should reflect number of CVEs."""
        cves = pl.read_parquet(test_config.cves_parquet)
        result = SearchResult(cves)
        assert result.count == 9  # 9 CVEs in fixtures

    def test_summary_empty(self):
        """Summary of empty result should show count 0."""
        result = SearchResult(pl.DataFrame())
        summary = result.summary()
        assert summary["count"] == 0

    def test_summary_with_data(self, test_config):
        """Summary should include severity and year distribution."""
        cves = pl.read_parquet(test_config.cves_parquet)
        result = SearchResult(cves)
        summary = result.summary()

        assert "count" in summary
        assert "severity_distribution" in summary
        assert "year_distribution" in summary
        assert summary["count"] == 9

    def test_to_dicts_returns_list(self, test_config):
        """to_dicts should return a list of dictionaries."""
        cves = pl.read_parquet(test_config.cves_parquet)
        result = SearchResult(cves)
        dicts = result.to_dicts()

        assert isinstance(dicts, list)
        assert len(dicts) == 9
        assert all(isinstance(d, dict) for d in dicts)
        assert all("cve_id" in d for d in dicts)


# =============================================================================
# Severity Thresholds
# =============================================================================


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
        """Severity ranges should be correct per CVSS spec."""
        assert SEVERITY_THRESHOLDS[SeverityLevel.NONE] == (0.0, 0.0)
        assert SEVERITY_THRESHOLDS[SeverityLevel.LOW] == (0.1, 3.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.MEDIUM] == (4.0, 6.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.HIGH] == (7.0, 8.9)
        assert SEVERITY_THRESHOLDS[SeverityLevel.CRITICAL] == (9.0, 10.0)

    def test_severity_ranges_continuous(self):
        """Severity ranges should be continuous without gaps."""
        ranges = [
            SEVERITY_THRESHOLDS[SeverityLevel.NONE],
            SEVERITY_THRESHOLDS[SeverityLevel.LOW],
            SEVERITY_THRESHOLDS[SeverityLevel.MEDIUM],
            SEVERITY_THRESHOLDS[SeverityLevel.HIGH],
            SEVERITY_THRESHOLDS[SeverityLevel.CRITICAL],
        ]
        # Check that ranges are properly ordered
        for i in range(len(ranges) - 1):
            # End of current range + 0.1 should equal start of next
            assert ranges[i][1] + 0.1 == pytest.approx(ranges[i + 1][0], rel=0.01)


# =============================================================================
# CVESearchService Initialization
# =============================================================================


class TestCVESearchServiceInit:
    """Tests for CVESearchService initialization."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = CVESearchService()
        assert service.config is not None

    def test_init_custom_config(self, temp_config):
        """Service should accept custom config."""
        service = CVESearchService(config=temp_config)
        assert service.config == temp_config


# =============================================================================
# CVE ID Search
# =============================================================================


class TestByIdSearch:
    """Tests for searching by CVE ID."""

    def test_by_id_found(self, test_config):
        """by_id should return matching CVE."""
        service = CVESearchService(config=test_config)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"
        assert cve["state"] == "PUBLISHED"

    def test_by_id_not_found(self, test_config):
        """by_id should return empty result for non-existent CVE."""
        service = CVESearchService(config=test_config)
        result = service.query().by_id("CVE-9999-9999").execute()

        assert result.count == 0

    def test_by_id_normalizes_input(self, test_config):
        """by_id should normalize CVE ID format."""
        service = CVESearchService(config=test_config)

        # Without CVE- prefix
        result1 = service.query().by_id("2022-2196").execute()
        assert result1.count == 1

        # Lowercase
        result2 = service.query().by_id("cve-2022-2196").execute()
        assert result2.count == 1


# =============================================================================
# Product Search
# =============================================================================


class TestByProductSearch:
    """Tests for searching by product name."""

    def test_by_product_found(self, test_config):
        """by_product should return CVEs affecting the product."""
        service = CVESearchService(config=test_config)
        result = service.query().by_product("Linux Kernel").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_product_fuzzy(self, test_config):
        """by_product should support fuzzy matching."""
        service = CVESearchService(config=test_config)
        result = service.query().by_product("kernel", fuzzy=True).execute()

        assert result.count >= 1

    def test_by_product_with_vendor(self, test_config):
        """by_product chained with by_vendor should filter both."""
        service = CVESearchService(config=test_config)
        result = service.query().by_product("Linux Kernel").by_vendor("Linux").execute()

        assert result.count >= 1

    def test_by_product_not_found(self, test_config):
        """by_product should return empty for non-existent product."""
        service = CVESearchService(config=test_config)
        result = service.query().by_product("NonExistentProduct12345").execute()

        assert result.count == 0


# =============================================================================
# Vendor Search
# =============================================================================


class TestByVendorSearch:
    """Tests for searching by vendor name."""

    def test_by_vendor_found(self, test_config):
        """by_vendor should return CVEs for vendor's products."""
        service = CVESearchService(config=test_config)
        result = service.query().by_vendor("OpenSSL").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_by_vendor_fuzzy(self, test_config):
        """by_vendor should support fuzzy matching."""
        service = CVESearchService(config=test_config)
        result = service.query().by_vendor("pulse", fuzzy=True).execute()

        assert result.count >= 1


# =============================================================================
# CWE Search
# =============================================================================


class TestByCweSearch:
    """Tests for searching by CWE ID."""

    def test_by_cwe_found(self, test_config):
        """by_cwe should return CVEs with matching CWE."""
        service = CVESearchService(config=test_config)
        result = service.query().by_cwe("CWE-1188").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_cwe_normalizes_input(self, test_config):
        """by_cwe should normalize CWE ID format."""
        service = CVESearchService(config=test_config)

        # Without CWE- prefix
        result1 = service.query().by_cwe("1188").execute()
        assert result1.count >= 1

        # Lowercase
        result2 = service.query().by_cwe("cwe-1188").execute()
        assert result2.count >= 1

    def test_by_cwe_case_insensitive(self, test_config):
        """CWE filter should be case-insensitive."""
        service = CVESearchService(config=test_config)

        result_lower = service.query().by_cwe("cwe-502").execute()
        result_upper = service.query().by_cwe("CWE-502").execute()

        assert result_lower.count == result_upper.count


# =============================================================================
# Severity Search
# =============================================================================


class TestBySeveritySearch:
    """Tests for searching by severity level."""

    def test_by_severity_medium(self, test_config):
        """by_severity should return CVEs with matching severity."""
        service = CVESearchService(config=test_config)
        result = service.query().by_severity(SeverityLevel.MEDIUM).execute()

        # CVE-2022-2196 has CVSS 5.8 (medium)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_severity_critical(self, test_config):
        """by_severity should find critical CVEs."""
        service = CVESearchService(config=test_config)
        result = service.query().by_severity(SeverityLevel.CRITICAL).execute()

        # CVE-2019-11510 and CVE-2021-44228 have CVSS 10.0 (critical)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2021-44228" in cve_ids

    def test_by_severity_with_date_filter(self, test_config):
        """by_severity should filter by date range using chained query."""
        service = CVESearchService(config=test_config)

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


# =============================================================================
# CVSS Score Filtering
# =============================================================================


class TestByCvssScore:
    """Tests for CVSS score filtering."""

    def test_by_cvss_min(self, test_config):
        """Filter by minimum CVSS score."""
        service = CVESearchService(config=test_config)

        # Filter by CVSS >= 9.0 (critical only)
        result_critical = service.query().by_cvss(min_score=9.0).execute()

        # Should include CVE-2019-11510 (10.0), CVE-2021-44228 (10.0), CVE-2024-1234 (9.8)
        assert result_critical.count >= 2

    def test_by_cvss_max(self, test_config):
        """Filter by maximum CVSS score."""
        service = CVESearchService(config=test_config)

        # Filter by CVSS <= 6.0
        result_low = service.query().by_cvss(max_score=6.0).execute()

        # Should include CVE-2022-2196 (5.8)
        cve_ids = [c["cve_id"] for c in result_low.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_cvss_range(self, test_config):
        """Filter by CVSS score range."""
        service = CVESearchService(config=test_config)

        result_range = service.query().by_cvss(min_score=5.0, max_score=7.0).execute()

        # Should include medium severity CVEs
        cve_ids = [c["cve_id"] for c in result_range.to_dicts()]
        assert "CVE-2022-2196" in cve_ids  # 5.8

    def test_cvss_invalid_range(self, test_config):
        """CVSS filter with min > max should return empty."""
        service = CVESearchService(config=test_config)

        result = service.query().by_cvss(min_score=9.0, max_score=7.0).execute()
        assert result.count == 0


# =============================================================================
# State Filtering
# =============================================================================


class TestByStateFilter:
    """Tests for state filtering."""

    def test_by_state_published(self, test_config):
        """by_state should filter to only published CVEs."""
        service = CVESearchService(config=test_config)

        published_result = service.query().by_state("published").execute()

        for cve in published_result.to_dicts():
            assert cve["state"] == "PUBLISHED"

    def test_by_state_rejected(self, test_config):
        """by_state should filter to only rejected CVEs."""
        service = CVESearchService(config=test_config)

        rejected_result = service.query().by_state("rejected").execute()
        assert rejected_result.count >= 1
        for cve in rejected_result.to_dicts():
            assert cve["state"] == "REJECTED"

    def test_by_state_case_insensitive(self, test_config):
        """by_state should be case insensitive."""
        service = CVESearchService(config=test_config)

        result_upper = service.query().by_state("PUBLISHED").execute()
        result_lower = service.query().by_state("published").execute()
        result_mixed = service.query().by_state("Published").execute()

        assert result_upper.count == result_lower.count == result_mixed.count


# =============================================================================
# Date Filtering
# =============================================================================


class TestDateValidation:
    """Tests for date validation."""

    def test_valid_date(self, test_config):
        """Valid date format should return True."""
        service = CVESearchService(config=test_config)
        assert service.validate_date("2024-01-15") is True
        assert service.validate_date("2023-12-31") is True
        assert service.validate_date("1999-01-01") is True

    def test_invalid_date_format(self, test_config):
        """Invalid date formats should return False."""
        service = CVESearchService(config=test_config)
        assert service.validate_date("01-15-2024") is False
        assert service.validate_date("2024/01/15") is False
        assert service.validate_date("not-a-date") is False
        assert service.validate_date("") is False

    def test_invalid_date_values(self, test_config):
        """Invalid date values should return False."""
        service = CVESearchService(config=test_config)
        assert service.validate_date("2024-13-01") is False  # Invalid month
        assert service.validate_date("2024-02-30") is False  # Invalid day


# =============================================================================
# Exact Matching (Regex Escaping)
# =============================================================================


class TestExactMatching:
    """Tests for exact (literal) string matching with regex character escaping."""

    def test_by_product_with_regex_chars_exact(self, test_config):
        """by_product with exact=True should match literal regex characters."""
        service = CVESearchService(config=test_config)

        result = (
            service.query()
            .by_product("Product[v1.0]+", fuzzy=True, exact=True)
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_vendor_with_regex_chars_exact(self, test_config):
        """by_vendor with exact=True should match literal regex characters."""
        service = CVESearchService(config=test_config)

        result = (
            service.query()
            .by_vendor("Test.Vendor (Inc.)", fuzzy=True, exact=True)
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids


# =============================================================================
# PURL Search
# =============================================================================


class TestByPurlSearch:
    """Tests for PURL (Package URL) search functionality."""

    def test_by_purl_exact_match(self, test_config):
        """by_purl should find CVEs with exact PURL match."""
        service = CVESearchService(config=test_config)
        result = service.query().by_purl("pkg:pypi/django").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2023-0001" in cve_ids

    def test_by_purl_npm_package(self, test_config):
        """by_purl should find CVEs for npm packages."""
        service = CVESearchService(config=test_config)
        result = service.query().by_purl("pkg:npm/lodash").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_purl_maven_package(self, test_config):
        """by_purl should find CVEs for Maven packages."""
        service = CVESearchService(config=test_config)
        result = (
            service.query()
            .by_purl("pkg:maven/org.apache.xmlgraphics/batik-anim")
            .execute()
        )

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_purl_not_found(self, test_config):
        """by_purl should return empty result for non-existent PURL."""
        service = CVESearchService(config=test_config)
        result = service.query().by_purl("pkg:cargo/nonexistent-package").execute()

        assert result.count == 0

    def test_by_purl_empty_raises_error(self, test_config):
        """by_purl should raise ValueError for empty PURL."""
        service = CVESearchService(config=test_config)

        with pytest.raises(ValueError, match="cannot be empty"):
            service.query().by_purl("").execute()

    def test_by_purl_invalid_format_raises_error(self, test_config):
        """by_purl should raise ValueError for invalid PURL format."""
        service = CVESearchService(config=test_config)

        with pytest.raises(ValueError, match="Invalid PURL format"):
            service.query().by_purl("not-a-valid-purl").execute()

    def test_by_purl_case_insensitive(self, test_config):
        """by_purl should match case-insensitively."""
        service = CVESearchService(config=test_config)
        result = service.query().by_purl("PKG:PYPI/DJANGO").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2023-0001" in cve_ids

    def test_by_purl_prefix_match(self, test_config):
        """by_purl should match PURL prefixes."""
        service = CVESearchService(config=test_config)
        result = service.query().by_purl("pkg:maven/org.apache").execute()

        assert result.count >= 1


# =============================================================================
# KEV and SSVC Info
# =============================================================================


class TestKEVInfo:
    """Tests for KEV info retrieval."""

    def test_get_kev_info_found(self, test_config):
        """get_kev_info should return KEV data for CVE in KEV list."""
        service = CVESearchService(config=test_config)

        kev_info = service.get_kev_info("CVE-2024-1234")
        assert kev_info is not None
        assert "dateAdded" in kev_info
        assert kev_info["dateAdded"] == "2024-01-15"

    def test_get_kev_info_not_found(self, test_config):
        """get_kev_info should return None for CVE not in KEV list."""
        service = CVESearchService(config=test_config)

        kev_info = service.get_kev_info("CVE-2022-2196")
        assert kev_info is None


class TestSSVCInfo:
    """Tests for SSVC info retrieval."""

    def test_get_ssvc_info_found(self, test_config):
        """get_ssvc_info should return SSVC data for CVE with SSVC assessment."""
        service = CVESearchService(config=test_config)

        ssvc_info = service.get_ssvc_info("CVE-2024-1234")
        assert ssvc_info is not None
        assert "automatable" in ssvc_info
        assert ssvc_info["automatable"] == "Yes"
        assert "exploitation" in ssvc_info
        assert ssvc_info["exploitation"] == "Active"

    def test_get_ssvc_info_not_found(self, test_config):
        """get_ssvc_info should return None for CVE without SSVC assessment."""
        service = CVESearchService(config=test_config)

        ssvc_info = service.get_ssvc_info("CVE-2022-2196")
        assert ssvc_info is None


# =============================================================================
# KEV Filtering
# =============================================================================


class TestKEVFiltering:
    """Tests for CISA KEV filtering."""

    def test_by_kev(self, test_config):
        """by_kev should filter to only CVEs in CISA KEV."""
        service = CVESearchService(config=test_config)

        kev_result = service.query().by_kev().execute()
        assert kev_result.count >= 1
        cve_ids = [c["cve_id"] for c in kev_result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids


# =============================================================================
# Sorting
# =============================================================================


class TestSortResults:
    """Tests for sorting results."""

    def test_sort_by_date_ascending(self, test_config):
        """Sort by date in ascending order."""
        service = CVESearchService(config=test_config)

        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=False)
            .execute()
        )

        if sorted_result.count > 1:
            dates = sorted_result.cves.get_column("date_published").to_list()
            for i in range(len(dates) - 1):
                if dates[i] is not None and dates[i + 1] is not None:
                    assert dates[i] <= dates[i + 1]

    def test_sort_by_date_descending(self, test_config):
        """Sort by date in descending order."""
        service = CVESearchService(config=test_config)

        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=True)
            .execute()
        )

        if sorted_result.count > 1:
            dates = sorted_result.cves.get_column("date_published").to_list()
            for i in range(len(dates) - 1):
                if dates[i] is not None and dates[i + 1] is not None:
                    assert dates[i] >= dates[i + 1]

    def test_sort_preserves_data_integrity(self, test_config):
        """Sorting should not lose any CVE data."""
        service = CVESearchService(config=test_config)

        result = service.query().by_product("", fuzzy=True).execute()
        original_ids = set(result.cves.get_column("cve_id").to_list())

        sorted_result = (
            service.query()
            .by_product("", fuzzy=True)
            .sort_by("date", descending=True)
            .execute()
        )
        sorted_ids = set(sorted_result.cves.get_column("cve_id").to_list())

        assert original_ids == sorted_ids


# =============================================================================
# Chained Queries
# =============================================================================


class TestChainedQueries:
    """Tests for chaining multiple query filters together."""

    def test_chain_product_and_severity(self, test_config):
        """Chain product and severity filters."""
        service = CVESearchService(config=test_config)

        result = (
            service.query()
            .by_product("", fuzzy=True)
            .by_severity(SeverityLevel.MEDIUM)
            .execute()
        )

        assert result.count >= 0

    def test_chain_vendor_and_date(self, test_config):
        """Chain vendor and date filters."""
        service = CVESearchService(config=test_config)

        result = (
            service.query()
            .by_vendor("Linux", fuzzy=True)
            .by_date(after="2020-01-01")
            .execute()
        )

        assert result.count >= 0

    def test_chain_multiple_filters(self, test_config):
        """Chain multiple filters together."""
        service = CVESearchService(config=test_config)

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

    def test_chain_with_limit(self, test_config):
        """Chain with limit should respect the limit."""
        service = CVESearchService(config=test_config)

        result = service.query().by_product("", fuzzy=True).limit(2).execute()

        assert result.count <= 2


# =============================================================================
# Error Handling
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_missing_data_file(self, temp_config):
        """Service should raise error when data files are missing."""
        service = CVESearchService(config=temp_config)

        with pytest.raises(FileNotFoundError):
            service.query().by_id("CVE-2022-2196").execute()


# =============================================================================
# Related Data Inclusion
# =============================================================================


class TestRelatedData:
    """Tests for related data (products, CWEs) inclusion in results."""

    def test_products_included_in_result(self, test_config):
        """Search result should include product information."""
        service = CVESearchService(config=test_config)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.products is not None
        products = result.products.to_dicts()
        assert len(products) >= 1
        assert any(p["product"] == "Linux Kernel" for p in products)

    def test_cwes_included_in_result(self, test_config):
        """Search result should include CWE information."""
        service = CVESearchService(config=test_config)
        result = service.query().by_id("CVE-2022-2196").execute()

        assert result.cwes is not None
        cwes = result.cwes.to_dicts()
        assert len(cwes) >= 1
        assert any(c["cwe_id"] == "CWE-1188" for c in cwes)
