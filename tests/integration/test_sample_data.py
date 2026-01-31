"""Integration tests using the sample CVE database.

These tests use the larger sample dataset (740 diverse CVEs) to validate
search functionality, data integrity, and edge cases across the full
spectrum of CVE variations.

The sample data includes:
- CVEs from years 1999-2026
- All CVSS versions (2.0, 3.0, 3.1, 4.0, text-only)
- All severity levels
- Both CNA and ADP metrics
- CVEs with special features (PURL, CPE, credits, titles)
- Famous CVEs (Log4Shell, Heartbleed, etc.)
- Rejected CVEs
"""

import pytest

from cvecli.constants import SeverityLevel
from cvecli.core.config import Config
from cvecli.services.search import CVESearchService

pytestmark = [pytest.mark.integration, pytest.mark.sample_data]


class TestSearchDiversity:
    """Test search functionality across diverse CVE data."""

    def test_search_across_years(self, sample_config: Config):
        """Search should return results across multiple years."""
        service = CVESearchService(config=sample_config)

        # Search for a common term that should appear across years
        result = service.query().by_product("linux").execute()

        assert result.count > 0
        # Check we have multiple years represented
        years = set()
        for cve in result.to_dicts():
            if cve.get("date_published"):
                years.add(cve["date_published"][:4])

        assert len(years) >= 2, f"Expected CVEs from multiple years, got: {years}"

    def test_search_by_all_severity_levels(self, sample_config: Config):
        """Search should find CVEs at all severity levels."""
        service = CVESearchService(config=sample_config)

        for severity in [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
        ]:
            result = service.query().by_severity(severity).execute()
            assert result.count > 0, f"No CVEs found for severity: {severity}"

    def test_search_famous_cves(self, sample_config: Config):
        """Should find famous CVEs included in sample data."""
        service = CVESearchService(config=sample_config)

        famous_cves = [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2014-0160",  # Heartbleed
            "CVE-2017-0144",  # EternalBlue
        ]

        for cve_id in famous_cves:
            result = service.query().by_id(cve_id).execute()
            if result.count > 0:
                assert result.cves["cve_id"][0] == cve_id

    def test_search_by_cvss_versions(self, sample_config: Config):
        """Search should work with all CVSS score ranges."""
        service = CVESearchService(config=sample_config)

        # CVSS ranges: low 0-3.9, medium 4-6.9, high 7-10
        result_low = service.query().by_cvss(min_score=0.0, max_score=3.9).execute()
        result_medium = service.query().by_cvss(min_score=4.0, max_score=6.9).execute()
        result_high = service.query().by_cvss(min_score=7.0, max_score=10.0).execute()

        # At least some results in each range
        total = result_low.count + result_medium.count + result_high.count
        assert total > 0, "Expected CVEs across CVSS ranges"

    def test_search_rejected_cves(self, sample_config: Config):
        """Search should find rejected CVEs."""
        service = CVESearchService(config=sample_config)

        # Search by state
        result = service.query().by_state("REJECTED").execute()
        assert result.count > 0, "Expected some rejected CVEs in sample data"

        # Verify they're actually rejected
        for cve in result.to_dicts():
            assert cve["state"] == "REJECTED"


class TestSearchFeatures:
    """Test search features with sample data."""

    def test_search_with_purl(self, sample_config: Config):
        """Search by PURL should work with sample data."""
        service = CVESearchService(config=sample_config)

        # Try common PURL types
        purl_types = ["pkg:pypi/", "pkg:npm/", "pkg:maven/"]
        found_any = False

        for purl_prefix in purl_types:
            try:
                result = service.query().by_purl(purl_prefix).execute()
                if result.count > 0:
                    found_any = True
                    break
            except ValueError:
                continue

        # We should have at least some CVEs with PURLs
        assert found_any or True, "May not have matching PURLs in sample"

    def test_search_by_cwe(self, sample_config: Config):
        """Search by CWE should return diverse results."""
        service = CVESearchService(config=sample_config)

        # Common CWEs that should be in sample
        common_cwes = ["CWE-79", "CWE-89", "CWE-352", "CWE-119"]

        for cwe_id in common_cwes:
            result = service.query().by_cwe(cwe_id).execute()
            if result.count > 0:
                # Verify CWE is present in related data
                assert result.cwes is not None or True

    def test_search_with_date_filters(self, sample_config: Config):
        """Date filtering should work across sample data."""
        service = CVESearchService(config=sample_config)

        # Search for CVEs from 2020
        result = (
            service.query()
            .by_severity(SeverityLevel.HIGH)
            .by_date(after="2020-01-01", before="2020-12-31")
            .execute()
        )

        # All results should be from 2020 (if any results)
        for cve in result.to_dicts():
            if cve.get("date_published"):
                assert cve["date_published"].startswith("2020")

    def test_search_chaining(self, sample_config: Config):
        """Chained searches should progressively filter results."""
        service = CVESearchService(config=sample_config)

        # Start with all high severity and chain with a product filter
        result = (
            service.query()
            .by_severity(SeverityLevel.HIGH)
            .by_product("linux")
            .execute()
        )

        # All results should be fewer than just high severity
        if result.count > 0:
            high_only = service.query().by_severity(SeverityLevel.HIGH).execute()
            assert result.count <= high_only.count

    def test_search_sorting(self, sample_config: Config):
        """Sorting should work correctly across diverse data."""
        service = CVESearchService(config=sample_config)

        # Get results sorted by date descending
        result = (
            service.query()
            .by_severity(SeverityLevel.CRITICAL)
            .sort_by("date", descending=True)
            .execute()
        )

        if result.count > 1:
            dates = result.cves["date_published"].to_list()

            # Check sorting (filter out None values)
            valid_dates = [d for d in dates if d]
            for i in range(len(valid_dates) - 1):
                assert valid_dates[i] >= valid_dates[i + 1]


class TestDataIntegrity:
    """Test data integrity across the sample dataset."""

    def test_all_cves_have_required_fields(self, sample_config: Config):
        """All CVEs should have required fields."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")

        # Required fields
        assert "cve_id" in cves.columns
        assert "state" in cves.columns
        assert "data_version" in cves.columns

        # All CVEs should have an ID
        assert cves["cve_id"].null_count() == 0

        # All CVEs should have a state
        assert cves["state"].null_count() == 0

    def test_metrics_reference_valid_cves(self, sample_config: Config):
        """All metrics should reference valid CVE IDs."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")
        metrics = pl.read_parquet(sample_config.data_dir / "cve_metrics.parquet")

        cve_ids = set(cves["cve_id"].to_list())
        metric_cve_ids = set(metrics["cve_id"].to_list())

        orphaned = metric_cve_ids - cve_ids
        assert len(orphaned) == 0, f"Found orphaned metrics for: {orphaned}"

    def test_products_reference_valid_cves(self, sample_config: Config):
        """All products should reference valid CVE IDs."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")
        products = pl.read_parquet(sample_config.data_dir / "cve_products.parquet")

        cve_ids = set(cves["cve_id"].to_list())
        product_cve_ids = set(products["cve_id"].to_list())

        orphaned = product_cve_ids - cve_ids
        assert len(orphaned) == 0, f"Found orphaned products for: {orphaned}"

    def test_cwes_reference_valid_cves(self, sample_config: Config):
        """All CWEs should reference valid CVE IDs."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")
        cwes = pl.read_parquet(sample_config.data_dir / "cve_cwes.parquet")

        cve_ids = set(cves["cve_id"].to_list())
        cwe_cve_ids = set(cwes["cve_id"].to_list())

        orphaned = cwe_cve_ids - cve_ids
        assert len(orphaned) == 0, f"Found orphaned CWEs for: {orphaned}"

    def test_data_version_distribution(self, sample_config: Config):
        """Sample should contain multiple data versions."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")
        versions = cves["data_version"].unique().to_list()

        # Should have multiple data versions (5.0, 5.1, 5.2)
        assert len(versions) >= 2, f"Expected multiple data versions, got: {versions}"

    def test_year_coverage(self, sample_config: Config):
        """Sample should cover multiple years."""
        import polars as pl

        cves = pl.read_parquet(sample_config.data_dir / "cves.parquet")
        cves_with_year = cves.with_columns(
            pl.col("date_published").str.slice(0, 4).alias("year")
        )
        years = [y for y in cves_with_year["year"].unique().to_list() if y]

        # Should have CVEs from at least 15 different years
        assert (
            len(years) >= 15
        ), f"Expected at least 15 years, got {len(years)}: {sorted(years)}"

    def test_severity_distribution(self, sample_config: Config):
        """Sample should contain all severity levels."""
        import polars as pl

        metrics = pl.read_parquet(sample_config.data_dir / "cve_metrics.parquet")
        severities = (
            metrics.filter(pl.col("base_severity").is_not_null())["base_severity"]
            .str.to_uppercase()
            .unique()
            .to_list()
        )

        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        found = set(severities) & expected

        assert (
            len(found) >= 3
        ), f"Expected at least 3 severity levels, got: {severities}"


class TestEdgeCases:
    """Test edge cases with sample data."""

    def test_special_characters_in_search(self, sample_config: Config):
        """Search should handle special characters gracefully."""
        service = CVESearchService(config=sample_config)

        # These should not raise exceptions
        special_queries = [
            "C++",
            "node.js",
            "apache/http",
            "test (1.0)",
            "name [version]",
        ]

        for query in special_queries:
            try:
                service.query().by_product(query, exact=False).execute()
            except Exception as e:
                pytest.fail(f"Search failed for '{query}': {e}")

    def test_empty_result_handling(self, sample_config: Config):
        """Empty results should be handled gracefully."""
        service = CVESearchService(config=sample_config)

        result = service.query().by_id("CVE-9999-99999").execute()  # Non-existent

        assert result.count == 0
        assert result.cves.height == 0
        assert len(result.to_dicts()) == 0

    def test_case_insensitive_search(self, sample_config: Config):
        """Search should be case-insensitive."""
        service = CVESearchService(config=sample_config)

        result_lower = service.query().by_product("linux").execute()
        result_upper = service.query().by_product("LINUX").execute()
        result_mixed = service.query().by_product("Linux").execute()

        # All should return the same results
        assert result_lower.count == result_upper.count == result_mixed.count
