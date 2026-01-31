"""Integration tests for the extraction -> search pipeline.

These tests verify that the full extraction and search pipeline works correctly.
They use temporary directories and JSON fixtures to test the complete flow.
"""

import json
import tempfile
from pathlib import Path

import polars as pl
import pytest

from cvecli.core.config import Config
from cvecli.models.cve_model import CveJsonRecordFormat
from cvecli.services.extractor import ExtractorService, _extract_single_cve
from cvecli.services.search import CVESearchService

# =============================================================================
# Sample CVE JSON Data
# =============================================================================


SAMPLE_CVE_2022_2196 = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2022-2196",
        "assignerOrgId": "14ed7db2-1595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "Google",
        "dateReserved": "2022-06-24T13:29:09.969Z",
        "datePublished": "2023-01-09T10:59:53.099Z",
        "dateUpdated": "2025-02-13T16:28:57.097Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "defaultStatus": "unaffected",
                    "packageName": "KVM",
                    "product": "Linux Kernel",
                    "vendor": "Linux",
                    "versions": [
                        {
                            "lessThan": "6.2",
                            "status": "affected",
                            "version": "0",
                            "versionType": "custom",
                        }
                    ],
                }
            ],
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A regression exists in the Linux Kernel within KVM.",
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "attackComplexity": "HIGH",
                        "attackVector": "LOCAL",
                        "availabilityImpact": "LOW",
                        "baseScore": 5.8,
                        "baseSeverity": "MEDIUM",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "HIGH",
                        "privilegesRequired": "LOW",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
                        "version": "3.1",
                    }
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-1188",
                            "description": "CWE-1188 Insecure Default Initialization",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "14ed7db2-1595-443d-9d34-6215bf890778",
                "shortName": "Google",
            },
            "references": [{"url": "https://kernel.dance/#2e7eab81425a"}],
            "title": "KVM nVMX Spectre v2 vulnerability",
        }
    },
}

SAMPLE_CVE_2016_7054 = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2016-7054",
        "assignerOrgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
        "state": "PUBLISHED",
        "assignerShortName": "openssl",
        "datePublished": "2017-05-04T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "product": "OpenSSL",
                    "vendor": "OpenSSL",
                    "versions": [{"status": "affected", "version": "1.1.0"}],
                }
            ],
            "descriptions": [
                {"lang": "en", "value": "ChaCha20/Poly1305 heap-buffer-overflow"}
            ],
            "metrics": [{"other": {"content": {"value": "High"}, "type": "unknown"}}],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-119",
                            "description": "CWE-119 Buffer Errors",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
                "shortName": "openssl",
            },
            "references": [{"url": "https://www.openssl.org/news/secadv/20161110.txt"}],
            "title": "ChaCha20/Poly1305 heap-buffer-overflow",
        }
    },
}


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def extraction_config():
    """Create config with sample CVE files for extraction tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        download_dir = tmpdir / "download"
        cve_dir = download_dir / "cve_github" / "individual"

        # Create year directories with sample CVEs
        for sample, year in [
            (SAMPLE_CVE_2022_2196, "2022"),
            (SAMPLE_CVE_2016_7054, "2016"),
        ]:
            year_dir = cve_dir / year
            year_dir.mkdir(parents=True, exist_ok=True)

            cve_id = sample["cveMetadata"]["cveId"]
            filepath = year_dir / f"{cve_id}.json"
            with open(filepath, "w") as f:
                json.dump(sample, f)

        config = Config(
            data_dir=tmpdir / "data",
            download_dir=download_dir,
        )
        config.ensure_directories()

        yield config


# =============================================================================
# Extraction -> Search Pipeline Tests
# =============================================================================


class TestExtractionToSearchPipeline:
    """Integration tests for the extract -> search pipeline."""

    def test_extract_and_search_single_cve(self, extraction_config):
        """Test extracting a CVE and then searching for it."""
        # Extract
        extractor = ExtractorService(config=extraction_config)
        result = extractor.extract_all(years=[2022])

        # Check result has paths
        assert "paths" in result
        assert result["paths"]["cves"].exists()

        # Search
        search = CVESearchService(config=extraction_config)
        search_result = search.query().by_id("CVE-2022-2196").execute()

        assert search_result.count == 1
        cve = search_result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"

        # Check metric via service
        metric = search.get_best_metric("CVE-2022-2196")
        assert metric is not None
        assert metric["base_score"] == 5.8

    def test_extract_and_search_by_product(self, extraction_config):
        """Test extracting CVEs and searching by product."""
        # Extract all sample years
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2016, 2022])

        # Search by product
        search = CVESearchService(config=extraction_config)
        result = search.query().by_product("OpenSSL").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_extract_and_search_by_cwe(self, extraction_config):
        """Test extracting CVEs and searching by CWE."""
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2022])

        search = CVESearchService(config=extraction_config)
        result = search.query().by_cwe("CWE-1188").execute()

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_extract_preserves_severity_text(self, extraction_config):
        """Test that text severity is preserved through extraction."""
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2016])

        search = CVESearchService(config=extraction_config)
        result = search.query().by_id("CVE-2016-7054").execute()

        assert result.count == 1
        # Check metric - should be an "other" type with text severity
        metric = search.get_best_metric("CVE-2016-7054")
        assert metric is not None
        assert metric["base_severity"] == "High"


# =============================================================================
# Data Integrity Tests
# =============================================================================


class TestCVEDataIntegrity:
    """Tests for data integrity through the pipeline."""

    def test_all_fields_extracted(self):
        """Test that all expected fields are extracted."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        cve = result.cve
        assert cve.cve_id == "CVE-2022-2196"
        assert cve.state == "PUBLISHED"
        assert cve.assigner_short_name == "Google"
        assert cve.cna_title is not None
        assert cve.date_published is not None

        # Check descriptions are extracted
        assert len(result.descriptions) >= 1
        en_desc = [d for d in result.descriptions if d.lang == "en"]
        assert len(en_desc) >= 1

        # Check metrics are extracted
        cvss_metrics = [m for m in result.metrics if m.metric_type == "cvssV3_1"]
        assert len(cvss_metrics) >= 1
        assert cvss_metrics[0].base_score == 5.8
        assert cvss_metrics[0].vector_string is not None

    def test_products_have_required_fields(self):
        """Test that products have required fields."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.products) >= 1
        product = result.products[0]
        assert product.cve_id == "CVE-2022-2196"
        assert product.vendor == "Linux"
        assert product.product == "Linux Kernel"

    def test_cwes_have_required_fields(self):
        """Test that CWE mappings have required fields."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.cwes) >= 1
        cwe = result.cwes[0]
        assert cwe.cve_id == "CVE-2022-2196"
        assert cwe.cwe_id == "CWE-1188"


# =============================================================================
# Parquet Output Tests
# =============================================================================


class TestParquetOutput:
    """Tests for Parquet file output."""

    def test_parquet_files_created(self, extraction_config):
        """Test that extraction creates Parquet files."""
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2022])

        assert extraction_config.cves_parquet.exists()
        assert extraction_config.cve_products_parquet.exists()
        assert extraction_config.cve_cwes_parquet.exists()

    def test_parquet_readable(self, extraction_config):
        """Test that Parquet files are readable."""
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(extraction_config.cves_parquet)
        assert len(cves_df) >= 1
        assert "cve_id" in cves_df.columns
        assert "state" in cves_df.columns

    def test_parquet_schema(self, extraction_config):
        """Test that Parquet files have expected schema."""
        extractor = ExtractorService(config=extraction_config)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(extraction_config.cves_parquet)

        expected_columns = [
            "cve_id",
            "state",
            "assigner_short_name",
            "cna_title",
            "date_published",
        ]
        for col in expected_columns:
            assert col in cves_df.columns, f"Missing column: {col}"

        # Check metrics table
        metrics_df = pl.read_parquet(extraction_config.cve_metrics_parquet)
        metrics_cols = [
            "cve_id",
            "metric_type",
            "source",
            "base_score",
            "base_severity",
        ]
        for col in metrics_cols:
            assert col in metrics_df.columns, f"Missing metrics column: {col}"
