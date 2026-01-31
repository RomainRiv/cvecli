"""Unit tests for parquet data models.

These tests verify the Pydantic models and Polars schemas used for CVE data.
"""

import pytest
from pydantic import ValidationError

from cvecli.models.parquet_models import (
    CVE_SCHEMA,
    CVECWE,
    CVECredit,
    CVEDescription,
    CVEMetric,
    CVEProduct,
    CVERecord,
    CVEReference,
    CVETag,
    CVEVersion,
    ExtractedData,
    ExtractionError,
)

# =============================================================================
# CVERecord Model Tests
# =============================================================================


class TestCVERecord:
    """Tests for CVERecord Pydantic model."""

    def test_minimal_record(self):
        """Should create record with required fields only."""
        record = CVERecord(
            cve_id="CVE-2024-1234",
            data_type="CVE_RECORD",
            data_version="5.1",
            state="PUBLISHED",
        )
        assert record.cve_id == "CVE-2024-1234"
        assert record.state == "PUBLISHED"
        assert record.cna_title is None

    def test_full_record(self):
        """Should create record with all fields."""
        record = CVERecord(
            cve_id="CVE-2024-1234",
            data_type="CVE_RECORD",
            data_version="5.1",
            state="PUBLISHED",
            assigner_org_id="org-123",
            assigner_short_name="TestOrg",
            date_reserved="2024-01-01T00:00:00Z",
            date_published="2024-01-15T12:00:00Z",
            date_updated="2024-02-01T08:00:00Z",
            cna_title="Test Vulnerability",
            has_cna_metrics=True,
            has_affected=True,
        )
        assert record.assigner_short_name == "TestOrg"
        assert record.cna_title == "Test Vulnerability"
        assert record.has_cna_metrics is True

    def test_missing_required_field_raises(self):
        """Should raise ValidationError for missing required fields."""
        with pytest.raises(ValidationError):
            CVERecord(
                cve_id="CVE-2024-1234",
                # Missing data_type, data_version, state
            )

    def test_rejected_state(self):
        """Should handle REJECTED state."""
        record = CVERecord(
            cve_id="CVE-2024-9999",
            data_type="CVE_RECORD",
            data_version="5.1",
            state="REJECTED",
            date_rejected="2024-03-01T00:00:00Z",
        )
        assert record.state == "REJECTED"
        assert record.date_rejected is not None


# =============================================================================
# CVEDescription Model Tests
# =============================================================================


class TestCVEDescription:
    """Tests for CVEDescription model."""

    def test_basic_description(self):
        """Should create description with required fields."""
        desc = CVEDescription(
            cve_id="CVE-2024-1234",
            source="cna",
            lang="en",
            value="A vulnerability exists in the software.",
        )
        assert desc.cve_id == "CVE-2024-1234"
        assert desc.lang == "en"
        assert "vulnerability" in desc.value

    def test_description_with_supporting_media(self):
        """Should handle supporting media fields."""
        desc = CVEDescription(
            cve_id="CVE-2024-1234",
            source="cna",
            lang="en",
            value="Description text",
            supporting_media_type="text/html",
            supporting_media_base64=True,
        )
        assert desc.supporting_media_type == "text/html"
        assert desc.supporting_media_base64 is True

    def test_adp_source(self):
        """Should handle ADP source."""
        desc = CVEDescription(
            cve_id="CVE-2024-1234",
            source="adp:CISA-ADP",
            lang="en",
            value="ADP-provided description",
        )
        assert desc.source == "adp:CISA-ADP"


# =============================================================================
# CVEMetric Model Tests
# =============================================================================


class TestCVEMetric:
    """Tests for CVEMetric model."""

    def test_cvss_v3_1_metric(self):
        """Should create CVSS v3.1 metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            source="cna",
            metric_type="cvssV3_1",
            base_score=7.5,
            base_severity="HIGH",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            version="3.1",
            attack_vector="NETWORK",
            attack_complexity="LOW",
        )
        assert metric.base_score == 7.5
        assert metric.metric_type == "cvssV3_1"
        assert metric.attack_vector == "NETWORK"

    def test_cvss_v4_metric(self):
        """Should create CVSS v4.0 metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            source="cna",
            metric_type="cvssV4_0",
            base_score=8.5,
            base_severity="HIGH",
            attack_requirements="NONE",
            vulnerable_system_confidentiality="HIGH",
        )
        assert metric.metric_type == "cvssV4_0"
        assert metric.attack_requirements == "NONE"

    def test_cvss_v2_metric(self):
        """Should create CVSS v2.0 metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            source="cna",
            metric_type="cvssV2_0",
            base_score=5.0,
            access_vector="NETWORK",
            access_complexity="LOW",
            authentication="NONE",
        )
        assert metric.metric_type == "cvssV2_0"
        assert metric.access_vector == "NETWORK"

    def test_text_severity_metric(self):
        """Should create text-only severity metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            source="cna",
            metric_type="other",
            base_severity="High",
            other_type="unknown",
            other_content='{"value": "High"}',
        )
        assert metric.base_score is None
        assert metric.base_severity == "High"

    def test_ssvc_metric(self):
        """Should create SSVC metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            source="adp:CISA-ADP",
            metric_type="ssvc",
            other_type="ssvc",
            other_content='{"automatable": "Yes", "exploitation": "Active"}',
        )
        assert metric.metric_type == "ssvc"


# =============================================================================
# CVEProduct Model Tests
# =============================================================================


class TestCVEProduct:
    """Tests for CVEProduct model."""

    def test_minimal_product(self):
        """Should create product with required fields."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            source="cna",
            product_id="1",
        )
        assert product.cve_id == "CVE-2024-1234"
        assert product.product_id == "1"

    def test_full_product(self):
        """Should create product with all fields."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            source="cna",
            product_id="1",
            vendor="TestVendor",
            product="TestProduct",
            package_name="test-package",
            platforms="linux,windows",
            default_status="unaffected",
            cpes="cpe:2.3:a:testvendor:testproduct:*:*:*:*:*:*:*:*",
            package_url="pkg:pypi/test-package",
        )
        assert product.vendor == "TestVendor"
        assert product.package_url == "pkg:pypi/test-package"
        assert product.platforms == "linux,windows"

    def test_product_with_collection_url(self):
        """Should handle collection URL."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            source="cna",
            product_id="1",
            collection_url="https://pypi.org/project/django/",
            repo="https://github.com/django/django",
        )
        assert product.collection_url is not None
        assert product.repo is not None


# =============================================================================
# CVEVersion Model Tests
# =============================================================================


class TestCVEVersion:
    """Tests for CVEVersion model."""

    def test_version_range(self):
        """Should create version range."""
        version = CVEVersion(
            cve_id="CVE-2024-1234",
            product_id="1",
            version="1.0.0",
            status="affected",
            less_than="2.0.0",
        )
        assert version.version == "1.0.0"
        assert version.less_than == "2.0.0"
        assert version.status == "affected"

    def test_version_less_than_or_equal(self):
        """Should handle less_than_or_equal."""
        version = CVEVersion(
            cve_id="CVE-2024-1234",
            product_id="1",
            version="1.0.0",
            status="affected",
            less_than_or_equal="1.5.0",
        )
        assert version.less_than_or_equal == "1.5.0"

    def test_version_with_changes(self):
        """Should handle version changes."""
        version = CVEVersion(
            cve_id="CVE-2024-1234",
            product_id="1",
            version="1.0.0",
            changes='[{"at": "1.2.0", "status": "unaffected"}]',
        )
        assert version.changes is not None


# =============================================================================
# CVECWE Model Tests
# =============================================================================


class TestCVECWE:
    """Tests for CVECWE model."""

    def test_cwe_with_id(self):
        """Should create CWE with ID."""
        cwe = CVECWE(
            cve_id="CVE-2024-1234",
            source="cna",
            cwe_id="CWE-79",
            cwe_type="CWE",
            lang="en",
            description="Cross-site Scripting (XSS)",
        )
        assert cwe.cwe_id == "CWE-79"
        assert cwe.cwe_type == "CWE"

    def test_cwe_text_only(self):
        """Should handle text-only CWE (no ID)."""
        cwe = CVECWE(
            cve_id="CVE-2024-1234",
            source="cna",
            cwe_id=None,
            cwe_type="text",
            lang="en",
            description="Memory corruption vulnerability",
        )
        assert cwe.cwe_id is None
        assert cwe.cwe_type == "text"


# =============================================================================
# CVEReference Model Tests
# =============================================================================


class TestCVEReference:
    """Tests for CVEReference model."""

    def test_basic_reference(self):
        """Should create reference with URL."""
        ref = CVEReference(
            cve_id="CVE-2024-1234",
            source="cna",
            url="https://example.com/advisory",
        )
        assert ref.url == "https://example.com/advisory"

    def test_reference_with_tags(self):
        """Should handle reference tags."""
        ref = CVEReference(
            cve_id="CVE-2024-1234",
            source="cna",
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            name="NVD",
            tags="vendor-advisory,patch",
        )
        assert ref.tags == "vendor-advisory,patch"
        assert ref.name == "NVD"


# =============================================================================
# CVECredit Model Tests
# =============================================================================


class TestCVECredit:
    """Tests for CVECredit model."""

    def test_basic_credit(self):
        """Should create credit."""
        credit = CVECredit(
            cve_id="CVE-2024-1234",
            source="cna",
            lang="en",
            value="John Doe of Security Corp",
        )
        assert credit.value == "John Doe of Security Corp"

    def test_credit_with_type(self):
        """Should handle credit type."""
        credit = CVECredit(
            cve_id="CVE-2024-1234",
            source="cna",
            lang="en",
            value="Jane Smith",
            credit_type="finder",
        )
        assert credit.credit_type == "finder"


# =============================================================================
# CVETag Model Tests
# =============================================================================


class TestCVETag:
    """Tests for CVETag model."""

    def test_simple_tag(self):
        """Should create simple tag."""
        tag = CVETag(
            cve_id="CVE-2024-1234",
            source="cna",
            tag_key="x_generator",
            tag_value="CVEAW/5.0",
        )
        assert tag.tag_key == "x_generator"

    def test_complex_tag(self):
        """Should handle complex tag values."""
        tag = CVETag(
            cve_id="CVE-2024-1234",
            source="metadata",
            tag_key="x_legacyV4Record",
            tag_value='{"dataType": "CVE", "dataVersion": "4.0"}',
        )
        assert tag.tag_key == "x_legacyV4Record"
        assert "dataType" in tag.tag_value


# =============================================================================
# ExtractedData and ExtractionError Tests
# =============================================================================


class TestExtractedData:
    """Tests for ExtractedData namedtuple."""

    def test_create_extracted_data(self):
        """Should create ExtractedData with all components."""
        cve = CVERecord(
            cve_id="CVE-2024-1234",
            data_type="CVE_RECORD",
            data_version="5.1",
            state="PUBLISHED",
        )

        data = ExtractedData(
            cve=cve,
            descriptions=[],
            metrics=[],
            products=[],
            versions=[],
            cwes=[],
            references=[],
            credits=[],
            tags=[],
        )

        assert data.cve.cve_id == "CVE-2024-1234"
        assert isinstance(data.descriptions, list)


class TestExtractionError:
    """Tests for ExtractionError namedtuple."""

    def test_create_extraction_error(self):
        """Should create ExtractionError with error info."""
        error = ExtractionError(
            cve_id="CVE-2024-1234",
            file_path="/data/CVE-2024-1234.json",
            error_type="ValidationError",
            error_message="Invalid JSON structure",
        )

        assert error.cve_id == "CVE-2024-1234"
        assert error.error_type == "ValidationError"


# =============================================================================
# Schema Tests
# =============================================================================


class TestPolarsSchema:
    """Tests for Polars schema definitions."""

    def test_cve_schema_has_required_columns(self):
        """CVE_SCHEMA should have required columns."""
        assert "cve_id" in CVE_SCHEMA
        assert "state" in CVE_SCHEMA
        assert "date_published" in CVE_SCHEMA
        assert "cna_title" in CVE_SCHEMA

    def test_cve_schema_types(self):
        """CVE_SCHEMA should have correct types."""
        import polars as pl

        assert CVE_SCHEMA["cve_id"] == pl.Utf8
        assert CVE_SCHEMA["state"] == pl.Utf8
