"""Unit tests for the extractor service.

These tests focus on extraction logic, data models, and helper functions.
"""

from cvecli.models.cve_model import CveJsonRecordFormat
from cvecli.services.extractor import (
    CVEDescription,
    CVEMetric,
    CVEProduct,
    CVERecord,
    _extract_single_cve,
    _get_iterable,
    _get_value,
)

# =============================================================================
# Sample CVE Data for Tests
# =============================================================================


SAMPLE_CVE_DATA = {
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


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestGetIterable:
    """Tests for _get_iterable helper function."""

    def test_none_returns_empty_list(self):
        """None should return empty list."""
        assert list(_get_iterable(None)) == []

    def test_list_returns_list(self):
        """List should be returned as-is."""
        items = [1, 2, 3]
        result = _get_iterable(items)
        assert list(result) == items

    def test_tuple_returns_tuple(self):
        """Tuple should be returned as-is."""
        items = (1, 2, 3)
        result = _get_iterable(items)
        assert list(result) == [1, 2, 3]

    def test_object_with_root_returns_root(self):
        """Object with .root attribute should return .root."""

        class MockPydantic:
            root = [1, 2, 3]

        result = _get_iterable(MockPydantic())
        assert list(result) == [1, 2, 3]

    def test_single_value_wrapped_in_list(self):
        """Single value should be wrapped in list."""
        result = _get_iterable("single")
        assert list(result) == ["single"]


class TestGetValue:
    """Tests for _get_value helper function."""

    def test_none_returns_none(self):
        """None should return None."""
        assert _get_value(None) is None

    def test_string_returns_string(self):
        """String should be returned as-is."""
        assert _get_value("test") == "test"

    def test_int_returns_string(self):
        """Integer should be converted to string."""
        assert _get_value(123) == "123"

    def test_object_with_root(self):
        """Object with .root should unwrap to .root value."""

        class MockPydantic:
            root = "wrapped_value"

        assert _get_value(MockPydantic()) == "wrapped_value"

    def test_nested_root(self):
        """Nested .root should be fully unwrapped."""

        class Inner:
            root = "final_value"

        class Outer:
            root = Inner()

        assert _get_value(Outer()) == "final_value"

    def test_enum_with_value(self):
        """Enum-like object with _value_ should return _value_."""
        from enum import Enum

        class State(Enum):
            PUBLISHED = "PUBLISHED"

        assert _get_value(State.PUBLISHED) == "PUBLISHED"


# =============================================================================
# Model Tests
# =============================================================================


class TestCVERecordModel:
    """Tests for CVERecord Pydantic model."""

    def test_minimal_record(self):
        """Test creating a minimal CVE record."""
        record = CVERecord(
            cve_id="CVE-2024-1234",
            state="PUBLISHED",
            data_type="CVE_RECORD",
            data_version="5.1",
        )
        assert record.cve_id == "CVE-2024-1234"
        assert record.state == "PUBLISHED"
        assert record.cna_title is None
        assert record.date_published is None

    def test_full_record(self):
        """Test creating a full CVE record."""
        record = CVERecord(
            cve_id="CVE-2024-1234",
            state="PUBLISHED",
            data_type="CVE_RECORD",
            data_version="5.1",
            assigner_org_id="14ed7db2-1595-443d-9d34-6215bf890778",
            assigner_short_name="Google",
            date_published="2024-01-01T00:00:00.000Z",
            cna_title="Test vulnerability",
        )
        assert record.assigner_short_name == "Google"
        assert record.cna_title == "Test vulnerability"


class TestCVEMetricModel:
    """Tests for CVEMetric model."""

    def test_cvss_v3_1_metric(self):
        """Test creating a CVSS v3.1 metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            metric_type="cvssV3_1",
            source="cna",
            base_score=7.5,
            base_severity="HIGH",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
        assert metric.base_score == 7.5
        assert metric.metric_type == "cvssV3_1"

    def test_text_severity_metric(self):
        """Test creating a text severity metric."""
        metric = CVEMetric(
            cve_id="CVE-2024-1234",
            metric_type="other",
            source="cna",
            base_severity="High",
        )
        assert metric.base_score is None
        assert metric.base_severity == "High"


class TestCVEDescriptionModel:
    """Tests for CVEDescription model."""

    def test_basic_description(self):
        """Test creating a description."""
        desc = CVEDescription(
            cve_id="CVE-2024-1234",
            lang="en",
            value="Test vulnerability description",
            source="cna",
        )
        assert desc.lang == "en"
        assert desc.value == "Test vulnerability description"


class TestCVEProductModel:
    """Tests for CVEProduct model."""

    def test_minimal_product(self):
        """Test creating a minimal product record."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            product_id="1",
            vendor="TestVendor",
            product="TestProduct",
            source="cna",
        )
        assert product.cve_id == "CVE-2024-1234"
        assert product.vendor == "TestVendor"
        assert product.product == "TestProduct"

    def test_product_with_package_name(self):
        """Test creating a product with package name."""
        product = CVEProduct(
            cve_id="CVE-2024-1234",
            product_id="1",
            vendor="Linux",
            product="Linux Kernel",
            package_name="KVM",
            default_status="unaffected",
            source="cna",
        )
        assert product.package_name == "KVM"
        assert product.default_status == "unaffected"


# =============================================================================
# Extraction Tests
# =============================================================================


class TestExtractSingleCVE:
    """Tests for _extract_single_cve function."""

    def test_extract_basic_cve(self):
        """Test extracting a basic CVE from JSON."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_DATA)
        result = _extract_single_cve(cve_model)

        assert result.cve.cve_id == "CVE-2022-2196"
        assert result.cve.state == "PUBLISHED"
        assert result.cve.cna_title == "KVM nVMX Spectre v2 vulnerability"

        # Check metrics
        cvss_metrics = [m for m in result.metrics if m.metric_type == "cvssV3_1"]
        assert len(cvss_metrics) >= 1
        assert cvss_metrics[0].base_score == 5.8

        # Check descriptions
        en_desc = [d for d in result.descriptions if d.lang == "en"]
        assert len(en_desc) >= 1
        assert "KVM" in en_desc[0].value

    def test_extract_products(self):
        """Test extracting affected products."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_DATA)
        result = _extract_single_cve(cve_model)

        assert len(result.products) >= 1
        products = {(p.vendor, p.product) for p in result.products}
        assert ("Linux", "Linux Kernel") in products

    def test_extract_cwes(self):
        """Test extracting CWE mappings."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_DATA)
        result = _extract_single_cve(cve_model)

        assert len(result.cwes) >= 1
        cwe_ids = [c.cwe_id for c in result.cwes]
        assert "CWE-1188" in cwe_ids

    def test_extract_versions(self):
        """Test extracting version information."""
        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_DATA)
        result = _extract_single_cve(cve_model)

        assert len(result.versions) >= 1
        version = result.versions[0]
        assert version.less_than == "6.2"
        assert version.version == "0"
