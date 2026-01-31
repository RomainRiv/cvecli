"""Unit tests for CLI constants and patterns.

These are pure unit tests that don't require any fixtures.
"""

from cvecli.constants import CVE_ID_PATTERN


class TestCVEIDPattern:
    """Tests for CVE ID pattern matching."""

    def test_valid_cve_id_patterns(self):
        """Valid CVE ID formats should match."""
        # Standard formats
        assert CVE_ID_PATTERN.match("CVE-2024-1234") is not None
        assert CVE_ID_PATTERN.match("CVE-2024-12345") is not None
        assert CVE_ID_PATTERN.match("CVE-2024-123456") is not None

        # Case insensitive
        assert CVE_ID_PATTERN.match("cve-2024-1234") is not None
        assert CVE_ID_PATTERN.match("Cve-2024-1234") is not None

    def test_invalid_cve_id_patterns(self):
        """Invalid CVE ID formats should not match."""
        # Too few digits in sequence number
        assert CVE_ID_PATTERN.match("CVE-2024-123") is None

        # Missing prefix
        assert CVE_ID_PATTERN.match("2024-1234") is None

        # Wrong separator
        assert CVE_ID_PATTERN.match("CVE_2024_1234") is None

        # Non-numeric
        assert CVE_ID_PATTERN.match("CVE-ABCD-1234") is None

        # Product name that looks like CVE but isn't
        assert CVE_ID_PATTERN.match("CVE-viewer") is None


class TestCVEAutoDetect:
    """Tests for CVE ID auto-detection in search."""

    def test_is_cve_id_with_standard_format(self):
        """Standard CVE ID should be detected."""
        assert CVE_ID_PATTERN.match("CVE-2024-1234") is not None

    def test_is_not_cve_id_with_product_name(self):
        """Product names should not be detected as CVE IDs."""
        # These are product searches, not CVE IDs
        assert CVE_ID_PATTERN.match("openssl") is None
        assert CVE_ID_PATTERN.match("linux kernel") is None
        assert CVE_ID_PATTERN.match("apache") is None

    def test_is_not_cve_id_with_cwe(self):
        """CWE IDs should not be detected as CVE IDs."""
        assert CVE_ID_PATTERN.match("CWE-79") is None
        assert CVE_ID_PATTERN.match("CWE-1234") is None
