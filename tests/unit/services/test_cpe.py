"""Unit tests for CPE parsing utilities.

These are pure unit tests that don't require any fixtures.
"""

from cvecli.services.cpe import (
    parse_cpe,
    is_valid_cpe,
    match_cpe_to_product,
    _wildcard_match,
)


class TestParseCPE23:
    """Tests for CPE 2.3 format parsing."""

    def test_parse_full_cpe23(self):
        """Parse a complete CPE 2.3 string."""
        cpe = parse_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.format == "2.3"
        assert cpe.part == "a"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows"
        assert cpe.version == "10"
        assert cpe.original == "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

    def test_parse_cpe23_with_dashes(self):
        """Parse CPE 2.3 with NA (-) values."""
        cpe = parse_cpe("cpe:2.3:o:linux:linux_kernel:5.10:-:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "linux"
        assert cpe.product == "linux_kernel"
        assert cpe.version == "5.10"
        assert cpe.update == "-"

    def test_parse_cpe23_apache(self):
        """Parse Apache HTTP Server CPE."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.vendor == "apache"
        assert cpe.product == "http_server"
        assert cpe.version == "2.4.51"

    def test_parse_cpe23_with_escaped_chars(self):
        """Parse CPE 2.3 with escaped special characters."""
        cpe = parse_cpe("cpe:2.3:a:vendor\\:name:product:1.0:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.vendor is not None
        # The escaped colon should be preserved in vendor
        assert "vendor" in cpe.vendor

    def test_parse_cpe23_wildcards(self):
        """Parse CPE 2.3 with wildcard values."""
        cpe = parse_cpe("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "a"
        assert cpe.vendor is None  # * is converted to None
        assert cpe.product is None

    def test_parse_cpe23_os(self):
        """Parse operating system CPE."""
        cpe = parse_cpe("cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:x64:*")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows_10"
        assert cpe.version == "1909"

    def test_parse_cpe23_hardware(self):
        """Parse hardware CPE."""
        cpe = parse_cpe("cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "h"
        assert cpe.vendor == "cisco"
        assert cpe.product == "router"


class TestParseCPE22:
    """Tests for CPE 2.2 format parsing."""

    def test_parse_simple_cpe22(self):
        """Parse a simple CPE 2.2 string."""
        cpe = parse_cpe("cpe:/a:microsoft:windows:10")
        assert cpe is not None
        assert cpe.format == "2.2"
        assert cpe.part == "a"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows"
        assert cpe.version == "10"

    def test_parse_cpe22_apache(self):
        """Parse Apache CPE 2.2."""
        cpe = parse_cpe("cpe:/a:apache:http_server:2.4.51")
        assert cpe is not None
        assert cpe.vendor == "apache"
        assert cpe.product == "http_server"
        assert cpe.version == "2.4.51"

    def test_parse_cpe22_linux_kernel(self):
        """Parse Linux kernel CPE 2.2."""
        cpe = parse_cpe("cpe:/o:linux:linux_kernel:5.10")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "linux"
        assert cpe.product == "linux_kernel"
        assert cpe.version == "5.10"


class TestParseCPEInvalid:
    """Tests for invalid CPE handling."""

    def test_parse_invalid_returns_none(self):
        """Invalid CPE should return None."""
        assert parse_cpe("not-a-cpe") is None
        assert parse_cpe("") is None
        assert parse_cpe("cpe:") is None

    def test_parse_none_returns_none(self):
        """None input should return None."""
        assert parse_cpe(None) is None


class TestIsValidCPE:
    """Tests for CPE validation."""

    def test_valid_cpe23(self):
        """Valid CPE 2.3 should return True."""
        assert is_valid_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")

    def test_valid_cpe22(self):
        """Valid CPE 2.2 should return True."""
        assert is_valid_cpe("cpe:/a:microsoft:windows:10")

    def test_invalid_cpe(self):
        """Invalid CPE should return False."""
        assert not is_valid_cpe("not-a-cpe")
        assert not is_valid_cpe("")
        assert not is_valid_cpe(None)


class TestWildcardMatch:
    """Tests for wildcard matching."""

    def test_exact_match(self):
        """Exact match should return True."""
        assert _wildcard_match("value", "value")

    def test_wildcard_matches_anything(self):
        """Wildcard should match any value."""
        # _wildcard_match(pattern, text) - pattern "*" matches any text
        assert _wildcard_match("*", "anything")
        assert _wildcard_match("*", "")

    def test_empty_pattern_matches_anything(self):
        """Empty pattern should match anything."""
        # Empty string pattern matches anything (per implementation)
        assert _wildcard_match("", "anything")

    def test_case_insensitive(self):
        """Matching should be case insensitive."""
        assert _wildcard_match("value", "Value")
        assert _wildcard_match("value", "VALUE")


class TestMatchCPEToProduct:
    """Tests for CPE to product matching."""

    def test_match_vendor_and_product(self):
        """Match CPE vendor and product."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "apache", "http_server")

    def test_no_match_different_vendor(self):
        """Different vendor should not match."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert not match_cpe_to_product(cpe, "nginx", "http_server")

    def test_no_match_different_product(self):
        """Different product should not match."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert not match_cpe_to_product(cpe, "apache", "tomcat")

    def test_match_with_wildcard_vendor(self):
        """Wildcard vendor should match any vendor."""
        cpe = parse_cpe("cpe:2.3:a:*:http_server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "apache", "http_server")
        assert match_cpe_to_product(cpe, "nginx", "http_server")
