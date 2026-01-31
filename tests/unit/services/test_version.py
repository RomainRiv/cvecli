"""Unit tests for version comparison utilities.

These are pure unit tests that don't require any fixtures.
"""

from cvecli.services.version import (
    parse_version,
    compare_versions,
    is_version_affected,
    version_in_range,
)


class TestParseVersion:
    """Tests for version parsing."""

    def test_simple_version(self):
        """Parse simple version number."""
        v = parse_version("1.2.3")
        assert v.parts == [1, 2, 3]
        assert v.prerelease is None

    def test_two_part_version(self):
        """Parse two-part version."""
        v = parse_version("1.2")
        assert v.parts == [1, 2]

    def test_single_number(self):
        """Parse single number version."""
        v = parse_version("5")
        assert v.parts == [5]

    def test_four_part_version(self):
        """Parse four-part version (Windows style)."""
        v = parse_version("10.0.19041.1234")
        assert v.parts == [10, 0, 19041, 1234]

    def test_version_with_v_prefix(self):
        """Parse version with v prefix."""
        v = parse_version("v1.2.3")
        assert v.parts == [1, 2, 3]

    def test_version_with_prerelease(self):
        """Parse version with prerelease suffix."""
        v = parse_version("1.2.3-beta")
        assert v.parts == [1, 2, 3]
        assert v.prerelease is not None
        assert "beta" in v.prerelease

    def test_version_with_alpha(self):
        """Parse version with alpha suffix."""
        v = parse_version("1.0.0-alpha.1")
        assert v.parts == [1, 0, 0]
        assert v.prerelease is not None

    def test_version_with_rc(self):
        """Parse version with rc suffix."""
        v = parse_version("2.0.0-rc1")
        assert v.parts == [2, 0, 0]
        assert v.prerelease is not None

    def test_version_with_build_metadata(self):
        """Parse version with build metadata."""
        v = parse_version("1.2.3+build.123")
        assert v.parts == [1, 2, 3]
        assert v.build == "build.123"

    def test_version_letter_suffix(self):
        """Parse version with letter suffix (e.g., 1.0a)."""
        v = parse_version("1.0a")
        assert v.parts == [1, 0]
        # Letter suffixes are patch_suffix (post-release), not prerelease
        assert v.patch_suffix is not None
        assert "a" in v.patch_suffix

    def test_empty_version(self):
        """Empty version should default to 0."""
        v = parse_version("")
        assert v.parts == [0]

    def test_version_with_underscores(self):
        """Parse version with underscores (common in some projects)."""
        v = parse_version("1_2_3")
        assert v.parts == [1, 2, 3]


class TestVersionComparison:
    """Tests for version comparison."""

    def test_equal_versions(self):
        """Equal versions should be equal."""
        v1 = parse_version("1.2.3")
        v2 = parse_version("1.2.3")
        assert v1 == v2

    def test_equal_with_trailing_zeros(self):
        """1.0 should equal 1.0.0."""
        v1 = parse_version("1.0")
        v2 = parse_version("1.0.0")
        assert v1 == v2

    def test_less_than(self):
        """Test less than comparison."""
        v1 = parse_version("1.0.0")
        v2 = parse_version("1.0.1")
        assert v1 < v2

    def test_greater_than(self):
        """Test greater than comparison."""
        v1 = parse_version("2.0.0")
        v2 = parse_version("1.9.9")
        assert v1 > v2

    def test_major_version_comparison(self):
        """Major version difference should dominate."""
        v1 = parse_version("2.0.0")
        v2 = parse_version("1.99.99")
        assert v1 > v2

    def test_prerelease_less_than_release(self):
        """Prerelease should be less than release."""
        v1 = parse_version("1.0.0-alpha")
        v2 = parse_version("1.0.0")
        assert v1 < v2

    def test_prerelease_ordering(self):
        """Prereleases should order alphabetically."""
        alpha = parse_version("1.0.0-alpha")
        beta = parse_version("1.0.0-beta")
        assert alpha < beta


class TestCompareVersions:
    """Tests for compare_versions function."""

    def test_compare_equal(self):
        """Equal versions should return 0."""
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_compare_less_than(self):
        """First version less than second should return -1."""
        assert compare_versions("1.0.0", "2.0.0") == -1

    def test_compare_greater_than(self):
        """First version greater than second should return 1."""
        assert compare_versions("2.0.0", "1.0.0") == 1


class TestIsVersionAffected:
    """Tests for is_version_affected function."""

    def test_single_affected_version(self):
        """Test with a single affected version."""
        assert is_version_affected("1.0.0", version_start="1.0.0", status="affected")

    def test_less_than_range(self):
        """Test version less than boundary."""
        assert is_version_affected("1.5.0", version_start="1.0.0", less_than="2.0.0")
        assert not is_version_affected(
            "2.0.0", version_start="1.0.0", less_than="2.0.0"
        )
        assert not is_version_affected(
            "2.1.0", version_start="1.0.0", less_than="2.0.0"
        )

    def test_less_than_or_equal_range(self):
        """Test version less than or equal boundary."""
        assert is_version_affected(
            "2.0.0", version_start="1.0.0", less_than_or_equal="2.0.0"
        )
        assert is_version_affected(
            "1.5.0", version_start="1.0.0", less_than_or_equal="2.0.0"
        )
        assert not is_version_affected(
            "2.0.1", version_start="1.0.0", less_than_or_equal="2.0.0"
        )

    def test_unaffected_status(self):
        """Version with unaffected status should not be affected."""
        assert not is_version_affected(
            "1.0.0", version_start="1.0.0", status="unaffected"
        )


class TestVersionInRange:
    """Tests for version_in_range function."""

    def test_in_range(self):
        """Version within range should return (True, reason)."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, reason = version_in_range("1.5.0", ranges)
        assert is_affected

    def test_below_range(self):
        """Version below range should return (False, None)."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, reason = version_in_range("0.5.0", ranges)
        # Below version start, not in range
        assert not is_affected

    def test_above_range(self):
        """Version above range should return (False, None)."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, reason = version_in_range("2.5.0", ranges)
        assert not is_affected

    def test_at_lower_boundary(self):
        """Version at lower boundary should return (True, reason)."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, reason = version_in_range("1.0.0", ranges)
        assert is_affected


class TestVersionRangeParsing:
    """Tests for version range string parsing."""

    def test_version_range_string_parsing(self):
        """Version range strings like '0.5.6 - 1.13.2' should be parsed correctly."""
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
