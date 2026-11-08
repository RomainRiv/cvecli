"""CVE schema version algorithm and SemVer specification examples."""

import pytest

from cvecli.services.applicability import version_status

PRODUCT = {"default_status": "unaffected"}


def entry(**kwargs):
    return {
        "version": "1.0.0",
        "less_than": "2.0.0",
        "version_type": "semver",
        "status": "affected",
        **kwargs,
    }


# SemVer 2.0.0 specification, item 11, increasing precedence example.
ORDER = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
]


@pytest.mark.parametrize("lower,upper", list(zip(ORDER, ORDER[1:])))
def test_semver_official_precedence(lower, upper):
    row = entry(version=lower, less_than=upper)
    assert version_status(lower, PRODUCT, [row])["status"] == "affected"
    assert version_status(upper, PRODUCT, [row])["status"] == "unaffected"


@pytest.mark.parametrize(
    "version,status",
    [
        ("0.9.0", "unaffected"),
        ("1.0.0", "affected"),
        ("1.9.0", "affected"),
        ("2.0.0", "unaffected"),
    ],
)
def test_cve_range_and_default(version, status):
    assert version_status(version, PRODUCT, [entry()])["status"] == status


def test_cve_inclusive_end_and_changes_are_sorted():
    row = entry(
        less_than=None,
        less_than_or_equal="2.0.0",
        changes='[{"at":"1.8.0","status":"affected"},{"at":"1.5.0","status":"unaffected"}]',
    )
    assert version_status("1.6.0", PRODUCT, [row])["status"] == "unaffected"
    assert version_status("1.9.0", PRODUCT, [row])["status"] == "affected"
    assert version_status("2.0.0", PRODUCT, [row])["status"] == "affected"


def test_cve_single_version_is_not_a_range_and_first_match_wins():
    row = {"version": "1.0", "status": "affected"}
    assert version_status("1.1", PRODUCT, [row])["status"] == "unaffected"
    assert (
        version_status("1.0", PRODUCT, [row, {**row, "status": "unaffected"}])["status"]
        == "affected"
    )


@pytest.mark.parametrize("scheme", [None, "custom", "git", "rpm", "maven", "python"])
def test_unsupported_ordering_never_falls_through_to_default(scheme):
    assert (
        version_status("1.5.0", PRODUCT, [entry(version_type=scheme)])["status"]
        == "unknown"
    )


def test_build_metadata_is_ignored_for_semver_and_invalid_values_unknown():
    assert (
        version_status(
            "1.0.0+build2",
            PRODUCT,
            [
                {
                    "version": "1.0.0+build1",
                    "version_type": "semver",
                    "status": "affected",
                }
            ],
        )["status"]
        == "affected"
    )
    assert version_status("1.5", PRODUCT, [entry()])["status"] == "unknown"


@pytest.mark.parametrize(
    "upper,version,status",
    [
        ("1.*", "1.99.0", "affected"),
        ("1.*", "2.0.0", "unaffected"),
        ("1.2.*", "1.3.0", "unaffected"),
        ("*", "99.0.0", "affected"),
    ],
)
def test_cve_wildcard_upper_bounds(upper, version, status):
    assert (
        version_status(version, PRODUCT, [entry(version="0", less_than=upper)])[
            "status"
        ]
        == status
    )


def test_unspecified_version_and_conflicting_changes_unknown():
    assert version_status(None, PRODUCT, [entry()])["status"] == "unknown"
    row = entry(
        changes=[
            {"at": "1.5.0", "status": "affected"},
            {"at": "1.5.0", "status": "unaffected"},
        ]
    )
    assert version_status("1.6.0", PRODUCT, [row])["status"] == "unknown"
