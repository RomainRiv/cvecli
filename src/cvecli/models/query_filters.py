"""Query filter models for CVE searches.

This module provides strongly-typed filter models for the CVEQuery builder.
Each filter type has a dedicated class with validated fields, replacing
the previous loosely-typed dictionary approach.

All filter classes inherit from QueryFilter and are immutable.
The FilterType enum provides type-safe filter type identification.

Example:
    from cvecli.models.query_filters import ProductFilter, SeverityFilter
    from cvecli.constants import SeverityLevel

    # Type-safe filter creation
    product_filter = ProductFilter(product="linux")
    severity_filter = SeverityFilter(severity=SeverityLevel.CRITICAL)
"""

from abc import ABC
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from cvecli.constants import SearchMode, SeverityLevel


class FilterType(Enum):
    """Enumeration of available filter types.

    Each filter type corresponds to a specific QueryFilter subclass.
    This provides type-safe filter identification and pattern matching.
    """

    ID = auto()
    EXCLUDE_IDS = auto()
    PRODUCT = auto()
    VENDOR = auto()
    CWE = auto()
    SEVERITY = auto()
    CVSS = auto()
    DATE = auto()
    YEAR = auto()
    STATE = auto()
    CPE = auto()
    PURL = auto()
    VERSION = auto()
    KEV = auto()
    RECENT = auto()
    TEXT_SEARCH = auto()
    DESCRIPTION = auto()
    HAS_METRICS = auto()
    REFERENCE_TAG = auto()


@dataclass(frozen=True)
class QueryFilter(ABC):
    """Base class for all query filters.

    All filters are immutable (frozen dataclasses) to ensure
    query builders remain pure and composable.
    """

    @property
    def filter_type(self) -> FilterType:
        """Return the filter type for this filter.

        Returns:
            The FilterType enum value for this filter class.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class IdFilter(QueryFilter):
    """Filter by specific CVE ID.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2024-1234" or "2024-1234").
    """

    cve_id: str

    @property
    def filter_type(self) -> FilterType:
        return FilterType.ID


@dataclass(frozen=True)
class ExcludeIdsFilter(QueryFilter):
    """Exclude specific CVE IDs from results.

    Useful for filtering out known false positives or already-processed CVEs.

    Attributes:
        cve_ids: List of CVE identifiers to exclude.
    """

    cve_ids: tuple[str, ...]

    @property
    def filter_type(self) -> FilterType:
        return FilterType.EXCLUDE_IDS


@dataclass(frozen=True)
class ProductFilter(QueryFilter):
    """Filter by product name.

    Attributes:
        product: Product name to search for.
        fuzzy: If True, use case-insensitive substring matching.
        exact: If True, use literal string matching (no regex).
    """

    product: str
    fuzzy: bool = True
    exact: bool = False

    @property
    def filter_type(self) -> FilterType:
        return FilterType.PRODUCT


@dataclass(frozen=True)
class VendorFilter(QueryFilter):
    """Filter by vendor name.

    Attributes:
        vendor: Vendor name to search for.
        fuzzy: If True, use case-insensitive substring matching.
        exact: If True, use literal string matching (no regex).
    """

    vendor: str
    fuzzy: bool = True
    exact: bool = False

    @property
    def filter_type(self) -> FilterType:
        return FilterType.VENDOR


@dataclass(frozen=True)
class CweFilter(QueryFilter):
    """Filter by CWE identifier.

    Attributes:
        cwe_id: CWE identifier (e.g., "CWE-79" or "79").
    """

    cwe_id: str

    @property
    def filter_type(self) -> FilterType:
        return FilterType.CWE


@dataclass(frozen=True)
class SeverityFilter(QueryFilter):
    """Filter by severity level.

    Attributes:
        severity: Severity level (none, low, medium, high, critical).
    """

    severity: SeverityLevel

    @property
    def filter_type(self) -> FilterType:
        return FilterType.SEVERITY


@dataclass(frozen=True)
class CvssFilter(QueryFilter):
    """Filter by CVSS score range.

    Attributes:
        min_score: Minimum CVSS score (inclusive).
        max_score: Maximum CVSS score (inclusive).
    """

    min_score: Optional[float] = None
    max_score: Optional[float] = None

    @property
    def filter_type(self) -> FilterType:
        return FilterType.CVSS


@dataclass(frozen=True)
class DateFilter(QueryFilter):
    """Filter by publication date range.

    Attributes:
        after: Only include CVEs published after this date (YYYY-MM-DD).
        before: Only include CVEs published before this date (YYYY-MM-DD).
    """

    after: Optional[str] = None
    before: Optional[str] = None

    @property
    def filter_type(self) -> FilterType:
        return FilterType.DATE


@dataclass(frozen=True)
class YearFilter(QueryFilter):
    """Filter by CVE year(s).

    Filters CVEs based on the year in their CVE ID (e.g., CVE-2024-xxxx).

    Attributes:
        years: Tuple of years to include.
    """

    years: tuple[int, ...]

    @property
    def filter_type(self) -> FilterType:
        return FilterType.YEAR


@dataclass(frozen=True)
class StateFilter(QueryFilter):
    """Filter by CVE state.

    Attributes:
        state: CVE state (e.g., "PUBLISHED", "REJECTED").
    """

    state: str

    @property
    def filter_type(self) -> FilterType:
        return FilterType.STATE


@dataclass(frozen=True)
class CpeFilter(QueryFilter):
    """Filter by CPE (Common Platform Enumeration) string.

    Attributes:
        cpe_string: CPE string in 2.2 or 2.3 format.
        check_version: Optional version to check for affected range.
    """

    cpe_string: str
    check_version: Optional[str] = None

    @property
    def filter_type(self) -> FilterType:
        return FilterType.CPE


@dataclass(frozen=True)
class PurlFilter(QueryFilter):
    """Filter by Package URL (PURL).

    Attributes:
        purl: Package URL string (e.g., "pkg:pypi/django").
        check_version: Optional version to check for affected range.
        fuzzy: If True, use substring matching.
    """

    purl: str
    check_version: Optional[str] = None
    fuzzy: bool = False

    @property
    def filter_type(self) -> FilterType:
        return FilterType.PURL


@dataclass(frozen=True)
class VersionFilter(QueryFilter):
    """Filter to only CVEs affecting a specific version.

    This filter checks version ranges in the CVE data to determine
    if the specified version is affected. For best results, chain
    with by_product() or by_vendor() to narrow down the scope.

    Attributes:
        version: Version string to check.
    """

    version: str

    @property
    def filter_type(self) -> FilterType:
        return FilterType.VERSION


@dataclass(frozen=True)
class KevFilter(QueryFilter):
    """Filter to only CVEs in CISA Known Exploited Vulnerabilities."""

    @property
    def filter_type(self) -> FilterType:
        return FilterType.KEV


@dataclass(frozen=True)
class RecentFilter(QueryFilter):
    """Filter to recently published CVEs.

    Attributes:
        days: Number of days to look back.
    """

    days: int = 30

    @property
    def filter_type(self) -> FilterType:
        return FilterType.RECENT


@dataclass(frozen=True)
class TextSearchFilter(QueryFilter):
    """Search by text in product/vendor fields.

    Attributes:
        query: Search query string.
        mode: Search mode (strict, regex, fuzzy).
    """

    query: str
    mode: SearchMode = SearchMode.FUZZY

    @property
    def filter_type(self) -> FilterType:
        return FilterType.TEXT_SEARCH


@dataclass(frozen=True)
class DescriptionFilter(QueryFilter):
    """Search within CVE descriptions.

    Performs text search on CVE description content.

    Attributes:
        query: Search query string.
        mode: Search mode (strict, regex, fuzzy).
        lang: Language code to search in (default: "en").
    """

    query: str
    mode: SearchMode = SearchMode.FUZZY
    lang: str = "en"

    @property
    def filter_type(self) -> FilterType:
        return FilterType.DESCRIPTION


@dataclass(frozen=True)
class HasMetricsFilter(QueryFilter):
    """Filter to CVEs that have CVSS metrics.

    Useful to exclude CVEs without severity scores.

    Attributes:
        has_metrics: If True, include only CVEs with metrics.
                     If False, include only CVEs without metrics.
    """

    has_metrics: bool = True

    @property
    def filter_type(self) -> FilterType:
        return FilterType.HAS_METRICS


@dataclass(frozen=True)
class ReferenceTagFilter(QueryFilter):
    """Filter by reference tag.

    CVE references are tagged with types like "Exploit", "Patch",
    "Vendor Advisory", "Third Party Advisory", etc.

    Attributes:
        tags: Tuple of tags to match (e.g., ("Exploit", "Patch")).
        match_all: If True, CVE must have all tags. If False, any tag matches.
    """

    tags: tuple[str, ...]
    match_all: bool = False

    @property
    def filter_type(self) -> FilterType:
        return FilterType.REFERENCE_TAG


# Type alias for any filter
AnyFilter = (
    IdFilter
    | ExcludeIdsFilter
    | ProductFilter
    | VendorFilter
    | CweFilter
    | SeverityFilter
    | CvssFilter
    | DateFilter
    | YearFilter
    | StateFilter
    | CpeFilter
    | PurlFilter
    | VersionFilter
    | KevFilter
    | RecentFilter
    | TextSearchFilter
    | DescriptionFilter
    | HasMetricsFilter
    | ReferenceTagFilter
)
