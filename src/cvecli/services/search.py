"""CVE search service.

This service provides a fluent, chainable API for searching CVE data.
All searches are composable - you can chain filters in any order.

Example usage:
    from cvecli.services.search import CVESearchService
    from cvecli.constants import SeverityLevel

    search = CVESearchService()

    # Chain filters in any order
    results = (
        search.query()
        .by_product("linux")
        .by_severity(SeverityLevel.CRITICAL)
        .by_date(after="2024-01-01")
        .sort_by("cvss", descending=True)
        .limit(100)
        .execute()
    )

    # Simple lookups
    result = search.query().by_id("CVE-2024-1234").execute()

    # Semantic search
    results = search.query().semantic("memory corruption").execute()
"""

from __future__ import annotations

import json as json_module
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import polars as pl

from cvecli.constants import (
    SEVERITY_THRESHOLDS,
    SearchMode,
    SeverityLevel,
)
from cvecli.core.config import Config, get_config
from cvecli.models.query_filters import (
    CpeFilter,
    CvssFilter,
    CweFilter,
    DateFilter,
    DescriptionFilter,
    ExcludeIdsFilter,
    HasMetricsFilter,
    IdFilter,
    KevFilter,
    ProductFilter,
    PurlFilter,
    QueryFilter,
    RecentFilter,
    ReferenceTagFilter,
    SeverityFilter,
    StateFilter,
    TextSearchFilter,
    VendorFilter,
    VersionFilter,
    YearFilter,
)
from cvecli.services.cpe import parse_cpe
from cvecli.services.version import is_version_affected


class SearchResult:
    """Container for search results with metadata and chainable filter methods.

    SearchResult is immutable - all filter methods return new SearchResult instances.
    This allows composable, chainable queries in any order.

    Example:
        result = (
            search.query()
            .by_product("linux")
            .by_severity(SeverityLevel.CRITICAL)
            .execute()
        )
        print(f"Found {result.count} CVEs")
    """

    def __init__(
        self,
        cves: pl.DataFrame,
        descriptions: Optional[pl.DataFrame] = None,
        metrics: Optional[pl.DataFrame] = None,
        products: Optional[pl.DataFrame] = None,
        versions: Optional[pl.DataFrame] = None,
        cwes: Optional[pl.DataFrame] = None,
        references: Optional[pl.DataFrame] = None,
        credits: Optional[pl.DataFrame] = None,
    ):
        self.cves = cves
        self.descriptions = descriptions
        self.metrics = metrics
        self.products = products
        self.versions = versions
        self.cwes = cwes
        self.references = references
        self.credits = credits

    @property
    def count(self) -> int:
        """Number of CVE results."""
        return len(self.cves)

    def to_dicts(self) -> List[dict]:
        """Convert results to list of dictionaries."""
        return self.cves.to_dicts()

    def to_json(self) -> str:
        """Convert results to JSON string."""
        return self.cves.write_json()

    def summary(self) -> dict:
        """Get a summary of the search results."""
        if self.count == 0:
            return {"count": 0, "cves": []}

        return {
            "count": self.count,
            "severity_distribution": self._get_severity_distribution(),
            "year_distribution": self._get_year_distribution(),
        }

    def _get_severity_distribution(self) -> dict:
        """Get count of CVEs by severity based on metrics."""
        result = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
            "unknown": 0,
        }

        if self.metrics is None or len(self.metrics) == 0:
            result["unknown"] = self.count
            return result

        # Get best score per CVE from metrics
        cve_ids = set(self.cves.get_column("cve_id").to_list())

        # Filter metrics for our CVEs and get best score per CVE
        relevant_metrics = self.metrics.filter(
            pl.col("cve_id").is_in(cve_ids)
            & pl.col("base_score").is_not_null()
            & pl.col("metric_type").str.starts_with("cvss")
        )

        if len(relevant_metrics) == 0:
            result["unknown"] = self.count
            return result

        # Preference order for metrics (prefer CNA over ADP, prefer newer versions)
        best_scores = (
            relevant_metrics.with_columns(
                [
                    # Score metrics by preference (higher = better)
                    pl.when(pl.col("source") == "cna")
                    .then(100)
                    .otherwise(0)
                    .alias("source_pref"),
                    pl.when(pl.col("metric_type") == "cvssV4_0")
                    .then(40)
                    .when(pl.col("metric_type") == "cvssV3_1")
                    .then(30)
                    .when(pl.col("metric_type") == "cvssV3_0")
                    .then(20)
                    .otherwise(10)
                    .alias("version_pref"),
                ]
            )
            .with_columns(
                [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
            )
            .sort(["cve_id", "preference"], descending=[False, True])
            .group_by("cve_id")
            .first()
        )

        cves_with_scores = set(best_scores.get_column("cve_id").to_list())

        for row in best_scores.iter_rows(named=True):
            score = row.get("base_score")
            if score is None:
                result["unknown"] += 1
            elif score >= 9.0:
                result["critical"] += 1
            elif score >= 7.0:
                result["high"] += 1
            elif score >= 4.0:
                result["medium"] += 1
            elif score >= 0.1:
                result["low"] += 1
            else:
                result["none"] += 1

        # Count CVEs without scores as unknown
        result["unknown"] += len(cve_ids - cves_with_scores)

        return result

    def _get_year_distribution(self) -> dict:
        """Get count of CVEs by year."""
        year_counts: dict[str, int] = {}

        for row in self.cves.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    year_counts[year] = year_counts.get(year, 0) + 1

        return year_counts


class CVEQuery:
    """Fluent query builder for CVE searches.

    CVEQuery provides a chainable API for building complex CVE queries.
    All filter methods return a new CVEQuery instance, making queries composable.

    Example:
        query = (
            CVEQuery(service)
            .by_product("linux")
            .by_severity(SeverityLevel.CRITICAL)
            .by_date(after="2024-01-01")
            .sort_by("cvss")
            .limit(100)
        )
        results = query.execute()
    """

    def __init__(self, service: CVESearchService):
        """Initialize a query builder.

        Args:
            service: The CVESearchService instance to execute queries against.
        """
        self._service = service
        self._filters: List[QueryFilter] = []
        self._sort_field: Optional[str] = None
        self._sort_descending: bool = True
        self._limit_count: Optional[int] = None
        self._semantic_query: Optional[str] = None
        self._semantic_top_k: int = 100
        self._semantic_min_similarity: float = 0.3

    def _copy(self) -> CVEQuery:
        """Create a copy of this query."""
        new_query = CVEQuery(self._service)
        new_query._filters = self._filters.copy()
        new_query._sort_field = self._sort_field
        new_query._sort_descending = self._sort_descending
        new_query._limit_count = self._limit_count
        new_query._semantic_query = self._semantic_query
        new_query._semantic_top_k = self._semantic_top_k
        new_query._semantic_min_similarity = self._semantic_min_similarity
        return new_query

    def by_id(self, cve_id: str) -> CVEQuery:
        """Filter by specific CVE ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234" or "2024-1234").

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(IdFilter(cve_id=cve_id))
        return q

    def exclude_ids(self, cve_ids: List[str]) -> CVEQuery:
        """Exclude specific CVE IDs from results.

        Useful for filtering out known false positives or already-processed CVEs.

        Args:
            cve_ids: List of CVE identifiers to exclude.

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(ExcludeIdsFilter(cve_ids=tuple(cve_ids)))
        return q

    def by_product(
        self,
        product: str,
        fuzzy: bool = True,
        exact: bool = False,
    ) -> CVEQuery:
        """Filter by product name.

        Args:
            product: Product name to search for.
            fuzzy: If True, use case-insensitive substring matching.
            exact: If True, use literal string matching (no regex).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            ProductFilter(
                product=product,
                fuzzy=fuzzy,
                exact=exact,
            )
        )
        return q

    def by_vendor(
        self,
        vendor: str,
        fuzzy: bool = True,
        exact: bool = False,
    ) -> CVEQuery:
        """Filter by vendor name.

        Args:
            vendor: Vendor name to search for.
            fuzzy: If True, use case-insensitive substring matching.
            exact: If True, use literal string matching (no regex).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            VendorFilter(
                vendor=vendor,
                fuzzy=fuzzy,
                exact=exact,
            )
        )
        return q

    def by_cwe(self, cwe_id: str) -> CVEQuery:
        """Filter by CWE identifier.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79" or "79").

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(CweFilter(cwe_id=cwe_id))
        return q

    def by_severity(self, severity: SeverityLevel) -> CVEQuery:
        """Filter by severity level.

        Args:
            severity: Severity level (none, low, medium, high, critical).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(SeverityFilter(severity=severity))
        return q

    def by_cvss(
        self,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
    ) -> CVEQuery:
        """Filter by CVSS score range.

        Args:
            min_score: Minimum CVSS score (inclusive).
            max_score: Maximum CVSS score (inclusive).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            CvssFilter(
                min_score=min_score,
                max_score=max_score,
            )
        )
        return q

    def by_date(
        self,
        after: Optional[str] = None,
        before: Optional[str] = None,
    ) -> CVEQuery:
        """Filter by publication date range.

        Args:
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(DateFilter(after=after, before=before))
        return q

    def by_year(self, *years: int) -> CVEQuery:
        """Filter by CVE year(s).

        Filters CVEs based on the year in their CVE ID (e.g., CVE-2024-xxxx).

        Args:
            *years: One or more years to include (e.g., 2023, 2024).

        Returns:
            New CVEQuery with the filter applied.

        Example:
            # Get CVEs from 2023 and 2024
            query.by_year(2023, 2024)
        """
        q = self._copy()
        q._filters.append(YearFilter(years=tuple(years)))
        return q

    def by_state(self, state: str) -> CVEQuery:
        """Filter by CVE state.

        Args:
            state: CVE state (e.g., "PUBLISHED", "REJECTED").

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(StateFilter(state=state))
        return q

    def by_cpe(
        self,
        cpe_string: str,
        check_version: Optional[str] = None,
    ) -> CVEQuery:
        """Filter by CPE (Common Platform Enumeration) string.

        Args:
            cpe_string: CPE string in 2.2 or 2.3 format.
            check_version: Optional version to check for affected range.

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            CpeFilter(
                cpe_string=cpe_string,
                check_version=check_version,
            )
        )
        return q

    def by_purl(
        self,
        purl: str,
        check_version: Optional[str] = None,
        fuzzy: bool = False,
    ) -> CVEQuery:
        """Filter by Package URL (PURL).

        Args:
            purl: Package URL string (e.g., "pkg:pypi/django").
            check_version: Optional version to check for affected range.
            fuzzy: If True, use substring matching.

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            PurlFilter(
                purl=purl,
                check_version=check_version,
                fuzzy=fuzzy,
            )
        )
        return q

    def by_version(self, version: str) -> CVEQuery:
        """Filter to only CVEs affecting a specific version.

        This filter checks version ranges in the CVE data to determine
        if the specified version is affected. For best results, chain
        with by_product() or by_vendor() to narrow down the scope.

        Args:
            version: Version string to check.

        Returns:
            New CVEQuery with the filter applied.

        Example:
            # Find CVEs affecting OpenSSL version 3.0.1
            query.by_product("openssl").by_version("3.0.1")
        """
        q = self._copy()
        q._filters.append(VersionFilter(version=version))
        return q

    def by_kev(self) -> CVEQuery:
        """Filter to only CVEs in CISA Known Exploited Vulnerabilities.

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(KevFilter())
        return q

    def recent(self, days: int = 30) -> CVEQuery:
        """Filter to recently published CVEs.

        Args:
            days: Number of days to look back.

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(RecentFilter(days=days))
        return q

    def semantic(
        self,
        query: str,
        top_k: int = 100,
        min_similarity: float = 0.3,
    ) -> CVEQuery:
        """Use semantic (natural language) search.

        This uses embeddings to find CVEs with semantically similar
        descriptions to the query.

        Args:
            query: Natural language search query.
            top_k: Maximum number of results.
            min_similarity: Minimum cosine similarity threshold (0-1).

        Returns:
            New CVEQuery with semantic search enabled.
        """
        q = self._copy()
        q._semantic_query = query
        q._semantic_top_k = top_k
        q._semantic_min_similarity = min_similarity
        return q

    def text_search(
        self,
        query: str,
        mode: SearchMode = SearchMode.FUZZY,
    ) -> CVEQuery:
        """Search by text in product/vendor fields.

        Args:
            query: Search query string.
            mode: Search mode (strict, regex, fuzzy).

        Returns:
            New CVEQuery with the filter applied.
        """
        q = self._copy()
        q._filters.append(
            TextSearchFilter(
                query=query,
                mode=mode,
            )
        )
        return q

    def by_description(
        self,
        query: str,
        mode: SearchMode = SearchMode.FUZZY,
        lang: str = "en",
    ) -> CVEQuery:
        """Search within CVE descriptions.

        Args:
            query: Search query string.
            mode: Search mode (strict, regex, fuzzy).
            lang: Language code to search in (default: "en").

        Returns:
            New CVEQuery with the filter applied.

        Example:
            # Find CVEs mentioning "buffer overflow"
            query.by_description("buffer overflow")
        """
        q = self._copy()
        q._filters.append(
            DescriptionFilter(
                query=query,
                mode=mode,
                lang=lang,
            )
        )
        return q

    def with_metrics(self, has_metrics: bool = True) -> CVEQuery:
        """Filter to CVEs that have (or don't have) CVSS metrics.

        Args:
            has_metrics: If True, include only CVEs with metrics.
                         If False, include only CVEs without metrics.

        Returns:
            New CVEQuery with the filter applied.

        Example:
            # Find CVEs without severity scores
            query.with_metrics(False)
        """
        q = self._copy()
        q._filters.append(HasMetricsFilter(has_metrics=has_metrics))
        return q

    def by_reference_tag(self, *tags: str, match_all: bool = False) -> CVEQuery:
        """Filter by reference tag.

        CVE references are tagged with types like "Exploit", "Patch",
        "Vendor Advisory", "Third Party Advisory", etc.

        Args:
            *tags: One or more tags to match (e.g., "Exploit", "Patch").
            match_all: If True, CVE must have all tags. If False, any tag matches.

        Returns:
            New CVEQuery with the filter applied.

        Example:
            # Find CVEs with known exploits
            query.by_reference_tag("Exploit")

            # Find CVEs with both exploit and patch available
            query.by_reference_tag("Exploit", "Patch", match_all=True)
        """
        q = self._copy()
        q._filters.append(ReferenceTagFilter(tags=tuple(tags), match_all=match_all))
        return q

    def sort_by(self, field: str, descending: bool = True) -> CVEQuery:
        """Sort results by the specified field.

        Args:
            field: Field to sort by. Valid values: date, severity, cvss
            descending: If True, sort in descending order.

        Returns:
            New CVEQuery with sorting applied.
        """
        q = self._copy()
        q._sort_field = field
        q._sort_descending = descending
        return q

    def limit(self, count: int) -> CVEQuery:
        """Limit the number of results.

        Args:
            count: Maximum number of results to return.

        Returns:
            New CVEQuery with limit applied.
        """
        q = self._copy()
        q._limit_count = count
        return q

    def execute(self) -> SearchResult:
        """Execute the query and return results.

        Returns:
            SearchResult containing matching CVEs.
        """
        return self._service._execute_query(self)


class CVESearchService:
    """Service for searching CVE data.

    Provides a fluent API for building and executing CVE queries.
    Use the `query()` method to start building a query.

    Example:
        service = CVESearchService()

        # Chain filters in any order
        results = (
            service.query()
            .by_product("linux")
            .by_severity(SeverityLevel.CRITICAL)
            .by_date(after="2024-01-01")
            .execute()
        )
    """

    def __init__(self, config: Optional[Config] = None):
        """Initialize the search service.

        Args:
            config: Configuration instance. Uses default if not provided.
        """
        self.config = config or get_config()
        self._cves_df: Optional[pl.DataFrame] = None
        self._descriptions_df: Optional[pl.DataFrame] = None
        self._metrics_df: Optional[pl.DataFrame] = None
        self._products_df: Optional[pl.DataFrame] = None
        self._versions_df: Optional[pl.DataFrame] = None
        self._cwes_df: Optional[pl.DataFrame] = None
        self._references_df: Optional[pl.DataFrame] = None
        self._credits_df: Optional[pl.DataFrame] = None

    def query(self) -> CVEQuery:
        """Start building a new query.

        Returns:
            A new CVEQuery builder instance.

        Example:
            results = service.query().by_product("apache").execute()
        """
        return CVEQuery(self)

    def _load_data(self) -> None:
        """Load data from Parquet files if not already loaded."""
        if self._cves_df is None:
            cves_path = self.config.cves_parquet
            if not cves_path.exists():
                raise FileNotFoundError(
                    f"CVE data not found at {cves_path}. "
                    "Run 'cvecli db update' or 'cvecli db build extract-parquet' first."
                )
            self._cves_df = pl.read_parquet(cves_path)

        if self._descriptions_df is None:
            desc_path = self.config.cve_descriptions_parquet
            if desc_path.exists():
                self._descriptions_df = pl.read_parquet(desc_path)

        if self._metrics_df is None:
            metrics_path = self.config.cve_metrics_parquet
            if metrics_path.exists():
                self._metrics_df = pl.read_parquet(metrics_path)

        if self._products_df is None:
            products_path = self.config.cve_products_parquet
            if products_path.exists():
                self._products_df = pl.read_parquet(products_path)

        if self._versions_df is None:
            versions_path = self.config.cve_versions_parquet
            if versions_path.exists():
                self._versions_df = pl.read_parquet(versions_path)

        if self._cwes_df is None:
            cwe_path = self.config.cve_cwes_parquet
            if cwe_path.exists():
                self._cwes_df = pl.read_parquet(cwe_path)

        if self._references_df is None:
            refs_path = self.config.cve_references_parquet
            if refs_path.exists():
                self._references_df = pl.read_parquet(refs_path)

        if self._credits_df is None:
            credits_path = self.config.cve_credits_parquet
            if credits_path.exists():
                self._credits_df = pl.read_parquet(credits_path)

    def _ensure_cves_loaded(self) -> pl.DataFrame:
        """Load data and return CVEs dataframe (guaranteed non-None)."""
        self._load_data()
        assert self._cves_df is not None
        return self._cves_df

    def _get_related_data(
        self, cve_ids: List[str]
    ) -> Dict[str, Optional[pl.DataFrame]]:
        """Get all related data for a set of CVE IDs."""
        result: Dict[str, Optional[pl.DataFrame]] = {
            "descriptions": None,
            "metrics": None,
            "products": None,
            "versions": None,
            "cwes": None,
            "references": None,
            "credits": None,
        }

        if not cve_ids:
            return result

        cve_id_set = set(cve_ids)

        if self._descriptions_df is not None:
            result["descriptions"] = self._descriptions_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._metrics_df is not None:
            result["metrics"] = self._metrics_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._products_df is not None:
            result["products"] = self._products_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._versions_df is not None:
            result["versions"] = self._versions_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._cwes_df is not None:
            result["cwes"] = self._cwes_df.filter(pl.col("cve_id").is_in(cve_id_set))

        if self._references_df is not None:
            result["references"] = self._references_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._credits_df is not None:
            result["credits"] = self._credits_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        return result

    def _execute_query(self, query: CVEQuery) -> SearchResult:
        """Execute a query and return results.

        This is the main query execution engine that applies all filters.
        """
        cves_df = self._ensure_cves_loaded()

        # Start with all CVEs
        result_cves = cves_df
        cve_ids: Optional[List[str]] = None

        # Handle semantic search specially - it determines the initial set
        if query._semantic_query:
            result = self._apply_semantic_search(
                query._semantic_query,
                query._semantic_top_k,
                query._semantic_min_similarity,
            )
            result_cves = result.cves
            cve_ids = result_cves.get_column("cve_id").to_list()

        # Apply each filter in order using type-safe pattern matching
        for f in query._filters:
            match f:
                case IdFilter(cve_id=cve_id):
                    result_cves, cve_ids = self._apply_id_filter(
                        result_cves, cve_id, cve_ids
                    )
                case ExcludeIdsFilter(cve_ids=exclude_ids):
                    result_cves, cve_ids = self._apply_exclude_ids_filter(
                        result_cves, exclude_ids, cve_ids
                    )
                case ProductFilter(product=product, fuzzy=fuzzy, exact=exact):
                    result_cves, cve_ids = self._apply_product_filter(
                        result_cves,
                        product,
                        fuzzy,
                        exact,
                        cve_ids,
                    )
                case VendorFilter(vendor=vendor, fuzzy=fuzzy, exact=exact):
                    result_cves, cve_ids = self._apply_vendor_filter(
                        result_cves,
                        vendor,
                        fuzzy,
                        exact,
                        cve_ids,
                    )
                case CweFilter(cwe_id=cwe_id):
                    result_cves, cve_ids = self._apply_cwe_filter(
                        result_cves, cwe_id, cve_ids
                    )
                case SeverityFilter(severity=severity):
                    result_cves, cve_ids = self._apply_severity_filter(
                        result_cves, severity, cve_ids
                    )
                case CvssFilter(min_score=min_score, max_score=max_score):
                    result_cves, cve_ids = self._apply_cvss_filter(
                        result_cves, min_score, max_score, cve_ids
                    )
                case DateFilter(after=after, before=before):
                    result_cves, cve_ids = self._apply_date_filter(
                        result_cves, after, before, cve_ids
                    )
                case YearFilter(years=years):
                    result_cves, cve_ids = self._apply_year_filter(
                        result_cves, years, cve_ids
                    )
                case StateFilter(state=state):
                    result_cves, cve_ids = self._apply_state_filter(
                        result_cves, state, cve_ids
                    )
                case CpeFilter(cpe_string=cpe_string, check_version=check_version):
                    result_cves, cve_ids = self._apply_cpe_filter(
                        result_cves,
                        cpe_string,
                        check_version,
                        cve_ids,
                    )
                case PurlFilter(purl=purl, check_version=check_version, fuzzy=fuzzy):
                    result_cves, cve_ids = self._apply_purl_filter(
                        result_cves,
                        purl,
                        check_version,
                        fuzzy,
                        cve_ids,
                    )
                case VersionFilter(version=version):
                    result_cves, cve_ids = self._apply_version_filter(
                        result_cves,
                        version,
                        cve_ids,
                    )
                case KevFilter():
                    result_cves, cve_ids = self._apply_kev_filter(result_cves, cve_ids)
                case RecentFilter(days=days):
                    result_cves, cve_ids = self._apply_recent_filter(
                        result_cves, days, cve_ids
                    )
                case TextSearchFilter(query=text_query, mode=mode):
                    result_cves, cve_ids = self._apply_text_search_filter(
                        result_cves,
                        text_query,
                        mode,
                        cve_ids,
                    )
                case DescriptionFilter(query=desc_query, mode=mode, lang=lang):
                    result_cves, cve_ids = self._apply_description_filter(
                        result_cves,
                        desc_query,
                        mode,
                        lang,
                        cve_ids,
                    )
                case HasMetricsFilter(has_metrics=has_metrics):
                    result_cves, cve_ids = self._apply_has_metrics_filter(
                        result_cves, has_metrics, cve_ids
                    )
                case ReferenceTagFilter(tags=tags, match_all=match_all):
                    result_cves, cve_ids = self._apply_reference_tag_filter(
                        result_cves, tags, match_all, cve_ids
                    )

        # Apply sorting
        if query._sort_field:
            result_cves = self._apply_sorting(
                result_cves, query._sort_field, query._sort_descending, cve_ids
            )
        else:
            # Default sort by date
            result_cves = result_cves.sort("date_published", descending=True)

        # Apply limit
        if query._limit_count:
            result_cves = result_cves.head(query._limit_count)

        # Get related data for final results
        final_cve_ids = result_cves.get_column("cve_id").to_list()
        related = self._get_related_data(final_cve_ids)

        return SearchResult(result_cves, **related)

    # =========================================================================
    # Filter implementations
    # =========================================================================

    def _apply_id_filter(
        self,
        cves: pl.DataFrame,
        cve_id: str,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CVE ID filter."""
        # Normalize ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        result = cves.filter(pl.col("cve_id") == cve_id)
        return result, result.get_column("cve_id").to_list()

    def _apply_exclude_ids_filter(
        self,
        cves: pl.DataFrame,
        cve_ids_to_exclude: tuple[str, ...],
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply exclude CVE IDs filter."""
        # Normalize IDs
        normalized_ids = set()
        for cve_id in cve_ids_to_exclude:
            cve_id = cve_id.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            normalized_ids.add(cve_id)

        result = cves.filter(~pl.col("cve_id").is_in(normalized_ids))
        return result, result.get_column("cve_id").to_list()

    def _apply_product_filter(
        self,
        cves: pl.DataFrame,
        product: str,
        fuzzy: bool,
        exact: bool,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply product filter."""
        if self._products_df is None:
            return pl.DataFrame(schema=cves.schema), []

        products_df = self._products_df
        if current_ids is not None:
            products_df = products_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        if fuzzy:
            if exact:
                search_product = product.lower()
            else:
                search_product = re.escape(product.lower())
            product_filter = (
                pl.col("product")
                .str.to_lowercase()
                .str.contains(search_product, literal=exact)
            )
        else:
            product_filter = pl.col("product") == product

        matching = products_df.filter(product_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_vendor_filter(
        self,
        cves: pl.DataFrame,
        vendor: str,
        fuzzy: bool,
        exact: bool,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply vendor filter."""
        if self._products_df is None:
            return pl.DataFrame(schema=cves.schema), []

        products_df = self._products_df
        if current_ids is not None:
            products_df = products_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        if fuzzy:
            if exact:
                search_vendor = vendor.lower()
            else:
                search_vendor = re.escape(vendor.lower())
            vendor_filter = (
                pl.col("vendor")
                .str.to_lowercase()
                .str.contains(search_vendor, literal=exact)
            )
        else:
            vendor_filter = pl.col("vendor") == vendor

        matching = products_df.filter(vendor_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_cwe_filter(
        self,
        cves: pl.DataFrame,
        cwe_id: str,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CWE filter."""
        if self._cwes_df is None:
            return pl.DataFrame(schema=cves.schema), []

        cwes_df = self._cwes_df
        if current_ids is not None:
            cwes_df = cwes_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        # Normalize CWE ID
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        matching = cwes_df.filter(pl.col("cwe_id") == cwe_id)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_severity_filter(
        self,
        cves: pl.DataFrame,
        severity: SeverityLevel,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply severity filter."""
        if self._metrics_df is None:
            return pl.DataFrame(schema=cves.schema), []

        metrics_df = self._metrics_df
        if current_ids is not None:
            metrics_df = metrics_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        min_score, max_score = SEVERITY_THRESHOLDS[severity]

        cvss_metrics = metrics_df.filter(
            pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cvss_metrics) == 0:
            return pl.DataFrame(schema=cves.schema), []

        # Get best metric per CVE using preference scoring
        best_metrics = self._get_best_metrics_per_cve(cvss_metrics)

        matching = best_metrics.filter(
            (pl.col("base_score") >= min_score) & (pl.col("base_score") <= max_score)
        )
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_cvss_filter(
        self,
        cves: pl.DataFrame,
        min_score: Optional[float],
        max_score: Optional[float],
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CVSS score range filter."""
        if min_score is None and max_score is None:
            return cves, cves.get_column("cve_id").to_list()

        if self._metrics_df is None:
            return pl.DataFrame(schema=cves.schema), []

        metrics_df = self._metrics_df
        if current_ids is not None:
            metrics_df = metrics_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        cvss_metrics = metrics_df.filter(
            pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cvss_metrics) == 0:
            return pl.DataFrame(schema=cves.schema), []

        best_metrics = self._get_best_metrics_per_cve(cvss_metrics)

        score_filter = pl.lit(True)
        if min_score is not None:
            score_filter = score_filter & (pl.col("base_score") >= min_score)
        if max_score is not None:
            score_filter = score_filter & (pl.col("base_score") <= max_score)

        matching = best_metrics.filter(score_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_date_filter(
        self,
        cves: pl.DataFrame,
        after: Optional[str],
        before: Optional[str],
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply date range filter."""
        if after:
            if not self._validate_date(after):
                raise ValueError(f"Invalid date format: {after}. Expected YYYY-MM-DD.")
        if before:
            if not self._validate_date(before):
                raise ValueError(f"Invalid date format: {before}. Expected YYYY-MM-DD.")

        result = cves
        if after:
            result = result.filter(pl.col("date_published") >= after)
        if before:
            result = result.filter(pl.col("date_published") <= before)

        return result, result.get_column("cve_id").to_list()

    def _apply_state_filter(
        self,
        cves: pl.DataFrame,
        state: str,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CVE state filter."""
        result = cves.filter(pl.col("state").str.to_uppercase() == state.upper())
        return result, result.get_column("cve_id").to_list()

    def _apply_cpe_filter(
        self,
        cves: pl.DataFrame,
        cpe_string: str,
        check_version: Optional[str],
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CPE filter."""
        if self._products_df is None:
            return pl.DataFrame(schema=cves.schema), []

        # Parse the CPE
        cpe = parse_cpe(cpe_string)
        if not cpe:
            raise ValueError(
                f"Invalid CPE string: {cpe_string}. "
                "Expected format: cpe:2.3:<part>:<vendor>:<product>:... "
                "or cpe:/<part>:<vendor>:<product>..."
            )

        # Extract version from CPE if not explicitly provided
        if check_version is None and cpe.version and cpe.version not in ("*", "-"):
            check_version = cpe.version

        vendor, product = cpe.to_search_terms()

        if not vendor and not product:
            raise ValueError(
                f"CPE string must contain at least vendor or product: {cpe_string}"
            )

        products_df = self._products_df
        if current_ids is not None:
            products_df = products_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        # Build filter - prefer exact CPE match, fallback to vendor/product
        cpe_exact_filter = (
            pl.col("cpes")
            .fill_null("")
            .str.to_lowercase()
            .str.contains(cpe_string.lower(), literal=True)
        )

        vendor_product_filter = pl.lit(False)
        if vendor and product:
            vendor_lower = vendor.lower()
            product_lower = product.lower()
            vendor_match = (
                pl.col("vendor").fill_null("").str.to_lowercase() == vendor_lower
            ) | (
                pl.col("cpes")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(f":{vendor_lower}:", literal=True)
            )
            product_match = (
                pl.col("product").fill_null("").str.to_lowercase() == product_lower
            ) | (
                pl.col("cpes")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(f":{product_lower}:", literal=True)
            )
            vendor_product_filter = vendor_match & product_match
        elif vendor:
            vendor_lower = vendor.lower()
            vendor_product_filter = (
                pl.col("vendor").fill_null("").str.to_lowercase() == vendor_lower
            ) | (
                pl.col("cpes")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(f":{vendor_lower}:", literal=True)
            )
        elif product:
            product_lower = product.lower()
            vendor_product_filter = (
                pl.col("product").fill_null("").str.to_lowercase() == product_lower
            ) | (
                pl.col("cpes")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(f":{product_lower}:", literal=True)
            )

        combined_filter = cpe_exact_filter | vendor_product_filter
        matching = products_df.filter(combined_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))

        # Apply version filter if specified
        if check_version and len(result) > 0:
            related = self._get_related_data(matching_ids)
            search_result = SearchResult(result, **related)
            search_result = self._filter_by_version_impl(
                search_result, check_version, vendor, product
            )
            return search_result.cves, search_result.cves.get_column("cve_id").to_list()

        return result, matching_ids

    def _apply_purl_filter(
        self,
        cves: pl.DataFrame,
        purl: str,
        check_version: Optional[str],
        fuzzy: bool,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply Package URL filter."""
        if self._products_df is None:
            return pl.DataFrame(schema=cves.schema), []

        purl = purl.strip()
        if not purl:
            raise ValueError("PURL string cannot be empty.")

        if not purl.lower().startswith("pkg:") and not fuzzy:
            raise ValueError(
                f"Invalid PURL format: {purl}. "
                "Expected format: pkg:<type>/<namespace>/<name> "
                "(e.g., pkg:npm/lodash, pkg:pypi/django)"
            )

        products_df = self._products_df
        if current_ids is not None:
            products_df = products_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        if fuzzy:
            purl_lower = purl.lower()
            purl_filter = (
                pl.col("package_url")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(purl_lower, literal=True)
            )
        else:
            purl_lower = purl.lower()
            purl_filter = (
                pl.col("package_url").fill_null("").str.to_lowercase() == purl_lower
            ) | (
                pl.col("package_url")
                .fill_null("")
                .str.to_lowercase()
                .str.starts_with(purl_lower)
            )

        matching = products_df.filter(purl_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))

        # Apply version filter if specified
        if check_version and len(result) > 0:
            related = self._get_related_data(matching_ids)
            search_result = SearchResult(result, **related)
            search_result = self._filter_by_version_impl(search_result, check_version)
            return search_result.cves, search_result.cves.get_column("cve_id").to_list()

        return result, matching_ids

    def _apply_version_filter(
        self,
        cves: pl.DataFrame,
        version: str,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply version filter."""
        if current_ids is None:
            current_ids = cves.get_column("cve_id").to_list()

        related = self._get_related_data(current_ids)
        search_result = SearchResult(cves, **related)
        filtered = self._filter_by_version_impl(search_result, version)

        return filtered.cves, filtered.cves.get_column("cve_id").to_list()

    def _apply_kev_filter(
        self,
        cves: pl.DataFrame,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply CISA KEV filter."""
        if self._metrics_df is None:
            return pl.DataFrame(schema=cves.schema), []

        metrics_df = self._metrics_df
        if current_ids is not None:
            metrics_df = metrics_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        kev_cves = (
            metrics_df.filter(pl.col("other_type") == "kev")
            .get_column("cve_id")
            .unique()
            .to_list()
        )

        result = cves.filter(pl.col("cve_id").is_in(kev_cves))
        return result, result.get_column("cve_id").to_list()

    def _apply_recent_filter(
        self,
        cves: pl.DataFrame,
        days: int,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply recent days filter."""
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        result = cves.filter(pl.col("date_published") >= cutoff)
        return result, result.get_column("cve_id").to_list()

    def _apply_text_search_filter(
        self,
        cves: pl.DataFrame,
        query: str,
        mode: SearchMode,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply text search filter on products."""
        if self._products_df is None:
            return pl.DataFrame(schema=cves.schema), []

        products_df = self._products_df
        if current_ids is not None:
            products_df = products_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        # Build filter based on mode
        if mode == SearchMode.STRICT:
            query_lower = query.lower()
            product_filter = pl.col("product").str.to_lowercase() == query_lower
        elif mode == SearchMode.REGEX:
            try:
                re.compile(query, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
            product_filter = (
                pl.col("product")
                .str.to_lowercase()
                .str.contains(query.lower(), literal=False)
            )
        else:  # FUZZY
            query_escaped = re.escape(query.lower())
            product_filter = (
                pl.col("product")
                .str.to_lowercase()
                .str.contains(query_escaped, literal=False)
            )

        matching = products_df.filter(product_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        # If no product matches, try vendor match
        if not matching_ids:
            if mode == SearchMode.STRICT:
                vendor_filter = pl.col("vendor").str.to_lowercase() == query.lower()
            elif mode == SearchMode.REGEX:
                vendor_filter = (
                    pl.col("vendor")
                    .str.to_lowercase()
                    .str.contains(query.lower(), literal=False)
                )
            else:
                query_escaped = re.escape(query.lower())
                vendor_filter = (
                    pl.col("vendor")
                    .str.to_lowercase()
                    .str.contains(query_escaped, literal=False)
                )
            matching = products_df.filter(vendor_filter)
            matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_year_filter(
        self,
        cves: pl.DataFrame,
        years: tuple[int, ...],
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply year filter based on CVE ID."""
        year_strs = {str(y) for y in years}

        # Extract year from CVE ID (format: CVE-YYYY-NNNNN)
        result = cves.filter(
            pl.col("cve_id").str.extract(r"CVE-(\d{4})-", 1).is_in(year_strs)
        )
        return result, result.get_column("cve_id").to_list()

    def _apply_description_filter(
        self,
        cves: pl.DataFrame,
        query: str,
        mode: SearchMode,
        lang: str,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply description search filter."""
        if self._descriptions_df is None:
            return pl.DataFrame(schema=cves.schema), []

        descriptions_df = self._descriptions_df
        if current_ids is not None:
            descriptions_df = descriptions_df.filter(
                pl.col("cve_id").is_in(set(current_ids))
            )

        # Filter by language
        descriptions_df = descriptions_df.filter(pl.col("lang") == lang)

        # Build filter based on mode
        if mode == SearchMode.STRICT:
            query_lower = query.lower()
            desc_filter = (
                pl.col("value")
                .str.to_lowercase()
                .str.contains(query_lower, literal=True)
            )
        elif mode == SearchMode.REGEX:
            try:
                re.compile(query, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
            desc_filter = (
                pl.col("value")
                .str.to_lowercase()
                .str.contains(query.lower(), literal=False)
            )
        else:  # FUZZY
            query_escaped = re.escape(query.lower())
            desc_filter = (
                pl.col("value")
                .str.to_lowercase()
                .str.contains(query_escaped, literal=False)
            )

        matching = descriptions_df.filter(desc_filter)
        matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_has_metrics_filter(
        self,
        cves: pl.DataFrame,
        has_metrics: bool,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply has metrics filter."""
        if self._metrics_df is None:
            if has_metrics:
                return pl.DataFrame(schema=cves.schema), []
            else:
                return cves, cves.get_column("cve_id").to_list()

        metrics_df = self._metrics_df
        if current_ids is not None:
            metrics_df = metrics_df.filter(pl.col("cve_id").is_in(set(current_ids)))

        # Get CVEs with CVSS metrics
        cves_with_metrics = (
            metrics_df.filter(
                pl.col("metric_type").str.starts_with("cvss")
                & pl.col("base_score").is_not_null()
            )
            .get_column("cve_id")
            .unique()
            .to_list()
        )
        cves_with_metrics_set = set(cves_with_metrics)

        if has_metrics:
            result = cves.filter(pl.col("cve_id").is_in(cves_with_metrics_set))
        else:
            result = cves.filter(~pl.col("cve_id").is_in(cves_with_metrics_set))

        return result, result.get_column("cve_id").to_list()

    def _apply_reference_tag_filter(
        self,
        cves: pl.DataFrame,
        tags: tuple[str, ...],
        match_all: bool,
        current_ids: Optional[List[str]],
    ) -> tuple[pl.DataFrame, List[str]]:
        """Apply reference tag filter."""
        if self._references_df is None:
            return pl.DataFrame(schema=cves.schema), []

        references_df = self._references_df
        if current_ids is not None:
            references_df = references_df.filter(
                pl.col("cve_id").is_in(set(current_ids))
            )

        # Normalize tags for case-insensitive matching
        tags_lower = {t.lower() for t in tags}

        if match_all:
            # CVE must have all specified tags
            matching_ids: List[str] = []
            for cve_id in references_df.get_column("cve_id").unique().to_list():
                cve_refs = references_df.filter(pl.col("cve_id") == cve_id)
                # Get all tags for this CVE (tags column contains comma-separated values)
                cve_tags_raw = cve_refs.get_column("tags").to_list()
                cve_tags: set[str] = set()
                for tags_str in cve_tags_raw:
                    if tags_str:
                        cve_tags.update(t.strip().lower() for t in tags_str.split(","))

                if tags_lower.issubset(cve_tags):
                    matching_ids.append(cve_id)
        else:
            # CVE must have any of the specified tags
            tag_pattern = "|".join(re.escape(t) for t in tags_lower)
            matching = references_df.filter(
                pl.col("tags")
                .fill_null("")
                .str.to_lowercase()
                .str.contains(tag_pattern, literal=False)
            )
            matching_ids = matching.get_column("cve_id").unique().to_list()

        result = cves.filter(pl.col("cve_id").is_in(matching_ids))
        return result, matching_ids

    def _apply_semantic_search(
        self,
        query: str,
        top_k: int,
        min_similarity: float,
    ) -> SearchResult:
        """Apply semantic search."""
        from cvecli.services.embeddings import EmbeddingsService, is_semantic_available

        if not is_semantic_available():
            from cvecli.services.embeddings import SemanticDependencyError

            raise SemanticDependencyError("semantic search")

        cves_df = self._ensure_cves_loaded()

        embeddings_service = EmbeddingsService(config=self.config, quiet=True)
        similarity_results = embeddings_service.search(
            query, top_k=top_k, min_similarity=min_similarity
        )

        if len(similarity_results) == 0:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        cve_ids = similarity_results.get_column("cve_id").to_list()
        similarity_scores = dict(
            zip(
                similarity_results.get_column("cve_id").to_list(),
                similarity_results.get_column("similarity_score").to_list(),
            )
        )

        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))
        result = result.with_columns(
            pl.col("cve_id")
            .replace_strict(similarity_scores, default=0.0)
            .alias("similarity_score")
        )
        result = result.sort("similarity_score", descending=True)

        related = self._get_related_data(cve_ids)
        return SearchResult(result, **related)

    def _apply_sorting(
        self,
        cves: pl.DataFrame,
        field: str,
        descending: bool,
        current_ids: Optional[List[str]],
    ) -> pl.DataFrame:
        """Apply sorting to results."""
        field = field.lower()
        valid_fields = ["date", "severity", "cvss"]

        if field not in valid_fields:
            raise ValueError(
                f"Invalid sort field: {field}. Must be one of: {', '.join(valid_fields)}"
            )

        if field == "date":
            return cves.sort("date_published", descending=descending)

        if field in ("severity", "cvss"):
            if self._metrics_df is None:
                return cves

            cve_ids = set(cves.get_column("cve_id").to_list())
            cvss_metrics = self._metrics_df.filter(
                pl.col("cve_id").is_in(cve_ids)
                & pl.col("metric_type").str.starts_with("cvss")
                & pl.col("base_score").is_not_null()
            )

            if len(cvss_metrics) == 0:
                return cves

            best_metrics = self._get_best_metrics_per_cve(cvss_metrics)
            best_metrics = best_metrics.select(["cve_id", "base_score"])

            return (
                cves.join(best_metrics, on="cve_id", how="left")
                .sort("base_score", descending=descending, nulls_last=True)
                .drop("base_score")
            )

        return cves

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_best_metrics_per_cve(self, cvss_metrics: pl.DataFrame) -> pl.DataFrame:
        """Get best metric per CVE using preference scoring."""
        scored = cvss_metrics.with_columns(
            [
                pl.when(pl.col("source") == "cna")
                .then(100)
                .otherwise(0)
                .alias("source_pref"),
                pl.when(pl.col("metric_type") == "cvssV4_0")
                .then(40)
                .when(pl.col("metric_type") == "cvssV3_1")
                .then(30)
                .when(pl.col("metric_type") == "cvssV3_0")
                .then(20)
                .otherwise(10)
                .alias("version_pref"),
            ]
        ).with_columns(
            [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
        )

        return (
            scored.sort(["cve_id", "preference"], descending=[False, True])
            .group_by("cve_id")
            .first()
        )

    def _filter_by_version_impl(
        self,
        result: SearchResult,
        version: str,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
    ) -> SearchResult:
        """Internal implementation for version filtering."""
        if result.count == 0:
            return result

        if result.versions is None or len(result.versions) == 0:
            return result

        if result.products is None or len(result.products) == 0:
            return result

        cve_ids_in_result = set(result.cves.get_column("cve_id").to_list())
        affected_cve_ids: List[str] = []

        products_df = result.products.filter(pl.col("cve_id").is_in(cve_ids_in_result))
        versions_df = result.versions.filter(pl.col("cve_id").is_in(cve_ids_in_result))

        if vendor:
            vendor_lower = vendor.lower()
            products_df = products_df.filter(
                pl.col("vendor")
                .str.to_lowercase()
                .str.contains(vendor_lower, literal=True)
            )
        if product:
            product_lower = product.lower()
            products_df = products_df.filter(
                pl.col("product")
                .str.to_lowercase()
                .str.contains(product_lower, literal=True)
            )

        product_cve_map: Dict[str, str] = {}
        for row in products_df.iter_rows(named=True):
            product_id = row.get("product_id")
            cve_id = row.get("cve_id")
            if product_id and cve_id:
                product_cve_map[str(product_id)] = cve_id

        for row in versions_df.iter_rows(named=True):
            product_id = str(row.get("product_id", ""))
            cve_id = row.get("cve_id")

            if product_id not in product_cve_map:
                continue

            version_start = row.get("version")
            less_than = row.get("less_than")
            less_than_or_equal = row.get("less_than_or_equal")
            status = row.get("status")

            if version_start and " - " in str(version_start):
                parts = str(version_start).split(" - ")
                if len(parts) == 2:
                    version_start = parts[0].strip()
                    if not less_than and not less_than_or_equal:
                        less_than_or_equal = parts[1].strip()

            is_affected = is_version_affected(
                check_version=version,
                version_start=version_start,
                less_than=less_than,
                less_than_or_equal=less_than_or_equal,
                status=status,
            )

            if is_affected and cve_id and cve_id not in affected_cve_ids:
                affected_cve_ids.append(cve_id)

        cves_with_version_info = set(
            versions_df.get_column("cve_id").unique().to_list()
        )
        for cve_id in cve_ids_in_result:
            if cve_id not in cves_with_version_info and cve_id not in affected_cve_ids:
                affected_cve_ids.append(cve_id)

        filtered_cves = result.cves.filter(pl.col("cve_id").is_in(affected_cve_ids))
        related = self._get_related_data(affected_cve_ids)

        return SearchResult(filtered_cves, **related)

    @staticmethod
    def _validate_date(date_str: str) -> bool:
        """Validate a date string is in YYYY-MM-DD format."""
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False

    # =========================================================================
    # Utility methods
    # =========================================================================

    def has_embeddings(self) -> bool:
        """Check if semantic search embeddings are available.

        Returns:
            True if embeddings file exists, False otherwise.
        """
        return self.config.cve_embeddings_parquet.exists()

    def stats(self) -> dict:
        """Get overall statistics about the CVE database.

        Returns:
            Dictionary with statistics.
        """
        cves_df = self._ensure_cves_loaded()

        total_cves = len(cves_df)

        # Count by state
        state_counts = cves_df.group_by("state").len().to_dicts()

        # Count by year
        year_counts: dict[str, int] = {}
        for row in cves_df.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    year_counts[year] = year_counts.get(year, 0) + 1

        # Product/vendor stats
        product_count = len(self._products_df) if self._products_df is not None else 0
        unique_products = 0
        unique_vendors = 0
        if self._products_df is not None:
            unique_products = self._products_df.select("product").n_unique()
            unique_vendors = self._products_df.select("vendor").n_unique()

        # Metrics stats
        metrics_count = len(self._metrics_df) if self._metrics_df is not None else 0
        cves_with_cvss = 0
        if self._metrics_df is not None:
            cvss_metrics = self._metrics_df.filter(
                pl.col("metric_type").str.starts_with("cvss")
            )
            cves_with_cvss = cvss_metrics.select("cve_id").n_unique()

        # CWE stats
        cwe_count = len(self._cwes_df) if self._cwes_df is not None else 0
        unique_cwes = 0
        if self._cwes_df is not None:
            unique_cwes = (
                self._cwes_df.filter(pl.col("cwe_id").is_not_null())
                .select("cwe_id")
                .n_unique()
            )

        # Reference stats
        reference_count = (
            len(self._references_df) if self._references_df is not None else 0
        )

        return {
            "total_cves": total_cves,
            "states": {d["state"]: d["len"] for d in state_counts},
            "by_year": dict(sorted(year_counts.items())),
            "total_product_entries": product_count,
            "unique_products": unique_products,
            "unique_vendors": unique_vendors,
            "total_metrics": metrics_count,
            "cves_with_cvss": cves_with_cvss,
            "total_cwe_mappings": cwe_count,
            "unique_cwes": unique_cwes,
            "total_references": reference_count,
        }

    def get_best_metric(self, cve_id: str) -> Optional[dict]:
        """Get the best (most preferred) metric for a CVE.

        Preference order:
        1. CNA metrics over ADP metrics
        2. Newer CVSS versions over older (v4 > v3.1 > v3 > v2)
        3. Falls back to text severity metrics if no CVSS found

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with metric data, or None if no metrics found.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        cve_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id)
            & pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cve_metrics) > 0:
            best = self._get_best_metrics_per_cve(cve_metrics)
            if len(best) > 0:
                return best.to_dicts()[0]

        # Fall back to text severity metrics
        text_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id)
            & (pl.col("metric_type") == "other")
            & pl.col("base_severity").is_not_null()
        )

        if len(text_metrics) > 0:
            cna_text = text_metrics.filter(pl.col("source") == "cna")
            if len(cna_text) > 0:
                return cna_text.head(1).to_dicts()[0]
            return text_metrics.head(1).to_dicts()[0]

        return None

    def get_description(self, cve_id: str, lang: str = "en") -> Optional[str]:
        """Get the description for a CVE in a specific language.

        Args:
            cve_id: CVE identifier.
            lang: Language code (default: "en").

        Returns:
            Description string, or None if not found.
        """
        self._load_data()

        if self._descriptions_df is None:
            return None

        # Prefer CNA descriptions over ADP
        desc = self._descriptions_df.filter(
            (pl.col("cve_id") == cve_id)
            & (pl.col("lang") == lang)
            & (pl.col("source") == "cna")
        )

        if len(desc) == 0:
            desc = self._descriptions_df.filter(
                (pl.col("cve_id") == cve_id) & (pl.col("lang") == lang)
            )

        if len(desc) == 0:
            desc = self._descriptions_df.filter(pl.col("cve_id") == cve_id)

        if len(desc) == 0:
            return None

        result: str = desc.head(1).get_column("value").to_list()[0]
        return result

    def get_kev_info(self, cve_id: str) -> Optional[dict]:
        """Get CISA Known Exploited Vulnerability (KEV) info for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with KEV data, or None if not in KEV.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        kev_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id) & (pl.col("other_type") == "kev")
        )

        if len(kev_metrics) == 0:
            return None

        kev_row = kev_metrics.head(1).to_dicts()[0]
        other_content = kev_row.get("other_content")

        if other_content:
            try:
                result: dict[str, Any] = json_module.loads(other_content)
                return result
            except (json_module.JSONDecodeError, TypeError):
                return {"raw": other_content}
        return None

    def get_ssvc_info(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Get CISA SSVC info for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with SSVC data, or None if not available.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        ssvc_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id) & (pl.col("other_type") == "ssvc")
        )

        if len(ssvc_metrics) == 0:
            return None

        ssvc_row = ssvc_metrics.head(1).to_dicts()[0]
        other_content = ssvc_row.get("other_content")

        if other_content:
            try:
                result: dict[str, Any] = json_module.loads(other_content)
                return result
            except (json_module.JSONDecodeError, TypeError):
                return {"raw": other_content}
        return None

    def search_products(
        self,
        query: str,
        mode: SearchMode = SearchMode.FUZZY,
        vendor: Optional[str] = None,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Search the products database to find product/vendor names.

        This is useful for discovering the exact syntax of products
        in the CPE database to refine CVE searches.

        Args:
            query: Search query for product or vendor name.
            mode: Search mode (strict, regex, fuzzy).
            vendor: Optional vendor filter.
            limit: Maximum number of results.

        Returns:
            DataFrame with vendor, product, and CVE count.
        """
        self._load_data()

        if self._products_df is None:
            return pl.DataFrame(
                {
                    "vendor": [],
                    "product": [],
                    "cve_count": [],
                    "package_name": [],
                }
            )

        if mode == SearchMode.STRICT:
            query_lower = query.lower()
            product_filter = (pl.col("product").str.to_lowercase() == query_lower) | (
                pl.col("vendor").str.to_lowercase() == query_lower
            )
        elif mode == SearchMode.REGEX:
            product_filter = pl.col("product").str.to_lowercase().str.contains(
                query.lower(), literal=False
            ) | pl.col("vendor").str.to_lowercase().str.contains(
                query.lower(), literal=False
            )
        else:  # FUZZY
            query_escaped = re.escape(query.lower())
            product_filter = pl.col("product").str.to_lowercase().str.contains(
                query_escaped, literal=False
            ) | pl.col("vendor").str.to_lowercase().str.contains(
                query_escaped, literal=False
            )

        if vendor:
            if mode == SearchMode.STRICT:
                vendor_filter = pl.col("vendor").str.to_lowercase() == vendor.lower()
            elif mode == SearchMode.REGEX:
                vendor_filter = (
                    pl.col("vendor")
                    .str.to_lowercase()
                    .str.contains(vendor.lower(), literal=False)
                )
            else:
                vendor_escaped = re.escape(vendor.lower())
                vendor_filter = (
                    pl.col("vendor")
                    .str.to_lowercase()
                    .str.contains(vendor_escaped, literal=False)
                )
            product_filter = product_filter & vendor_filter

        matching = self._products_df.filter(product_filter)

        result = (
            matching.group_by(["vendor", "product"])
            .agg(
                [
                    pl.col("cve_id").n_unique().alias("cve_count"),
                    pl.col("package_name").first().alias("package_name"),
                ]
            )
            .sort("cve_count", descending=True)
            .head(limit)
        )

        return result

    def get_descriptions_for_result(
        self, result: SearchResult, lang: str = "en"
    ) -> Dict[str, str]:
        """Get descriptions for all CVEs in a search result.

        Args:
            result: SearchResult to get descriptions for.
            lang: Language code (default: "en").

        Returns:
            Dictionary mapping CVE ID to description.
        """
        descriptions: Dict[str, str] = {}

        for row in result.cves.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            desc = self.get_description(cve_id, lang)
            if desc:
                descriptions[cve_id] = desc

        return descriptions

    @staticmethod
    def validate_date(date_str: str) -> bool:
        """Validate a date string is in YYYY-MM-DD format.

        Args:
            date_str: Date string to validate.

        Returns:
            True if valid, False otherwise.
        """
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False
