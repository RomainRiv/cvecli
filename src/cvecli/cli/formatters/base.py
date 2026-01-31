"""Base utilities for formatters.

This module provides common utilities used by all formatters.
"""

from typing import Optional, TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from cvecli.services.search import CVESearchService

console = Console()


class OutputFormat:
    """Output format constants."""

    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"

    ALL = [JSON, TABLE, MARKDOWN]


def get_severity_color(score: Optional[float]) -> str:
    """Get the Rich color for a severity score.

    Args:
        score: CVSS score (0-10).

    Returns:
        Color name for Rich formatting.
    """
    if score is None:
        return "dim"
    if score >= 9.0:
        return "red bold"
    if score >= 7.0:
        return "red"
    if score >= 4.0:
        return "yellow"
    return "green"


def get_severity_info(
    row: dict, search_service: Optional["CVESearchService"] = None
) -> tuple[str, str, Optional[float]]:
    """Get severity score, version, and numeric score from a CVE row.

    Returns a tuple of (score_str, version_str, numeric_score).
    - score_str: "8.1" or "High" or "-"
    - version_str: "v3.1", "v4.0*", "text", or "-"
    - numeric_score: Float score or None

    ADP scores are marked with * (e.g., "v3.1*").
    """
    cve_id = row.get("cve_id", "")

    if search_service:
        metric = search_service.get_best_metric(cve_id)
        if metric:
            score = metric.get("base_score")
            metric_type = metric.get("metric_type", "")
            source = metric.get("source", "cna")
            base_severity = metric.get("base_severity")

            # Build version string
            version = "v?"
            if "V4" in metric_type.upper():
                version = "v4.0"
            elif "V3_1" in metric_type.upper():
                version = "v3.1"
            elif "V3_0" in metric_type.upper():
                version = "v3.0"
            elif "V2" in metric_type.upper():
                version = "v2.0"
            elif metric_type == "other" or not metric_type.startswith("cvss"):
                version = "text"

            # Mark ADP scores with *
            if source.startswith("adp:"):
                version = f"{version}*"

            if score is not None:
                return f"{score:.1f}", version, float(score)
            elif base_severity:
                # Text severity only (no numeric score)
                return str(base_severity), "text", None

    return "-", "-", None


def truncate_text(text: str, max_length: int = 80) -> str:
    """Truncate text with ellipsis if needed.

    Args:
        text: Text to truncate.
        max_length: Maximum length including ellipsis.

    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_similarity_score(score: Optional[float]) -> str:
    """Format a similarity score for display.

    Args:
        score: Similarity score (0-1).

    Returns:
        Formatted score string.
    """
    if score is None:
        return "-"
    return f"{score:.2f}"


def build_cve_record(
    row: dict,
    search_service: Optional["CVESearchService"] = None,
    include_description: bool = False,
) -> dict:
    """Build a CVE record dictionary for JSON output.

    Args:
        row: Raw row from DataFrame.
        search_service: Service for getting additional info.
        include_description: Whether to include description.

    Returns:
        Enhanced record dictionary.
    """
    record = dict(row)

    if search_service:
        severity, version, _ = get_severity_info(row, search_service)
        record["severity"] = severity
        record["cvss_version"] = version

        if include_description:
            cve_id = row.get("cve_id", "")
            description = search_service.get_description(cve_id)
            if description:
                record["description"] = description

    return record
