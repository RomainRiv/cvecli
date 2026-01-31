"""Markdown output formatters for cvecli.

This module provides Markdown formatting for CVE search results and details.
"""

from typing import Optional, TYPE_CHECKING

from rich.console import Console

from cvecli.cli.formatters.base import get_severity_info

if TYPE_CHECKING:
    from cvecli.services.search import CVESearchService, SearchResult

console = Console()


def output_search_results_markdown(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    include_description: bool = True,
) -> None:
    """Output search results as Markdown.

    Args:
        result: Search results to output.
        verbose: Include summary statistics.
        limit: Maximum results (ignored with output_file).
        search_service: Service for additional info.
        output_file: Path to write output.
        include_description: Include CVE descriptions.
    """
    df = result.cves
    total_count = len(df)

    truncated = False if output_file else len(df) > limit
    if truncated:
        df = df.head(limit)

    lines = []
    lines.append("# CVE Search Results\n")
    lines.append(
        f"Found **{total_count}** CVEs"
        + (f" (showing first {limit})" if truncated else "")
        + "\n"
    )

    if verbose:
        summary = result.summary()
        lines.append("## Summary\n")
        lines.append(f"- Severity: {summary.get('severity_distribution', {})}")
        lines.append(f"- Years: {summary.get('year_distribution', {})}")
        lines.append("")

    lines.append("## Results\n")

    for row in df.iter_rows(named=True):
        cve_id = row.get("cve_id", "")
        state = row.get("state", "")
        title = row.get("cna_title") or "(No title)"
        severity, version, _ = get_severity_info(row, search_service)

        # Check for similarity score in row
        similarity = row.get("similarity_score")
        match_info = f" (match: {similarity:.2f})" if similarity else ""

        lines.append(f"### {cve_id}{match_info}\n")
        lines.append(f"**State:** {state} | **Severity:** {severity} ({version})\n")
        lines.append(f"**Title:** {title}\n")

        if include_description and search_service:
            description = search_service.get_description(cve_id)
            if description:
                # Truncate for markdown if very long
                if len(description) > 500:
                    description = description[:500] + "..."
                lines.append(f"\n{description}\n")

        lines.append("")

    markdown_output = "\n".join(lines)

    if output_file:
        from pathlib import Path

        Path(output_file).write_text(markdown_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(markdown_output)


def output_cve_detail_markdown(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    unique_refs: list[dict],
    output_file: Optional[str],
) -> None:
    """Output CVE detail as Markdown."""
    lines = []
    lines.append(f"# {row.get('cve_id')}\n")
    lines.append(f"**State:** {row.get('state')}\n")

    if row.get("cna_title"):
        lines.append(f"**Title:** {row.get('cna_title')}\n")
    lines.append(f"**Published:** {row.get('date_published')}\n")

    if best_metric:
        score = best_metric.get("base_score")
        metric_type = best_metric.get("metric_type", "")
        if score:
            lines.append(f"**CVSS Score:** {score} ({metric_type})\n")

    if kev_info:
        date_added = kev_info.get("dateAdded", "Unknown")
        lines.append(
            f"**⚠️ Known Exploited Vulnerability:** Added to KEV on {date_added}\n"
        )

    if description:
        lines.append(f"## Description\n\n{description}\n")

    if result.products is not None and len(result.products) > 0:
        lines.append("## Affected Products\n")
        for prod in result.products.iter_rows(named=True):
            vendor = prod.get("vendor", "")
            product = prod.get("product", "")
            lines.append(f"- {vendor}: {product}")

    if result.cwes is not None and len(result.cwes) > 0:
        lines.append("\n## CWEs\n")
        for cwe in result.cwes.iter_rows(named=True):
            cwe_id = cwe.get("cwe_id")
            cwe_desc = cwe.get("description", "")
            if cwe_id:
                lines.append(f"- {cwe_id}: {cwe_desc}")
            elif cwe_desc:
                lines.append(f"- (No CWE ID): {cwe_desc}")

    if unique_refs:
        lines.append("\n## References\n")
        for ref in unique_refs:
            url = ref.get("url", "")
            tags = ref.get("tags", "")
            if tags:
                clean_tags = ",".join(
                    t for t in tags.split(",") if "x_transferred" not in t
                )
                if clean_tags:
                    lines.append(f"- {url} ({clean_tags})")
                else:
                    lines.append(f"- {url}")
            else:
                lines.append(f"- {url}")

    markdown_output = "\n".join(lines)

    if output_file:
        from pathlib import Path

        Path(output_file).write_text(markdown_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(markdown_output)
