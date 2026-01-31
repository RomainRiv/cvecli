"""Output dispatch functions for cvecli formatters.

This module provides the main entry points for outputting CVE data
in various formats. It dispatches to the appropriate formatter based
on the requested format.
"""

from typing import Optional, TYPE_CHECKING

from rich.console import Console

from cvecli.cli.formatters.base import OutputFormat
from cvecli.cli.formatters.json_formatter import (
    output_search_results_json,
    output_cve_detail_json,
)
from cvecli.cli.formatters.table_formatter import (
    output_search_results_table,
    output_search_results_detailed,
    output_cve_detail_table,
)
from cvecli.cli.formatters.markdown_formatter import (
    output_search_results_markdown,
    output_cve_detail_markdown,
)

if TYPE_CHECKING:
    from cvecli.services.search import CVESearchService, SearchResult

console = Console()


def output_search_results(
    result: "SearchResult",
    format: str = OutputFormat.TABLE,
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    detailed: bool = False,
) -> None:
    """Output search results in the specified format.

    Args:
        result: Search results to output.
        format: Output format (table, json, markdown).
        verbose: Include detailed information.
        limit: Maximum number of results (ignored for file output).
        search_service: Service for getting severity info.
        output_file: Path to write output file (if specified, no truncation).
        detailed: Show detailed output with descriptions (table format only).
    """
    if len(result.cves) == 0:
        if output_file:
            # Still write empty result to file
            pass
        else:
            console.print("[yellow]No results found.[/yellow]")
            return

    # When writing to file, don't truncate
    file_limit = 10000 if output_file else limit

    if format == OutputFormat.JSON:
        output_search_results_json(
            result,
            verbose=verbose,
            limit=file_limit,
            search_service=search_service,
            output_file=output_file,
            include_description=True,
        )
    elif format == OutputFormat.MARKDOWN:
        output_search_results_markdown(
            result,
            verbose=verbose,
            limit=file_limit,
            search_service=search_service,
            output_file=output_file,
            include_description=True,
        )
    else:
        # Table format
        if output_file:
            # For file output with table format, use markdown instead
            output_search_results_markdown(
                result,
                verbose=verbose,
                limit=file_limit,
                search_service=search_service,
                output_file=output_file,
                include_description=True,
            )
        elif detailed:
            output_search_results_detailed(
                result,
                limit=limit,
                search_service=search_service,
            )
        else:
            output_search_results_table(
                result,
                verbose=verbose,
                limit=limit,
                search_service=search_service,
            )


def output_cve_detail(
    row: dict,
    result: "SearchResult",
    search_service: "CVESearchService",
    format: str = OutputFormat.TABLE,
    verbose: bool = False,
    output_file: Optional[str] = None,
) -> None:
    """Output detailed CVE information.

    Args:
        row: CVE row data.
        result: Full search result with related data.
        search_service: Service for additional info.
        format: Output format.
        verbose: Show all available details.
        output_file: Path to write output.
    """
    cve_id = row.get("cve_id", "")
    description = search_service.get_description(cve_id)
    best_metric = search_service.get_best_metric(cve_id)
    kev_info = search_service.get_kev_info(cve_id)
    ssvc_info = search_service.get_ssvc_info(cve_id)

    # Deduplicate references by URL
    unique_refs: list[dict] = []
    seen_urls: set[str] = set()
    if result.references is not None and len(result.references) > 0:
        for ref in result.references.iter_rows(named=True):
            url = ref.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_refs.append(dict(ref))

    if format == OutputFormat.JSON:
        output_cve_detail_json(
            row,
            result,
            description,
            best_metric,
            kev_info,
            ssvc_info,
            unique_refs,
            output_file,
        )
    elif format == OutputFormat.MARKDOWN:
        output_cve_detail_markdown(
            row, result, description, best_metric, kev_info, unique_refs, output_file
        )
    else:
        output_cve_detail_table(
            row,
            result,
            description,
            best_metric,
            kev_info,
            ssvc_info,
            unique_refs,
            verbose,
        )
