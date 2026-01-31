"""JSON output formatters for cvecli.

This module provides JSON formatting for CVE search results and details.
"""

import json
from typing import Optional, TYPE_CHECKING

from rich.console import Console

from cvecli.cli.formatters.base import build_cve_record

if TYPE_CHECKING:
    from cvecli.services.search import CVESearchService, SearchResult

console = Console()


def output_search_results_json(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    include_description: bool = True,
) -> None:
    """Output search results as JSON.

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

    records = []
    for row in df.iter_rows(named=True):
        record = build_cve_record(
            row, search_service, include_description=include_description
        )
        records.append(record)

    if verbose:
        output: object = {
            "count": total_count,
            "showing": len(records),
            "truncated": truncated,
            "results": records,
            "summary": result.summary(),
        }
    else:
        output = {
            "count": total_count,
            "showing": len(records),
            "truncated": truncated,
            "results": records,
        }

    json_output = json.dumps(output, indent=2, default=str)

    if output_file:
        from pathlib import Path

        Path(output_file).write_text(json_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(json_output)


def output_cve_detail_json(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    ssvc_info: Optional[dict],
    unique_refs: list[dict],
    output_file: Optional[str],
) -> None:
    """Output CVE detail as JSON."""
    output_data = row.copy()

    if description:
        output_data["description"] = description
    if best_metric:
        output_data["best_metric"] = best_metric
    if kev_info:
        output_data["kev_info"] = kev_info
    if ssvc_info:
        output_data["ssvc_info"] = ssvc_info
    if result.products is not None and len(result.products) > 0:
        output_data["affected_products"] = result.products.to_dicts()
    if result.cwes is not None and len(result.cwes) > 0:
        output_data["cwes"] = result.cwes.to_dicts()
    if unique_refs:
        output_data["references"] = unique_refs

    json_output = json.dumps(output_data, indent=2, default=str)

    if output_file:
        from pathlib import Path

        Path(output_file).write_text(json_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(json_output)
