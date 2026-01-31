"""Get command for cvecli.

This module contains the get command for retrieving detailed CVE information.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from cvecli.constants import OutputFormat
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.search import CVESearchService, SearchResult
from cvecli.cli.formatters import output_cve_detail, output_search_results

logger = get_logger(__name__)
console = Console()


def register_get_command(app: typer.Typer) -> None:
    """Register the get command with the Typer app."""

    @app.command()
    def get(
        cve_ids: list[str] = typer.Argument(
            ..., help="CVE ID(s) (e.g., CVE-2024-1234 CVE-2024-5678)"
        ),
        format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json, markdown"
        ),
        detailed: bool = typer.Option(
            False,
            "--detailed",
            "-d",
            help="Show all available details (descriptions, references, etc.)",
        ),
        output: Optional[str] = typer.Option(
            None, "--output", "-o", help="Write output to file"
        ),
        data_dir: Optional[str] = typer.Option(
            None,
            "--data-dir",
            help="Override data directory",
        ),
    ) -> None:
        """Get details for one or more CVEs.

        Examples:
            cvecli get CVE-2024-1234
            cvecli get CVE-2024-1234 CVE-2024-5678
            cvecli get CVE-2024-1234 --detailed
            cvecli get CVE-2024-1234 --format json --output cve.json
        """
        logger.info("Get command invoked for CVEs: %s", cve_ids)

        # Validate format option
        if format not in OutputFormat.ALL:
            console.print(
                f"[red]Error: Invalid format '{format}'. Must be one of: {', '.join(OutputFormat.ALL)}[/red]"
            )
            raise typer.Exit(1)

        data_path = Path(data_dir) if data_dir else None
        config = Config(data_dir=data_path)
        service = CVESearchService(config)

        all_results = []
        not_found = []

        for cve_id in cve_ids:
            result = service.query().by_id(cve_id).execute()
            if len(result.cves) == 0:
                not_found.append(cve_id)
            else:
                all_results.append((cve_id, result))

        if not_found:
            for cve_id in not_found:
                console.print(f"[yellow]CVE not found: {cve_id}[/yellow]")

        if not all_results:
            raise typer.Exit(1)

        # For single CVE, use the detailed output
        if len(all_results) == 1:
            cve_id, result = all_results[0]
            row = result.cves.to_dicts()[0]
            output_cve_detail(
                row,
                result,
                service,
                format=format,
                verbose=detailed,
                output_file=output,
            )
        else:
            # For multiple CVEs, merge results and use search output format
            import polars as pl

            merged_cves = pl.concat([r.cves for _, r in all_results])
            merged_result = SearchResult(cves=merged_cves)

            # Enrich with related data
            for _, r in all_results:
                if r.descriptions is not None:
                    if merged_result.descriptions is None:
                        merged_result.descriptions = r.descriptions
                    else:
                        merged_result.descriptions = pl.concat(
                            [merged_result.descriptions, r.descriptions]
                        )
                if r.metrics is not None:
                    if merged_result.metrics is None:
                        merged_result.metrics = r.metrics
                    else:
                        merged_result.metrics = pl.concat(
                            [merged_result.metrics, r.metrics]
                        )

            output_search_results(
                merged_result,
                format=format,
                verbose=False,
                limit=len(cve_ids),
                search_service=service,
                output_file=output,
                detailed=detailed,
            )

        logger.info("Get command completed for %d CVEs", len(all_results))
