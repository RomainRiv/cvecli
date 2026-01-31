"""Products command for cvecli.

This module contains the products command for searching product/vendor names.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from cvecli.constants import OutputFormat, SearchMode
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.search import CVESearchService
from cvecli.cli.formatters import output_products_table

logger = get_logger(__name__)
console = Console()


def register_products_command(app: typer.Typer) -> None:
    """Register the products command with the Typer app."""

    @app.command()
    def products(
        query: str = typer.Argument(
            ...,
            help="Search query for product or vendor name",
        ),
        mode: Optional[str] = typer.Option(
            None,
            "--mode",
            "-M",
            help="Search mode: strict (exact match), regex (pattern), fuzzy (substring, default)",
        ),
        vendor: Optional[str] = typer.Option(
            None, "--vendor", "-V", help="Filter by vendor name"
        ),
        limit: int = typer.Option(
            100, "--limit", "-n", help="Maximum number of results to show"
        ),
        format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json, markdown"
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
        """Search product/vendor names in the CVE database.

        This command helps you discover the exact product and vendor names
        used in the CVE database, which is useful for refining CVE searches.

        The results show how many CVEs affect each product/vendor combination.

        Examples:
            cvecli products "linux"                # Find all products with "linux"
            cvecli products "chrome" -V google     # Chrome products by Google
            cvecli products "windows" --mode strict # Exact match for "windows"
            cvecli products "apache.*http" -M regex # Regex pattern
        """
        logger.info("Products command invoked with query: %s", query)

        # Validate format option
        if format not in OutputFormat.ALL:
            console.print(
                f"[red]Error: Invalid format '{format}'. Must be one of: {', '.join(OutputFormat.ALL)}[/red]"
            )
            raise typer.Exit(1)

        data_path = Path(data_dir) if data_dir else None
        config = Config(data_dir=data_path)
        service = CVESearchService(config)

        # Validate non-empty query
        if not query or not query.strip():
            console.print("[red]Error: Search query cannot be empty.[/red]")
            raise typer.Exit(1)

        query = query.strip()

        # Determine search mode
        search_mode = SearchMode.FUZZY  # Default
        if mode == "strict":
            search_mode = SearchMode.STRICT
        elif mode == "regex":
            search_mode = SearchMode.REGEX
        elif mode == "fuzzy" or mode is None:
            search_mode = SearchMode.FUZZY
        elif mode:
            console.print(
                f"[red]Invalid mode: {mode}. Must be: strict, regex, fuzzy[/red]"
            )
            raise typer.Exit(1)

        try:
            products_df = service.search_products(
                query,
                mode=search_mode,
                vendor=vendor,
                limit=limit,
            )
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        output_products_table(
            products_df,
            limit=limit,
            format=format,
            output_file=output,
        )

        logger.info("Products command completed with %d results", len(products_df))
