"""Stats command for cvecli.

This module contains the stats command for displaying database statistics.
"""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cvecli.constants import OutputFormat
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.search import CVESearchService

logger = get_logger(__name__)
console = Console()


def register_stats_command(app: typer.Typer) -> None:
    """Register the stats command with the Typer app."""

    @app.command()
    def stats(
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
        """Show database statistics."""
        logger.info("Stats command invoked")

        # Validate format option
        if format not in OutputFormat.ALL:
            console.print(
                f"[red]Error: Invalid format '{format}'. Must be one of: {', '.join(OutputFormat.ALL)}[/red]"
            )
            raise typer.Exit(1)

        data_path = Path(data_dir) if data_dir else None
        config = Config(data_dir=data_path)
        service = CVESearchService(config)

        try:
            statistics = service.stats()
        except FileNotFoundError:
            console.print("[red]No data found. Run 'cvecli db update' first.[/red]")
            raise typer.Exit(1)

        # Generate output content
        output_content = None

        if format == OutputFormat.JSON:
            output_content = json.dumps(statistics, indent=2)

        elif format == OutputFormat.MARKDOWN:
            lines = [
                "# CVE Database Statistics\n",
                f"**Total CVEs:** {statistics['total_cves']}\n",
                f"**CVEs with CVSS:** {statistics['cves_with_cvss']}\n",
                f"**Unique Products:** {statistics['unique_products']}\n",
                f"**Unique Vendors:** {statistics['unique_vendors']}\n",
                f"**Unique CWEs:** {statistics['unique_cwes']}\n",
                f"**Total References:** {statistics['total_references']}\n",
                "\n## CVEs by State\n",
            ]
            for state_name, count in statistics.get("states", {}).items():
                lines.append(f"- {state_name}: {count}")
            lines.append("\n## CVEs by Year\n")
            for year, count in statistics.get("by_year", {}).items():
                lines.append(f"- {year}: {count}")
            output_content = "\n".join(lines)

        # Handle file output
        if output:
            if output_content is None:
                # Generate text content for table format when writing to file
                output_content = json.dumps(statistics, indent=2)
            with open(output, "w") as f:
                f.write(output_content)
            console.print(f"[green]Output written to {output}[/green]")
            return

        # Print to console
        if output_content:
            print(output_content)
        else:
            console.print(
                Panel(
                    f"[bold]Total CVEs:[/bold] {statistics['total_cves']}\n"
                    f"[bold]CVEs with CVSS:[/bold] {statistics['cves_with_cvss']}\n"
                    f"[bold]Product Entries:[/bold] {statistics['total_product_entries']}\n"
                    f"[bold]Unique Products:[/bold] {statistics['unique_products']}\n"
                    f"[bold]Unique Vendors:[/bold] {statistics['unique_vendors']}\n"
                    f"[bold]Unique CWEs:[/bold] {statistics['unique_cwes']}\n"
                    f"[bold]Total References:[/bold] {statistics['total_references']}",
                    title="CVE Database Statistics",
                )
            )

            if statistics.get("states"):
                table = Table(title="CVEs by State")
                table.add_column("State")
                table.add_column("Count", justify="right")
                for state_name, count in statistics.get("states", {}).items():
                    table.add_row(state_name, str(count))
                console.print(table)

            if statistics.get("by_year"):
                table = Table(title="CVEs by Year (recent)")
                table.add_column("Year")
                table.add_column("Count", justify="right")
                years = sorted(statistics.get("by_year", {}).items(), reverse=True)[:10]
                for year, count in years:
                    table.add_row(year, str(count))
                console.print(table)

        logger.info("Stats command completed")
