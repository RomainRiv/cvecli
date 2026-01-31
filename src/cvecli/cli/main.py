"""CLI for CVE analysis tool.

This module provides a command-line interface for downloading, extracting,
and searching CVE data from the cvelistV5 repository.

Usage:
    cvecli db update                     Update CVE database from pre-built parquet files
    cvecli db update --prerelease        Update from latest pre-release
    cvecli db status                     Show database status

    cvecli db build download-json        Download raw JSON files (advanced)
    cvecli db build extract-parquet      Extract JSON to parquet locally (advanced)
    cvecli db build extract-embeddings   Generate embeddings for semantic search
    cvecli db build create-manifest      Create manifest.json for distribution

    cvecli search <query>                Search CVEs (use --semantic for semantic search)
    cvecli get <cve-id>                  Get details for a specific CVE
    cvecli products <query>              Search product/vendor names in the database
    cvecli stats                         Show database statistics

This module is the main entry point for the CLI. Commands are organized
in separate modules under cvecli.cli.commands for better maintainability.
"""

import typer

from cvecli import __version__

# Import command registration functions from modular command files
from cvecli.cli.commands import (
    db_app,
    register_search_command,
    register_get_command,
    register_stats_command,
    register_products_command,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        print(f"cvecli version {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="cvecli",
    help="CVE analysis tool for LLM agents",
    no_args_is_help=True,
)


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """CVE analysis tool for LLM agents."""
    pass


# Add database management command group to main app
app.add_typer(db_app, name="db")

# Register top-level commands from modular command files
register_search_command(app)
register_get_command(app)
register_stats_command(app)
register_products_command(app)


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
