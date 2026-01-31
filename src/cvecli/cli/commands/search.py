"""Search command for cvecli.

This module contains the search command which supports various search modes
and filters for finding CVEs.
"""

import re
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from cvecli.constants import (
    CVE_ID_PATTERN,
    SearchMode,
    OutputFormat,
    SeverityLevel,
)
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.search import CVESearchService
from cvecli.services.embeddings import is_semantic_available
from cvecli.exceptions import SemanticDependencyError
from cvecli.cli.formatters import output_search_results

logger = get_logger(__name__)
console = Console()


def normalize_date(date_str: str) -> str:
    """Normalize partial date inputs to full YYYY-MM-DD format.

    Args:
        date_str: Date string in format YYYY, YYYY-MM, or YYYY-MM-DD

    Returns:
        Full date string in YYYY-MM-DD format

    Examples:
        "2024" -> "2024-01-01"
        "2024-06" -> "2024-06-01"
        "2024-06-15" -> "2024-06-15"
    """
    date_str = date_str.strip()

    # Check if it's just a year (4 digits)
    if re.match(r"^\d{4}$", date_str):
        return f"{date_str}-01-01"

    # Check if it's year-month (YYYY-MM)
    if re.match(r"^\d{4}-\d{2}$", date_str):
        return f"{date_str}-01"

    # Already full date or invalid - return as-is (will be validated later)
    return date_str


def register_search_command(app: typer.Typer) -> None:
    """Register the search command with the Typer app."""

    @app.command()
    def search(
        query: Optional[str] = typer.Argument(
            None,
            help="Search query (product name, vendor, CPE string, or natural language for semantic search). Optional when using --product, --vendor, --cpe, or --cwe filters.",
        ),
        cpe: Optional[str] = typer.Option(
            None,
            "--cpe",
            "-c",
            help="Search by CPE string (e.g., cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*)",
        ),
        purl: Optional[str] = typer.Option(
            None,
            "--purl",
            help="Search by Package URL (e.g., pkg:pypi/django, pkg:npm/lodash)",
        ),
        version: Optional[str] = typer.Option(
            None,
            "--version",
            help="Filter by affected version (only show CVEs affecting this version)",
        ),
        cwe: Optional[str] = typer.Option(
            None,
            "--cwe",
            "-w",
            help="Filter by CWE ID (e.g., 787 or CWE-787)",
        ),
        mode: Optional[str] = typer.Option(
            None,
            "--mode",
            "-M",
            help="Search mode: strict (exact match), regex (pattern), fuzzy (substring, default), semantic (AI)",
        ),
        semantic: bool = typer.Option(
            False,
            "--semantic",
            "-m",
            help="Use semantic (natural language) search (shortcut for --mode semantic)",
        ),
        vendor: Optional[str] = typer.Option(
            None, "--vendor", "-V", help="Filter by vendor name"
        ),
        product: Optional[str] = typer.Option(
            None, "--product", "-p", help="Filter by product name"
        ),
        severity: Optional[str] = typer.Option(
            None,
            "--severity",
            "-s",
            help="Filter by severity bucket (low, medium, high, critical)",
        ),
        cvss_min: Optional[float] = typer.Option(
            None,
            "--cvss-min",
            help="Minimum CVSS score (0.0-10.0)",
        ),
        cvss_max: Optional[float] = typer.Option(
            None,
            "--cvss-max",
            help="Maximum CVSS score (0.0-10.0)",
        ),
        state: Optional[str] = typer.Option(
            None,
            "--state",
            "-S",
            help="Filter by CVE state (published, rejected)",
        ),
        after: Optional[str] = typer.Option(
            None,
            "--after",
            help="Only CVEs published after this date (YYYY, YYYY-MM, or YYYY-MM-DD)",
        ),
        before: Optional[str] = typer.Option(
            None,
            "--before",
            help="Only CVEs published before this date (YYYY, YYYY-MM, or YYYY-MM-DD)",
        ),
        kev: bool = typer.Option(
            False,
            "--kev",
            "-k",
            help="Only show CVEs in CISA Known Exploited Vulnerabilities",
        ),
        sort: Optional[str] = typer.Option(
            None,
            "--sort",
            help="Sort results by: date, severity, cvss",
        ),
        order: str = typer.Option(
            "descending",
            "--order",
            help="Sort order: ascending or descending (default: descending)",
        ),
        min_similarity: float = typer.Option(
            0.3,
            "--min-similarity",
            help="Minimum similarity score for semantic search (0-1)",
        ),
        limit: int = typer.Option(
            100, "--limit", "-n", help="Maximum number of results to show"
        ),
        format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json, markdown"
        ),
        detailed: bool = typer.Option(
            False, "--detailed", "-d", help="Show detailed output with descriptions"
        ),
        stats: bool = typer.Option(False, "--stats", help="Show summary statistics"),
        ids_only: bool = typer.Option(
            False,
            "--ids-only",
            help="Output only CVE IDs, one per line (for scripting)",
        ),
        output: Optional[str] = typer.Option(
            None,
            "--output",
            "-o",
            help="Write output to file (no truncation when used)",
        ),
        data_dir: Optional[str] = typer.Option(
            None,
            "--data-dir",
            help="Override data directory",
        ),
        quiet: bool = typer.Option(
            False, "--quiet", "-q", help="Suppress status messages (for scripting)"
        ),
    ) -> None:
        """Search CVEs by product name, vendor, CWE, CPE, PURL, or natural language.

        Search Modes:
        - fuzzy (default): Case-insensitive substring matching
        - strict: Exact case-insensitive match
        - regex: Regular expression pattern matching
        - semantic: Natural language AI-powered search (requires embeddings)

        CPE Search:
        Search by CPE (Common Platform Enumeration) string to find vulnerabilities
        for specific software. Use --version to filter to only CVEs that affect
        your specific version.

        PURL Search:
        Search by Package URL (PURL) to find vulnerabilities for specific packages.
        PURLs are standardized identifiers for software packages across different
        ecosystems (PyPI, npm, Maven, etc.).

        Examples:
            cvecli search "linux kernel"                    # Fuzzy search (default)
            cvecli search "linux" --mode strict             # Exact match only
            cvecli search "linux.*kernel" --mode regex     # Regex pattern
            cvecli search "memory corruption" -m            # Semantic search
            cvecli search "windows" -V microsoft            # Filter by vendor
            cvecli search "chrome" -p browser               # Filter by product
            cvecli search --cwe 787                         # Search by CWE ID
            cvecli search --purl "pkg:pypi/django"          # Search by PURL
            cvecli search --purl "pkg:npm/lodash"           # npm package
            cvecli search "apache" --cvss-min 7.0           # CVSS >= 7.0
            cvecli search "linux" --sort date               # Sort by date (descending by default)
            cvecli search "linux" --sort cvss --order ascending  # Sort by CVSS ascending
            cvecli search "apache" --ids-only               # Output CVE IDs only
            cvecli search --cpe "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
            cvecli search "apache" --version 2.4.51         # Filter by affected version
            cvecli search --state rejected                  # Search by CVE state
        """
        logger.info("Search command invoked with query: %s", query)

        # Validate format option
        if format not in OutputFormat.ALL:
            console.print(
                f"[red]Error: Invalid format '{format}'. Must be one of: {', '.join(OutputFormat.ALL)}[/red]"
            )
            raise typer.Exit(1)

        data_path = Path(data_dir) if data_dir else None
        config = Config(data_dir=data_path)
        service = CVESearchService(config)

        # Build query using the fluent API
        q = service.query()

        # Determine search mode
        search_mode = SearchMode.FUZZY  # Default
        if semantic or mode == "semantic":
            search_mode = SearchMode.SEMANTIC
        elif mode == "strict":
            search_mode = SearchMode.STRICT
        elif mode == "regex":
            search_mode = SearchMode.REGEX
        elif mode == "fuzzy" or mode is None:
            search_mode = SearchMode.FUZZY
        elif mode:
            console.print(
                f"[red]Invalid mode: {mode}. Must be: strict, regex, fuzzy, semantic[/red]"
            )
            raise typer.Exit(1)

        # Handle semantic search
        if search_mode == SearchMode.SEMANTIC:
            if not query:
                console.print("[red]Error: Query required for semantic search.[/red]")
                raise typer.Exit(1)
            if not service.has_embeddings():
                console.print(
                    "[red]Error: Embeddings not found for semantic search.[/red]"
                )
                console.print()
                console.print("Download embeddings with:")
                console.print("  [cyan]cvecli db update --embeddings[/cyan]")
                console.print()
                console.print("Or generate them locally with:")
                console.print("  [cyan]cvecli db build extract-embeddings[/cyan]")
                raise typer.Exit(1)
            if not is_semantic_available():
                console.print(
                    "[red]Error: Semantic search dependencies not installed.[/red]"
                )
                console.print()
                console.print("Install with:")
                console.print("  [cyan]pip install cvecli\\[semantic][/cyan]")
                console.print("  [dim]or with uv:[/dim]")
                console.print("  [cyan]uv pip install cvecli\\[semantic][/cyan]")
                raise typer.Exit(1)
            try:
                q = q.semantic(query, top_k=limit, min_similarity=min_similarity)
            except SemanticDependencyError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
            except Exception as e:
                console.print(f"[red]Error in semantic search: {e}[/red]")
                raise typer.Exit(1)
        # Handle PURL search
        elif purl:
            try:
                q = q.by_purl(purl, check_version=version)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
        # Handle CPE search
        elif cpe:
            try:
                q = q.by_cpe(cpe, check_version=version)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
        # Handle query argument
        elif query:
            query = query.strip()
            if CVE_ID_PATTERN.match(query):
                q = q.by_id(query)
            elif query.lower().startswith("cpe:"):
                try:
                    q = q.by_cpe(query, check_version=version)
                except ValueError as e:
                    console.print(f"[red]Error: {e}[/red]")
                    raise typer.Exit(1)
            elif query.upper().startswith("CWE"):
                q = q.by_cwe(query)
            else:
                q = q.text_search(query, search_mode)
                if vendor:
                    q = q.by_vendor(vendor, fuzzy=True, exact=True)
        # If no query but filters are provided, that's okay
        elif not (product or vendor or cwe or state or kev):
            console.print(
                "[red]Error: Search query, --product, --vendor, --cpe, --purl, --cwe, or --state option required.[/red]"
            )
            raise typer.Exit(1)

        # Apply additional filters
        if product:
            q = q.by_product(product, fuzzy=True, exact=True)
            if vendor:
                q = q.by_vendor(vendor, fuzzy=True, exact=True)
        elif vendor and not (query and not query.upper().startswith("CWE")):
            q = q.by_vendor(vendor, fuzzy=True, exact=True)

        if cwe:
            q = q.by_cwe(cwe)

        if state:
            q = q.by_state(state)

        if kev:
            q = q.by_kev()

        if after or before:
            try:
                normalized_after = normalize_date(after) if after else None
                normalized_before = normalize_date(before) if before else None
                q = q.by_date(after=normalized_after, before=normalized_before)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

        if severity:
            sev_lower = severity.lower()
            try:
                sev = SeverityLevel(sev_lower)
            except ValueError:
                console.print(
                    f"[red]Invalid severity: {severity}. Must be: none, low, medium, high, critical[/red]"
                )
                raise typer.Exit(1)
            q = q.by_severity(sev)

        if cvss_min is not None or cvss_max is not None:
            q = q.by_cvss(min_score=cvss_min, max_score=cvss_max)

        if version and not purl and not cpe:
            q = q.by_version(version)
            if vendor:
                q = q.by_vendor(vendor)
            if product:
                q = q.by_product(product, fuzzy=True, exact=True)

        if sort:
            order_lower = order.lower()
            if order_lower not in ["ascending", "descending"]:
                console.print(
                    f"[red]Error: Invalid order '{order}'. Must be 'ascending' or 'descending'[/red]"
                )
                raise typer.Exit(1)
            try:
                q = q.sort_by(sort, descending=(order_lower == "descending"))
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

        q = q.limit(limit)

        # Execute the query
        try:
            result = q.execute()
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Check if CVE ID search found nothing
        if query and CVE_ID_PATTERN.match(query) and result.count == 0:
            console.print(f"[red]CVE not found: {query}[/red]")
            raise typer.Exit(1)

        # Output CVE IDs only (for scripting)
        if ids_only:
            cve_ids = result.cves.get_column("cve_id").to_list()
            if output:
                with open(output, "w") as f:
                    for cve_id in cve_ids[:limit]:
                        f.write(f"{cve_id}\n")
                console.print(f"[green]Output written to {output}[/green]")
            else:
                for cve_id in cve_ids[:limit]:
                    print(cve_id)
            return

        output_search_results(
            result,
            format=format,
            verbose=stats,
            limit=limit,
            search_service=service,
            output_file=output,
            detailed=detailed,
        )
