"""Table output formatters for cvecli.

This module provides Rich table formatting for CVE search results and details.
"""

import json
from typing import Any, Optional, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cvecli.cli.formatters.base import (
    OutputFormat,
    get_severity_color,
    get_severity_info,
    truncate_text,
    format_similarity_score,
)

if TYPE_CHECKING:
    from cvecli.services.search import CVESearchService, SearchResult

console = Console()


def output_search_results_table(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    compact: bool = False,
    show_description: bool = True,
) -> None:
    """Output search results as a Rich table.

    Args:
        result: Search results to output.
        verbose: Show summary statistics.
        limit: Maximum results to show.
        search_service: Service for additional info.
        compact: Use compact format (default).
        show_description: Show descriptions (when compact=False).
    """
    df = result.cves
    total_count = len(df)

    if total_count == 0:
        console.print("[yellow]No results found.[/yellow]")
        return

    truncated = len(df) > limit
    if truncated:
        df = df.head(limit)
        console.print(
            f"[yellow]Showing first {limit} of {total_count} results[/yellow]"
        )

    # Check if we have similarity scores
    has_similarity = "similarity_score" in df.columns

    table = Table(title=f"CVE Results ({total_count} total)")
    table.add_column("CVE ID", style="cyan", no_wrap=True)

    if has_similarity:
        table.add_column("Match", justify="center", style="magenta")

    table.add_column("Severity", justify="right")
    table.add_column("Ver", justify="center", style="dim")
    table.add_column("Title")
    table.add_column("Published", style="dim")

    for row in df.iter_rows(named=True):
        cve_id = row.get("cve_id", "")
        title = truncate_text(row.get("cna_title") or "", 55)
        severity, version, score = get_severity_info(row, search_service)
        published = str(row.get("date_published") or "")[:10]

        # Format severity with color
        severity_text = Text(severity)
        severity_text.stylize(get_severity_color(score))

        row_data = [cve_id]

        if has_similarity:
            sim_score = row.get("similarity_score")
            row_data.append(format_similarity_score(sim_score))

        row_data.extend([severity_text, version, title, published])
        table.add_row(*row_data)

    console.print(table)

    if verbose:
        summary = result.summary()
        console.print(
            Panel(
                f"Severity: {summary.get('severity_distribution', {})}\n"
                f"Years: {summary.get('year_distribution', {})}",
                title="Summary",
            )
        )


def output_search_results_detailed(
    result: "SearchResult",
    limit: int = 10,
    search_service: Optional["CVESearchService"] = None,
) -> None:
    """Output search results with detailed CVE information.

    This shows each CVE with description and key details,
    similar to 'cvecli get' but more compact for multiple results.

    Args:
        result: Search results to output.
        limit: Maximum results to show.
        search_service: Service for additional info.
    """
    df = result.cves
    total_count = len(df)

    if total_count == 0:
        console.print("[yellow]No results found.[/yellow]")
        return

    truncated = len(df) > limit
    if truncated:
        df = df.head(limit)
        console.print(
            f"[yellow]Showing first {limit} of {total_count} results (use -n to show more)[/yellow]\n"
        )

    # Check if we have similarity scores
    has_similarity = "similarity_score" in df.columns

    for i, row in enumerate(df.iter_rows(named=True)):
        if i > 0:
            console.print()  # Separator between CVEs

        cve_id = row.get("cve_id", "")
        state = row.get("state", "")
        title = row.get("cna_title") or "(No title)"
        published = str(row.get("date_published") or "")[:10]

        # Get severity info
        severity, version, score = get_severity_info(row, search_service)
        severity_color = get_severity_color(score)

        # Build header line
        header_parts = [f"[bold cyan]{cve_id}[/bold cyan]"]

        if has_similarity:
            sim_score = row.get("similarity_score")
            if sim_score:
                header_parts.append(f"[magenta](match: {sim_score:.2f})[/magenta]")

        header_parts.append(f"[{severity_color}]{severity}[/{severity_color}]")
        header_parts.append(f"[dim]({version})[/dim]")
        header_parts.append(f"[dim]{state}[/dim]")

        console.print(" | ".join(header_parts))
        console.print(f"[bold]{title}[/bold]")
        console.print(f"[dim]Published: {published}[/dim]")

        # Get and display description
        if search_service:
            description = search_service.get_description(cve_id)
            if description:
                # Truncate very long descriptions
                if len(description) > 300:
                    description = description[:300] + "..."
                console.print(f"[italic]{description}[/italic]")

            # Show affected products (brief)
            if result.products is not None and len(result.products) > 0:
                import polars as pl

                cve_products = result.products.filter(pl.col("cve_id") == cve_id)
                if len(cve_products) > 0:
                    products_list = []
                    for prod in cve_products.head(3).iter_rows(named=True):
                        vendor = prod.get("vendor", "")
                        product = prod.get("product", "")
                        if vendor and product:
                            products_list.append(f"{vendor}/{product}")
                        elif product:
                            products_list.append(product)
                    if products_list:
                        more = (
                            f" (+{len(cve_products) - 3} more)"
                            if len(cve_products) > 3
                            else ""
                        )
                        console.print(
                            f"[dim]Products: {', '.join(products_list)}{more}[/dim]"
                        )

            # Show CWEs (brief)
            if result.cwes is not None and len(result.cwes) > 0:
                import polars as pl

                cve_cwes = result.cwes.filter(pl.col("cve_id") == cve_id)
                if len(cve_cwes) > 0:
                    cwes_list = [
                        cwe.get("cwe_id", "")
                        for cwe in cve_cwes.head(3).iter_rows(named=True)
                        if cwe.get("cwe_id")
                    ]
                    if cwes_list:
                        console.print(f"[dim]CWEs: {', '.join(cwes_list)}[/dim]")


def output_cve_detail_table(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    ssvc_info: Optional[dict],
    unique_refs: list[dict],
    verbose: bool,
) -> None:
    """Output CVE detail as Rich table/panels."""
    title = row.get("cna_title") or "(No title)"

    console.print(
        Panel(
            f"[bold cyan]{row.get('cve_id')}[/bold cyan]\n\n"
            f"[bold]State:[/bold] {row.get('state')}\n"
            f"[bold]Title:[/bold] {title}\n"
            f"[bold]Published:[/bold] {row.get('date_published')}\n"
            f"[bold]Updated:[/bold] {row.get('date_updated')}",
            title="CVE Details",
        )
    )

    if best_metric:
        score = best_metric.get("base_score")
        if score:
            color = "red" if score >= 7.0 else "yellow" if score >= 4.0 else "green"
            metric_type = best_metric.get("metric_type", "")
            source = best_metric.get("source", "cna")
            source_label = "" if source == "cna" else f" (from {source})"
            console.print(
                f"\n[bold]CVSS Score:[/bold] [{color}]{score:.1f}[/{color}] ({metric_type}){source_label}"
            )

    if description:
        console.print(Panel(description, title="Description"))

    # Show detailed CVSS metrics in verbose mode
    if verbose and best_metric:
        _output_cvss_details(best_metric)

    # Show KEV info if present
    if kev_info:
        date_added = kev_info.get("dateAdded", "Unknown")
        console.print(
            Panel(
                f"[bold red]⚠️ This CVE is in CISA's Known Exploited Vulnerabilities catalog[/bold red]\n\n"
                f"[bold]Date Added:[/bold] {date_added}",
                title="Known Exploited Vulnerability",
                border_style="red",
            )
        )

    # Show SSVC info if present and verbose
    if ssvc_info and verbose:
        ssvc_details = []
        options = ssvc_info.get("options", [])
        for opt in options:
            for key, value in opt.items():
                ssvc_details.append(f"[bold]{key}:[/bold] {value}")
        if ssvc_details:
            console.print(Panel("\n".join(ssvc_details), title="SSVC Assessment"))

    # Show affected products
    if result.products is not None and len(result.products) > 0:
        table = Table(title="Affected Products")
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Package")
        table.add_column("Default Status")
        for prod in result.products.iter_rows(named=True):
            table.add_row(
                prod.get("vendor", ""),
                prod.get("product", ""),
                prod.get("package_name", ""),
                prod.get("default_status", ""),
            )
        console.print(table)

    # Show affected versions in verbose mode
    if result.versions is not None and len(result.versions) > 0 and verbose:
        table = Table(title="Affected Versions")
        table.add_column("Version")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Less Than")
        for ver in result.versions.iter_rows(named=True):
            table.add_row(
                ver.get("version", ""),
                ver.get("version_type", ""),
                ver.get("status", ""),
                ver.get("less_than", "") or ver.get("less_than_or_equal", ""),
            )
        console.print(table)

    # Show CWEs
    if result.cwes is not None and len(result.cwes) > 0:
        console.print("\n[bold]CWEs:[/bold]")
        for cwe in result.cwes.iter_rows(named=True):
            cwe_id = cwe.get("cwe_id")
            cwe_desc = cwe.get("description", "")[:80]
            if cwe_id:
                console.print(f"  - {cwe_id}: {cwe_desc}")
            elif cwe_desc:
                console.print(f"  - [dim](No CWE ID):[/dim] {cwe_desc}")

    # Show references in verbose mode
    if unique_refs and verbose:
        console.print("\n[bold]References:[/bold]")
        for ref in unique_refs:
            url = ref.get("url", "")
            console.print(f"  - {url}")


def _output_cvss_details(best_metric: dict) -> None:
    """Output CVSS metric details."""
    score = best_metric.get("base_score")
    metric_type = best_metric.get("metric_type", "")

    if not (score or best_metric.get("base_severity")):
        return

    cvss_details = []
    vector = best_metric.get("vector_string")
    severity = best_metric.get("base_severity")

    if vector:
        cvss_details.append(f"[bold]Vector:[/bold] {vector}")
    if severity:
        cvss_details.append(f"[bold]Severity:[/bold] {severity}")

    # Show CVSS v3.x/v4 specific metrics
    if metric_type.startswith("cvssV3") or metric_type.startswith("cvssV4"):
        cvss_details.append("")

        fields = [
            ("attack_vector", "Attack Vector"),
            ("attack_complexity", "Attack Complexity"),
            ("privileges_required", "Privileges Required"),
            ("user_interaction", "User Interaction"),
            ("scope", "Scope"),
        ]

        for field, label in fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")

        cvss_details.append("")

        impact_fields = [
            ("confidentiality_impact", "Confidentiality Impact"),
            ("integrity_impact", "Integrity Impact"),
            ("availability_impact", "Availability Impact"),
        ]

        for field, label in impact_fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")

        # CVSS v4 additional metrics
        if metric_type.startswith("cvssV4"):
            ar = best_metric.get("attack_requirements")
            if ar:
                cvss_details.append(f"[dim]Attack Requirements:[/dim] {ar}")

    # Show CVSS v2 specific metrics
    elif metric_type == "cvssV2":
        cvss_details.append("")

        fields = [
            ("access_vector", "Access Vector"),
            ("access_complexity", "Access Complexity"),
            ("authentication", "Authentication"),
        ]

        for field, label in fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")

        cvss_details.append("")

        impact_fields = [
            ("confidentiality_impact", "Confidentiality Impact"),
            ("integrity_impact", "Integrity Impact"),
            ("availability_impact", "Availability Impact"),
        ]

        for field, label in impact_fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")

    if cvss_details:
        console.print(Panel("\n".join(cvss_details), title="CVSS Details"))


def output_products_table(
    products: Any,  # polars DataFrame
    limit: int = 100,
    format: str = OutputFormat.TABLE,
    output_file: Optional[str] = None,
) -> None:
    """Output products search results.

    Args:
        products: DataFrame of products.
        limit: Maximum results to show.
        format: Output format.
        output_file: Path to write output.
    """
    total_count = len(products)

    if total_count == 0:
        console.print("[yellow]No products found.[/yellow]")
        return

    truncated = False if output_file else len(products) > limit
    if truncated:
        products = products.head(limit)

    if format == OutputFormat.JSON:
        records = products.to_dicts()
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

    elif format == OutputFormat.MARKDOWN:
        lines = ["# Product Search Results\n"]
        lines.append(f"Found **{total_count}** products\n")
        lines.append("| Vendor | Product | CVE Count |")
        lines.append("|--------|---------|-----------|")

        for row in products.iter_rows(named=True):
            vendor = row.get("vendor", "")
            product = row.get("product", "")
            count = row.get("cve_count", "")
            lines.append(f"| {vendor} | {product} | {count} |")

        markdown_output = "\n".join(lines)

        if output_file:
            from pathlib import Path

            Path(output_file).write_text(markdown_output)
            console.print(f"[green]Output written to {output_file}[/green]")
        else:
            print(markdown_output)

    else:
        if truncated:
            console.print(
                f"[yellow]Showing first {limit} of {total_count} results[/yellow]"
            )

        table = Table(title=f"Products ({total_count} total)")
        table.add_column("Vendor", style="cyan")
        table.add_column("Product", style="green")
        table.add_column("CVE Count", justify="right")
        table.add_column("Package", style="dim")

        for row in products.iter_rows(named=True):
            table.add_row(
                row.get("vendor", ""),
                row.get("product", ""),
                str(row.get("cve_count", "")),
                row.get("package_name", "") or "",
            )

        console.print(table)
