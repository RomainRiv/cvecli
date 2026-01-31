"""Formatters package for cvecli CLI.

This package provides output formatting utilities for displaying
CVE data in various formats (table, JSON, markdown).

The formatters are split into focused modules:
- base: Common utilities and base classes
- json_formatter: JSON output formatting
- table_formatter: Rich table output formatting
- markdown_formatter: Markdown output formatting
"""

from cvecli.cli.formatters.base import (
    OutputFormat,
    get_severity_color,
    get_severity_info,
    truncate_text,
    format_similarity_score,
)
from cvecli.cli.formatters.json_formatter import (
    output_search_results_json,
    output_cve_detail_json,
)
from cvecli.cli.formatters.table_formatter import (
    output_search_results_table,
    output_search_results_detailed,
    output_cve_detail_table,
    output_products_table,
)
from cvecli.cli.formatters.markdown_formatter import (
    output_search_results_markdown,
    output_cve_detail_markdown,
)

# Main entry points for outputting results
from cvecli.cli.formatters.output import (
    output_search_results,
    output_cve_detail,
)

__all__ = [
    # Base utilities
    "OutputFormat",
    "get_severity_color",
    "get_severity_info",
    "truncate_text",
    "format_similarity_score",
    # JSON formatters
    "output_search_results_json",
    "output_cve_detail_json",
    # Table formatters
    "output_search_results_table",
    "output_search_results_detailed",
    "output_cve_detail_table",
    "output_products_table",
    # Markdown formatters
    "output_search_results_markdown",
    "output_cve_detail_markdown",
    # Main entry points
    "output_search_results",
    "output_cve_detail",
]
