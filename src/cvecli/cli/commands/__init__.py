"""CLI commands package.

This package contains the individual command modules for the cvecli CLI.
Each module focuses on a specific command group or functionality.

Modules:
- db: Database management commands (update, status, build)
- search: Search command with various filters
- get: Get specific CVE details
- stats: Database statistics
- products: Product search
"""

from cvecli.cli.commands.db import db_app, build_app
from cvecli.cli.commands.search import register_search_command
from cvecli.cli.commands.get import register_get_command
from cvecli.cli.commands.stats import register_stats_command
from cvecli.cli.commands.products import register_products_command

__all__ = [
    "db_app",
    "build_app",
    "register_search_command",
    "register_get_command",
    "register_stats_command",
    "register_products_command",
]
