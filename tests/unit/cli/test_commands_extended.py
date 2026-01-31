"""Extended CLI command tests.

These tests cover CLI commands with lower coverage, including products,
additional search options, and edge cases.
"""

import json

import pytest
from typer.testing import CliRunner

from cvecli.cli.main import app


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


# =============================================================================
# Products Command Tests
# =============================================================================


class TestProductsCommand:
    """Tests for the products command."""

    def test_products_basic_search(self, cli_runner, test_config):
        """Products command should search for products."""
        result = cli_runner.invoke(
            app,
            ["products", "linux", "--limit", "10"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        # Should execute without error
        assert result.exit_code == 0

    def test_products_with_vendor_filter(self, cli_runner, test_config):
        """Products command should filter by vendor."""
        result = cli_runner.invoke(
            app,
            ["products", "kernel", "--vendor", "Linux", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_products_strict_mode(self, cli_runner, test_config):
        """Products command should support strict mode."""
        result = cli_runner.invoke(
            app,
            ["products", "Linux Kernel", "--mode", "strict", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_products_regex_mode(self, cli_runner, test_config):
        """Products command should support regex mode."""
        result = cli_runner.invoke(
            app,
            ["products", "linux.*kernel", "--mode", "regex", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_products_json_format(self, cli_runner, test_config):
        """Products command should support JSON output."""
        result = cli_runner.invoke(
            app,
            ["products", "linux", "--format", "json", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Output should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, (dict, list))

    def test_products_empty_query_error(self, cli_runner, test_config):
        """Products command should reject empty query."""
        result = cli_runner.invoke(
            app,
            ["products", "   "],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        # Should fail with error
        assert result.exit_code != 0

    def test_products_invalid_mode_error(self, cli_runner, test_config):
        """Products command should reject invalid mode."""
        result = cli_runner.invoke(
            app,
            ["products", "test", "--mode", "invalid"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code != 0

    def test_products_invalid_format_error(self, cli_runner, test_config):
        """Products command should reject invalid format."""
        result = cli_runner.invoke(
            app,
            ["products", "test", "--format", "invalid"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code != 0


# =============================================================================
# Search Command Extended Tests
# =============================================================================


class TestSearchCommandExtended:
    """Extended tests for search command options."""

    def test_search_with_vendor_filter(self, cli_runner, test_config):
        """Search with --vendor filter."""
        result = cli_runner.invoke(
            app,
            ["search", "--vendor", "linux", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_product_filter(self, cli_runner, test_config):
        """Search with --product filter."""
        result = cli_runner.invoke(
            app,
            ["search", "--product", "Linux Kernel", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_state_filter(self, cli_runner, test_config):
        """Search with --state filter."""
        result = cli_runner.invoke(
            app,
            ["search", "--state", "REJECTED", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_severity_filter(self, cli_runner, test_config):
        """Search with --severity filter."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--severity", "critical", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_date_after(self, cli_runner, test_config):
        """Search with --after date filter."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--after", "2020-01-01", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_date_before(self, cli_runner, test_config):
        """Search with --before date filter."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--before", "2025-01-01", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_date_range(self, cli_runner, test_config):
        """Search with both --after and --before."""
        result = cli_runner.invoke(
            app,
            [
                "search",
                "linux",
                "--after",
                "2020-01-01",
                "--before",
                "2024-01-01",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_purl(self, cli_runner, test_config):
        """Search with --purl filter."""
        result = cli_runner.invoke(
            app,
            ["search", "--purl", "pkg:pypi/django", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_markdown_format(self, cli_runner, test_config):
        """Search with --format markdown."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--format", "markdown", "--limit", "3"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert "# CVE Search Results" in result.output

    def test_search_no_results(self, cli_runner, test_config):
        """Search with no matching results."""
        result = cli_runner.invoke(
            app,
            ["search", "nonexistentproduct12345678", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        # Should complete without error
        assert result.exit_code == 0
        # Should indicate no results
        assert "0" in result.output or "No" in result.output

    def test_search_with_output_file(self, cli_runner, test_config, tmp_path):
        """Search with --output to file."""
        output_file = tmp_path / "results.json"

        result = cli_runner.invoke(
            app,
            [
                "search",
                "linux",
                "--format",
                "json",
                "--output",
                str(output_file),
                "--limit",
                "3",
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert output_file.exists()
        # Verify the file contains valid JSON
        content = output_file.read_text()
        data = json.loads(content)
        assert "results" in data


# =============================================================================
# Get Command Extended Tests
# =============================================================================


class TestGetCommandExtended:
    """Extended tests for get command."""

    def test_get_with_json_format(self, cli_runner, test_config):
        """Get command with JSON output."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-2022-2196", "--format", "json"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["cve_id"] == "CVE-2022-2196"

    def test_get_with_markdown_format(self, cli_runner, test_config):
        """Get command with markdown output."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-2022-2196", "--format", "markdown"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert "# CVE-2022-2196" in result.output

    def test_get_with_output_file(self, cli_runner, test_config, tmp_path):
        """Get command with --output to file."""
        output_file = tmp_path / "cve.json"

        result = cli_runner.invoke(
            app,
            [
                "get",
                "CVE-2022-2196",
                "--format",
                "json",
                "--output",
                str(output_file),
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert output_file.exists()

    def test_get_cve_with_case_insensitive_id(self, cli_runner, test_config):
        """Get command should handle lowercase CVE IDs."""
        result = cli_runner.invoke(
            app,
            ["get", "cve-2022-2196"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert "CVE-2022-2196" in result.output


# =============================================================================
# Stats Command Extended Tests
# =============================================================================


class TestStatsCommandExtended:
    """Extended tests for stats command."""

    def test_stats_markdown_format(self, cli_runner, test_config):
        """Stats command with markdown format."""
        result = cli_runner.invoke(
            app,
            ["stats", "--format", "markdown"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Markdown should have headers
        assert "#" in result.output or "CVE" in result.output

    def test_stats_detailed_json(self, cli_runner, test_config):
        """Stats command should provide detailed statistics."""
        result = cli_runner.invoke(
            app,
            ["stats", "--format", "json"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        # Should have key statistics
        assert isinstance(data, dict)


# =============================================================================
# Help and Version Tests
# =============================================================================


class TestHelpAndVersion:
    """Tests for help and version output."""

    def test_main_help(self, cli_runner):
        """Main app --help should show all commands."""
        result = cli_runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "search" in result.output
        assert "get" in result.output
        assert "stats" in result.output
        assert "db" in result.output

    def test_search_help(self, cli_runner):
        """Search command --help should show options."""
        result = cli_runner.invoke(app, ["search", "--help"])

        assert result.exit_code == 0
        assert "--product" in result.output or "product" in result.output
        assert "--vendor" in result.output or "vendor" in result.output

    def test_get_help(self, cli_runner):
        """Get command --help should show options."""
        result = cli_runner.invoke(app, ["get", "--help"])

        assert result.exit_code == 0
        assert "--format" in result.output or "format" in result.output

    def test_stats_help(self, cli_runner):
        """Stats command --help should show options."""
        result = cli_runner.invoke(app, ["stats", "--help"])

        assert result.exit_code == 0

    def test_products_help(self, cli_runner):
        """Products command --help should show options."""
        result = cli_runner.invoke(app, ["products", "--help"])

        assert result.exit_code == 0
        assert "--vendor" in result.output or "vendor" in result.output

    def test_db_help(self, cli_runner):
        """DB command group --help should show subcommands."""
        result = cli_runner.invoke(app, ["db", "--help"])

        assert result.exit_code == 0
        assert "update" in result.output
        assert "status" in result.output


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for CLI error handling."""

    def test_invalid_data_dir(self, cli_runner, tmp_path):
        """Commands should handle invalid data directory."""
        non_existent = tmp_path / "nonexistent"

        result = cli_runner.invoke(
            app,
            ["search", "linux"],
            env={"CVE_DATA_DIR": str(non_existent)},
        )

        # Should fail with appropriate error
        assert result.exit_code != 0

    def test_invalid_date_format(self, cli_runner, test_config):
        """Search should reject invalid date format."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--after", "not-a-date"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        # Should fail with error
        assert result.exit_code != 0 or "invalid" in result.output.lower()

    def test_invalid_cvss_value(self, cli_runner, test_config):
        """Search should handle invalid CVSS values."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--cvss-min", "invalid"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        # Should fail with error
        assert result.exit_code != 0
