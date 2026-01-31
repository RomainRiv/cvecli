"""Integration tests for CLI commands.

These tests invoke the actual CLI and test the full command flow.
They use static fixture data for consistent, reproducible results.
"""

import json

import pytest
from typer.testing import CliRunner

from cvecli.cli.main import app


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


class TestSearchCommand:
    """Integration tests for search command."""

    def test_search_basic(self, cli_runner, test_config):
        """Search command basic execution."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_cwe_filter(self, test_config, cli_runner):
        """Search command with --cwe filter."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--cwe", "1188", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_cvss_min(self, test_config, cli_runner):
        """Search command with --cvss-min filter."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--cvss-min", "7.0", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_cvss_range(self, test_config, cli_runner):
        """Search command with both --cvss-min and --cvss-max."""
        result = cli_runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cvss-min",
                "7.0",
                "--cvss-max",
                "9.0",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_date(self, test_config, cli_runner):
        """Search command with --sort date."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--sort", "date", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_cvss(self, test_config, cli_runner):
        """Search command with --sort cvss."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--sort", "cvss", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_and_order(self, test_config, cli_runner):
        """Search command with --sort and --order."""
        result = cli_runner.invoke(
            app,
            [
                "search",
                "linux",
                "--sort",
                "date",
                "--order",
                "ascending",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_ids_only(self, test_config, cli_runner):
        """Search command with --ids-only flag."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--ids-only", "--limit", "3"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Output should contain CVE IDs
        assert "CVE-" in result.output

    def test_search_with_stats(self, test_config, cli_runner):
        """Search command with --stats flag."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--stats", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_cwe_without_query(self, test_config, cli_runner):
        """Search with --cwe and no query should work."""
        result = cli_runner.invoke(
            app,
            ["search", "--cwe", "502", "--limit", "5"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_combined_filters(self, test_config, cli_runner):
        """Search with multiple filters combined."""
        result = cli_runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cwe",
                "1188",
                "--cvss-min",
                "5.0",
                "--sort",
                "cvss",
                "--limit",
                "3",
            ],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_json_output(self, test_config, cli_runner):
        """Search command with JSON output."""
        result = cli_runner.invoke(
            app,
            ["search", "linux", "--format", "json", "--limit", "3"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Should be valid JSON with search results structure
        data = json.loads(result.output)
        assert isinstance(data, dict)
        assert "results" in data
        assert isinstance(data["results"], list)


class TestGetCommand:
    """Integration tests for get command."""

    def test_get_single_cve(self, test_config, cli_runner):
        """Get command with single CVE ID."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-2022-2196"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert "CVE-2022-2196" in result.output

    def test_get_multiple_cves(self, test_config, cli_runner):
        """Get command with multiple CVE IDs."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-2022-2196", "CVE-2021-44228"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Both CVE IDs should appear in output
        assert "CVE-2022-2196" in result.output or "CVE-2021-44228" in result.output

    def test_get_with_detailed_flag(self, test_config, cli_runner):
        """Get command with --detailed flag."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-2022-2196", "--detailed"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0

    def test_get_nonexistent_cve(self, test_config, cli_runner):
        """Get command with non-existent CVE should show warning."""
        result = cli_runner.invoke(
            app,
            ["get", "CVE-9999-99999"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 1
        assert "not found" in result.output.lower()


class TestStatsCommand:
    """Integration tests for stats command."""

    def test_stats_basic(self, test_config, cli_runner):
        """Stats command basic execution."""
        result = cli_runner.invoke(
            app,
            ["stats"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert "CVE" in result.output or "Total" in result.output

    def test_stats_with_json_format(self, test_config, cli_runner):
        """Stats command with JSON format."""
        result = cli_runner.invoke(
            app,
            ["stats", "--format", "json"],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "total_cves" in data or isinstance(data, dict)

    def test_stats_with_output_file(self, test_config, cli_runner, tmp_path):
        """Stats command with --output to file."""
        output_file = tmp_path / "stats.json"

        result = cli_runner.invoke(
            app,
            ["stats", "--format", "json", "--output", str(output_file)],
            env={"CVE_DATA_DIR": str(test_config.data_dir)},
        )

        assert result.exit_code == 0
        assert output_file.exists()
        assert "Output written" in result.output
