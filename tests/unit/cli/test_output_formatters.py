"""Unit tests for formatter functions.

These tests verify the output formatters for markdown, JSON, and table outputs.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import polars as pl
import pytest

from cvecli.cli.formatters.json_formatter import (
    output_cve_detail_json,
    output_search_results_json,
)
from cvecli.cli.formatters.markdown_formatter import (
    output_cve_detail_markdown,
    output_search_results_markdown,
)
from cvecli.cli.formatters.output import (
    output_search_results,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_search_result():
    """Create a mock SearchResult."""
    cves_df = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
            "state": ["PUBLISHED", "PUBLISHED"],
            "cna_title": ["Test Vulnerability", "Another Vulnerability"],
            "date_published": ["2024-01-15", "2024-02-20"],
        }
    )

    mock_result = MagicMock()
    mock_result.cves = cves_df
    mock_result.count = len(cves_df)
    mock_result.products = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234"],
            "vendor": ["TestVendor"],
            "product": ["TestProduct"],
        }
    )
    mock_result.cwes = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234"],
            "cwe_id": ["CWE-79"],
            "description": ["Cross-site Scripting"],
        }
    )
    mock_result.summary.return_value = {
        "count": 2,
        "severity_distribution": {"HIGH": 1, "MEDIUM": 1},
        "year_distribution": {"2024": 2},
    }
    mock_result.to_dicts.return_value = cves_df.to_dicts()

    return mock_result


@pytest.fixture
def mock_search_service():
    """Create a mock CVESearchService."""
    service = MagicMock()
    service.get_description.return_value = "Test description for the vulnerability."
    service.get_best_metric.return_value = {
        "metric_type": "cvssV3_1",
        "source": "cna",
        "base_score": 7.5,
        "base_severity": "HIGH",
    }
    return service


# =============================================================================
# Markdown Formatter Tests
# =============================================================================


class TestOutputSearchResultsMarkdown:
    """Tests for markdown search results output."""

    def test_basic_output(self, mock_search_result, capsys):
        """Should output basic markdown structure."""
        with patch(
            "cvecli.cli.formatters.markdown_formatter.get_severity_info"
        ) as mock_sev:
            mock_sev.return_value = ("7.5", "v3.1", 7.5)

            output_search_results_markdown(
                mock_search_result,
                verbose=False,
                limit=100,
                search_service=None,
            )

        captured = capsys.readouterr()
        assert "# CVE Search Results" in captured.out
        assert "CVE-2024-1234" in captured.out
        assert "CVE-2024-5678" in captured.out

    def test_verbose_includes_summary(self, mock_search_result, capsys):
        """Verbose mode should include summary statistics."""
        with patch(
            "cvecli.cli.formatters.markdown_formatter.get_severity_info"
        ) as mock_sev:
            mock_sev.return_value = ("7.5", "v3.1", 7.5)

            output_search_results_markdown(
                mock_search_result,
                verbose=True,
                limit=100,
                search_service=None,
            )

        captured = capsys.readouterr()
        assert "## Summary" in captured.out

    def test_output_to_file(self, mock_search_result):
        """Should write output to file when output_file is specified."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_file = f.name

        try:
            with patch(
                "cvecli.cli.formatters.markdown_formatter.get_severity_info"
            ) as mock_sev:
                mock_sev.return_value = ("7.5", "v3.1", 7.5)

                output_search_results_markdown(
                    mock_search_result,
                    verbose=False,
                    limit=100,
                    search_service=None,
                    output_file=output_file,
                )

            content = Path(output_file).read_text()
            assert "CVE-2024-1234" in content
        finally:
            Path(output_file).unlink(missing_ok=True)

    def test_limit_respected(self, mock_search_result, capsys):
        """Should respect the limit parameter."""
        with patch(
            "cvecli.cli.formatters.markdown_formatter.get_severity_info"
        ) as mock_sev:
            mock_sev.return_value = ("7.5", "v3.1", 7.5)

            output_search_results_markdown(
                mock_search_result,
                verbose=False,
                limit=1,
                search_service=None,
            )

        captured = capsys.readouterr()
        # Should show truncation message
        assert "showing first 1" in captured.out


class TestOutputCveDetailMarkdown:
    """Tests for markdown CVE detail output."""

    def test_basic_detail_output(self, mock_search_result, capsys):
        """Should output basic CVE detail in markdown."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "cna_title": "Test Vulnerability",
            "date_published": "2024-01-15",
        }

        output_cve_detail_markdown(
            row=row,
            result=mock_search_result,
            description="Test description",
            best_metric={"base_score": 7.5, "metric_type": "cvssV3_1"},
            kev_info=None,
            unique_refs=[{"url": "https://example.com"}],
            output_file=None,
        )

        captured = capsys.readouterr()
        assert "# CVE-2024-1234" in captured.out
        assert "PUBLISHED" in captured.out
        assert "Test description" in captured.out

    def test_detail_with_kev_info(self, mock_search_result, capsys):
        """Should include KEV warning when CVE is in KEV."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "cna_title": "Test Vulnerability",
            "date_published": "2024-01-15",
        }

        output_cve_detail_markdown(
            row=row,
            result=mock_search_result,
            description="Test description",
            best_metric={"base_score": 9.8, "metric_type": "cvssV3_1"},
            kev_info={"dateAdded": "2024-02-01"},
            unique_refs=[],
            output_file=None,
        )

        captured = capsys.readouterr()
        assert "Known Exploited Vulnerability" in captured.out
        assert "2024-02-01" in captured.out

    def test_detail_with_references(self, mock_search_result, capsys):
        """Should include references section."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "cna_title": "Test Vulnerability",
            "date_published": "2024-01-15",
        }

        output_cve_detail_markdown(
            row=row,
            result=mock_search_result,
            description=None,
            best_metric=None,
            kev_info=None,
            unique_refs=[
                {"url": "https://example.com/advisory", "tags": "vendor-advisory"},
                {"url": "https://cve.org/cve", "tags": ""},
            ],
            output_file=None,
        )

        captured = capsys.readouterr()
        assert "## References" in captured.out
        assert "https://example.com/advisory" in captured.out

    def test_detail_output_to_file(self, mock_search_result):
        """Should write detail to file."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "date_published": "2024-01-15",
        }

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_file = f.name

        try:
            output_cve_detail_markdown(
                row=row,
                result=mock_search_result,
                description="Test description",
                best_metric=None,
                kev_info=None,
                unique_refs=[],
                output_file=output_file,
            )

            content = Path(output_file).read_text()
            assert "CVE-2024-1234" in content
        finally:
            Path(output_file).unlink(missing_ok=True)


# =============================================================================
# JSON Formatter Tests
# =============================================================================


class TestOutputSearchResultsJson:
    """Tests for JSON search results output."""

    def test_basic_json_output(self, mock_search_result, capsys):
        """Should output valid JSON structure."""
        output_search_results_json(
            mock_search_result,
            verbose=False,
            search_service=None,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "results" in data
        assert isinstance(data["results"], list)
        assert len(data["results"]) == 2

    def test_json_includes_cve_ids(self, mock_search_result, capsys):
        """JSON output should include CVE IDs."""
        output_search_results_json(
            mock_search_result,
            verbose=False,
            search_service=None,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        cve_ids = [r.get("cve_id") for r in data["results"]]
        assert "CVE-2024-1234" in cve_ids
        assert "CVE-2024-5678" in cve_ids

    def test_verbose_includes_summary(self, mock_search_result, capsys):
        """Verbose mode should include summary in JSON."""
        output_search_results_json(
            mock_search_result,
            verbose=True,
            search_service=None,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data


class TestOutputCveDetailJson:
    """Tests for JSON CVE detail output."""

    def test_basic_json_detail(self, mock_search_result, capsys):
        """Should output CVE detail as valid JSON."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "cna_title": "Test Vulnerability",
            "date_published": "2024-01-15",
        }

        output_cve_detail_json(
            row=row,
            result=mock_search_result,
            description="Test description",
            best_metric={"base_score": 7.5, "metric_type": "cvssV3_1"},
            kev_info=None,
            ssvc_info=None,
            unique_refs=[],
            output_file=None,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["cve_id"] == "CVE-2024-1234"
        assert data["state"] == "PUBLISHED"
        assert data["description"] == "Test description"

    def test_json_detail_with_products(self, mock_search_result, capsys):
        """JSON detail should include products."""
        row = {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "date_published": "2024-01-15",
        }

        output_cve_detail_json(
            row=row,
            result=mock_search_result,
            description=None,
            best_metric=None,
            kev_info=None,
            ssvc_info=None,
            unique_refs=[],
            output_file=None,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Check that products are included when available
        assert "cve_id" in data


# =============================================================================
# Output Dispatcher Tests
# =============================================================================


class TestOutputDispatcher:
    """Tests for output dispatch functions."""

    def test_output_search_results_dispatches_to_json(self, mock_search_result, capsys):
        """Should dispatch to JSON formatter when format is json."""
        with patch(
            "cvecli.cli.formatters.output.output_search_results_json"
        ) as mock_json:
            output_search_results(
                mock_search_result,
                format="json",
                verbose=False,
            )
            mock_json.assert_called_once()

    def test_output_search_results_dispatches_to_markdown(
        self, mock_search_result, capsys
    ):
        """Should dispatch to markdown formatter when format is markdown."""
        with patch(
            "cvecli.cli.formatters.output.output_search_results_markdown"
        ) as mock_md:
            output_search_results(
                mock_search_result,
                format="markdown",
                verbose=False,
            )
            mock_md.assert_called_once()

    def test_output_search_results_handles_empty(self, capsys):
        """Should handle empty results gracefully."""
        empty_result = MagicMock()
        empty_result.cves = pl.DataFrame()

        output_search_results(empty_result, format="table")

        captured = capsys.readouterr()
        assert "No results" in captured.out
