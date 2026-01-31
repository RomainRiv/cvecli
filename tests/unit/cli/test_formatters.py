"""Unit tests for CLI formatters and helpers.

These tests focus on the presentation layer, using mocks for service dependencies.
"""

from unittest.mock import MagicMock


from cvecli.cli.formatters import get_severity_info, OutputFormat


class TestGetSeverityInfo:
    """Tests for get_severity_info helper function."""

    def test_cvssv4_preferred(self):
        """CVSS v4.0 should be preferred over other versions."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV4_0",
            "source": "cna",
            "base_score": 8.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "8.5"
        assert version == "v4.0"
        assert numeric == 8.5

    def test_cvssv3_1_second(self):
        """CVSS v3.1 should be used when v4.0 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.5"
        assert version == "v3.1"
        assert numeric == 7.5

    def test_cvssv3_fallback(self):
        """CVSS v3.0 should be used when v3.1 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_0",
            "source": "cna",
            "base_score": 7.0,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.0"
        assert version == "v3.0"
        assert numeric == 7.0

    def test_adp_cvss_with_asterisk(self):
        """ADP scores should be marked with asterisk."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "adp:CISA-ADP",
            "base_score": 9.8,
            "base_severity": "CRITICAL",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "9.8"
        assert version == "v3.1*"
        assert numeric == 9.8

    def test_cvssv2_fallback(self):
        """CVSS v2.0 should be used as last CVSS fallback."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV2_0",
            "source": "cna",
            "base_score": 5.0,
            "base_severity": "MEDIUM",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "5.0"
        assert version == "v2.0"
        assert numeric == 5.0

    def test_text_severity_fallback(self):
        """Text severity should be shown when no numeric score."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "other",
            "source": "cna",
            "base_score": None,
            "base_severity": "High",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "High"
        assert version == "text"
        assert numeric is None

    def test_no_metric_returns_dash(self):
        """No metric should return dashes."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = None
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "-"
        assert version == "-"
        assert numeric is None

    def test_no_service_returns_dash(self):
        """No search_service should return dashes."""
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, None)
        assert score == "-"
        assert version == "-"
        assert numeric is None

    def test_score_formatting(self):
        """Score should be formatted with one decimal place."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.123456,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.1"  # Rounded to one decimal
        assert numeric == 7.123456  # Original value preserved

    def test_zero_score(self):
        """Zero score should be displayed, not treated as missing."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 0.0,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "0.0"
        assert version == "v3.1"
        assert numeric == 0.0


class TestOutputFormat:
    """Tests for output format options."""

    def test_output_format_values(self):
        """OutputFormat should have expected values."""
        assert OutputFormat.JSON == "json"
        assert OutputFormat.TABLE == "table"
        assert OutputFormat.MARKDOWN == "markdown"

    def test_output_format_is_string_enum(self):
        """OutputFormat values should be usable as strings."""
        assert str(OutputFormat.JSON) == "json"
        assert str(OutputFormat.TABLE) == "table"
