"""Core configuration for cvecli."""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Default paths relative to project root
DEFAULT_DATA_DIR = Path("data")
DEFAULT_DOWNLOAD_DIR = Path("download")
DEFAULT_CVE_SUBDIR = "cve_github/individual"

# Default settings
DEFAULT_YEARS = 10
CURRENT_YEAR = datetime.now().year


class Config:
    """Configuration management for cvecli.

    Reads from environment variables or uses defaults.
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        download_dir: Optional[Path] = None,
        default_years: Optional[int] = None,
    ):
        if sys.platform == "darwin":
            user_data = Path.home() / "Library" / "Application Support" / "cvecli"
        elif os.name == "nt":
            user_data = (
                Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
                / "cvecli"
            )
        else:
            user_data = (
                Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
                / "cvecli"
            )

        # Data directory
        self.data_dir = data_dir or Path(os.environ.get("CVE_DATA_DIR", user_data))

        # Resolve once so all reads in this session use one coherent release.
        self.storage_dir = self.data_dir
        self.database_dir = self.data_dir
        current = self.storage_dir / "CURRENT"
        if current.exists():
            snapshot = current.read_text().strip()
            if (
                not snapshot
                or snapshot in (".", "..")
                or Path(snapshot).name != snapshot
            ):
                raise ValueError("Invalid database snapshot pointer")
            self.database_dir = self.storage_dir / "snapshots" / snapshot

        # Download directory
        self.download_dir = download_dir or Path(
            os.environ.get("CVE_DOWNLOAD_DIR", self.data_dir / "download")
        )

        # Default years to download
        self.default_years = default_years or int(
            os.environ.get("CVE_DEFAULT_YEARS", DEFAULT_YEARS)
        )

    @property
    def cve_dir(self) -> Path:
        """Directory containing individual CVE JSON files."""
        return self.download_dir / DEFAULT_CVE_SUBDIR

    @property
    def cves_parquet(self) -> Path:
        """Path to extracted CVEs parquet file."""
        return self.database_dir / "cves.parquet"

    @property
    def cve_descriptions_parquet(self) -> Path:
        """Path to CVE descriptions parquet file."""
        return self.database_dir / "cve_descriptions.parquet"

    @property
    def cve_metrics_parquet(self) -> Path:
        """Path to CVE metrics parquet file."""
        return self.database_dir / "cve_metrics.parquet"

    @property
    def cve_products_parquet(self) -> Path:
        """Path to CVE products parquet file."""
        return self.database_dir / "cve_products.parquet"

    @property
    def cve_versions_parquet(self) -> Path:
        """Path to CVE versions parquet file."""
        return self.database_dir / "cve_versions.parquet"

    @property
    def cve_cwes_parquet(self) -> Path:
        """Path to CVE-CWE mapping parquet file."""
        return self.database_dir / "cve_cwes.parquet"

    @property
    def cve_references_parquet(self) -> Path:
        """Path to CVE references parquet file."""
        return self.database_dir / "cve_references.parquet"

    @property
    def cve_credits_parquet(self) -> Path:
        """Path to CVE credits parquet file."""
        return self.database_dir / "cve_credits.parquet"

    @property
    def cve_tags_parquet(self) -> Path:
        """Path to CVE tags parquet file."""
        return self.database_dir / "cve_tags.parquet"

    @property
    def capec_json(self) -> Path:
        """Path to CAPEC JSON file."""
        return self.data_dir / "capec.json"

    @property
    def cwe_json(self) -> Path:
        """Path to CWE JSON file."""
        return self.data_dir / "cwe.json"

    @property
    def capec_xml(self) -> Path:
        """Path to downloaded CAPEC XML file."""
        return self.download_dir / "capec" / "attack_patterns.xml"

    @property
    def cwe_xml(self) -> Path:
        """Path to downloaded CWE XML file."""
        return self.download_dir / "cwe" / "cwec_latest.xml"

    @property
    def cve_zip(self) -> Path:
        """Path to downloaded CVE zip file."""
        return self.download_dir / "cve_github" / "cvelistV5-main.zip"

    def get_year_range(self, years: Optional[int] = None) -> tuple[int, int]:
        """Get the year range to process.

        Args:
            years: Number of years to include. If None, uses default_years.

        Returns:
            Tuple of (start_year, end_year) inclusive.
        """
        years = years or self.default_years
        end_year = CURRENT_YEAR
        start_year = end_year - years + 1
        return (start_year, end_year)

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        (self.download_dir / "capec").mkdir(parents=True, exist_ok=True)
        (self.download_dir / "cwe").mkdir(parents=True, exist_ok=True)
        (self.download_dir / "cve_github").mkdir(parents=True, exist_ok=True)


# Global default config instance
_default_config: Optional[Config] = None


def get_config() -> Config:
    """Get the default configuration instance."""
    global _default_config
    if _default_config is None:
        _default_config = Config()
    return _default_config


def reset_config() -> None:
    """Reset the global configuration instance.

    This is primarily useful for testing to ensure a clean state.
    """
    global _default_config
    _default_config = None
