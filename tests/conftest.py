"""Root conftest.py - Shared fixtures for all tests.

This conftest provides core fixtures used across all test categories.
More specific fixtures are defined in subpackage conftest files.

Test Categories:
- tests/unit/services/: Library/service unit tests (no I/O, mocked deps)
- tests/unit/cli/: CLI presentation layer tests
- tests/integration/: Tests involving real file I/O and service integration

Fixture Data:
- tests/fixtures/data/: Small hand-crafted fixtures (9 CVEs)
- tests/fixtures/sample_data/: Diverse sampled fixtures (740 CVEs)
"""

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from cvecli.core.config import Config

# Path to static test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "data"
SAMPLE_DATA_DIR = Path(__file__).parent / "fixtures" / "sample_data"


# =============================================================================
# Core Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the path to static test fixtures directory (small dataset)."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def sample_data_dir() -> Path:
    """Return the path to sample data fixtures directory (larger, diverse dataset)."""
    return SAMPLE_DATA_DIR


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_config(temp_dir: Path) -> Config:
    """Create a Config pointing to a temporary directory.

    Use this fixture when you need a Config but don't need actual data files.
    For tests that need data, use `test_config` instead.
    """
    download_dir = temp_dir / "download"
    cve_dir = download_dir / "cve_github" / "individual"
    cve_dir.mkdir(parents=True)

    return Config(
        data_dir=temp_dir,
        download_dir=download_dir,
    )


@pytest.fixture
def test_config(temp_dir: Path, fixtures_dir: Path) -> Config:
    """Create a Config pointing to a temp directory with static fixture data.

    This copies the static parquet fixtures to a temporary directory,
    allowing tests to read from consistent data without side effects.
    """
    import shutil

    data_dir = temp_dir / "data"
    data_dir.mkdir(parents=True)

    # Copy all parquet files from fixtures to temp data dir
    for parquet_file in fixtures_dir.glob("*.parquet"):
        shutil.copy(parquet_file, data_dir / parquet_file.name)

    download_dir = temp_dir / "download"
    cve_dir = download_dir / "cve_github" / "individual"
    cve_dir.mkdir(parents=True)

    return Config(
        data_dir=data_dir,
        download_dir=download_dir,
    )


@pytest.fixture
def sample_config(temp_dir: Path, sample_data_dir: Path) -> Config:
    """Create a Config pointing to a temp directory with sample data fixtures.

    This copies the larger sample_data parquet files to a temporary directory.
    The sample data contains ~740 diverse CVEs across all years and features.
    Use this for more comprehensive testing than test_config.
    """
    import shutil

    if not sample_data_dir.exists():
        pytest.skip(
            "Sample data not available - run 'python tests/fixtures/generate_sample_data.py'"
        )

    data_dir = temp_dir / "data"
    data_dir.mkdir(parents=True)

    # Copy all parquet files from sample_data to temp data dir
    for parquet_file in sample_data_dir.glob("*.parquet"):
        shutil.copy(parquet_file, data_dir / parquet_file.name)

    download_dir = temp_dir / "download"
    cve_dir = download_dir / "cve_github" / "individual"
    cve_dir.mkdir(parents=True)

    return Config(
        data_dir=data_dir,
        download_dir=download_dir,
    )


# =============================================================================
# Markers
# =============================================================================


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test (fast, no I/O)")
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (may involve I/O)"
    )
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line(
        "markers", "requires_real_data: mark test as requiring real CVE database"
    )
    config.addinivalue_line(
        "markers", "sample_data: mark test as using sample data (740 CVEs)"
    )


# =============================================================================
# Skip Conditions
# =============================================================================


@pytest.fixture
def real_data_config() -> Config:
    """Get Config pointing to real data, skip if not available.

    Use this for tests that need the real CVE database.
    """
    import polars as pl

    config = Config()
    if not config.cves_parquet.exists():
        pytest.skip("Real CVE data not available - run 'cvecli db update' first")

    # Verify schema is current
    try:
        df = pl.read_parquet(config.cves_parquet)
        if "cve_id" not in df.columns:
            pytest.skip(
                "Real CVE data is in old schema format - "
                "run 'cvecli db build extract-parquet' to regenerate"
            )
    except Exception as e:
        pytest.skip(f"Error reading parquet file: {e}")

    return config
