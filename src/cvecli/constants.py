"""Constants and configuration values for cvecli.

This module centralizes all magic numbers, strings, and configuration
constants used throughout the cvecli package. This improves maintainability
and makes it easier to adjust values.
"""

import re
from enum import Enum
from typing import TypeAlias

# =============================================================================
# Type Aliases
# =============================================================================

CVEId: TypeAlias = str  # Format: CVE-YYYY-NNNNN


# =============================================================================
# Severity Levels
# =============================================================================


class SeverityLevel(Enum):
    """CVSS severity level classification.

    Based on CVSS v3.x scoring:
    - NONE: 0.0
    - LOW: 0.1-3.9
    - MEDIUM: 4.0-6.9
    - HIGH: 7.0-8.9
    - CRITICAL: 9.0-10.0
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# CVSS Severity Configuration
# =============================================================================

SEVERITY_THRESHOLDS: dict[SeverityLevel, tuple[float, float]] = {
    SeverityLevel.NONE: (0.0, 0.0),
    SeverityLevel.LOW: (0.1, 3.9),
    SeverityLevel.MEDIUM: (4.0, 6.9),
    SeverityLevel.HIGH: (7.0, 8.9),
    SeverityLevel.CRITICAL: (9.0, 10.0),
}

# Severity levels in order from lowest to highest
SEVERITY_ORDER: list[SeverityLevel] = [
    SeverityLevel.NONE,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]

# =============================================================================
# Embedding Model Configuration
# =============================================================================

# Default model for semantic embeddings (fastembed compatible)
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# Dimension of embeddings produced by the default model
EMBEDDING_DIMENSION = 384

# Default batch size for embedding generation
DEFAULT_EMBEDDING_BATCH_SIZE = 512

# Minimum similarity score for semantic search results
DEFAULT_MIN_SIMILARITY = 0.3

# =============================================================================
# HTTP Configuration
# =============================================================================

# Timeout for API requests (connect_timeout, read_timeout) in seconds
DEFAULT_API_TIMEOUT: tuple[int, int] = (10, 30)

# Timeout for file downloads (connect_timeout, read_timeout) in seconds
DEFAULT_DOWNLOAD_TIMEOUT: tuple[int, int] = (30, 300)

# Chunk size for streaming downloads (8KB)
DOWNLOAD_CHUNK_SIZE = 8192

# =============================================================================
# Data Source URLs
# =============================================================================

# CAPEC attack patterns XML
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

# CWE weakness enumeration XML (zipped)
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# CVE list repository (GitHub)
CVE_GITHUB_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

# Default cvecli-db repository for pre-built parquet files
DEFAULT_CVECLI_DB_REPO = "RomainRiv/cvecli-db"

# =============================================================================
# File Names and Paths
# =============================================================================

# Parquet file names
PARQUET_FILES = {
    "cves": "cves.parquet",
    "descriptions": "cve_descriptions.parquet",
    "metrics": "cve_metrics.parquet",
    "products": "cve_products.parquet",
    "versions": "cve_versions.parquet",
    "cwes": "cve_cwes.parquet",
    "references": "cve_references.parquet",
    "credits": "cve_credits.parquet",
    "tags": "cve_tags.parquet",
    "embeddings": "cve_embeddings.parquet",
}

# Files that require semantic search capability (optional)
SEMANTIC_FILES = {"cve_embeddings.parquet"}

# Manifest file name
MANIFEST_FILE = "manifest.json"

# Default subdirectory for CVE JSON files
DEFAULT_CVE_SUBDIR = "cve_github/individual"

# =============================================================================
# Default Settings
# =============================================================================

# Default number of years of CVE data to download/process
DEFAULT_YEARS = 10

# Default search result limit
DEFAULT_SEARCH_LIMIT = 100

# Maximum description length for truncated display
DEFAULT_MAX_DESCRIPTION_LENGTH = 80

# =============================================================================
# CVE ID Pattern
# =============================================================================

# Regex pattern to match CVE IDs (CVE-YYYY-NNNNN...)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# =============================================================================
# Output Formats
# =============================================================================


class OutputFormat:
    """Output format constants for CLI commands."""

    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"

    ALL = [JSON, TABLE, MARKDOWN]


# =============================================================================
# Search Modes
# =============================================================================


class SearchMode(Enum):
    """Search mode for text matching.

    - STRICT: Exact case-insensitive match (query must match exactly)
    - REGEX: Regular expression pattern matching
    - FUZZY: Case-insensitive substring matching (default, most flexible)
    - SEMANTIC: Natural language similarity search using embeddings
    """

    STRICT = "strict"
    REGEX = "regex"
    FUZZY = "fuzzy"
    SEMANTIC = "semantic"


# =============================================================================
# Metric Preferences
# =============================================================================

# Preference order for CVSS versions (higher = better)
CVSS_VERSION_PREFERENCE = {
    "cvssV4_0": 40,
    "cvssV3_1": 30,
    "cvssV3_0": 20,
    "cvssV2_0": 10,
}

# Preference for metric source (CNA preferred over ADP)
METRIC_SOURCE_PREFERENCE = {
    "cna": 100,
    "adp": 0,
}
