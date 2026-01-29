"""Parquet data models for CVE data.

This module defines Pydantic models and Polars schemas for the normalized
CVE parquet files. These models provide type safety and IDE support when
working with CVE data.

The models correspond to the following parquet files:
- cves.parquet: CVERecord
- cve_descriptions.parquet: CVEDescription
- cve_metrics.parquet: CVEMetric
- cve_products.parquet: CVEProduct
- cve_versions.parquet: CVEVersion
- cve_cwes.parquet: CVECWE
- cve_references.parquet: CVEReference
- cve_credits.parquet: CVECredit
- cve_tags.parquet: CVETag
"""

from pathlib import Path
from typing import List, NamedTuple, Optional, Union

import polars as pl
from pydantic import BaseModel

# =============================================================================
# Pydantic Models - Normalized CVE representation
# =============================================================================


class CVERecord(BaseModel):
    """Core CVE metadata - one record per CVE."""

    # Identifiers
    cve_id: str
    data_type: str  # CVE_RECORD
    data_version: str  # 5.0, 5.1

    # Metadata
    state: str  # PUBLISHED, REJECTED, RESERVED
    assigner_org_id: Optional[str] = None
    assigner_short_name: Optional[str] = None

    # Dates from cveMetadata
    date_reserved: Optional[str] = None
    date_published: Optional[str] = None
    date_updated: Optional[str] = None
    date_rejected: Optional[str] = None

    # CNA container metadata
    cna_date_public: Optional[str] = None
    cna_title: Optional[str] = None
    cna_provider_org_id: Optional[str] = None
    cna_provider_short_name: Optional[str] = None
    cna_provider_date_updated: Optional[str] = None

    # Source info
    source_discovery: Optional[str] = None
    source_defect: Optional[str] = None  # comma-separated if multiple

    # Aggregated fields for quick filtering (derived, but useful)
    has_cna_metrics: bool = False
    has_adp_metrics: bool = False
    has_affected: bool = False
    has_references: bool = False
    has_credits: bool = False


class CVEDescription(BaseModel):
    """CVE descriptions - multiple per CVE (different languages, sources)."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    lang: str
    value: str
    supporting_media_type: Optional[str] = None  # e.g., "text/html"
    supporting_media_base64: Optional[bool] = None


class CVEMetric(BaseModel):
    """CVSS and other metrics - normalized with all component fields."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"

    # Metric type
    metric_type: str  # "cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0", "other", "ssvc"
    format: Optional[str] = None  # for "other" type, e.g., "CVSS"

    # Scores
    base_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

    # Severity
    base_severity: Optional[str] = None
    vector_string: Optional[str] = None
    version: Optional[str] = None

    # CVSS v2 specific
    access_vector: Optional[str] = None  # v2
    access_complexity: Optional[str] = None  # v2
    authentication: Optional[str] = None  # v2

    # CVSS v3/v4 shared
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None

    # CVSS v4 additional
    attack_requirements: Optional[str] = None
    vulnerable_system_confidentiality: Optional[str] = None
    vulnerable_system_integrity: Optional[str] = None
    vulnerable_system_availability: Optional[str] = None
    subsequent_system_confidentiality: Optional[str] = None
    subsequent_system_integrity: Optional[str] = None
    subsequent_system_availability: Optional[str] = None

    # "other" type content (for ssvc, text severity, etc.)
    other_type: Optional[str] = None  # e.g., "ssvc", "unknown"
    other_content: Optional[str] = None  # JSON-encoded content


class CVEProduct(BaseModel):
    """Affected products - one record per affected product entry."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    product_id: str  # unique id within CVE for linking to versions

    vendor: Optional[str] = None
    product: Optional[str] = None
    package_name: Optional[str] = None
    collection_url: Optional[str] = None
    repo: Optional[str] = None
    modules: Optional[str] = None  # comma-separated
    program_files: Optional[str] = None  # comma-separated
    program_routines: Optional[str] = None  # comma-separated
    platforms: Optional[str] = None  # comma-separated
    default_status: Optional[str] = None
    cpes: Optional[str] = None  # comma-separated CPE strings
    package_url: Optional[str] = None  # Package URL (PURL) identifier


class CVEVersion(BaseModel):
    """Version ranges for affected products."""

    cve_id: str
    product_id: str  # links to CVEProduct

    version: Optional[str] = None
    version_type: Optional[str] = None
    status: Optional[str] = None  # affected, unaffected, unknown
    less_than: Optional[str] = None
    less_than_or_equal: Optional[str] = None

    # Changes within a version range
    changes: Optional[str] = None  # JSON-encoded list of {at, status}


class CVECWE(BaseModel):
    """CWE/problem type mappings."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    cwe_id: Optional[str] = None
    cwe_type: str  # "CWE" or "text"
    lang: str
    description: str


class CVEReference(BaseModel):
    """References with tags."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    url: str
    name: Optional[str] = None
    tags: Optional[str] = None  # comma-separated


class CVECredit(BaseModel):
    """Credits and acknowledgments."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    lang: str
    value: str
    credit_type: Optional[str] = None
    user_uuid: Optional[str] = None


class CVETag(BaseModel):
    """CVE-level tags (x_legacyV4Record, x_generator, etc.)."""

    cve_id: str
    source: str  # "cna", "adp:<short_name>", or "metadata"
    tag_key: str
    tag_value: Optional[str] = None  # JSON-encoded if complex


class ExtractedData(NamedTuple):
    """Complete extracted data from a CVE."""

    cve: CVERecord
    descriptions: List[CVEDescription]
    metrics: List[CVEMetric]
    products: List[CVEProduct]
    versions: List[CVEVersion]
    cwes: List[CVECWE]
    references: List[CVEReference]
    credits: List[CVECredit]
    tags: List[CVETag]


class ExtractionError(NamedTuple):
    """Information about a CVE that failed to extract."""

    cve_id: str
    file_path: str
    error_type: str
    error_message: str


# Type alias for process result
ProcessResult = Union[ExtractedData, ExtractionError]


# =============================================================================
# Polars Schemas - For reading/writing parquet files with type safety
# =============================================================================

CVE_SCHEMA = {
    "cve_id": pl.Utf8,
    "data_type": pl.Utf8,
    "data_version": pl.Utf8,
    "state": pl.Utf8,
    "assigner_org_id": pl.Utf8,
    "assigner_short_name": pl.Utf8,
    "date_reserved": pl.Utf8,
    "date_published": pl.Utf8,
    "date_updated": pl.Utf8,
    "date_rejected": pl.Utf8,
    "cna_date_public": pl.Utf8,
    "cna_title": pl.Utf8,
    "cna_provider_org_id": pl.Utf8,
    "cna_provider_short_name": pl.Utf8,
    "cna_provider_date_updated": pl.Utf8,
    "source_discovery": pl.Utf8,
    "source_defect": pl.Utf8,
    "has_cna_metrics": pl.Boolean,
    "has_adp_metrics": pl.Boolean,
    "has_affected": pl.Boolean,
    "has_references": pl.Boolean,
    "has_credits": pl.Boolean,
}

DESCRIPTION_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "lang": pl.Utf8,
    "value": pl.Utf8,
    "supporting_media_type": pl.Utf8,
    "supporting_media_base64": pl.Boolean,
}

METRIC_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "metric_type": pl.Utf8,
    "format": pl.Utf8,
    "base_score": pl.Float64,
    "exploitability_score": pl.Float64,
    "impact_score": pl.Float64,
    "base_severity": pl.Utf8,
    "vector_string": pl.Utf8,
    "version": pl.Utf8,
    "access_vector": pl.Utf8,
    "access_complexity": pl.Utf8,
    "authentication": pl.Utf8,
    "attack_vector": pl.Utf8,
    "attack_complexity": pl.Utf8,
    "privileges_required": pl.Utf8,
    "user_interaction": pl.Utf8,
    "scope": pl.Utf8,
    "confidentiality_impact": pl.Utf8,
    "integrity_impact": pl.Utf8,
    "availability_impact": pl.Utf8,
    "attack_requirements": pl.Utf8,
    "vulnerable_system_confidentiality": pl.Utf8,
    "vulnerable_system_integrity": pl.Utf8,
    "vulnerable_system_availability": pl.Utf8,
    "subsequent_system_confidentiality": pl.Utf8,
    "subsequent_system_integrity": pl.Utf8,
    "subsequent_system_availability": pl.Utf8,
    "other_type": pl.Utf8,
    "other_content": pl.Utf8,
}

PRODUCT_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "product_id": pl.Utf8,
    "vendor": pl.Utf8,
    "product": pl.Utf8,
    "package_name": pl.Utf8,
    "collection_url": pl.Utf8,
    "repo": pl.Utf8,
    "modules": pl.Utf8,
    "program_files": pl.Utf8,
    "program_routines": pl.Utf8,
    "platforms": pl.Utf8,
    "default_status": pl.Utf8,
    "cpes": pl.Utf8,
    "package_url": pl.Utf8,
}

VERSION_SCHEMA = {
    "cve_id": pl.Utf8,
    "product_id": pl.Utf8,
    "version": pl.Utf8,
    "version_type": pl.Utf8,
    "status": pl.Utf8,
    "less_than": pl.Utf8,
    "less_than_or_equal": pl.Utf8,
    "changes": pl.Utf8,
}

CWE_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "cwe_id": pl.Utf8,
    "cwe_type": pl.Utf8,
    "lang": pl.Utf8,
    "description": pl.Utf8,
}

REFERENCE_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "url": pl.Utf8,
    "name": pl.Utf8,
    "tags": pl.Utf8,
}

CREDIT_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "lang": pl.Utf8,
    "value": pl.Utf8,
    "credit_type": pl.Utf8,
    "user_uuid": pl.Utf8,
}

TAG_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "tag_key": pl.Utf8,
    "tag_value": pl.Utf8,
}


# =============================================================================
# Typed DataFrame Loading Functions
# =============================================================================


class CVEDataFrames(NamedTuple):
    """Container for all CVE DataFrames with proper typing."""

    cves: pl.DataFrame
    descriptions: pl.DataFrame
    metrics: pl.DataFrame
    products: pl.DataFrame
    versions: pl.DataFrame
    cwes: pl.DataFrame
    references: pl.DataFrame
    credits: pl.DataFrame


def load_cves(path: Path) -> pl.DataFrame:
    """Load CVE records from parquet file.

    Args:
        path: Path to cves.parquet file.

    Returns:
        DataFrame with CVE records matching CVE_SCHEMA.
    """
    return pl.read_parquet(path)


def load_descriptions(path: Path) -> pl.DataFrame:
    """Load CVE descriptions from parquet file.

    Args:
        path: Path to cve_descriptions.parquet file.

    Returns:
        DataFrame with CVE descriptions matching DESCRIPTION_SCHEMA.
    """
    return pl.read_parquet(path)


def load_metrics(path: Path) -> pl.DataFrame:
    """Load CVE metrics from parquet file.

    Args:
        path: Path to cve_metrics.parquet file.

    Returns:
        DataFrame with CVE metrics matching METRIC_SCHEMA.
    """
    return pl.read_parquet(path)


def load_products(path: Path) -> pl.DataFrame:
    """Load CVE products from parquet file.

    Args:
        path: Path to cve_products.parquet file.

    Returns:
        DataFrame with CVE products matching PRODUCT_SCHEMA.
    """
    return pl.read_parquet(path)


def load_versions(path: Path) -> pl.DataFrame:
    """Load CVE versions from parquet file.

    Args:
        path: Path to cve_versions.parquet file.

    Returns:
        DataFrame with CVE versions matching VERSION_SCHEMA.
    """
    return pl.read_parquet(path)


def load_cwes(path: Path) -> pl.DataFrame:
    """Load CVE CWE mappings from parquet file.

    Args:
        path: Path to cve_cwes.parquet file.

    Returns:
        DataFrame with CWE mappings matching CWE_SCHEMA.
    """
    return pl.read_parquet(path)


def load_references(path: Path) -> pl.DataFrame:
    """Load CVE references from parquet file.

    Args:
        path: Path to cve_references.parquet file.

    Returns:
        DataFrame with CVE references matching REFERENCE_SCHEMA.
    """
    return pl.read_parquet(path)


def load_credits(path: Path) -> pl.DataFrame:
    """Load CVE credits from parquet file.

    Args:
        path: Path to cve_credits.parquet file.

    Returns:
        DataFrame with CVE credits matching CREDIT_SCHEMA.
    """
    return pl.read_parquet(path)


def load_all_dataframes(data_dir: Path) -> CVEDataFrames:
    """Load all CVE DataFrames from a data directory.

    Args:
        data_dir: Directory containing parquet files.

    Returns:
        CVEDataFrames containing all loaded DataFrames.

    Raises:
        FileNotFoundError: If required files are missing.
    """
    cves_path = data_dir / "cves.parquet"
    if not cves_path.exists():
        raise FileNotFoundError(
            f"CVE data not found at {cves_path}. "
            "Run 'cvecli db update' or 'cvecli db build extract-parquet' first."
        )

    return CVEDataFrames(
        cves=load_cves(cves_path),
        descriptions=load_descriptions(data_dir / "cve_descriptions.parquet"),
        metrics=load_metrics(data_dir / "cve_metrics.parquet"),
        products=load_products(data_dir / "cve_products.parquet"),
        versions=load_versions(data_dir / "cve_versions.parquet"),
        cwes=load_cwes(data_dir / "cve_cwes.parquet"),
        references=load_references(data_dir / "cve_references.parquet"),
        credits=load_credits(data_dir / "cve_credits.parquet"),
    )
