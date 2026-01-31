#!/usr/bin/env python3
"""Generate diverse sample CVE dataset for testing.

This script creates a representative test dataset by sampling CVEs across
multiple dimensions to maximize diversity:

- Years of publication (1999-2026)
- CVSS versions (2.0, 3.0, 3.1, 4.0, text-only)
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW, none)
- Metric sources (CNA, ADP, both)
- Data versions (5.0, 5.1, 5.2)
- States (PUBLISHED, REJECTED)
- Special features (PURL, CPE, credits, titles)
- Top CWEs and assigners
- Famous CVEs (Log4Shell, Heartbleed, etc.)

Usage:
    python generate_sample_data.py

Output:
    Creates sample_data/ directory with 9 parquet files containing ~740 CVEs.
"""

import random
from pathlib import Path
from typing import Dict, Set

import polars as pl

# Configuration constants
TARGET_SAMPLE_SIZE = 300
RANDOM_SEED = 42
OUTPUT_DIR = Path(__file__).parent / "sample_data"

# Set random seed for reproducibility
random.seed(RANDOM_SEED)


def load_data(data_dir: Path) -> Dict[str, pl.DataFrame]:
    """Load all CVE data tables.

    Args:
        data_dir: Path to directory containing parquet files.

    Returns:
        Dictionary mapping table names to DataFrames.
    """
    return {
        "cves": pl.read_parquet(data_dir / "cves.parquet"),
        "metrics": pl.read_parquet(data_dir / "cve_metrics.parquet"),
        "products": pl.read_parquet(data_dir / "cve_products.parquet"),
        "cwes": pl.read_parquet(data_dir / "cve_cwes.parquet"),
        "descriptions": pl.read_parquet(data_dir / "cve_descriptions.parquet"),
        "versions": pl.read_parquet(data_dir / "cve_versions.parquet"),
        "references": pl.read_parquet(data_dir / "cve_references.parquet"),
        "credits": pl.read_parquet(data_dir / "cve_credits.parquet"),
        "tags": pl.read_parquet(data_dir / "cve_tags.parquet"),
    }


def sample_by_year(cves: pl.DataFrame, samples_per_year: int = 10) -> Set[str]:
    """Sample CVEs evenly distributed across publication years.

    Args:
        cves: DataFrame containing CVE records.
        samples_per_year: Target number of CVEs to sample per year.

    Returns:
        Set of CVE IDs sampled across years.
    """
    sampled = set()
    cves_with_year = cves.with_columns(
        pl.col("date_published").str.slice(0, 4).alias("year")
    )

    years = sorted([y for y in cves_with_year["year"].unique().to_list() if y])

    for year in years:
        year_cves = cves_with_year.filter(pl.col("year") == year)["cve_id"].to_list()
        sample_size = min(samples_per_year, len(year_cves))
        sampled.update(random.sample(year_cves, sample_size))

    print(f"Sampled {len(sampled)} CVEs across {len(years)} years")
    return sampled


def sample_by_cvss_version(
    metrics: pl.DataFrame, cves: pl.DataFrame, samples_per_version: int = 15
) -> Set[str]:
    """Sample CVEs across different CVSS scoring versions.

    Args:
        metrics: DataFrame containing CVSS metrics.
        cves: DataFrame containing CVE records.
        samples_per_version: Target samples per CVSS version.

    Returns:
        Set of CVE IDs covering different CVSS versions.
    """
    sampled = set()

    for version in ["2.0", "3.0", "3.1", "4.0"]:
        version_cves = (
            metrics.filter(pl.col("version") == version)["cve_id"].unique().to_list()
        )
        sample_size = min(samples_per_version, len(version_cves))
        sampled.update(random.sample(version_cves, sample_size))
        print(f"  CVSS {version}: sampled {sample_size}")

    # Also sample CVEs with text-only severity (no CVSS version)
    text_only = (
        metrics.filter(
            (pl.col("version").is_null()) & (pl.col("other_type").is_not_null())
        )["cve_id"]
        .unique()
        .to_list()
    )
    if text_only:
        sample_size = min(samples_per_version, len(text_only))
        sampled.update(random.sample(text_only, sample_size))
        print(f"  Text-only severity: sampled {sample_size}")

    print(f"Sampled {len(sampled)} CVEs by CVSS version")
    return sampled


def sample_by_severity(
    metrics: pl.DataFrame, samples_per_severity: int = 15
) -> Set[str]:
    """Sample CVEs across all severity levels.

    Args:
        metrics: DataFrame containing CVSS metrics with severity ratings.
        samples_per_severity: Target samples per severity level.

    Returns:
        Set of CVE IDs covering different severities.
    """
    sampled = set()

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_cves = (
            metrics.filter(pl.col("base_severity").str.to_uppercase() == severity)[
                "cve_id"
            ]
            .unique()
            .to_list()
        )
        sample_size = min(samples_per_severity, len(severity_cves))
        if severity_cves:
            sampled.update(random.sample(severity_cves, sample_size))
            print(f"  {severity}: sampled {sample_size}")

    print(f"Sampled {len(sampled)} CVEs by severity")
    return sampled


def sample_by_metric_source(
    metrics: pl.DataFrame, samples_per_source: int = 20
) -> Set[str]:
    """Sample CVEs by metric source (CNA vs ADP).

    Args:
        metrics: DataFrame containing CVSS metrics with source information.
        samples_per_source: Target samples per metric source type.

    Returns:
        Set of CVE IDs covering different metric sources.
    """
    sampled = set()

    # CNA-only metrics
    cna_cves = metrics.filter(pl.col("source") == "cna")["cve_id"].unique().to_list()
    adp_cves = (
        metrics.filter(pl.col("source").str.contains("adp"))["cve_id"]
        .unique()
        .to_list()
    )

    # CVEs with both CNA and ADP
    both = set(cna_cves) & set(adp_cves)
    cna_only = set(cna_cves) - both
    adp_only = set(adp_cves) - both

    for name, cve_set in [
        ("CNA-only", cna_only),
        ("ADP-only", adp_only),
        ("Both", both),
    ]:
        cve_list = list(cve_set)
        sample_size = min(samples_per_source, len(cve_list))
        if cve_list:
            sampled.update(random.sample(cve_list, sample_size))
            print(f"  {name}: sampled {sample_size}")

    print(f"Sampled {len(sampled)} CVEs by metric source")
    return sampled


def sample_by_data_version(
    cves: pl.DataFrame, samples_per_version: int = 15
) -> Set[str]:
    """Sample CVEs across different CVE schema versions.

    Args:
        cves: DataFrame containing CVE records.
        samples_per_version: Target samples per schema version.

    Returns:
        Set of CVE IDs covering different data versions.
    """
    sampled = set()

    for version in ["5.0", "5.1", "5.2"]:
        version_cves = cves.filter(pl.col("data_version") == version)[
            "cve_id"
        ].to_list()
        sample_size = min(samples_per_version, len(version_cves))
        if version_cves:
            sampled.update(random.sample(version_cves, sample_size))
            print(f"  Version {version}: sampled {sample_size}")

    print(f"Sampled {len(sampled)} CVEs by data version")
    return sampled


def sample_by_state(cves: pl.DataFrame, num_rejected: int = 10) -> Set[str]:
    """Sample rejected CVEs for testing edge cases.

    Args:
        cves: DataFrame containing CVE records.
        num_rejected: Number of rejected CVEs to sample.

    Returns:
        Set of rejected CVE IDs.
    """
    sampled = set()

    rejected = cves.filter(pl.col("state") == "REJECTED")["cve_id"].to_list()
    sample_size = min(num_rejected, len(rejected))
    if rejected:
        sampled.update(random.sample(rejected, sample_size))
        print(f"  REJECTED: sampled {sample_size}")

    print(f"Sampled {len(sampled)} rejected CVEs")
    return sampled


def sample_special_features(
    cves: pl.DataFrame, products: pl.DataFrame, samples_per_feature: int = 10
) -> Set[str]:
    """Sample CVEs with special features (PURL, CPE, credits, titles).

    Args:
        cves: DataFrame containing CVE records.
        products: DataFrame containing affected products.
        samples_per_feature: Target samples per feature type.

    Returns:
        Set of CVE IDs with various special features.
    """
    sampled = set()

    # CVEs with PURL
    purl_cves = (
        products.filter(pl.col("package_url").is_not_null())["cve_id"]
        .unique()
        .to_list()
    )
    # Take all of them since there are only 41
    sampled.update(purl_cves)
    print(f"  With PURL: sampled {len(purl_cves)}")

    # CVEs with CPE
    cpe_cves = (
        products.filter(pl.col("cpes").is_not_null())["cve_id"].unique().to_list()
    )
    sample_size = min(samples_per_feature, len(cpe_cves))
    sampled.update(random.sample(cpe_cves, sample_size))
    print(f"  With CPE: sampled {sample_size}")

    # CVEs with credits
    with_credits = cves.filter(pl.col("has_credits"))["cve_id"].to_list()
    sample_size = min(samples_per_feature, len(with_credits))
    sampled.update(random.sample(with_credits, sample_size))
    print(f"  With credits: sampled {sample_size}")

    # CVEs with title
    with_title = cves.filter(pl.col("cna_title").is_not_null())["cve_id"].to_list()
    sample_size = min(samples_per_feature, len(with_title))
    sampled.update(random.sample(with_title, sample_size))
    print(f"  With title: sampled {sample_size}")

    print(f"Sampled {len(sampled)} CVEs with special features")
    return sampled


def sample_by_cwe(
    cwes: pl.DataFrame, samples_per_cwe: int = 5, top_n_cwes: int = 20
) -> Set[str]:
    """Sample CVEs from most common CWE categories.

    Args:
        cwes: DataFrame containing CWE mappings.
        samples_per_cwe: Target samples per CWE.
        top_n_cwes: Number of top CWEs to sample from.

    Returns:
        Set of CVE IDs covering top CWEs.
    """
    sampled = set()

    # Get top CWEs
    top_cwes = (
        cwes.filter(pl.col("cwe_id").is_not_null())
        .group_by("cwe_id")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(top_n_cwes)["cwe_id"]
        .to_list()
    )

    for cwe_id in top_cwes:
        cwe_cves = cwes.filter(pl.col("cwe_id") == cwe_id)["cve_id"].unique().to_list()
        sample_size = min(samples_per_cwe, len(cwe_cves))
        sampled.update(random.sample(cwe_cves, sample_size))

    print(f"Sampled {len(sampled)} CVEs from top {top_n_cwes} CWEs")
    return sampled


def sample_by_assigner(
    cves: pl.DataFrame, samples_per_assigner: int = 5, top_n_assigners: int = 15
) -> Set[str]:
    """Sample CVEs from most active CVE assigners.

    Args:
        cves: DataFrame containing CVE records.
        samples_per_assigner: Target samples per assigner.
        top_n_assigners: Number of top assigners to sample from.

    Returns:
        Set of CVE IDs from various assigners.
    """
    sampled = set()

    # Get top assigners
    top_assigners = (
        cves.group_by("assigner_short_name")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
        .head(top_n_assigners)["assigner_short_name"]
        .to_list()
    )

    for assigner in top_assigners:
        assigner_cves = cves.filter(pl.col("assigner_short_name") == assigner)[
            "cve_id"
        ].to_list()
        sample_size = min(samples_per_assigner, len(assigner_cves))
        sampled.update(random.sample(assigner_cves, sample_size))

    print(f"Sampled {len(sampled)} CVEs from top {top_n_assigners} assigners")
    return sampled


def sample_famous_cves() -> Set[str]:
    """Include famous/well-known CVEs for recognizability and testing.

    Returns:
        Set of famous CVE IDs (Log4Shell, Heartbleed, etc.).
    """
    famous = {
        # Log4Shell
        "CVE-2021-44228",
        "CVE-2021-45046",
        # Heartbleed
        "CVE-2014-0160",
        # Shellshock
        "CVE-2014-6271",
        # EternalBlue
        "CVE-2017-0144",
        # Spectre/Meltdown
        "CVE-2017-5753",
        "CVE-2017-5754",
        # ProxyLogon
        "CVE-2021-26855",
        # Spring4Shell
        "CVE-2022-22965",
        # Apache Struts
        "CVE-2017-5638",
        # SolarWinds
        "CVE-2020-10148",
        # MOVEit
        "CVE-2023-34362",
        # PrintNightmare
        "CVE-2021-34527",
        # Citrix ADC
        "CVE-2019-19781",
        # Zerologon
        "CVE-2020-1472",
        # BlueKeep
        "CVE-2019-0708",
        # POODLE
        "CVE-2014-3566",
        # DROWN
        "CVE-2016-0800",
        # BEAST
        "CVE-2011-3389",
        # Dirty COW
        "CVE-2016-5195",
    }
    print(f"Added {len(famous)} famous CVEs")
    return famous


def filter_and_save(
    sampled_cve_ids: Set[str], data: Dict[str, pl.DataFrame], output_dir: Path
) -> None:
    """Filter data tables to sampled CVEs and save as parquet files.

    Args:
        sampled_cve_ids: Set of CVE IDs to include.
        data: Dictionary of DataFrames to filter.
        output_dir: Output directory for parquet files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Verify which CVEs actually exist
    all_cve_ids = set(data["cves"]["cve_id"].to_list())
    valid_ids = sampled_cve_ids & all_cve_ids
    missing = sampled_cve_ids - all_cve_ids

    if missing:
        print(f"Warning: {len(missing)} CVE IDs not found in database")
        for cve_id in sorted(missing)[:10]:
            print(f"  - {cve_id}")

    print(f"\nFiltering {len(valid_ids)} CVEs...")

    # Map from dict key to output filename (must match Config expectations)
    output_names = {
        "cves": "cves.parquet",
        "metrics": "cve_metrics.parquet",
        "products": "cve_products.parquet",
        "cwes": "cve_cwes.parquet",
        "descriptions": "cve_descriptions.parquet",
        "versions": "cve_versions.parquet",
        "references": "cve_references.parquet",
        "credits": "cve_credits.parquet",
        "tags": "cve_tags.parquet",
    }

    # Filter and save each table
    for name, df in data.items():
        filtered = df.filter(pl.col("cve_id").is_in(valid_ids))
        output_path = output_dir / output_names[name]
        filtered.write_parquet(output_path)
        print(f"  {name}: {len(filtered):,} rows -> {output_path.name}")


def print_sample_stats(data: Dict[str, pl.DataFrame], sampled_ids: Set[str]) -> None:
    """Print statistics about the sampled dataset.

    Args:
        data: Dictionary of DataFrames.
        sampled_ids: Set of sampled CVE IDs.
    """
    cves = data["cves"].filter(pl.col("cve_id").is_in(sampled_ids))
    metrics = data["metrics"].filter(pl.col("cve_id").is_in(sampled_ids))

    print("\n=== Sample Statistics ===")
    print(f"Total CVEs: {len(cves)}")

    # Year distribution
    cves_with_year = cves.with_columns(
        pl.col("date_published").str.slice(0, 4).alias("year")
    )
    years = sorted([y for y in cves_with_year["year"].unique().to_list() if y])
    print(f"Years covered: {min(years)} - {max(years)} ({len(years)} years)")

    # State distribution
    print(f"States: {cves.group_by('state').agg(pl.len()).to_dicts()}")

    # CVSS versions
    versions = metrics.group_by("version").agg(pl.len().alias("count")).to_dicts()
    print(f"CVSS versions: {versions}")

    # Severities
    severities = (
        metrics.group_by("base_severity").agg(pl.len().alias("count")).to_dicts()
    )
    print(f"Severities: {len(severities)} distinct values")

    # Data versions
    data_versions = cves.group_by("data_version").agg(pl.len()).to_dicts()
    print(f"Data versions: {data_versions}")


def main() -> None:
    """Main execution function."""
    print("=== Diverse CVE Sampling ===\n")

    # Load data from parent data directory
    data_dir = Path(__file__).parent.parent.parent / "data"
    print(f"Loading data from {data_dir}...")
    data = load_data(data_dir)
    print(f"Loaded {len(data['cves']):,} CVEs\n")

    # Collect samples from various dimensions
    sampled: Set[str] = set()

    print("Sampling by year...")
    sampled.update(sample_by_year(data["cves"], samples_per_year=8))

    print("\nSampling by CVSS version...")
    sampled.update(sample_by_cvss_version(data["metrics"], data["cves"]))

    print("\nSampling by severity...")
    sampled.update(sample_by_severity(data["metrics"]))

    print("\nSampling by metric source...")
    sampled.update(sample_by_metric_source(data["metrics"]))

    print("\nSampling by data version...")
    sampled.update(sample_by_data_version(data["cves"]))

    print("\nSampling rejected CVEs...")
    sampled.update(sample_by_state(data["cves"]))

    print("\nSampling special features...")
    sampled.update(sample_special_features(data["cves"], data["products"]))

    print("\nSampling by CWE...")
    sampled.update(sample_by_cwe(data["cwes"]))

    print("\nSampling by assigner...")
    sampled.update(sample_by_assigner(data["cves"]))

    print("\nAdding famous CVEs...")
    sampled.update(sample_famous_cves())

    print(f"\n{'='*50}")
    print(f"Total unique CVEs sampled: {len(sampled)}")

    # Print stats before saving
    print_sample_stats(data, sampled)

    # Save filtered data
    print(f"\nSaving to {OUTPUT_DIR}...")
    filter_and_save(sampled, data, OUTPUT_DIR)

    print("\nDone!")


if __name__ == "__main__":
    main()
