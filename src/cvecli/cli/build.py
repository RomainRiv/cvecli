"""Maintainer-only commands. Never write into an installed database snapshot."""

import hashlib
import json
from importlib.resources import files
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from cvecli import MANIFEST_SCHEMA_VERSION
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.downloader import DownloadService

app = typer.Typer(no_args_is_help=True)
console = Console()
logger = get_logger(__name__)


@app.command("download-json")
def db_download_json(
    years: int = typer.Option(
        None,
        "--years",
        "-y",
        min=1,
        help="Number of years to download (default: from config)",
    ),
    all_data: bool = typer.Option(
        False, "--all", "-a", help="Download all data (CVEs, CWEs, CAPECs)"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data and download directory",
    ),
) -> None:
    """Download raw CVE JSON files from GitHub.

    This downloads the raw JSON files from the cvelistV5 repository.
    Use this if you need the original JSON data or want to build
    parquet files locally.

    For most users, 'cvecli update' is faster and easier.

    Example:
        cvecli-build download-json
        cvecli-build download-json --years 5
        cvecli-build download-json --all
        cvecli-build download-json --data-dir /path/to/data
    """
    logger.info("Starting JSON download")
    data_path = Path(data_dir) if data_dir else Path("build-data")
    if (data_path / "CURRENT").exists() or data_path.parent.name == "snapshots":
        raise ValueError("Build into a separate directory, not an installed database")
    config = Config(data_dir=data_path, download_dir=data_path)
    if years:
        config.default_years = years

    service = DownloadService(config)

    if all_data:
        console.print("[blue]Downloading CAPEC data...[/blue]")
        service.download_capec()
        console.print("[green]✓ CAPEC downloaded[/green]\n")

        console.print("[blue]Downloading CWE data...[/blue]")
        service.download_cwe()
        console.print("[green]✓ CWE downloaded[/green]\n")

    console.print(
        f"[blue]Downloading CVE data (last {config.default_years} years)...[/blue]"
    )
    service.download_cves()
    console.print("[green]✓ CVE data downloaded[/green]\n")

    console.print("[blue]Extracting CVE JSON files...[/blue]")
    extracted = service.extract_cves()
    console.print(f"[green]✓ Extracted to {extracted}[/green]")

    console.print("\n[bold green]✓ Download complete![/bold green]")
    console.print(
        "[dim]Hint: Run 'cvecli-build extract-parquet' to convert to parquet format.[/dim]"
    )
    logger.info("JSON download complete")


@app.command("extract-parquet")
def db_extract_parquet(
    years: int = typer.Option(
        None,
        "--years",
        "-y",
        min=1,
        help="Number of years to process (default: from config)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data and download directory",
    ),
) -> None:
    """Extract CVE JSON files to parquet format.

    This converts the downloaded JSON files into optimized parquet files.
    You must run 'cvecli-build download-json' first.

    For most users, 'cvecli update' is faster and easier.

    Example:
        cvecli-build extract-parquet
        cvecli-build extract-parquet --years 5 --verbose
        cvecli-build extract-parquet --data-dir /path/to/data
    """
    logger.info("Starting parquet extraction")
    data_path = Path(data_dir) if data_dir else Path("build-data")
    if (data_path / "CURRENT").exists() or data_path.parent.name == "snapshots":
        raise ValueError("Build into a separate directory, not an installed database")
    config = Config(data_dir=data_path, download_dir=data_path)
    if years:
        config.default_years = years

    # Check if JSON files exist
    if not config.cve_dir.exists():
        console.print("[red]Error: No CVE JSON files found.[/red]")
        console.print("[yellow]Hint: Run 'cvecli-build download-json' first.[/yellow]")
        raise typer.Exit(1)

    from cvecli.services.extractor import ExtractorService

    service = ExtractorService(config)

    console.print("[blue]Extracting CVE data...[/blue]")
    result = service.extract_all()

    stats = result.get("stats", {})

    console.print(f"[green]✓ Extracted {stats.get('cves', 0)} CVEs[/green]")

    if verbose:
        console.print(f"  - Descriptions: {stats.get('descriptions', 0)}")
        console.print(f"  - Metrics: {stats.get('metrics', 0)}")
        console.print(f"  - Products: {stats.get('products', 0)}")
        console.print(f"  - Versions: {stats.get('versions', 0)}")
        console.print(f"  - CWEs: {stats.get('cwes', 0)}")
        console.print(f"  - References: {stats.get('references', 0)}")
        console.print(f"  - Credits: {stats.get('credits', 0)}")
        console.print(f"  - Tags: {stats.get('tags', 0)}")

    console.print("[bold green]✓ Extraction complete![/bold green]")
    logger.info("Parquet extraction complete: %d CVEs", stats.get("cves", 0))


@app.command("enrich-nvd")
def enrich_nvd(
    data_dir: Path = typer.Option(Path("build-data"), "--data-dir", "-d"),
    years: int = typer.Option(50, "--years", min=1),
    cve_feed: Optional[list[Path]] = typer.Option(
        None, "--cve-feed", help="Local NVD 2.0 CVE feeds; repeat for multiple files."
    ),
    match_feed: Optional[Path] = typer.Option(
        None, "--match-feed", help="Local NVD CPE Match 2.0 JSON or tar.gz archive."
    ),
) -> None:
    """Add NVD configurations and authoritative dictionary expansions for offline CPE lookup.

    Downloads yearly CVE feeds and the full CPE Match archive unless local inputs
    are supplied. The match archive is large (roughly 1 GB); import is streamed.
    """
    from cvecli.services.nvd import import_nvd

    if (data_dir / "CURRENT").exists() or data_dir.parent.name == "snapshots":
        raise ValueError("Enrich a build directory, not an installed snapshot")
    config = Config(data_dir=data_dir, download_dir=data_dir)
    if not config.cves_parquet.is_file():
        raise ValueError("Run extract-parquet before NVD enrichment")
    downloader = DownloadService(config)
    downloads = data_dir / "nvd-downloads"
    downloads.mkdir(exist_ok=True)

    def download(url: str, name: str) -> Path:
        destination = downloads / name
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        try:
            downloader._download_with_progress(url, temporary, name)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    if not cve_feed:
        first, last = config.get_year_range(years)
        cve_feed = [
            download(
                f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
                f"nvdcve-2.0-{year}.json.gz",
            )
            for year in range(max(2002, first), last + 1)
        ]
    if match_feed is None:
        match_feed = download(
            "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz",
            "nvdcpematch-2.0.tar.gz",
        )
    result = import_nvd(config, cve_feed, match_feed)
    console.print(json.dumps(result, indent=2))


@app.command("create-manifest")
def db_create_manifest(
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory containing parquet files",
    ),
    source: Optional[str] = typer.Option(
        None,
        "--source",
        "-s",
        help="Source identifier (e.g., 'ci', 'local', 'github-actions')",
    ),
    release_status: str = typer.Option(
        "draft",
        "--release-status",
        "-r",
        help="Release status: 'official', 'prerelease', or 'draft' (default: draft)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for manifest.json (default: <data-dir>/manifest.json)",
    ),
) -> None:
    """Create manifest.json for distribution.

    Generates a manifest file from the extracted parquet files. The manifest
    includes file checksums, statistics, and metadata required for the
    pre-built database distribution.

    This command is primarily used by CI/CD pipelines to create release artifacts.

    Example:
        cvecli-build create-manifest
        cvecli-build create-manifest --source github-actions --release-status official
        cvecli-build create-manifest --release-status prerelease
        cvecli-build create-manifest --data-dir /path/to/data --output manifest.json
    """
    import polars as pl

    logger.info("Creating manifest")
    data_path = Path(data_dir) if data_dir else Path("build-data")
    if (data_path / "CURRENT").exists() or data_path.parent.name == "snapshots":
        raise ValueError("Build into a separate directory, not an installed database")
    config = Config(data_dir=data_path)

    from cvecli.services.artifact_fetcher import REQUIRED_FILES

    missing = sorted(
        name for name in REQUIRED_FILES if not (data_path / name).is_file()
    )
    if missing:
        raise ValueError(
            "Cannot publish an incomplete database; missing: " + ", ".join(missing)
        )
    if release_status not in ("official", "prerelease", "draft"):
        raise ValueError("Release status must be official, prerelease, or draft")

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvecli-build extract-parquet' first.[/yellow]"
        )
        raise typer.Exit(1)

    console.print("[blue]Creating manifest...[/blue]")

    # List of parquet files to include in manifest
    parquet_files = [
        "cves.parquet",
        "cve_descriptions.parquet",
        "cve_metrics.parquet",
        "cve_products.parquet",
        "cve_versions.parquet",
        "cve_cwes.parquet",
        "cve_references.parquet",
        "cve_credits.parquet",
        "cve_tags.parquet",
    ]

    from cvecli.services.nvd import NVD_FILES

    present = [name for name in NVD_FILES if (data_path / name).is_file()]
    if present and len(present) != len(NVD_FILES):
        raise ValueError("NVD enrichment is incomplete")
    parquet_files.extend(sorted(present))

    # License and notice files to include from project
    license_files_info = [
        ("CVE_TERMS_OF_USE.md", "CVE_TERMS_OF_USE.md"),
        ("NOTICE.txt", "NOTICE.txt"),
    ]

    # Copy license files to data directory
    for source_name, target_name in license_files_info:
        source_path = None
        resource = files("cvecli").joinpath("licences").joinpath(source_name)

        # Try 1: Development - relative to project root
        project_root = Path(__file__).resolve().parents[3]
        dev_path = project_root / "licences" / source_name
        if resource.is_file():
            source_path = resource
        elif dev_path.exists():
            source_path = dev_path
        else:
            # Try 2: Installed package - try to find in sys.prefix/share
            import sys

            share_path = (
                Path(sys.prefix) / "share" / "cvecli" / "licences" / source_name
            )
            if share_path.exists():
                source_path = share_path
            else:
                # Try 3: Check current directory (for unusual installations)
                local_path = Path("licences") / source_name
                if local_path.exists():
                    source_path = local_path

        if source_path and source_path.is_file():
            target_path = config.data_dir / target_name
            target_path.write_bytes(source_path.read_bytes())
            console.print(f"[blue]Copied {target_name} to data directory[/blue]")
        else:
            console.print(
                f"[yellow]Warning: {source_name} not found in any location, skipping[/yellow]"
            )

    # Build files list with checksums
    files_info = []
    for filename in parquet_files:
        file_path = config.data_dir / filename
        if file_path.exists():
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)

            files_info.append(
                {
                    "name": filename,
                    "sha256": sha256.hexdigest(),
                    "size": file_path.stat().st_size,
                }
            )
        else:
            console.print(f"[yellow]Warning: {filename} not found, skipping[/yellow]")

    # Include license files
    for _, target_name in license_files_info:
        file_path = config.data_dir / target_name
        if file_path.exists():
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)

            files_info.append(
                {
                    "name": target_name,
                    "sha256": sha256.hexdigest(),
                    "size": file_path.stat().st_size,
                }
            )

    # Gather stats from CVEs parquet
    stats = {}
    try:
        df_cves = pl.read_parquet(config.cves_parquet)
        stats["cves"] = len(df_cves)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read CVEs stats: {e}[/yellow]")

    # Validate release_status
    valid_statuses = ["official", "prerelease", "draft"]
    if release_status not in valid_statuses:
        console.print(
            f"[red]Error: Invalid release status '{release_status}'. "
            f"Must be one of: {', '.join(valid_statuses)}[/red]"
        )
        raise typer.Exit(1)

    # Build manifest
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_status": release_status,
        "stats": stats,
        "files": files_info,
    }

    if source:
        manifest["source"] = source

    coverage_path = config.data_dir / "coverage.json"
    if coverage_path.exists():
        manifest["coverage"] = json.loads(coverage_path.read_text())

    nvd_path = config.data_dir / "nvd_metadata.json"
    if nvd_path.is_file():
        manifest["nvd"] = json.loads(nvd_path.read_text(encoding="utf-8"))

    # Determine output path
    output_path = Path(output) if output else config.data_dir / "manifest.json"

    # Write manifest
    output_path.write_text(json.dumps(manifest, indent=2))

    console.print(f"[green]✓ Manifest created: {output_path}[/green]")
    console.print(f"  - Schema version: {MANIFEST_SCHEMA_VERSION}")
    console.print(f"  - Release status: {release_status}")
    console.print(f"  - Files: {len(files_info)}")
    console.print(f"  - CVEs: {stats.get('cves', 'unknown')}")
    if source:
        console.print(f"  - Source: {source}")
    logger.info("Manifest created at %s", output_path)


def main() -> None:
    try:
        app()
    except ModuleNotFoundError as error:
        if error.name not in ("pydantic", "ijson"):
            raise
        console.print(
            "[red]Database production requires cvecli[build]. Install with: uv tool install 'cvecli[build]'[/red]"
        )
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
