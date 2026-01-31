"""Database management commands for cvecli.

This module contains commands for managing the CVE database:
- db update: Download pre-built parquet files
- db status: Show database status
- db build download-json: Download raw JSON files
- db build extract-parquet: Extract JSON to parquet
- db build extract-embeddings: Generate embeddings
- db build create-manifest: Create manifest for distribution
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from cvecli import MANIFEST_SCHEMA_VERSION
from cvecli.core.config import Config
from cvecli.logging_config import get_logger
from cvecli.services.downloader import DownloadService
from cvecli.services.extractor import ExtractorService
from cvecli.services.embeddings import (
    EmbeddingsService,
    is_semantic_available,
)
from cvecli.exceptions import (
    SemanticDependencyError,
    ManifestIncompatibleError,
    ChecksumMismatchError,
)
from cvecli.services.artifact_fetcher import (
    ArtifactFetcher,
    SUPPORTED_SCHEMA_VERSION,
)

logger = get_logger(__name__)
console = Console()

# Database management subcommand group
db_app = typer.Typer(
    name="db",
    help="Database management commands",
    no_args_is_help=True,
)

# Build subcommand group for advanced/CI commands
build_app = typer.Typer(
    name="build",
    help="Advanced commands for building CVE database from source (used by CI)",
    no_args_is_help=True,
)
db_app.add_typer(build_app, name="build")


@db_app.command("update")
def db_update(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force update even if local is up-to-date"
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag", "-t", help="Specific release tag to download"
    ),
    prerelease: bool = typer.Option(
        False, "--prerelease", "-p", help="Include pre-release versions"
    ),
    embeddings: bool = typer.Option(
        False, "--embeddings", "-e", help="Download embeddings for semantic search"
    ),
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory (also used as download dir)",
    ),
) -> None:
    """Update CVE database from pre-built parquet files.

    This is the recommended way to get CVE data. It downloads pre-built
    parquet files from the cvecli-db repository, which is much faster than
    downloading and processing raw JSON files.

    By default, embeddings are not downloaded. Use --embeddings to download
    them for semantic search support.

    Example:
        cvecli db update
        cvecli db update --force
        cvecli db update --embeddings
        cvecli db update --tag v20260106
        cvecli db update --prerelease
        cvecli db update --data-dir /path/to/data
    """
    logger.info("Starting database update")
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path, download_dir=data_path)
    fetcher = ArtifactFetcher(config, repo=repo)

    try:
        result = fetcher.update(
            tag=tag,
            force=force,
            include_prerelease=prerelease,
            include_embeddings=embeddings,
        )

        if result["status"] == "up-to-date":
            console.print("[green]✓ Database is already up-to-date.[/green]")
            logger.info("Database already up-to-date")
        else:
            stats = result.get("stats", {})
            tag_display = result["tag"]
            if result.get("is_prerelease"):
                tag_display += " (pre-release)"
            console.print(f"[green]✓ Updated to {tag_display}[/green]")
            console.print(f"  - CVEs: {stats.get('cves', 0)}")
            console.print(f"  - Downloaded {len(result['downloaded'])} files")
            logger.info(
                "Database updated to %s with %d CVEs",
                tag_display,
                stats.get("cves", 0),
            )
            if result.get("skipped_semantic"):
                console.print()
                console.print(
                    "[dim]Tip: Use 'cvecli db update --embeddings' to download embeddings for semantic search.[/dim]"
                )

    except ManifestIncompatibleError as e:
        logger.error("Manifest incompatible: %s", e)
        console.print(f"[red]Error: {e}[/red]")
        console.print(
            "[yellow]Hint: Run 'pip install --upgrade cvecli' to get the latest version.[/yellow]"
        )
        raise typer.Exit(1)
    except ChecksumMismatchError as e:
        logger.error("Checksum mismatch: %s", e)
        console.print(f"[red]Error: {e}[/red]")
        console.print(
            "[yellow]Hint: Try running the command again. If the problem persists, the release may be corrupted.[/yellow]"
        )
        raise typer.Exit(1)
    except Exception as e:
        logger.exception("Error updating database")
        console.print(f"[red]Error updating database: {e}[/red]")
        raise typer.Exit(1)


@db_app.command("status")
def db_status(
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory",
    ),
) -> None:
    """Show database status and check for updates.

    Displays information about the local database and checks if
    a newer version is available from the cvecli-db repository.

    Example:
        cvecli db status
        cvecli db status --data-dir /path/to/data
    """
    logger.info("Checking database status")
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)
    fetcher = ArtifactFetcher(config, repo=repo)

    console.print("[bold]CVE Database Status[/bold]\n")

    # Local status
    local_manifest = fetcher.get_local_manifest()
    if local_manifest:
        console.print("[green]✓ Local database found[/green]")
        console.print(
            f"  - Schema version: {local_manifest.get('schema_version', 'unknown')}"
        )
        console.print(f"  - Generated: {local_manifest.get('generated_at', 'unknown')}")
        stats = local_manifest.get("stats", {})
        console.print(f"  - CVEs: {stats.get('cves', 'unknown')}")
        console.print(f"  - Files: {len(local_manifest.get('files', []))}")
    else:
        console.print("[yellow]⚠ No local database found[/yellow]")
        console.print("  Run 'cvecli db update' to download the database.")

    console.print()

    # Semantic search capability status
    if is_semantic_available():
        embeddings_service = EmbeddingsService(config, quiet=True)
        embeddings_stats = embeddings_service.get_stats()
        if embeddings_stats:
            console.print("[green]✓ Semantic search enabled[/green]")
            console.print(f"  - Embeddings: {embeddings_stats['count']}")
            console.print(f"  - Model: {embeddings_stats['model']}")
        else:
            console.print(
                "[yellow]⚠ Semantic search available but no embeddings[/yellow]"
            )
            console.print(
                "  Run 'cvecli db build extract-embeddings' to generate embeddings."
            )
    else:
        console.print("[dim]⚠ Semantic search not installed[/dim]")
        console.print("  Install with: pip install cvecli\\[semantic]")

    console.print()

    # Remote status
    try:
        status = fetcher.status()

        if status["remote"]["available"]:
            remote = status["remote"]["manifest"]
            console.print("[green]✓ Remote database available[/green]")
            console.print(
                f"  - Schema version: {remote.get('schema_version', 'unknown')}"
            )
            console.print(f"  - Generated: {remote.get('generated_at', 'unknown')}")
            remote_stats = remote.get("stats", {})
            console.print(f"  - CVEs: {remote_stats.get('cves', 'unknown')}")

            if status["needs_update"]:
                console.print("\n[yellow]⚠ Update available![/yellow]")
                console.print(
                    "  Run 'cvecli db update' to download the latest version."
                )
            else:
                console.print("\n[green]✓ Local database is up-to-date[/green]")
        else:
            console.print("[yellow]⚠ Could not check remote database[/yellow]")
    except Exception as e:
        logger.warning("Could not check remote database: %s", e)
        console.print(f"[yellow]⚠ Could not check remote database: {e}[/yellow]")

    console.print()
    console.print(f"[dim]Supported schema version: {SUPPORTED_SCHEMA_VERSION}[/dim]")
    console.print(f"[dim]Data directory: {config.data_dir}[/dim]")


@build_app.command("download-json")
def db_download_json(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to download (default: from config)"
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

    For most users, 'cvecli db update' is faster and easier.

    Example:
        cvecli db build download-json
        cvecli db build download-json --years 5
        cvecli db build download-json --all
        cvecli db build download-json --data-dir /path/to/data
    """
    logger.info("Starting JSON download")
    data_path = Path(data_dir) if data_dir else None
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
        "[dim]Hint: Run 'cvecli db extract-parquet' to convert to parquet format.[/dim]"
    )
    logger.info("JSON download complete")


@build_app.command("extract-parquet")
def db_extract_parquet(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to process (default: from config)"
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
    You must run 'cvecli db build download-json' first.

    For most users, 'cvecli db update' is faster and easier.

    Example:
        cvecli db build extract-parquet
        cvecli db build extract-parquet --years 5 --verbose
        cvecli db build extract-parquet --data-dir /path/to/data
    """
    logger.info("Starting parquet extraction")
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path, download_dir=data_path)
    if years:
        config.default_years = years

    # Check if JSON files exist
    if not config.cve_dir.exists():
        console.print("[red]Error: No CVE JSON files found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvecli db build download-json' first.[/yellow]"
        )
        raise typer.Exit(1)

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


@build_app.command("extract-embeddings")
def db_extract_embeddings(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to process (default: from config)"
    ),
    batch_size: int = typer.Option(
        256, "--batch-size", "-b", help="Number of CVEs to process per batch"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory",
    ),
) -> None:
    r"""Generate embeddings for semantic search.

    This creates embeddings from CVE titles and descriptions using the
    all-MiniLM-L6-v2 model via fastembed. These embeddings enable
    semantic (natural language) search across CVEs.

    Requires the 'semantic' optional dependency:
        pip install 'cvecli\[semantic]'

    You must have parquet data first - run 'cvecli db update' or 'cvecli db build extract-parquet'.

    Example:
        cvecli db build extract-embeddings
        cvecli db build extract-embeddings --years 5 --batch-size 512 --verbose
        cvecli db build extract-embeddings --data-dir /path/to/data
    """
    logger.info("Starting embeddings extraction")

    # Check for semantic dependency
    if not is_semantic_available():
        console.print("[red]Error: Semantic search dependencies not installed.[/red]")
        console.print()
        console.print("Install with:")
        console.print("  [cyan]pip install cvecli\\[semantic][/cyan]")
        console.print("  [dim]or with uv:[/dim]")
        console.print("  [cyan]uv pip install cvecli\\[semantic][/cyan]")
        raise typer.Exit(1)

    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)
    if years:
        config.default_years = years

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvecli db update' or 'cvecli db build extract-parquet' first.[/yellow]"
        )
        raise typer.Exit(1)

    console.print("[blue]Generating embeddings for semantic search...[/blue]")
    console.print(
        "[dim]Using model: sentence-transformers/all-MiniLM-L6-v2 (via fastembed)[/dim]"
    )

    try:
        service = EmbeddingsService(config, quiet=not verbose)
        result = service.extract_embeddings(batch_size=batch_size, years=years)

        console.print(f"[green]✓ Generated {result['count']} embeddings[/green]")
        console.print(f"  - Model: {result['model']}")
        console.print(f"  - Dimension: {result['dimension']}")
        console.print(f"  - Saved to: {result['path']}")
        logger.info("Generated %d embeddings", result["count"])

    except SemanticDependencyError as e:
        logger.error("Semantic dependency error: %s", e)
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        logger.exception("Error generating embeddings")
        console.print(f"[red]Error generating embeddings: {e}[/red]")
        raise typer.Exit(1)


@build_app.command("create-manifest")
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
        cvecli db build create-manifest
        cvecli db build create-manifest --source github-actions --release-status official
        cvecli db build create-manifest --release-status prerelease
        cvecli db build create-manifest --data-dir /path/to/data --output manifest.json
    """
    import polars as pl

    logger.info("Creating manifest")
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvecli db build extract-parquet' first.[/yellow]"
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

    # Optionally include embeddings if they exist
    embeddings_path = config.data_dir / "cve_embeddings.parquet"
    if embeddings_path.exists():
        parquet_files.append("cve_embeddings.parquet")

    # License and notice files to include from project
    license_files_info = [
        ("CVE_TERMS_OF_USE.md", "CVE_TERMS_OF_USE.md"),
        ("NOTICE.txt", "NOTICE.txt"),
    ]

    # Copy license files to data directory
    for source_name, target_name in license_files_info:
        source_path = None

        # Try 1: Development - relative to project root
        project_root = Path(__file__).parent.parent.parent.parent
        dev_path = project_root / "licences" / source_name
        if dev_path.exists():
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

        if source_path and source_path.exists():
            target_path = config.data_dir / target_name
            target_path.write_text(source_path.read_text())
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
