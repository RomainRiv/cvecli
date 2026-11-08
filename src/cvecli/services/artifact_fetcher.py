"""Service for fetching pre-built parquet files from cvecli-db GitHub releases."""

import hashlib
import json
import os
import tempfile
import uuid
import shutil
import re
import sys
from contextlib import contextmanager

import polars as pl
from pathlib import Path
from typing import Any, Optional

import requests
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from cvecli import MANIFEST_SCHEMA_VERSION
from cvecli.services.search import TABLE_COLUMNS
from cvecli.core.config import Config, get_config
from cvecli.exceptions import ChecksumMismatchError, ManifestIncompatibleError

# Manifest schema version this cvecli version supports
SUPPORTED_SCHEMA_VERSION = MANIFEST_SCHEMA_VERSION

# Default cvecli-db repository
DEFAULT_CVECLI_DB_REPO = "RomainRiv/cvecli-db"  # Update with actual repo

# Tables required by the reference API; legacy release extras are ignored.
REQUIRED_FILES = {
    "cves.parquet",
    "cve_descriptions.parquet",
    "cve_products.parquet",
    "cve_versions.parquet",
    "cve_metrics.parquet",
    "cve_references.parquet",
    "cve_cwes.parquet",
}
OPTIONAL_FILES = {
    "cve_credits.parquet",
    "cve_tags.parquet",
    "cve_cpe_configurations.parquet",
    "cpe_matches.parquet",
    "CVE_TERMS_OF_USE.md",
    "NOTICE.txt",
}


@contextmanager
def update_lock(root: Path):
    """Serialize updates; the OS releases the lock even if a process crashes."""
    with (root / ".update.lock").open("a+b") as lock:
        if sys.platform == "win32":
            import msvcrt

            lock.write(b"0")
            lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if sys.platform == "win32":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Default timeouts for HTTP requests (connect timeout, read timeout) in seconds
DEFAULT_API_TIMEOUT = (10, 30)  # 10s connect, 30s read for API calls
DEFAULT_DOWNLOAD_TIMEOUT = (30, 300)  # 30s connect, 5min read for file downloads


class ArtifactFetcher:
    """Service for downloading pre-built CVE parquet files from GitHub releases."""

    def __init__(
        self,
        config: Optional[Config] = None,
        quiet: bool = False,
        repo: Optional[str] = None,
    ):
        """Initialize the artifact fetcher.

        Args:
            config: Configuration instance. Uses default if not provided.
            quiet: If True, suppress progress output.
            repo: GitHub repository in "owner/repo" format.
        """
        self.config = config or get_config()
        self.quiet = quiet
        self.repo = repo or os.environ.get("CVECLI_DB_REPO", DEFAULT_CVECLI_DB_REPO)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)

    def _get_latest_release(self, include_prerelease: bool = False) -> dict[str, Any]:
        """Get the latest release from the cvecli-db repository.

        Args:
            include_prerelease: If True, include pre-releases in search.

        Returns:
            Release metadata including tag_name and assets.
        """
        if include_prerelease:
            # Get all releases and find the latest (including pre-releases)
            url = f"https://api.github.com/repos/{self.repo}/releases"
            response = requests.get(url, timeout=DEFAULT_API_TIMEOUT)
            response.raise_for_status()
            releases = response.json()
            if not releases:
                raise ValueError("No releases found")
            # First release in the list is the latest (including pre-releases)
            result: dict[str, Any] = releases[0]
            return result
        else:
            # Get the latest official release only
            url = f"https://api.github.com/repos/{self.repo}/releases/latest"
            response = requests.get(url, timeout=DEFAULT_API_TIMEOUT)
            response.raise_for_status()
            latest_result: dict[str, Any] = response.json()
            return latest_result

    def _get_release_by_tag(self, tag: str) -> dict[str, Any]:
        """Get a specific release by tag.

        Args:
            tag: Release tag (e.g., "v20260106")

        Returns:
            Release metadata.
        """
        url = f"https://api.github.com/repos/{self.repo}/releases/tags/{tag}"
        response = requests.get(url, timeout=DEFAULT_API_TIMEOUT)
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result

    def _download_file(
        self,
        url: str,
        dest_path: Path,
        expected_sha256: Optional[str] = None,
        desc: Optional[str] = None,
    ) -> None:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=dest_path.parent) as temporary:
            staged = Path(temporary) / dest_path.name
            self._download_to_path(url, staged, expected_sha256, desc)
            os.replace(staged, dest_path)

    def _download_to_path(
        self,
        url: str,
        dest_path: Path,
        expected_sha256: Optional[str] = None,
        desc: Optional[str] = None,
    ) -> None:
        """Download a file with progress bar and optional checksum verification.

        Args:
            url: URL to download from.
            dest_path: Destination file path.
            expected_sha256: Expected SHA256 hash for verification.
            desc: Description for progress bar.
        """
        response = requests.get(url, stream=True, timeout=DEFAULT_DOWNLOAD_TIMEOUT)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        sha256 = hashlib.sha256()

        if self.quiet:
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        sha256.update(chunk)
        else:
            progress = Progress(
                TextColumn("{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
            )
            with progress:
                task = progress.add_task(desc or dest_path.name, total=total)
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            sha256.update(chunk)
                            progress.update(task, advance=len(chunk))

        # Verify checksum
        if expected_sha256:
            actual_sha256 = sha256.hexdigest()
            if actual_sha256 != expected_sha256:
                dest_path.unlink()  # Remove corrupted file
                raise ChecksumMismatchError(
                    filename=dest_path.name,
                    expected=expected_sha256,
                    actual=actual_sha256,
                )

    def fetch_manifest(
        self, tag: Optional[str] = None, include_prerelease: bool = False
    ) -> dict[str, Any]:
        """Fetch the manifest from a release.

        Args:
            tag: Release tag. If None, uses latest release.
            include_prerelease: If True, include pre-releases when fetching latest.

        Returns:
            Parsed manifest dictionary.
        """
        if tag:
            release = self._get_release_by_tag(tag)
        else:
            release = self._get_latest_release(include_prerelease=include_prerelease)

        # Find manifest asset
        manifest_asset = None
        for asset in release.get("assets", []):
            if asset["name"] == "manifest.json":
                manifest_asset = asset
                break

        if not manifest_asset:
            raise ValueError(
                f"No manifest.json found in release {release.get('tag_name')}"
            )

        # Download manifest
        response = requests.get(
            manifest_asset["browser_download_url"], timeout=DEFAULT_API_TIMEOUT
        )
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result

    def check_compatibility(self, manifest: dict) -> bool:
        """Check if the manifest is compatible with this version of cvecli.

        Args:
            manifest: Parsed manifest dictionary.

        Returns:
            True if compatible.

        Raises:
            ManifestIncompatibleError: If the schema version is incompatible.
        """
        schema_version = manifest.get("schema_version", 0)
        if schema_version != SUPPORTED_SCHEMA_VERSION:
            raise ManifestIncompatibleError(schema_version, SUPPORTED_SCHEMA_VERSION)
        return True

    def get_local_manifest(self) -> Optional[dict[str, Any]]:
        """Get the local manifest if it exists.

        Returns:
            Parsed manifest dictionary or None if not found.
        """
        manifest_path = self.config.database_dir / "manifest.json"
        if manifest_path.exists():
            result: dict[str, Any] = json.loads(manifest_path.read_text())
            return result
        return None

    def needs_update(
        self,
        remote_manifest: dict[str, Any],
        remote_tag: str,
        include_prerelease: bool,
    ) -> bool:
        """Check if local database needs to be updated.

        Args:
            remote_manifest: Remote manifest to compare against.
            remote_tag: Tag name of the remote release.
            include_prerelease: Whether user wants pre-releases.

        Returns:
            True if update is needed.
        """
        local_manifest = self.get_local_manifest()
        if not local_manifest:
            return True

        # Get release status from manifests
        remote_status = remote_manifest.get("release_status", "draft")
        local_status = local_manifest.get("release_status", "draft")

        # If user wants official but has pre-release/draft, update
        if (
            not include_prerelease
            and remote_status == "official"
            and local_status != "official"
        ):
            return True

        # If user wants pre-release but has different release, check by tag
        local_tag = local_manifest.get("release_tag")
        if local_tag and local_tag != remote_tag:
            # Different tags means we should update
            return True

        # Same tag/status, compare timestamps as fallback
        local_time = local_manifest.get("generated_at", "")
        remote_time = remote_manifest.get("generated_at", "")

        result: bool = remote_time > local_time
        return result

    def update(self, tag: Optional[str] = None, force: bool = False) -> dict:
        with update_lock(self.config.data_dir):
            # Re-resolve after locking: a concurrent updater may have finished.
            self.config.database_dir = Config(
                data_dir=self.config.data_dir
            ).database_dir
            return self._update(tag, force)

    def _update(self, tag: Optional[str], force: bool) -> dict:
        release = self._get_release_by_tag(tag) if tag else self._get_latest_release()
        tag_name = release["tag_name"]
        manifest = self.fetch_manifest(tag_name)
        self.check_compatibility(manifest)
        files = manifest.get("files", [])
        names = [item["name"] for item in files]
        if len(names) != len(set(names)) or not REQUIRED_FILES.issubset(names):
            raise ValueError(
                "Release manifest is incomplete or contains duplicate files"
            )
        files = [
            item for item in files if item["name"] in REQUIRED_FILES | OPTIONAL_FILES
        ]
        if any(
            not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) for item in files
        ):
            raise ValueError("Every database asset must have a SHA-256 checksum")
        complete = all(
            (path := self.config.database_dir / item["name"]).is_file()
            and file_digest(path) == item["sha256"]
            for item in files
        )
        if complete and not force and not self.needs_update(manifest, tag_name, False):
            return {"status": "up-to-date", "tag": tag_name, "downloaded": []}
        assets = {asset["name"]: asset for asset in release.get("assets", [])}
        missing = [item["name"] for item in files if item["name"] not in assets]
        if missing:
            raise ValueError("Missing release assets: " + ", ".join(missing))
        previous = self.config.database_dir
        with tempfile.TemporaryDirectory(dir=self.config.data_dir) as temporary:
            staging = Path(temporary)
            for item in files:
                name = item["name"]
                self._download_file(
                    assets[name]["browser_download_url"],
                    staging / name,
                    item["sha256"],
                    name,
                )
                if name.endswith(".parquet"):
                    schema = pl.read_parquet_schema(staging / name)
                    table = (
                        "cves"
                        if name == "cves.parquet"
                        else name.removeprefix("cve_").removesuffix(".parquet")
                    )
                    if name in (
                        "cve_cpe_configurations.parquet",
                        "cpe_matches.parquet",
                    ):
                        from cvecli.services.nvd import CONFIG_SCHEMA, MATCH_SCHEMA

                        expected = set(
                            CONFIG_SCHEMA
                            if name == "cve_cpe_configurations.parquet"
                            else MATCH_SCHEMA
                        )
                    else:
                        expected = TABLE_COLUMNS.get(table, {"cve_id"})
                    if not set(expected).issubset(schema):
                        raise ValueError(f"Invalid table: {name}")
            installed_manifest = {**manifest, "release_tag": tag_name, "files": files}
            (staging / "manifest.json").write_text(
                json.dumps(installed_manifest, indent=2)
            )
            snapshots = self.config.data_dir / "snapshots"
            snapshots.mkdir(exist_ok=True)
            snapshot_name = uuid.uuid4().hex
            destination = snapshots / snapshot_name
            os.replace(staging, destination)
            pointer = self.config.data_dir / f".CURRENT-{snapshot_name}"
            try:
                pointer.write_text(snapshot_name)
                os.replace(pointer, self.config.data_dir / "CURRENT")
            finally:
                pointer.unlink(missing_ok=True)
            self.config.database_dir = destination
            for path in snapshots.iterdir():
                if (
                    path not in (destination, previous)
                    and re.fullmatch(r"[0-9a-f]{32}", path.name)
                    and path.is_dir()
                    and not path.is_symlink()
                ):
                    shutil.rmtree(path)
        return {
            "status": "updated",
            "tag": tag_name,
            "downloaded": [item["name"] for item in files],
        }
