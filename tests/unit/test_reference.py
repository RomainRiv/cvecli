"""Acceptance contracts for the small reference API and CLI."""

import json
import hashlib
from pathlib import Path
from unittest.mock import patch

import polars as pl
import pytest
from typer.testing import CliRunner

from cvecli import MANIFEST_SCHEMA_VERSION
from cvecli.cli.main import app
from cvecli.core.config import Config
from cvecli.models.parquet_models import (
    CVE_SCHEMA,
    DESCRIPTION_SCHEMA,
    PRODUCT_SCHEMA,
    VERSION_SCHEMA,
    METRIC_SCHEMA,
    REFERENCE_SCHEMA,
    CWE_SCHEMA,
)
from cvecli.services.artifact_fetcher import ArtifactFetcher, REQUIRED_FILES
from cvecli.services.search import CVESearchService, SearchRequest, ReferenceError


@pytest.fixture
def reference(tmp_path):
    schemas = {
        "cves": CVE_SCHEMA,
        "descriptions": DESCRIPTION_SCHEMA,
        "products": PRODUCT_SCHEMA,
        "versions": VERSION_SCHEMA,
        "metrics": METRIC_SCHEMA,
        "references": REFERENCE_SCHEMA,
        "cwes": CWE_SCHEMA,
    }
    data = {
        "cves": [
            {
                "cve_id": f"CVE-2024-{i:04}",
                "state": "PUBLISHED",
                "cna_title": title,
                "date_published": "2024-01-01",
            }
            for i, title in [
                (1, "Widget overflow"),
                (2, "Other vulnerability"),
                (3, "Third vulnerability"),
            ]
        ],
        "descriptions": [
            {
                "cve_id": "CVE-2024-0001",
                "source": "cna",
                "lang": "en",
                "value": "Remote memory corruption " * 30,
            },
            {
                "cve_id": "CVE-2024-0002",
                "source": "cna",
                "lang": "en",
                "value": "Widget memory bug",
            },
        ],
        "products": [
            {
                "cve_id": "CVE-2024-0001",
                "source": "cna",
                "product_id": "a",
                "vendor": "Acme",
                "product": "Widget",
                "package_url": "pkg:npm/widget",
            },
            {
                "cve_id": "CVE-2024-0001",
                "source": "cna",
                "product_id": "b",
                "vendor": "Other",
                "product": "Different",
            },
            {
                "cve_id": "CVE-2024-0003",
                "source": "cna",
                "product_id": "c",
                "vendor": "Widget",
                "product": "Gadget",
                "package_url": "pkg:npm/widget-extra",
            },
        ],
        "versions": [
            {
                "cve_id": "CVE-2024-0001",
                "product_id": "a",
                "version": "1.0",
                "less_than": "2.0",
                "status": "affected",
                "version_type": "custom",
                "changes": '[{"at":"1.5","status":"unaffected"}]',
            }
        ],
        "metrics": [
            {
                "cve_id": "CVE-2024-0001",
                "source": "cna",
                "metric_type": "cvssV3_1",
                "version": "3.1",
                "base_score": 8.1,
                "base_severity": "HIGH",
            },
            {
                "cve_id": "CVE-2024-0001",
                "source": "adp:test",
                "metric_type": "cvssV4_0",
                "version": "4.0",
                "base_score": 9.0,
                "base_severity": "CRITICAL",
            },
        ],
        "references": [
            {
                "cve_id": "CVE-2024-0001",
                "source": "cna",
                "url": "https://example.org/advisory",
            }
        ],
        "cwes": [],
    }
    for name, schema in schemas.items():
        filename = "cves.parquet" if name == "cves" else f"cve_{name}.parquet"
        pl.DataFrame(data[name], schema=schema).write_parquet(tmp_path / filename)
    return Config(data_dir=tmp_path)


def invoke(config, *args):
    result = CliRunner().invoke(
        app, [*args, "--json", "--data-dir", str(config.data_dir)]
    )
    payload = json.loads(result.stdout)
    return result, payload


def test_lexical_search_is_stable_and_searches_all_fields(reference):
    service = CVESearchService(reference)
    result = service.search(SearchRequest("widget"))
    assert result["total"] == 3
    assert result["results"][0]["id"] == "CVE-2024-0001"
    assert "vendor" in result["results"][2]["matched_fields"]
    assert service.search(SearchRequest("remote corruption"))["total"] == 1
    assert service.search(SearchRequest("remote impossible"))["total"] == 0
    assert (
        service.search(SearchRequest(product="Different", vendor="Acme"))["total"] == 0
    )


def test_pagination_and_output_bounds(reference):
    service = CVESearchService(reference)
    pages = [
        service.search(SearchRequest("widget", limit=1, offset=i)) for i in range(3)
    ]
    assert all(page["total"] == 3 and len(page["results"]) == 1 for page in pages)
    assert len({page["results"][0]["id"] for page in pages}) == 3
    assert pages[-1]["next_offset"] is None
    assert len(json.dumps(pages[0])) < 2500
    assert pages[0]["results"][0]["description_truncated"]
    with pytest.raises(ReferenceError):
        SearchRequest(limit=0)


def test_typed_metric_and_complete_evidence(reference):
    result = CVESearchService(reference).get(["CVE-2024-0001"])["results"][0]
    assert result["cvss"]["score"] == 8.1
    assert result["cvss"]["source"] == "cna"
    assert len(result["metrics"]) == 2
    assert len(result["description"]) > 240
    assert result["products"][0]["versions"][0]["changes"]
    assert result["products"][1]["versions"] == []
    assert result["references"][0]["url"] == "https://example.org/advisory"


def test_purl_version_is_metadata_not_an_assessment(reference):
    result = CVESearchService(reference).search(
        SearchRequest(purl="pkg:npm/widget@9.9")
    )
    assert result["total"] == 1
    assert result["package_query"] == {
        "identity": "pkg:npm/widget",
        "version": "9.9",
        "version_evaluated": False,
    }
    assert "assessments" not in result


@pytest.mark.parametrize(
    "arguments",
    [
        ("search", "no_such_term"),
        ("search", "widget"),
        ("get", "CVE-2024-0001"),
        ("products", "widget"),
        ("status",),
    ],
)
def test_success_and_absence_always_json(reference, arguments):
    result, payload = invoke(reference, *arguments)
    assert result.exit_code == 0, result.exception
    assert payload["schema_version"] == 1
    assert payload["errors"] == []


@pytest.mark.parametrize(
    "arguments",
    [
        ("search", "--limit", "invalid"),
        ("get",),
        ("search", "--semantic", "test"),
        ("search", "--after", "bad-date"),
        ("search", "--version", "1.0"),
    ],
)
def test_invalid_arguments_are_json(reference, arguments):
    result, payload = invoke(reference, *arguments)
    assert result.exit_code == 2
    assert payload["errors"][0]["code"] == "invalid_request"


def test_partial_batch_failure(reference):
    result, payload = invoke(reference, "get", "CVE-2024-0001", "CVE-2099-99999")
    assert result.exit_code == 1
    assert len(payload["results"]) == 1
    assert payload["errors"][0]["code"] == "not_found"


def test_status_is_offline_and_missing_data_explicit(reference):
    with patch("requests.get", side_effect=AssertionError("network access")):
        result, payload = invoke(reference, "status")
    assert result.exit_code == 0 and payload["ready"]
    (reference.data_dir / "cve_descriptions.parquet").unlink()
    result, payload = invoke(reference, "search", "widget")
    assert result.exit_code == 1
    assert payload["errors"][0]["code"] == "missing_data"


def test_local_snapshot_coverage_is_not_invented(reference):
    metadata = CVESearchService(reference).metadata()
    assert metadata["coverage"] is None
    assert metadata["source_updated_at"] is None


def test_snapshot_update_validation_retention_and_recovery(reference, tmp_path):
    root = tmp_path / "installed"
    fetcher = ArtifactFetcher(Config(data_dir=root), quiet=True)
    files = [
        {
            "name": name,
            "sha256": hashlib.sha256(
                (reference.data_dir / name).read_bytes()
            ).hexdigest(),
        }
        for name in sorted(REQUIRED_FILES)
    ]
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": "2026-11-08",
        "files": files,
    }
    release = {
        "tag_name": "v1",
        "assets": [
            {"name": item["name"], "browser_download_url": item["name"]}
            for item in files
        ],
    }

    def download(url, destination, *args, **kwargs):
        destination.write_bytes((reference.data_dir / url).read_bytes())

    with (
        patch.object(fetcher, "_get_latest_release", return_value=release),
        patch.object(fetcher, "fetch_manifest", return_value=manifest),
        patch.object(fetcher, "_download_file", side_effect=download),
    ):
        fetcher.update()
        reader = CVESearchService(Config(data_dir=root))
        assert reader.search(SearchRequest("widget"))["total"] == 3
        assert fetcher.update()["status"] == "up-to-date"
        # Corrupt installed bytes: the next update repairs, rather than reporting current.
        fetcher.config.cves_parquet.write_bytes(b"corrupt")
        assert fetcher.update()["status"] == "updated"
        pointer = (root / "CURRENT").read_text()
        with patch.object(
            fetcher, "_download_file", side_effect=OSError("interrupted")
        ):
            with pytest.raises(OSError):
                fetcher.update(force=True)
        assert (root / "CURRENT").read_text() == pointer
        assert CVESearchService(Config(data_dir=root)).status()["ready"]
        fetcher.update(force=True)
        assert len(list((root / "snapshots").iterdir())) == 2
        manifest["files"] = files[:-1]
        with pytest.raises(ValueError, match="incomplete"):
            fetcher.update(force=True)
        assert len(list((root / "snapshots").iterdir())) == 2


def test_default_storage_is_user_owned(monkeypatch, tmp_path):
    monkeypatch.delenv("CVE_DATA_DIR", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    config = Config()
    assert config.data_dir.is_relative_to(tmp_path)
    assert config.data_dir == config.database_dir


def test_download_checksum_failure_preserves_installed_file(tmp_path):
    from unittest.mock import MagicMock
    from cvecli.exceptions import ChecksumMismatchError

    fetcher = ArtifactFetcher(Config(data_dir=tmp_path), quiet=True)
    destination = tmp_path / "existing.parquet"
    destination.write_bytes(b"previous version")
    response = MagicMock()
    response.headers = {"content-length": "3"}
    response.iter_content.return_value = [b"bad"]
    with patch("requests.get", return_value=response):
        with pytest.raises(ChecksumMismatchError):
            fetcher._download_file("https://example.org/data", destination, "0" * 64)
    assert destination.read_bytes() == b"previous version"


def test_updates_are_serialized_and_lock_is_released(tmp_path):
    from cvecli.services.artifact_fetcher import update_lock

    with update_lock(tmp_path):
        with pytest.raises(OSError):
            with update_lock(tmp_path):
                pytest.fail("second updater acquired the lock")
    with update_lock(tmp_path):
        pass


def test_identical_json_when_stdout_is_redirected(reference, tmp_path):
    import os
    import subprocess
    import sys

    arguments = [
        sys.executable,
        "-m",
        "cvecli.cli.main",
        "search",
        "widget",
        "--limit",
        "1",
        "--json",
        "--data-dir",
        str(reference.data_dir),
    ]
    first = subprocess.run(
        arguments, check=True, capture_output=True, text=True, env=os.environ
    )
    output = tmp_path / "response.json"
    with output.open("w") as stream:
        subprocess.run(arguments, check=True, stdout=stream, env=os.environ)
    assert json.loads(first.stdout) == json.loads(output.read_text())
    assert len(json.loads(first.stdout)["results"]) == 1


def test_status_rejects_corrupt_related_table(reference):
    (reference.data_dir / "cve_products.parquet").write_bytes(b"corrupt")
    result, payload = invoke(reference, "status")
    assert result.exit_code == 1
    assert not payload["ready"]
    assert payload["invalid_tables"] == ["products"]
    assert payload["errors"][0]["code"] == "invalid_data"


def test_update_failure_is_not_reported_as_invalid_arguments(reference):
    with patch.object(
        ArtifactFetcher, "update", side_effect=ValueError("Invalid release manifest")
    ):
        result, payload = invoke(reference, "update")
    assert result.exit_code == 1
    assert payload["errors"][0]["code"] == "unavailable"
