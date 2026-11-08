"""Installed builder commands must produce assets the reference client accepts."""

import hashlib
import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from cvecli import MANIFEST_SCHEMA_VERSION
from cvecli.cli.build import app
from cvecli.services.artifact_fetcher import ArtifactFetcher


def test_manifest_contains_complete_database_and_distribution_files(test_config):
    result = CliRunner().invoke(
        app,
        [
            "create-manifest",
            "-d",
            str(test_config.data_dir),
            "--source",
            "ci",
            "--release-status",
            "official",
        ],
    )
    assert result.exit_code == 0, result.exception
    manifest = json.loads((test_config.data_dir / "manifest.json").read_text())
    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest["source"] == "ci"
    names = {item["name"] for item in manifest["files"]}
    assert len([name for name in names if name.endswith(".parquet")]) == 9
    assert {"NOTICE.txt", "CVE_TERMS_OF_USE.md"}.issubset(names)
    assert not any("embedding" in name for name in names)
    for item in manifest["files"]:
        data = (test_config.data_dir / item["name"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(data).hexdigest()
        assert item["size"] == len(data)
    assert ArtifactFetcher(test_config, quiet=True).check_compatibility(manifest)


def test_manifest_refuses_incomplete_release(test_config):
    (test_config.data_dir / "cve_versions.parquet").unlink()
    result = CliRunner().invoke(
        app, ["create-manifest", "-d", str(test_config.data_dir)]
    )
    assert result.exit_code != 0
    assert not (test_config.data_dir / "manifest.json").exists()


@pytest.mark.parametrize("command", ["download-json", "extract-parquet"])
def test_builder_passes_years_and_directories(tmp_path, command):
    from cvecli.core.config import Config

    config = Config(data_dir=tmp_path, download_dir=tmp_path)
    config.cve_dir.mkdir(parents=True)
    target = (
        "cvecli.cli.build.DownloadService"
        if command == "download-json"
        else "cvecli.services.extractor.ExtractorService"
    )
    with patch(target) as service:
        service.return_value.extract_all.return_value = {"stats": {"cves": 1}}
        result = CliRunner().invoke(app, [command, "--years", "3", "-d", str(tmp_path)])
        assert result.exit_code == 0, result.exception
        supplied = service.call_args.args[0]
        assert supplied.default_years == 3
        assert supplied.data_dir == tmp_path
        assert supplied.download_dir == tmp_path


def test_manifest_preserves_notice_bytes(test_config, tmp_path):
    resources = tmp_path / "resources"
    notices = resources / "licences"
    notices.mkdir(parents=True)
    content = "CVE®\r\nProvided “AS IS”.\r\n".encode("utf-8")
    for name in ("NOTICE.txt", "CVE_TERMS_OF_USE.md"):
        (notices / name).write_bytes(content)
    with patch("cvecli.cli.build.files", return_value=resources):
        result = CliRunner().invoke(
            app, ["create-manifest", "-d", str(test_config.data_dir)]
        )
    assert result.exit_code == 0, result.exception
    for name in ("NOTICE.txt", "CVE_TERMS_OF_USE.md"):
        assert (test_config.data_dir / name).read_bytes() == content
    manifest = json.loads((test_config.data_dir / "manifest.json").read_text())
    for item in manifest["files"]:
        if item["name"] in ("NOTICE.txt", "CVE_TERMS_OF_USE.md"):
            assert item["sha256"] == hashlib.sha256(content).hexdigest()
