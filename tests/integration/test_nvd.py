"""End-to-end regressions from the official OpenSSH CPE query (31 CVEs)."""

import gzip
import io
import json
import tarfile
from pathlib import Path

import polars as pl
import pytest
from typer.testing import CliRunner

from cvecli.cli.build import app
from cvecli.models.parquet_models import CVE_SCHEMA
from cvecli.services.cpe import parse_cpe
from cvecli.services.nvd import CONFIG_FILE, MATCH_FILE, NVDLookup, import_nvd
from cvecli.services.search import CVESearchService, SearchRequest

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nvd"
QUERY = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"


@pytest.fixture
def nvd_config(test_config):
    response = json.loads(
        (FIXTURES / "openssh-9.6p1-cves.json").read_text(encoding="utf-8")
    )
    rows = [
        {
            "cve_id": item["cve"]["id"],
            "state": "PUBLISHED",
            "cna_title": "OpenSSH regression",
            "date_published": "2026-01-01",
        }
        for item in response["vulnerabilities"]
    ]
    pl.DataFrame(rows, schema=CVE_SCHEMA).write_parquet(test_config.cves_parquet)
    return test_config


def enrich(config, match_feed=None):
    return import_nvd(
        config,
        [FIXTURES / "openssh-9.6p1-cves.json"],
        match_feed or FIXTURES / "openssh-matchstrings.json",
    )


def test_official_openssh_result_set_survives_import_and_lookup(nvd_config):
    before = CVESearchService(nvd_config).search(SearchRequest(cpe=QUERY, limit=100))
    assert before["total"] == 0
    assert not before["cpe_query"]["nvd_available"]
    assert before["cpe_query"]["warnings"]
    imported = CliRunner().invoke(
        app,
        [
            "enrich-nvd",
            "--data-dir",
            str(nvd_config.data_dir),
            "--cve-feed",
            str(FIXTURES / "openssh-9.6p1-cves.json"),
            "--match-feed",
            str(FIXTURES / "openssh-matchstrings.json"),
        ],
    )
    assert imported.exit_code == 0, imported.exception
    assert json.loads(imported.stdout)["cve_records"] == 31
    result = CVESearchService(nvd_config).search(SearchRequest(cpe=QUERY, limit=100))
    expected = {
        item["cve"]["id"]
        for item in json.loads(
            (FIXTURES / "openssh-9.6p1-cves.json").read_text(encoding="utf-8")
        )["vulnerabilities"]
    }
    assert result["total"] == len(expected) == 31
    assert {row["id"] for row in result["results"]} == expected
    assert result["cpe_query"]["nvd_cpe_matches"] == 31
    assert not result["cpe_query"]["warnings"]
    records = {row["id"]: row for row in result["results"]}
    for key in ("CVE-2025-32728", "CVE-2025-26466", "CVE-2026-73283"):
        assert records[key]["applicability"]["status"] == "affected"
    # NVD search membership includes configurations needing additional inventory.
    assert records["CVE-2008-3844"]["applicability"]["status"] == "unknown"


def test_official_p1_update_is_not_equivalent_to_na(nvd_config):
    enrich(nvd_config)
    result = NVDLookup(nvd_config.data_dir).lookup(
        parse_cpe(QUERY.replace(":p1:", ":-:")), ["CVE-2025-26466"]
    )
    # This CVE lists both 9.6 base and 9.6p1 explicitly, so both match.
    assert result["CVE-2025-26466"][0]["status"] == "affected"
    wrong = NVDLookup(nvd_config.data_dir).lookup(
        parse_cpe(QUERY.replace(":p1:", ":p999:")), ["CVE-2025-26466"]
    )
    assert "CVE-2025-26466" not in wrong


def test_streamed_gzip_and_chunked_match_tar_match_json_results(nvd_config, tmp_path):
    cves = tmp_path / "cves.json.gz"
    with gzip.open(cves, "wb") as output:
        output.write((FIXTURES / "openssh-9.6p1-cves.json").read_bytes())
    archive = tmp_path / "matches.tar.gz"
    payload = json.loads(
        (FIXTURES / "openssh-matchstrings.json").read_text(encoding="utf-8")
    )["matchStrings"]
    with tarfile.open(archive, "w:gz") as tar:
        for number, batch in enumerate((payload[:10], payload[10:])):
            data = json.dumps({"matchStrings": batch}).encode("utf-8")
            info = tarfile.TarInfo(f"chunk-{number}.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    stats = import_nvd(nvd_config, [cves], archive)
    assert stats["cve_records"] == 31
    assert stats["match_criteria"] == 22
    result = CVESearchService(nvd_config).search(SearchRequest(cpe=QUERY, limit=100))
    assert result["cpe_query"]["nvd_cpe_matches"] == 31


def test_missing_or_inconsistent_expansions_do_not_guess_versions(nvd_config):
    enrich(nvd_config)
    matches = pl.read_parquet(nvd_config.data_dir / MATCH_FILE)
    matches = matches.with_columns(pl.lit("{}").alias("bounds"))
    matches.write_parquet(nvd_config.data_dir / MATCH_FILE)
    result = NVDLookup(nvd_config.data_dir).lookup(parse_cpe(QUERY), ["CVE-2025-32728"])
    assert result["CVE-2025-32728"][0]["status"] == "unknown"
    assert "bounds differ" in result["CVE-2025-32728"][0]["criteria"][0]["reason"]


def test_partial_import_does_not_replace_existing_data(nvd_config, tmp_path):
    enrich(nvd_config)
    previous = (nvd_config.data_dir / CONFIG_FILE).read_bytes()
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"matchStrings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="no usable"):
        enrich(nvd_config, invalid)
    assert (nvd_config.data_dir / CONFIG_FILE).read_bytes() == previous


def test_registered_name_exclusion_is_independent_of_cve_filters(nvd_config):
    enrich(nvd_config)
    lookup = NVDLookup(nvd_config.data_dir)
    result = lookup.lookup(
        parse_cpe(QUERY.replace(":9.6:p1:", ":10.0:p2:")), ["CVE-2025-32728"]
    )
    assert result["CVE-2025-32728"][0]["status"] == "unaffected"
    result = lookup.lookup(
        parse_cpe(QUERY.replace(":9.6:", ":99.0:")), ["CVE-2025-32728"]
    )
    assert result["CVE-2025-32728"][0]["status"] == "unknown"


def test_nvd_context_negation_and_nonvulnerable_leaves(tmp_path):
    lookup = NVDLookup(tmp_path)
    query = parse_cpe(QUERY)
    target = {"vulnerable": True, "criteria": QUERY}
    environment = {
        "vulnerable": False,
        "criteria": "cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*",
    }
    assert (
        lookup._node(
            {"operator": "AND", "cpeMatch": [target, environment]}, query, {}, []
        )[2]
        is None
    )
    assert (
        lookup._node(
            {"operator": "OR", "cpeMatch": [target, environment]}, query, {}, []
        )[2]
        is True
    )
    assert (
        lookup._node(
            {"operator": "OR", "negate": True, "cpeMatch": [target]}, query, {}, []
        )[2]
        is None
    )
    assert not lookup._node(
        {"cpeMatch": [{**target, "vulnerable": False}]}, query, {}, []
    )[1]
    # A satisfied nonvulnerable condition cannot stand in for a vulnerable match.
    other_version = {**target, "criteria": QUERY.replace(":9.6:", ":9.5:")}
    tree = {
        "operator": "AND",
        "nodes": [
            {
                "operator": "OR",
                "cpeMatch": [other_version, {**target, "vulnerable": False}],
            }
        ],
    }
    assert lookup._node(tree, query, {}, [])[2] is False


def test_manifest_and_detail_preserve_nvd_data(nvd_config):
    from typer.testing import CliRunner
    from cvecli.cli.build import app

    enrich(nvd_config)
    response = CliRunner().invoke(
        app, ["create-manifest", "-d", str(nvd_config.data_dir)]
    )
    assert response.exit_code == 0, response.exception
    manifest = json.loads((nvd_config.data_dir / "manifest.json").read_text())
    assert {CONFIG_FILE, MATCH_FILE}.issubset(
        {row["name"] for row in manifest["files"]}
    )
    assert manifest["nvd"]["cve_records"] == 31
    record = CVESearchService(nvd_config).get(["CVE-2025-32728"])["results"][0]
    assert record["nvd_configurations"]
