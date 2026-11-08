"""CPE lookup preserves product scope, uncertainty, and bounded evidence."""

import json

import polars as pl
import pytest
from typer.testing import CliRunner

from cvecli.cli.main import app
from cvecli.models.parquet_models import PRODUCT_SCHEMA, VERSION_SCHEMA
from cvecli.services.search import CVESearchService, SearchRequest

NAME = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"


@pytest.fixture
def cpe_db(test_config):
    cves = (
        pl.read_parquet(test_config.cves_parquet)
        .head(5)
        .with_columns(pl.lit("PUBLISHED").alias("state"))
    )
    cves.write_parquet(test_config.cves_parquet)
    ids = cves["cve_id"].to_list()
    schema = PRODUCT_SCHEMA
    version_schema = VERSION_SCHEMA
    products = [
        {
            "cve_id": key,
            "product_id": "p",
            "source": "cna",
            "vendor": "Acme",
            "product": "Widget",
            "cpes": NAME,
            "default_status": "unaffected",
        }
        for key in ids
    ]
    products[4]["default_status"] = None
    products += [
        {**products[3], "product_id": "adp", "source": "adp:example"},
        {
            **products[0],
            "product_id": "other",
            "product": "Other",
            "cpes": NAME.replace("widget", "other"),
        },
    ]
    versions = [
        {
            "cve_id": ids[0],
            "product_id": "p",
            "version": "1.0.0",
            "less_than": "2.0.0",
            "version_type": "semver",
            "status": "affected",
            "changes": '[{"at":"1.5.0","status":"unaffected"}]',
        },
        {
            "cve_id": ids[1],
            "product_id": "p",
            "version": "1.0.0",
            "less_than": "2.0.0",
            "version_type": "git",
            "status": "affected",
        },
        {"cve_id": ids[2], "product_id": "p", "version": "1.4.0", "status": "affected"},
        {"cve_id": ids[3], "product_id": "p", "version": "1.4.0", "status": "affected"},
        {
            "cve_id": ids[3],
            "product_id": "adp",
            "version": "1.4.0",
            "status": "unaffected",
        },
        {
            "cve_id": ids[0],
            "product_id": "other",
            "version": "3.0.0",
            "status": "affected",
        },
    ]
    pl.DataFrame(products, schema=schema).write_parquet(
        test_config.cve_products_parquet
    )
    pl.DataFrame(versions, schema=version_schema).write_parquet(
        test_config.cve_versions_parquet
    )
    return test_config, ids


def statuses(response):
    return {
        record["id"]: record["applicability"]["status"]
        for record in response["results"]
    }


def test_cpe_version_statuses_and_product_scope(cpe_db):
    config, ids = cpe_db
    reader = CVESearchService(config)
    response = reader.search(SearchRequest(cpe=NAME, version="1.4.0"))
    assert statuses(response) == dict(
        zip(ids, ["affected", "unknown", "affected", "unknown", "unknown"])
    )
    assert (
        statuses(reader.search(SearchRequest(cpe=NAME, version="3.0.0")))[ids[0]]
        == "unaffected"
    )
    assert (
        statuses(reader.search(SearchRequest(cpe=NAME, version="1.6.0")))[ids[0]]
        == "unaffected"
    )
    assert all(
        item["product_id"] != "other"
        for record in response["results"]
        for item in record["applicability"]["products"]
    )


def test_cpe_binding_equivalence_and_unknown_without_version(cpe_db):
    config, _ = cpe_db
    reader = CVESearchService(config)
    a = reader.search(SearchRequest(cpe=NAME.replace(":*:", ":1.4.0:", 1)))
    b = reader.search(SearchRequest(cpe="cpe:/a:acme:widget:1.4.0"))
    assert statuses(a) == statuses(b)
    assert set(statuses(reader.search(SearchRequest(cpe=NAME))).values()) == {"unknown"}


def test_cli_cpe_lookup_is_bounded_and_validates_input(cpe_db):
    config, _ = cpe_db
    response = CliRunner().invoke(
        app,
        [
            "search",
            "--cpe",
            NAME,
            "--version",
            "1.4.0",
            "--limit",
            "1",
            "--json",
            "--data-dir",
            str(config.data_dir),
        ],
    )
    assert response.exit_code == 0, response.exception
    payload = json.loads(response.stdout)
    assert payload["total"] == 5
    assert len(payload["results"]) == 1
    assert len(payload["results"][0]["applicability"]["products"]) <= 2
    response = CliRunner().invoke(
        app,
        ["search", "--cpe", "invalid", "--json", "--data-dir", str(config.data_dir)],
    )
    assert response.exit_code == 2
    assert json.loads(response.stdout)["errors"][0]["code"] == "invalid_request"


def test_platform_constraints_and_cpe_version_conflicts(cpe_db):
    config, ids = cpe_db
    data = pl.read_parquet(config.cve_products_parquet)
    data = data.with_columns(
        pl.when((pl.col("cve_id") == ids[0]) & (pl.col("product_id") == "p"))
        .then(pl.lit(NAME.replace(":widget:*:", ":widget:1.0.0:")))
        .otherwise(pl.col("cpes"))
        .alias("cpes")
    )
    data.write_parquet(config.cve_products_parquet)
    assert (
        statuses(
            CVESearchService(config).search(SearchRequest(cpe=NAME, version="1.4.0"))
        )[ids[0]]
        == "unknown"
    )
    data = data.with_columns(
        pl.when((pl.col("cve_id") == ids[0]) & (pl.col("product_id") == "p"))
        .then(pl.lit("cpe:2.3:a:acme:widget:*:*:*:*:*:linux:*:*"))
        .otherwise(pl.col("cpes"))
        .alias("cpes")
    )
    data.write_parquet(config.cve_products_parquet)
    assert (
        statuses(
            CVESearchService(config).search(SearchRequest(cpe=NAME, version="1.4.0"))
        )[ids[0]]
        == "unknown"
    )
    matching = "cpe:2.3:a:acme:widget:1.4.0:*:*:*:*:linux:*:*"
    assert (
        statuses(CVESearchService(config).search(SearchRequest(cpe=matching)))[ids[0]]
        == "affected"
    )


def test_missing_cpe_and_version_coverage_is_explicit(cpe_db):
    config, _ = cpe_db
    config.cve_versions_parquet.unlink()
    response = CVESearchService(config).search(SearchRequest(cpe=NAME, version="1.4.0"))
    assert set(statuses(response).values()) == {"unknown"}
    assert not response["cpe_query"]["version_data_available"]
    data = pl.read_parquet(config.cve_products_parquet).with_columns(
        pl.lit(None, dtype=pl.String).alias("cpes")
    )
    data.write_parquet(config.cve_products_parquet)
    response = CVESearchService(config).search(SearchRequest(cpe=NAME))
    assert response["total"] == 0
    assert response["cpe_query"]["products_without_cpes"] > 0
