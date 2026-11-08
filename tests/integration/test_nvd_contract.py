"""Product-independent NVD contracts using deliberately synthetic source feeds.

The expansion lists are authoritative test inputs, not version-ordering guesses.
No live NVD result counts or real product-specific exceptions are involved.
"""

import json

import polars as pl
import pytest

from cvecli.models.parquet_models import CVE_SCHEMA
from cvecli.services.cpe import parse_cpe
from cvecli.services.nvd import NVDLookup, import_nvd
from cvecli.services.search import CVESearchService, SearchRequest


def name(part, vendor, product, version="*"):
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "part,vendor,product",
    [("a", "example", "editor"), ("o", "another", "system"), ("h", "third", "router")],
)
@pytest.mark.parametrize(
    "bound,scenario,expected",
    [
        (bound, scenario, status)
        for bound in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
        for scenario, status in (("included", "affected"), ("excluded", "unaffected"))
    ]
    + [
        ("versionEndExcluding", scenario, "unknown")
        for scenario in ("unregistered", "missing", "inactive", "inconsistent")
    ],
)
def test_import_and_public_search_obey_expansions_for_any_product(
    test_config, tmp_path, part, vendor, product, bound, scenario, expected
):
    affected_id, registry_id = "CVE-2024-10001", "CVE-2024-10002"
    criterion = name(part, vendor, product)
    # Opaque release labels deliberately cannot be ordered as SemVer.
    included = name(part, vendor, product, "release_a")
    excluded = name(part, vendor, product, "release_b")
    query = (
        name(part, vendor, product, "unregistered")
        if scenario == "unregistered"
        else excluded if scenario == "excluded" else included
    )
    target = {
        "vulnerable": True,
        "criteria": criterion,
        "matchCriteriaId": "range",
        bound: "source_defined_boundary",
    }
    # A separate CVE registers the excluded release in the dictionary. Its
    # expansion must still be usable when that CVE is excluded by search filters.
    registry = {
        "vulnerable": True,
        "criteria": excluded,
        "matchCriteriaId": "registry",
    }
    cves = tmp_path / "synthetic-cves.json"
    cves.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cve": {"id": key, "configurations": [{"cpeMatch": [leaf]}]}}
                    for key, leaf in ((affected_id, target), (registry_id, registry))
                ]
            }
        ),
        encoding="utf-8",
    )
    match_records = [
        {
            "matchString": {
                "matchCriteriaId": "registry",
                "criteria": excluded,
                "status": "Active",
                "matches": [{"cpeName": excluded}],
            }
        }
    ]
    if scenario != "missing":
        match_records.append(
            {
                "matchString": {
                    "matchCriteriaId": "range",
                    "criteria": criterion,
                    "status": "Inactive" if scenario == "inactive" else "Active",
                    bound: (
                        "different_boundary"
                        if scenario == "inconsistent"
                        else target[bound]
                    ),
                    "matches": [{"cpeName": included}],
                }
            }
        )
    matches = tmp_path / "synthetic-matches.json"
    matches.write_text(json.dumps({"matchStrings": match_records}), encoding="utf-8")
    pl.DataFrame(
        [
            {
                "cve_id": key,
                "state": "PUBLISHED",
                "cna_title": title,
                "date_published": "2024-01-01",
            }
            for key, title in ((affected_id, "target"), (registry_id, "registry"))
        ],
        schema=CVE_SCHEMA,
    ).write_parquet(test_config.cves_parquet)
    metadata = import_nvd(test_config, [cves], matches)
    assert metadata["missing_match_criteria"] == (1 if scenario == "missing" else 0)
    result = CVESearchService(test_config).search(
        SearchRequest(cpe=query, query="target")
    )
    assert result["total"] == 1
    assert result["results"][0]["id"] == affected_id
    assert result["results"][0]["applicability"]["status"] == expected
    assert result["cpe_query"]["nvd_cpe_matches"] == (expected == "affected")


@pytest.mark.parametrize("operator,expected", [("AND", "unknown"), ("OR", "affected")])
@pytest.mark.parametrize("nested", [False, True])
def test_environment_requirements_are_not_assumed_satisfied(
    tmp_path, operator, expected, nested
):
    query = name("a", "example", "editor", "release_a")
    target = {"vulnerable": True, "criteria": query}
    environment = {
        "vulnerable": False,
        "criteria": name("o", "another", "system", "release_b"),
    }
    tree = {"operator": operator, "cpeMatch": [target, environment]}
    if nested:
        tree = {"operator": "OR", "nodes": [tree]}
    truth, relevant, assessment = NVDLookup(tmp_path)._node(
        tree, parse_cpe(query), {}, []
    )
    assert relevant
    assert truth == (None if expected == "unknown" else True)
    assert assessment == (None if expected == "unknown" else True)
