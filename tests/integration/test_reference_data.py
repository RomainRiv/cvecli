"""Exercise the reference contract against sampled CVE data, not mocks."""

import pytest

from cvecli.services.search import CVESearchService, SearchRequest


@pytest.mark.parametrize("query", ["openssl", "linux", "memory", "apache"])
def test_sample_search_and_detail(sample_config, query):
    reader = CVESearchService(sample_config)
    page = reader.search(SearchRequest(query, limit=5))
    assert page["results"]
    ids = [record["id"] for record in page["results"]]
    detail = reader.get(ids)
    assert [record["id"] for record in detail["results"]] == ids
    assert detail["errors"] == []
    for record in detail["results"]:
        assert "descriptions" in record
        for product in record["products"]:
            assert "versions" in product


def test_sample_all_pages_are_complete_and_stable(sample_config):
    reader = CVESearchService(sample_config)
    offset = 0
    ids = []
    while True:
        page = reader.search(SearchRequest(state="all", limit=100, offset=offset))
        ids.extend(record["id"] for record in page["results"])
        offset = page["next_offset"]
        if offset is None:
            break
    assert len(ids) == len(set(ids)) == page["total"]
    assert len(ids) == len(reader.table("cves"))


@pytest.mark.requires_real_data
def test_installed_database_contract(real_data_config):
    reader = CVESearchService(real_data_config)
    page = reader.search(SearchRequest("openssl", limit=3))
    assert page["results"]
    assert reader.get([record["id"] for record in page["results"]])["errors"] == []
