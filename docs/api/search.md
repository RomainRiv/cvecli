# Reference API

The API and CLI share a single request and response contract.

```python
from cvecli.services.search import CVESearchService, SearchRequest
reader = CVESearchService()
page = reader.search(SearchRequest(query="buffer overflow", limit=10))
print(page["total"], page["next_offset"])
if page["results"]:
    detail = reader.get([page["results"][0]["id"]])
```

Use `SearchRequest(cpe="cpe:/a:vendor:product", version="1.2.3")` for CPE lookup.
Each result includes sourced affected/unaffected/unknown assessments. All outcomes,
including unknown and unaffected candidates, remain in the result set. CPE name
matching is separate from CVE range ordering; only declared SemVer ranges are
ordered. Unsupported schemes and unresolved platform context remain unknown.
NVD-enriched databases additionally resolve NVD ranges through official dictionary
expansions and preserve AND/OR configurations. Missing environment context remains
unknown. `get` exposes the original NVD configuration trees. See
[CPE coverage and regression sources](../cpe-matching.md). Readers pin a snapshot; reopen a
reader after updating. Only the active and previous snapshots are retained.

::: cvecli.services.search.SearchRequest
::: cvecli.services.search.CVESearchService
::: cvecli.services.search.ReferenceError
