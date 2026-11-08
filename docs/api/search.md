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

No version applicability is inferred. Product version records are evidence, not
an evaluation of the caller's installation. Readers pin a snapshot; reopen a
reader after updating. Only the active and previous snapshots are retained.

::: cvecli.services.search.SearchRequest
::: cvecli.services.search.CVESearchService
::: cvecli.services.search.ReferenceError
