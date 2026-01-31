# Search Service

The main search functionality for querying CVE data.

## Overview

The `CVESearchService` provides methods to search CVEs by:

- Product and vendor names
- CVE ID
- CWE identifier  
- CPE (Common Platform Enumeration) strings
- PURL (Package URL)
- Severity and CVSS scores
- Date ranges
- Semantic similarity (with embeddings)

## Usage

```python
from cvecli.services.search import CVESearchService

# Initialize with default config
search = CVESearchService()

# Search by product using fluent query API
results = search.query().by_product("http_server", vendor="apache").execute()
print(f"Found {results.count} CVEs")

# Search by CVE ID
result = search.query().by_id("CVE-2024-1234").execute()

# Search by CWE
results = search.query().by_cwe("CWE-79").execute()

# Search by CPE with version check
results = search.query().by_cpe(
    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    check_version="2.4.51"
).execute()

# Search by PURL
results = search.query().by_purl("pkg:pypi/django").execute()

# Chain multiple filters
results = (
    search.query()
    .by_product("linux", fuzzy=True)
    .by_severity("critical")
    .by_date(after="2024-01-01")
    .sort_by("date", descending=True)
    .limit(100)
    .execute()
)
```

## API Reference

::: cvecli.services.search.SearchResult
    options:
      show_root_heading: true
      members:
        - count
        - to_dicts
        - to_json
        - summary

::: cvecli.services.search.CVESearchService
    options:
      show_root_heading: true
      members:
        - __init__
        - query
        - has_embeddings
        - stats
        - get_best_metric
        - get_description
        - get_kev_info
        - get_ssvc_info
        - search_products
        - validate_date

::: cvecli.services.search.CVEQuery
    options:
      show_root_heading: true
      members:
        - by_id
        - by_product
        - by_vendor
        - by_cwe
        - by_cpe
        - by_purl
        - by_severity
        - by_date
        - by_cvss
        - by_state
        - by_kev
        - recent
        - semantic
        - text_search
        - sort_by
        - limit
        - execute

