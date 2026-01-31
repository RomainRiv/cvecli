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

# Search by product
results = search.by_product("apache", "http_server")
print(f"Found {results.count} CVEs")

# Search by CVE ID
result = search.by_id("CVE-2024-1234")

# Search by CWE
results = search.by_cwe("CWE-79")

# Search by CPE with version check
results = search.by_cpe(
    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    check_version="2.4.51"
)

# Search by PURL
results = search.by_purl("pkg:pypi/django")
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
        - by_id
        - by_product
        - by_cwe
        - by_cpe
        - by_purl
        - by_severity
        - by_date_range
        - by_kev
        - search
        - semantic_search
        - all_cves

