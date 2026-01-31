# API Reference

Use cvecli as a Python library for programmatic CVE analysis.

## Quick Start

```python
from cvecli.services.search import CVESearchService

search = CVESearchService()
results = search.by_product("apache", "http_server")
print(f"Found {results.count} CVEs")
```

## Examples

See the [examples/](https://github.com/RomainRiv/cvecli/tree/main/examples) directory for runnable code:

| Example | Description |
|---------|-------------|
| [basic_search.py](https://github.com/RomainRiv/cvecli/blob/main/examples/basic_search.py) | Basic CVE search by product, ID, and CWE |
| [purl_search.py](https://github.com/RomainRiv/cvecli/blob/main/examples/purl_search.py) | Search by Package URL (PyPI, npm, Maven) |
| [cpe_version_search.py](https://github.com/RomainRiv/cvecli/blob/main/examples/cpe_version_search.py) | CPE search with version filtering |
| [severity_date_filter.py](https://github.com/RomainRiv/cvecli/blob/main/examples/severity_date_filter.py) | Filter by severity, CVSS, and dates |
| [export_data.py](https://github.com/RomainRiv/cvecli/blob/main/examples/export_data.py) | Export results to JSON, CSV, Parquet |

## Services

| Service | Description |
|---------|-------------|
| [CVESearchService](search.md) | Main search functionality |
| [DownloadService](downloader.md) | Download raw CVE data |
| [ExtractorService](extractor.md) | Extract data to Parquet |
| [EmbeddingsService](embeddings.md) | Semantic search embeddings |
| [ArtifactFetcher](artifact_fetcher.md) | Fetch pre-built database |
| [Config](config.md) | Configuration management |
