# cvecli Examples

Runnable examples demonstrating how to use cvecli as a Python library.

## Prerequisites

1. Install cvecli:
   ```bash
   uv add cvecli
   ```

2. Download the CVE database:
   ```bash
   cvecli db update
   ```

## Examples

| File | Description |
|------|-------------|
| [chainable_search.py](chainable_search.py) | **Recommended**: Fluent API with chainable filters |
| [basic_search.py](basic_search.py) | Basic CVE search by product, ID, and CWE |
| [purl_search.py](purl_search.py) | Search by Package URL (PyPI, npm, Maven, etc.) |
| [cpe_version_search.py](cpe_version_search.py) | CPE search with version filtering |
| [severity_date_filter.py](severity_date_filter.py) | Filter by severity, CVSS, and dates |
| [export_data.py](export_data.py) | Export results to JSON, CSV, Parquet |

## Running Examples

```bash
# Run from the project root
uv run python examples/basic_search.py
uv run python examples/purl_search.py
uv run python examples/cpe_version_search.py
uv run python examples/severity_date_filter.py
uv run python examples/export_data.py
```

## API Documentation

For complete API reference, see the [generated documentation](https://romainriv.github.io/cvecli/api/).
