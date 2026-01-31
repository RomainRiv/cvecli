# cvecli

A CLI tool and Python library for downloading, extracting, and searching CVE (Common Vulnerabilities and Exposures) data.

!!! info "Documentation"
    You're viewing the official documentation at [romainriv.github.io/cvecli](https://romainriv.github.io/cvecli/).
    For the source code, visit the [GitHub repository](https://github.com/RomainRiv/cvecli).

## Features

- **Fast CVE Database**: Downloads and stores CVE data in optimized Parquet format using Polars
- **Multiple Search Modes**: Fuzzy, strict, regex, and semantic (AI-powered) search
- **Rich Filtering**: Filter by vendor, product, CWE, severity, CVSS score, date range, and more
- **PURL Support**: Search by Package URL (PyPI, npm, Maven, etc.) - CVE schema 5.2+
- **CPE Search**: Search by Common Platform Enumeration strings with version filtering
- **Library API**: Use cvecli as a Python library for programmatic CVE analysis
- **Multiple Output Formats**: Table, JSON, and Markdown output

## Quick Start

### Installation

```bash
uv add cvecli
```

Or install as a tool:

```bash
uv tool install cvecli
```

### Update the CVE Database

```bash
cvecli db update
```

### Search for CVEs

```bash
# Basic search
cvecli search "linux kernel"

# Filter by vendor
cvecli search "windows" --vendor microsoft

# Search by severity
cvecli search "apache" --severity critical

# Search by Package URL
cvecli search --purl "pkg:pypi/django"

# Semantic search (requires embeddings)
cvecli search "memory corruption vulnerability" --semantic
```

### Get CVE Details

```bash
cvecli get CVE-2024-1234
```

## Documentation

- [Getting Started](getting-started.md) - Installation and first steps
- [CLI Reference](cli/index.md) - Complete command-line documentation
- [API Reference](api/index.md) - Python library documentation for developers

## Use Cases

### As a CLI Tool

cvecli provides a powerful command-line interface for security researchers, 
DevSecOps engineers, and vulnerability analysts to quickly search and analyze CVE data.

### As a Python Library

cvecli can be used as a library in your Python projects for programmatic CVE analysis:

```python
from cvecli.services.search import CVESearchService

# Initialize the search service
search = CVESearchService()

# Search for CVEs
results = search.by_product("apache", "http_server")
print(f"Found {results.count} CVEs")

# Get severity distribution
summary = results.summary()
print(summary["severity_distribution"])
```

## License

MIT License - see [LICENSE](https://github.com/RomainRiv/cvecli/blob/main/LICENSE) for details.

CVE data is subject to the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
