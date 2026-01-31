# Getting Started

This guide will help you install cvecli and get started with searching CVE data.

## Installation

### Using uv (recommended)

```bash
uv add cvecli
```

Or install as a tool:

```bash
uv tool install cvecli
```

### Using pip

```bash
pip install cvecli
```

### With Semantic Search Support

To enable AI-powered semantic search, install with the semantic extras:

```bash
uv add "cvecli[semantic]"
```

!!! note "Semantic Search Requirements"
    The semantic search feature requires ~500MB for the embedding model download.

## Initial Setup

### Download the CVE Database

Before you can search, you need to download the CVE database:

```bash
cvecli db update
```

This downloads pre-built Parquet files from the [cvecli-db](https://github.com/RomainRiv/cvecli-db) repository, which is much faster than processing raw JSON files.

### Check Database Status

```bash
cvecli db status
```

This shows the number of CVEs in your database and the last update time.

## Basic Usage

### Search for CVEs

```bash
# Search by keyword (fuzzy matching)
cvecli search "linux kernel"

# Exact match
cvecli search "linux" --mode strict

# Regex pattern
cvecli search "linux.*kernel" --mode regex

# Semantic search (natural language)
cvecli search "memory corruption in web browser" --semantic
```

### Filter Results

```bash
# By vendor
cvecli search "windows" --vendor microsoft

# By product
cvecli search "apache" --product http_server

# By severity
cvecli search "linux" --severity critical

# By CVSS score range
cvecli search "apache" --cvss-min 7.0 --cvss-max 10.0

# By date range
cvecli search "chrome" --after 2024-01-01 --before 2024-12-31

# By CWE
cvecli search --cwe 787
```

### Search by Identifiers

```bash
# By CPE (Common Platform Enumeration)
cvecli search --cpe "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"

# By PURL (Package URL) - CVE schema 5.2+
cvecli search --purl "pkg:pypi/django"
cvecli search --purl "pkg:npm/lodash"
cvecli search --purl "pkg:maven/org.apache.struts/struts2-core"
```

### Get CVE Details

```bash
# Single CVE
cvecli get CVE-2024-1234

# Multiple CVEs
cvecli get CVE-2024-1234 CVE-2024-5678

# With full details
cvecli get CVE-2024-1234 --detailed
```

### Output Formats

```bash
# Table (default)
cvecli search "apache" --format table

# JSON
cvecli search "apache" --format json

# Markdown
cvecli search "apache" --format markdown

# Save to file
cvecli search "apache" --output results.json --format json
```

## Using as a Library

cvecli can also be used as a Python library:

```python
from cvecli.services.search import CVESearchService
from cvecli.core.config import Config

# Use default config
search = CVESearchService()

# Or custom data directory
config = Config(data_dir=Path("/path/to/data"))
search = CVESearchService(config)

# Search by product using fluent query API
results = search.query().by_product("http_server", vendor="apache").execute()

# Search by CVE ID
result = search.query().by_id("CVE-2024-1234").execute()

# Chain multiple filters
results = (
    search.query()
    .by_product("linux", fuzzy=True)
    .by_severity("high")
    .by_date(after="2024-01-01")
    .sort_by("date", descending=True)
    .limit(50)
    .execute()
)

# Access results
for cve in results.cves.iter_rows(named=True):
    print(f"{cve['cve_id']}: {cve['state']}")
```

## Advanced Database Management

For users who need to build the database from source:

```bash
# Download raw JSON files
cvecli db build download-json

# Extract to Parquet format
cvecli db build extract-parquet

# Generate embeddings for semantic search
cvecli db build extract-embeddings

# Create manifest for distribution
cvecli db build create-manifest
```

## Configuration

### Environment Variables

- `CVE_DATA_DIR`: Override the data directory
- `CVE_DOWNLOAD_DIR`: Override the download directory
- `CVE_DEFAULT_YEARS`: Number of years of CVE data to download (default: 10)

### Command-line Override

Most commands support `--data-dir` to override the data directory:

```bash
cvecli search "apache" --data-dir /custom/path/to/data
```

## Next Steps

- Browse the [CLI Reference](cli/index.md) for complete command documentation
- Check the [API Reference](api/index.md) for library usage
- See database statistics with `cvecli stats`
