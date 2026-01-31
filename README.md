# cvecli

A CLI tool for downloading, extracting, and searching CVE (Common Vulnerabilities and Exposures) data.

📖 **[Full Documentation](https://romainriv.github.io/cvecli/)**

## Features

- **Database Management**: Fetch pre-built parquet files or build locally from JSON
- **Search**: Search CVEs by product, vendor, CWE ID, severity, and more
- **Get**: Retrieve detailed information about specific CVEs
- **Stats**: View database statistics

## Installation

```bash
# Using uv (recommended)
uv pip install .

# With semantic search support (optional, adds ~500MB dependencies)
uv pip install ".[semantic]"

# For development (includes all features)
uv pip install -e ".[dev]"
```

## Quick Start

```bash
# Download pre-built CVE database (recommended, fast!)
cvecli db update

# Search for CVEs
cvecli search "linux kernel"
cvecli search --vendor "Microsoft" "Windows"
cvecli search --severity critical
cvecli search "CWE-79"

# Semantic search (natural language) - requires: pip install cvecli[semantic]
cvecli search --semantic "memory corruption in image parsing"
cvecli search --semantic "authentication bypass in web applications"

# Get details for a specific CVE
cvecli get CVE-2024-1234

# Show database statistics
cvecli stats
```

## Usage

### Database Management

The `db` subcommand manages the CVE database. The recommended approach is to use pre-built parquet files from the [cvecli-db](https://github.com/RomainRiv/cvecli-db) repository:

```bash
# Download latest pre-built database (recommended)
cvecli db update

# Force update even if local is up-to-date
cvecli db update --force

# Download specific version
cvecli db update --tag v20260106

# Check database status
cvecli db status
```

For advanced users who want to build the database locally:

```bash
# Download raw JSON files
cvecli db build download-json
cvecli db build download-json --years 5
cvecli db build download-json --all  # Include CAPEC/CWE

# Extract JSON to parquet
cvecli db build extract-parquet
cvecli db build extract-parquet --verbose

# Generate embeddings for semantic search
cvecli db build extract-embeddings
cvecli db build extract-embeddings --batch-size 512
```

### Search

Search for CVEs using various criteria:

```bash
# Search by product name
cvecli search "Apache HTTP Server"

# Search by vendor
cvecli search --vendor "Apache" "HTTP Server"

# Search by CWE
cvecli search "CWE-79"

# Filter by severity
cvecli search "linux" --severity critical
cvecli search "linux" --severity high

# Filter by CVSS score range
cvecli search "linux" --cvss-min 7.0
cvecli search "linux" --cvss-min 9.0 --cvss-max 10.0

# Filter by CWE
cvecli search --cwe 787                    # CWE-787 (Out-of-bounds Write)
cvecli search "linux" --cwe 416            # Combined with query

# Filter by date
cvecli search "windows" --after 2024-01-01
cvecli search "windows" --before 2024-06-01

# Filter by KEV (Known Exploited Vulnerabilities)
cvecli search "windows" --kev

# Search by Package URL (PURL) - new in CVE schema 5.2
cvecli search --purl "pkg:pypi/django"
cvecli search --purl "pkg:npm/lodash"
cvecli search --purl "pkg:maven/org.apache.xmlgraphics/batik-anim"
cvecli search --purl "pkg:github/package-url/purl-spec"

# Sort results
cvecli search "linux" --sort date          # Sort by date (descending by default)
cvecli search "linux" --sort date --order ascending   # Sort by date, oldest first
cvecli search "linux" --sort cvss          # Sort by CVSS (highest first)
cvecli search "linux" --sort severity --order ascending  # Sort by severity, lowest first

# Output formats
cvecli search "linux" --format json
cvecli search "linux" --format markdown
cvecli search "linux" --format table       # default

# Scripting: output only CVE IDs (one per line)
cvecli search "linux" --ids-only
cvecli search "linux" --ids-only | xargs -I {} cvecli get {}
cvecli search "linux" --ids-only | xargs -I {} cvecli get {}

# Save to file
cvecli search "linux" --output results.json --format json

# Limit results
cvecli search "linux" --limit 50
```

### Semantic Search

Semantic search uses natural language to find CVEs with similar meaning, even if the exact words don't match. This is powered by the `all-MiniLM-L6-v2` model via [fastembed](https://github.com/qdrant/fastembed).

**Note:** Semantic search requires the optional `semantic` dependencies:

```bash
# Install semantic search support
pip install cvecli[semantic]
# or with uv:
uv pip install cvecli[semantic]
```

```bash
# First, generate embeddings (one-time setup, ~10-60 min depending on dataset size)
cvecli db build extract-embeddings

# Search using natural language
cvecli search --semantic "memory corruption vulnerabilities in image processing"
cvecli search --semantic "privilege escalation through kernel race conditions"
cvecli search --semantic "SQL injection in web login forms"

# Adjust minimum similarity threshold (default: 0.3)
cvecli search --semantic "buffer overflow" --min-similarity 0.5

# Combine with other filters
cvecli search --semantic "remote code execution" --severity critical
cvecli search --semantic "authentication bypass" --after 2024-01-01

# Output in different formats
cvecli search --semantic "XSS attacks" --format json
```

### Get

Get detailed information about one or more CVEs:

```bash
cvecli get CVE-2024-1234
cvecli get CVE-2024-1234 CVE-2024-5678   # Multiple CVEs
cvecli get CVE-2024-1234 --detailed       # Include all details
cvecli get CVE-2024-1234 --format json
cvecli get CVE-2024-1234 --output cve-details.json --format json
```

### Stats

Show database statistics:

```bash
cvecli stats
cvecli stats --format json
cvecli stats --format markdown
cvecli stats --output stats.json --format json
```

## Output Formats

- **table**: Human-readable table format (default)
- **json**: Machine-readable JSON format, ideal for LLM consumption
- **markdown**: Markdown format for documentation

## Configuration

Configuration can be set via environment variables:

- `CVE_DATA_DIR`: Directory for extracted data (default: `./data`)
- `CVE_DOWNLOAD_DIR`: Directory for downloaded files (default: `./download`)
- `CVE_DEFAULT_YEARS`: Number of years to download by default (default: 10)
- `CVECLI_DB_REPO`: GitHub repository for pre-built parquet files (default: `RomainRiv/cvecli-db`)

## Development

```bash
# Clone the repository
git clone https://github.com/RomainRiv/cvecli.git
cd cvecli

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=cvecli
```

## Semantic Search

cvecli supports semantic (natural language) search using sentence embeddings. This allows you to search for CVEs using descriptive phrases rather than exact keywords.

**This feature is optional** and requires additional dependencies (~500MB). Install with:

```bash
pip install cvecli[semantic]
# or with uv:
uv pip install cvecli[semantic]
```

### How it works

1. CVE titles and descriptions are concatenated and encoded into dense vector embeddings using the `all-MiniLM-L6-v2` model via [fastembed](https://github.com/qdrant/fastembed).
2. Your search query is encoded using the same model.
3. CVEs are ranked by cosine similarity between the query and CVE embeddings.

### Setup

After installing the semantic dependencies, generate embeddings:

```bash
cvecli db update                          # Download CVE database
cvecli db build extract-embeddings        # Generate embeddings (~10-60 min on CPU)
```

Alternatively, if the cvecli-db repository provides pre-computed embeddings, they will be downloaded automatically when you have the semantic dependencies installed:

```bash
pip install cvecli[semantic]        # Install semantic support
cvecli db update                    # Downloads database + embeddings
```

### Model Details

- **Model**: `all-MiniLM-L6-v2`
- **Embedding dimension**: 384
- **Speed**: ~5× faster than larger models, suitable for CPU
- **Training**: 1B+ sentence pairs for broad semantic understanding

### Performance

- Embedding generation: ~300k CVEs in under 1 hour on a multi-core CPU
- Search queries: Near-instant (milliseconds)
- Storage: ~500MB for embeddings parquet file

## License

**Project Code**: This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

**CVE Data**: CVE data is made available under the [CVE Program Terms of Use](licences/CVE_TERMS_OF_USE.md). When you download the CVE database using `cvecli db update`, the license terms and notices are included with the data files.

**Redistribution**: If you redistribute the CVE database files, you must include the `CVE_TERMS_OF_USE.md` and `NOTICE.txt` files that come with the database. These files are automatically included when building a release with `cvecli db build create-manifest`.
