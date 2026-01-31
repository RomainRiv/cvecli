# cvecli

A batteries included CLI tool and Python library for searching CVE (Common Vulnerabilities and Exposures) data locally.

[![PyPI](https://img.shields.io/pypi/v/cvecli)](https://pypi.org/project/cvecli/)
[![Python](https://img.shields.io/pypi/pyversions/cvecli)](https://pypi.org/project/cvecli/)
[![License](https://img.shields.io/github/license/RomainRiv/cvecli)](LICENSE)

📖 **[Documentation](https://romainriv.github.io/cvecli/)** · 💡 **[Examples](examples/)**

## Installation

Install it as a standalone tool using `uv`
```bash
uv tool install cvecli
```

Or install it with `pip`
```bash
pip install cvecli
```

Install optional semantic search capability with `cvecli[semantic]`.

## Quick Start

```bash
# Download CVE database (~100MB)
cvecli db update

# Search CVEs
cvecli search "apache http server"
cvecli search --vendor Microsoft --severity critical "Windows"
cvecli search --purl "pkg:pypi/pytest"

# Get CVE details
cvecli get CVE-2024-1234

# Database stats
cvecli stats
```

## Features

| Feature | Command |
|---------|---------|
| **Text search** | `cvecli search "query"` |
| **Vendor/product filter** | `--vendor`, `--product` |
| **Severity filter** | `--severity critical\|high\|medium\|low` |
| **CVSS range** | `--cvss-min 7.0 --cvss-max 10.0` |
| **CWE filter** | `--cwe 79` |
| **Date filter** | `--after 2024-01-01 --before 2024-12-31` |
| **KEV filter** | `--kev` (Known Exploited Vulnerabilities) |
| **PURL search** | `--purl "pkg:pypi/pytest` |
| **Semantic search** | `--semantic "memory corruption"` |
| **Output formats** | `--format table\|json\|markdown` |

## Semantic Search

Natural language search using sentence embeddings:

```bash
# Install semantic dependencies
pip install cvecli[semantic]

# Download pre-computed embeddings (approx. 700MB)
cvecli db update --embeddings

# Search
cvecli search --semantic "privilege escalation via kernel race condition"
```

## Development

```bash
git clone https://github.com/RomainRiv/cvecli.git && cd cvecli
uv sync --all-extras
just test  # or: uv run pytest
```

This project uses [just](https://just.systems/) as a task runner. 

## License

MIT License. CVE data is subject to [CVE Terms of Use](licences/CVE_TERMS_OF_USE.md).
