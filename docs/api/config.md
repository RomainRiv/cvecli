# Configuration

Configuration management for cvecli.

## Overview

The `Config` class manages paths and settings for cvecli. It supports:

- Default paths relative to the project
- Environment variable overrides
- Custom paths via constructor

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CVE_DATA_DIR` | Data directory for Parquet files | `./data` |
| `CVE_DOWNLOAD_DIR` | Directory for downloaded files | `./download` |
| `CVE_DEFAULT_YEARS` | Years of CVE data to download | `10` |

## Usage

```python
from cvecli.core.config import Config, get_config
from pathlib import Path

# Use default configuration
config = get_config()

# Custom configuration
config = Config(
    data_dir=Path("/custom/data"),
    download_dir=Path("/custom/download")
)

# Access paths
print(config.cves_parquet)  # Path to cves.parquet
print(config.cve_products_parquet)  # Path to products.parquet
```

## API Reference

::: cvecli.core.config.Config
    options:
      show_root_heading: true
      members:
        - __init__
        - data_dir
        - download_dir
        - cves_parquet
        - cve_descriptions_parquet
        - cve_metrics_parquet
        - cve_products_parquet
        - cve_versions_parquet
        - cve_cwes_parquet
        - cve_references_parquet
        - cve_credits_parquet
        - cve_embeddings_parquet

::: cvecli.core.config.get_config
    options:
      show_root_heading: true
