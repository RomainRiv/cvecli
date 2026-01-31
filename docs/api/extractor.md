# Extractor Service

Service for extracting and normalizing CVE data into Parquet format.

## Overview

The `ExtractorService` processes raw CVE JSON files and creates normalized Parquet tables:

- `cves.parquet` - Main CVE records
- `cve_descriptions.parquet` - CVE descriptions
- `cve_metrics.parquet` - CVSS metrics
- `cve_products.parquet` - Affected products (CPE, PURL)
- `cve_versions.parquet` - Version ranges
- `cve_cwes.parquet` - CWE mappings
- `cve_references.parquet` - External references
- `cve_credits.parquet` - Credits/acknowledgments

## Usage

```python
from cvecli.services.extractor import ExtractorService
from cvecli.core.config import Config

config = Config()
extractor = ExtractorService(config)

# Extract all CVE data to Parquet
stats = extractor.extract_all()
print(f"Extracted {stats['cves']} CVEs")
```

## API Reference

::: cvecli.services.extractor.ExtractorService
    options:
      show_root_heading: true
      members:
        - __init__
        - extract_all
