# Download Service

Service for downloading raw CVE data from the cvelistV5 GitHub repository.

## Overview

The `DownloadService` handles downloading:

- CVE JSON files from the cvelistV5 repository
- CAPEC (Common Attack Pattern Enumeration and Classification) data
- CWE (Common Weakness Enumeration) data

## Usage

```python
from cvecli.services.downloader import DownloadService
from cvecli.core.config import Config

config = Config()
downloader = DownloadService(config)

# Download CVE data for specific years
downloader.download_cves(years=[2024, 2025])

# Download all supplementary data
downloader.download_capec()
downloader.download_cwe()
```

## API Reference

::: cvecli.services.downloader.DownloadService
    options:
      show_root_heading: true
      members:
        - __init__
        - download_cves
        - download_capec
        - download_cwe
