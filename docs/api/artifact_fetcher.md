# Artifact Fetcher

Service for fetching pre-built CVE database files from GitHub releases.

## Overview

The `ArtifactFetcher` downloads pre-built Parquet files from the 
[cvecli-db](https://github.com/RomainRiv/cvecli-db) repository, which is 
much faster than downloading and processing raw JSON files.

## Usage

```python
from cvecli.services.artifact_fetcher import ArtifactFetcher
from cvecli.core.config import Config

config = Config()
fetcher = ArtifactFetcher(config)

# Update to latest release
result = fetcher.update()
print(f"Updated to {result['tag']}")

# Update with specific options
result = fetcher.update(
    force=True,
    include_prerelease=False,
    include_embeddings=True
)
```

## API Reference

::: cvecli.services.artifact_fetcher.ArtifactFetcher
    options:
      show_root_heading: true
      members:
        - __init__
        - update
        - get_latest_release
        - get_local_version
