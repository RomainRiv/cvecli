# Database updates

```python
from cvecli.services.artifact_fetcher import ArtifactFetcher
ArtifactFetcher(quiet=True).update()
```

Updates require a compatible manifest, complete required tables, valid checksums,
and readable Parquet. Downloads are staged before activation. Updates are serialized
with an operating-system lock, and retain the active and previous snapshots.

::: cvecli.services.artifact_fetcher.ArtifactFetcher
