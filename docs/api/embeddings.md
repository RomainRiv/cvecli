# Embeddings Service

Service for generating embeddings for semantic search.

## Overview

The `EmbeddingsService` generates vector embeddings from CVE descriptions,
enabling natural language semantic search across the CVE database.

!!! note "Optional Dependency"
    This service requires the `semantic` extras to be installed:
    ```bash
    uv add "cvecli[semantic]"
    ```

## Usage

```python
from cvecli.services.embeddings import EmbeddingsService, is_semantic_available
from cvecli.core.config import Config

# Check if semantic search is available
if is_semantic_available():
    config = Config()
    embeddings = EmbeddingsService(config)
    
    # Generate embeddings for all CVEs
    embeddings.generate_embeddings()
```

## API Reference

::: cvecli.services.embeddings.is_semantic_available
    options:
      show_root_heading: true

::: cvecli.services.embeddings.EmbeddingsService
    options:
      show_root_heading: true
      members:
        - __init__
        - generate_embeddings
