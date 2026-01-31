# AGENTS.md

AI agent guidelines for the cvecli repository.

## Project Overview

**cvecli** - CLI tool and Python library for downloading and searching CVE data. Python 3.10+, uses Polars DataFrames stored as Parquet.

## Stack

- **Package manager**: uv (use `uv run`, not bare `python`/`pip`)
- **Task runner**: just (run `just --list`)
- **Testing**: pytest
- **Code quality**: Black, ruff, mypy, ty

## Structure

```
src/cvecli/
├── cli/          # Typer CLI (commands/, formatters/)
├── core/         # Config
├── models/       # Pydantic models
└── services/     # Business logic (search, downloader, extractor, embeddings)
```

## Essential Commands

```bash
just sync          # Install all deps
just test          # Run tests
just format        # Format with Black
just lint          # Lint with ruff
just ty            # Type check with ty
just check         # All checks (format, lint, ty) without tests
just ci            # Full CI pipeline
```

## Development Workflow

1. Make changes
2. Run `just format`
3. Run `just lint` and `just ty` — fix all issues
4. Run `just test`

## Key Notes

- Always use `uv run <command>`, never bare `python` or `pip`
- Data uses Polars, not pandas
- `cve_model.py` is auto-generated (excluded from Black)
- Semantic search requires optional `[semantic]` extras
- Test fixtures are in `tests/fixtures/` (generated via `just test`)
- Config respects `CVE_DATA_DIR` and `CVE_DOWNLOAD_DIR` env vars

## Guidelines

- Keep changes minimal and focused
- Don't over-engineer or add unrequested features
- Don't add error handling for impossible scenarios
- Reuse existing abstractions (DRY)
- Read and understand code before editing