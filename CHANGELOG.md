# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-31

### Added

- Initial release
- CLI commands: `search`, `get`, `stats`, `db update`
- Text search with vendor/product/severity/CWE/date/CVSS filters
- PURL-based search for package vulnerabilities
- KEV (Known Exploited Vulnerabilities) filter
- Semantic search using sentence embeddings (optional)
- Output formats: table, JSON, Markdown
- Local Polars-based Parquet database for fast queries

[Unreleased]: https://github.com/RomainRiv/cvecli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RomainRiv/cvecli/releases/tag/v0.1.0
