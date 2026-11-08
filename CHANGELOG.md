# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.2.0] - 2026-11-08

### Breaking changes

- Replace the fluent query builder with `CVESearchService` and `SearchRequest`.
- Replace `db update` and `db status` with top-level `update` and `status`.
- Replace output format flags with `--json`; use shell redirection for files.
- Remove semantic search, embeddings, automatic version applicability assessment,
  CPE inference, regex/fuzzy search modes, `stats`, and Markdown output.
- Move production commands from `cvecli db build` to the installed `cvecli-build`
  executable. Install `cvecli[build]` for extraction dependencies.
- Store downloaded databases in the operating system's user data directory.
  Point `--data-dir` or `CVE_DATA_DIR` at an existing directory to keep using it.

### Added

- Lexical search across titles, descriptions, vendors and products, with exact
  product/vendor filters and package identity matching.
- Bounded summaries, full evidence retrieval, stable pagination, truthful totals,
  structured JSON errors, and explicit partial failures for batch retrieval.
- Source-labelled CVSS metrics and original product version evidence in details.
- Offline status with readiness, source metadata, and coverage information.
- Verified atomic database snapshots, update locking, checksum-based repair,
  and retention of the current and previous snapshots.
- Packaged database downloading, Parquet extraction, and manifest generation for
  cvecli-db releases, including extraction coverage and checksummed notices.

### Fixed

- Bundle distribution notices as package resources so installed builders can
  include them in manifests even in isolated environments.
- Reject release tags that do not match the package version before publishing.

### Migration

Use `cvecli search "words" --json`, `cvecli get CVE-YYYY-NNNN --json`, and
`cvecli update`. Python callers should use `reader.search(SearchRequest(...))`
and `reader.get([...])`. Database publishers should use `cvecli-build download-json`,
`extract-parquet`, and `create-manifest`; see README for complete examples.

The Parquet manifest schema remains **1**. No database rebuild is required solely
for this version bump. Version entries are preserved as evidence; applicability
is no longer inferred. The cvecli-db workflow must use this version's builder.

## [0.1.1] - 2026-01-31

### Changed

- Package version update following the initial release.

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

[Unreleased]: https://github.com/RomainRiv/cvecli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RomainRiv/cvecli/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/RomainRiv/cvecli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/RomainRiv/cvecli/releases/tag/v0.1.0
