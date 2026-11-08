# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Enrich prebuilt databases with NVD configurations and authoritative CPE Match
  expansions via `cvecli-build enrich-nvd`, with streamed JSON/gzip/tar imports.
- Preserve NVD Boolean context and expose original configurations in `get`.
- Add the official 31-CVE OpenSSH 9.6p1 result set as an offline end-to-end regression.
- Restore explicit CPE lookup through `search --cpe NAME` and
  `SearchRequest(cpe=...)`, supporting CPE 2.3 formatted strings and legacy URIs.
  Use the embedded version or override it with `--version VERSION`.
- Return affected, unaffected, and unknown assessments with matched CPE names,
  source, version entry or product default, and decision reasons. Unaffected and
  unknown candidates remain visible; evidence is limited to the returned page.
- Match all eleven CPE attributes with directional relations, distinct ANY/NA
  values, escaped literals, case-insensitive comparisons, and boundary wildcards.
- Evaluate exact version entries and explicitly declared SemVer ranges using
  python-semver, including inclusive/exclusive bounds, status changes, and defaults.
- Add pinned offline examples from NIST's reference implementation, all 17
  attribute relation cases in IR 7696 Table 6-2, and SemVer/CVE status regressions.
  Document their provenance and supported scope in `docs/cpe-matching.md`.

### Changed

- Separate CPE string matching from CVE version ordering: CPE versions such as
  `9.1` and `9.1.0` remain distinct names. Unsupported range schemes, conflicting
  sources, missing versions, and unresolved platform constraints yield unknown.
- Scope CVE-product assessments to their CPEs/version entries and evaluate NVD
  configurations separately. Unresolved environment and negation context remains
  unknown; CVE Record Format `cpeApplicability` blocks are not yet extracted.

### Fixed

- Recover CPE mappings absent from CVE product records through NVD enrichment,
  rather than guessing names or ordering untyped version ranges.
- Report missing NVD coverage explicitly and distinguish confirmed NVD CPE hits
  from broader affected/unaffected/unknown candidate counts.
- Copy distribution notices as bytes to avoid Windows default-encoding errors
  and preserve their original contents and manifest checksums.
- Isolate default-storage tests from host `LOCALAPPDATA` and `XDG_DATA_HOME` values.

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
