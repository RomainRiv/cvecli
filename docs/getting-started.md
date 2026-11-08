# cvecli

A small, offline-capable CLI and Python library for finding CVE records and reading
their evidence. Download a prebuilt database once; searches do not access the network.

```bash
uv tool install cvecli
cvecli update
cvecli search "apache http server"
cvecli get CVE-2021-44228
```

Use `cvecli status` to see local readiness, source information, and coverage.
The database lives in your operating system's user data directory, independently
of the Python installation. Override it with `CVE_DATA_DIR` or `--data-dir`.

## Find records, then inspect evidence

```bash
cvecli search "memory corruption" --limit 10
cvecli products openssl
cvecli search --vendor OpenSSL --product OpenSSL
cvecli search --purl 'pkg:pypi/django' --min-score 7
cvecli search --after 2024-01-01 --before 2024-12-31
cvecli search --cpe 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*' --json
cvecli get CVE-2021-44228 CVE-2021-45046 --json > records.json
```

Search matches all query words across titles, descriptions, vendors, and products.
Title matches rank first, then matches across more fields, then publication date
and CVE ID. Product and vendor filters are exact, case-insensitive matches on the
same product entry. The default includes published records; use `--state all` to
include rejected records.

Results are candidate records, **not an assessment of installed software**.
`get` preserves descriptions, source-labelled metrics, product version entries,
status changes, and advisory links. It does not invent affected or fixed versions.
PURL versions are reported as query metadata and are not evaluated.

## CPE lookup and version status

`--cpe` accepts a complete CPE 2.3 formatted string or a legacy `cpe:/` URI.
It searches recorded CPE identities rather than guessing from vendor/product text.
Use the version in the CPE, or override it with `--version`:

```bash
cvecli search --cpe 'cpe:/a:apache:http_server' --version 2.4.51 --json
```

All matching product candidates stay visible with `affected`, `unaffected`, or
`unknown` in each result's `applicability` field. The evidence includes the source,
matched CPE, directional name relation, version entry/default, and status reason.
Conflicting source/product statuses yield `unknown`. A wildcard or unspecified
query version cannot establish a concrete version status.

CPE name matching follows NIST's string/wildcard relations: ANY and NA differ,
quoted wildcards are literals, comparisons ignore case, and `9.1` is distinct
from `9.1.0`. CPE matching **does not define version ordering**. CVE version
ranges are evaluated separately using their declared scheme: exact string entries
work across schemes; ordered ranges currently support strict SemVer 2.0.0 only.
Unsupported/custom/Git/RPM/Maven/Python ranges remain `unknown`; numeric-looking
strings are never silently ordered. Status changes and product defaults are applied
according to the CVE Record Format. Exact CPE equality alone does not prove affectedness.

Lookup combines CVE product identifiers with NVD configurations when the database
contains NVD enrichment. NVD ranges are resolved through its published concrete
CPE dictionary expansions, including the CPE update field (such as OpenSSH `p1`),
without guessing a version ordering. AND/OR expressions are preserved; missing
companion products, negation, and unresolved environment requirements remain unknown.
CVE `cpeApplicability` blocks are not currently extracted; NVD configurations are
supplied by the separate enrichment step.

`cpe_query.nvd_cpe_matches` counts records with confirmed NVD CPE membership;
`total` counts all candidates, including unaffected and unknown CVE-product records.
Those numbers can differ, and an NVD CPE match can still need environmental context.
`get` includes the original NVD configurations for inspection.

Older databases contain only sparse CVE-product CPEs. The tool reports absent NVD
coverage instead of presenting those results as complete. Updating the binary alone
cannot recover missing mappings: rebuild/release an enriched database, then run
`cvecli update`. Lookup stays offline. Source counts, timestamps and missing mapping
counts are recorded in the manifest; results depend on the database snapshot.

## Automation

All commands accept `--json`. Responses use typed values, a schema version, and
structured errors. Search summaries are short; `get` returns full evidence.
CPE lookup includes a bounded product applicability assessment with evidence.
There is no semantic model or embedding download.

```bash
cvecli search apache --json --limit 20 > page1.json
cvecli search apache --json --limit 20 --offset 20 > page2.json
```

`total` counts all matches; `next_offset` is null at the end. Redirection never
changes the limit. Keep the same query and release while paging. Exit code 0 means
success (including an empty search), 1 means unavailable data/update failure or a
partially missing `get`, and 2 means invalid arguments.

## Python

```python
from cvecli.services.search import CVESearchService, SearchRequest

reader = CVESearchService()
page = reader.search(SearchRequest(query="memory corruption", limit=10))
records = reader.get([row["id"] for row in page["results"]])
```

The CLI and Python API return the same response structure.

## Data limits and updates

An absent identifier is not evidence that a product has no vulnerabilities. Source
and coverage information may be unknown in older releases and are labelled as such.
KEV annotations are preserved from CVE records, not independently synchronized with
a catalog. Selected CVSS scores prefer CNA reports, then newer CVSS versions;
`get` includes all reported metrics.

Updates verify checksums, stage complete releases, and atomically activate them.
The active and previous snapshots are retained. Long-lived readers must reopen
after their snapshot is retired by subsequent updates. Locally built flat databases
remain readable; missing tables produce explicit errors.

## Development and database production

```bash
uv sync --group dev
just test
just check
```

Database production uses the separately installed `cvecli-build` entry point, supplied by the same cvecli package. Install `cvecli[build]` in production (the development environment already includes it):

```bash
uv run cvecli-build download-json --data-dir build-data
uv run cvecli-build extract-parquet --data-dir build-data
uv run cvecli-build enrich-nvd --years 50 --data-dir build-data
uv run cvecli-build create-manifest --data-dir build-data
```

The [cvecli-db](https://github.com/RomainRiv/cvecli-db) release workflow installs
this same package with its `build` extra and invokes these commands. All database
production remains available from an installed package; no source checkout script
is required.

Build in a separate directory. Extraction writes empty tables when appropriate and
records extraction coverage, including skipped records. Pydantic is a build-only
extra (`cvecli[build]`); it is not needed for normal reference queries. NVD
enrichment streams the yearly CVE feeds and the CPE Match archive (roughly 1 GB
for the latter). For offline production, pass repeatable `--cve-feed FILE` options
and `--match-feed FILE` to `enrich-nvd`.

## Migration

This redesign replaces the fluent query API with `SearchRequest`. `db update` and
`db status` become `update` and `status`; `stats`, semantic search, generic version
filtering, CPE name guessing, regex/fuzzy modes, Markdown output, and output-file
options are removed. Explicit CPE lookup uses `--cpe` and optional `--version`. Use `--json` instead of `--format json`, shell redirection for files, and
`get` for full evidence. Legacy installed data can be used with `--data-dir`.

MIT License. CVE data is subject to the CVE Terms of Use distributed with the package.
