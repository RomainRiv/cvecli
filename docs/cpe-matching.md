# CPE matching: scope and external tests

CPE name matching and CVE version applicability are separate operations. The first
compares names as sets of strings; the second interprets product status entries.

## Primary sources and reusable examples

- [NIST IR 7696, CPE Name Matching 2.3](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf):
  Table 6-2 enumerates all 17 attribute comparison cases. Sections 6–7 define
  directional name relations, logical ANY/NA values, and wildcard matching.
- [NIST's Java reference implementation and tests](https://github.com/usnistgov/cpe-reference-implementation/tree/master/src/test/java/gov/nist/secauto/cpe):
  the matching and unbinding tests provide executable examples. cvecli stores
  offline adaptations pinned to commit `3d695a75fd851513708b770128fdf7aacfa0e639`.
- [CVE Record Format schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json):
  product version entries specify first-match semantics, defaults, inclusive and
  exclusive bounds, status changes, and the `versionType` comparison scheme.
- [SemVer specification, item 11](https://semver.org/#spec-item-11):
  provides the prerelease precedence sequence used in our ordered range tests.
  [python-semver](https://python-semver.readthedocs.io/en/latest/usage/compare-versions.html)
  implements the comparisons; invalid/incomplete semantic versions remain unknown.

Fixtures, attribution, and the NIST notice are in `tests/fixtures/cpe`. Tests run
offline with pytest; they do not require Java, a network connection, or model data.
These examples are regression coverage, not NIST certification or a comprehensive
official conformance suite. We do not claim full CPE Applicability Language support.

## What is supported

CPE 2.3 formatted names and URI bindings, including packed editions, quoted
punctuation, case-insensitive name relations, all eleven attributes, and directional
wildcards. `*` (ANY) and `-` (NA) have distinct meanings. `?` matches zero or one
characters per IR 7696; patterns occur only at attribute boundaries. Wildcards in
the comparison target yield an undefined relation; lookup keeps potential matches
unknown when it cannot establish that the recorded scope covers the query.

Version strings in CPEs are opaque. `9.1` and `9.1.0` are distinct CPE version names.
Ordered CVE ranges currently require `version_type=semver` and valid SemVer values.
CVE's `0` lower-bound convention and `*`, `1.*`, or `1.2.*` upper bounds are supported.
Exact single entries are not expanded into ranges. Unsupported schemes, malformed
ranges, source conflicts, or unresolved product constraints produce unknown.

## NVD coverage and end-to-end regression

CVE record product CPEs are sparse. NVD's configurations are a separate data
source; correct name matching cannot recover mappings that were never imported.
`cvecli-build enrich-nvd` preserves NVD configurations in
`cve_cpe_configurations.parquet` and authoritative dictionary expansions in
`cpe_matches.parquet`. Both files are checksummed and distributed with the database.
The optional files are additive; the base Parquet manifest schema remains 1.

NVD does not declare a SemVer scheme for its range bounds. We use the expanded
names from its CPE Match feed rather than inventing an ordering for arbitrary
versions. Expansions must be active and agree with the configuration's range
bounds. A known dictionary name outside an expansion does not match that range;
unregistered names or missing expansions remain unknown. This also keeps `9.6:p1`
distinct from `9.6:-`, and avoids folding update attributes into version strings.

The 2026-11-08 NVD API response for OpenSSH 9.6p1 contains 31 CVEs. The offline
regression in `tests/fixtures/nvd` passes that response and its match-criteria
records through import, Parquet persistence and the public query API, then compares
the resulting CVE IDs. Additional tests cover compressed/chunked feeds, update
attributes, context dependencies, negation, nonvulnerable criteria, missing or
inconsistent expansions, partial import failures, and source evidence in `get`.

Search distinguishes confirmed NVD CPE membership from the broader candidate
count, which can also include unknown/unaffected CVE-product evidence. NVD search
membership alone does not prove that every AND/OR environment condition holds:
for example, CVE-2008-3844 also requires a particular RHEL environment, so a query
containing only OpenSSH remains unknown. Unknown criteria are not discarded.

Production source references:

- [NVD CPE Match API and expansions](https://nvd.nist.gov/developers/products)
- [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds)
- [NIST's 2.0 feed description and chunking](https://www.nist.gov/itl/nvd)

The pipeline enriches the offline database; searches do not call NVD. Existing
CVE-only snapshots must be rebuilt/released to gain this coverage. Their absence
of NVD data is explicitly reported. The tool does not infer CPE names from free
text or extract CVE Record Format `cpeApplicability` blocks at present.
