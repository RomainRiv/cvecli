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

The database currently exposes `affected[].cpes` and version entries. This feature
does not evaluate `cpeApplicability` Boolean trees or infer names from free text.
CPE lists can contain vulnerable and nonvulnerable products, so a matching name
alone is not sufficient evidence of affected status. Each assessed result retains
the source, matching names, original version entry/default, and the decision reason.
