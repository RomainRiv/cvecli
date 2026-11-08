# CPE regression vector provenance

Offline fixtures adapted from NIST's CPE 2.3 reference implementation, pinned to
commit `3d695a75fd851513708b770128fdf7aacfa0e639`:

- `nist_matching.json`: both examples in
  https://github.com/usnistgov/cpe-reference-implementation/blob/3d695a75fd851513708b770128fdf7aacfa0e639/src/test/java/gov/nist/secauto/cpe/matching/CPENameMatcherTest.java
- `nist_unbinding.json`: all five examples in
  https://github.com/usnistgov/cpe-reference-implementation/blob/3d695a75fd851513708b770128fdf7aacfa0e639/src/test/java/gov/nist/secauto/cpe/naming/CPENameUnbinderTest.java
- `nist_table_6_2.json`: all 17 rows of IR 7696 Table 6-2, with concrete choices
  for the symbolic strings i, k, m. Row 14's nonmatching case is tested separately.
  https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf

The reference implementation license and notice are retained in `NIST-LICENSE.md`.
The matching example using a programmatically constructed WFN retains the original
language value `sp2`; it is not a formatted-string parser validation case.
These are regression cases, not a NIST certification or a comprehensive official
conformance suite. No network or Java runtime is required to run them.

SemVer ordering cases additionally follow specification item 11:
https://semver.org/#spec-item-11
CVE range/status/default tests follow the algorithm in the CVE Record Format:
https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
CPE name matching itself does not define numeric version ordering.
