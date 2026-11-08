# NVD OpenSSH regression snapshot

Retrieved on 2026-11-08 from the official NVD 2.0 APIs:

- CVEs: `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A9.6%3Ap1%3A*%3A*%3A*%3A*%3A*%3A*&resultsPerPage=2000`
- Each of the 22 OpenSSH criteria:
  `https://services.nvd.nist.gov/rest/json/cpematch/2.0?matchCriteriaId=UUID`

`openssh-9.6p1-cves.json` retains the API's pagination metadata and timestamp,
plus each returned CVE's ID, last-modified timestamp, and complete configurations.
Descriptions, scores, and references were omitted to keep this fixture focused.
The recorded response contains exactly 31 CVEs; future live counts may differ.

`openssh-matchstrings.json` preserves the complete official match records for
all OpenBSD OpenSSH criteria referenced by that response. Other vendors' match
expansions are intentionally absent: missing environment information must remain
unknown, not be invented or assumed satisfied.

These fixtures test the complete data path, not merely string comparison:
source JSON → streamed import → Parquet → public CPE query → expected CVE IDs.
They also demonstrate why OpenSSH's `version=9.6, update=p1` must not be treated as
an arbitrary SemVer string or an interchangeable base release.

The NVD's search result membership is not a declaration that all environment
conditions are satisfied by a single CPE. CVE-2008-3844 is deliberately asserted
unknown for an OpenSSH-only query because its configuration also requires RHEL.
Tests run entirely offline and do not assume that the current NVD result count
will forever remain 31.

Product-independent coverage lives in `tests/integration/test_nvd_contract.py`:
synthetic application, operating-system, and hardware feeds exercise all four
NVD range-bound fields, authoritative expansion membership, registered exclusions,
unregistered releases, missing/inactive/inconsistent expansions, search filtering,
and nested environment conditions. These tests do not depend on OpenSSH, real
CVE identifiers, or a live result count. The snapshot above is an additional
historical regression, not the specification of the matcher.
