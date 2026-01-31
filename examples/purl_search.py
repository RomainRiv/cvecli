"""Example: Search by Package URL (PURL)

This example demonstrates how to search for CVEs affecting specific packages
using Package URLs (PURLs) - a standardized way to identify software packages.

PURL format: pkg:<type>/<namespace>/<name>@<version>

Supported package types include:
- pypi (Python)
- npm (Node.js)
- maven (Java)
- gem (Ruby)
- cargo (Rust)
- nuget (.NET)
- github (GitHub repositories)

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/purl_search.py
"""

from cvecli.services.search import CVESearchService


def main() -> None:
    search = CVESearchService()

    # Example PURLs for popular packages
    packages = [
        ("pkg:pypi/django", "Django (Python web framework)"),
        ("pkg:pypi/requests", "Requests (Python HTTP library)"),
        ("pkg:npm/lodash", "Lodash (JavaScript utility library)"),
        ("pkg:maven/org.apache.struts/struts2-core", "Apache Struts 2"),
    ]

    print("=" * 70)
    print("Searching for CVEs by Package URL (PURL)")
    print("=" * 70)

    for purl, description in packages:
        print(f"\n{description}")
        print(f"  PURL: {purl}")

        results = search.query().by_purl(purl).execute()
        print(f"  Found: {results.count} CVEs")

        if results.count > 0:
            # Show severity breakdown
            summary = results.summary()
            severities = [
                f"{k}:{v}" for k, v in summary["severity_distribution"].items() if v > 0
            ]
            print(f"  Severity: {', '.join(severities)}")

            # Show most recent CVEs
            recent = results.cves.sort("cve_id", descending=True).head(3)
            print("  Recent CVEs:")
            for cve in recent.iter_rows(named=True):
                print(f"    - {cve['cve_id']}")


if __name__ == "__main__":
    main()
