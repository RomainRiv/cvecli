"""Example: Chainable Search with Fluent API

This example demonstrates the new fluent/chainable API for composing
complex CVE searches. Filters can be chained in any order for intuitive
and readable queries.

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/chainable_search.py
"""

from cvecli.constants import SeverityLevel
from cvecli.services.search import CVESearchService


def main() -> None:
    search = CVESearchService()

    # Simple chainable query
    print("=" * 70)
    print("Example 1: Critical Linux CVEs from 2024")
    print("=" * 70)

    # The new fluent API allows chaining any filters in any order
    results = (
        search.query()
        .by_product("linux_kernel")
        .by_vendor("linux")
        .by_severity(SeverityLevel.CRITICAL)
        .by_date(after="2024-01-01")
        .sort_by("date", descending=True)
        .execute()
    )

    print(f"Found {results.count} CVEs\n")
    if results.count > 0:
        for cve in results.cves.head(5).iter_rows(named=True):
            print(f"  {cve['cve_id']} - {cve['date_published']}")

    # Chain in different order - same result
    print("\n" + "=" * 70)
    print("Example 2: High+ CVSS Apache CVEs (filters in different order)")
    print("=" * 70)

    # Order doesn't matter - same filters, just arranged differently
    results = (
        search.query()
        .by_cvss(min_score=7.0)  # High severity threshold
        .by_vendor("apache")
        .limit(10)
        .execute()
    )

    print(f"Found {results.count} CVEs (showing first 10)\n")
    if results.count > 0:
        for cve in results.cves.iter_rows(named=True):
            print(f"  {cve['cve_id']}")

    # Combine multiple filter types
    print("\n" + "=" * 70)
    print("Example 3: SQL Injection (CWE-89) in Microsoft products, 2023+")
    print("=" * 70)

    results = (
        search.query()
        .by_cwe("CWE-89")
        .by_vendor("microsoft")
        .by_date(after="2023-01-01")
        .by_cvss(min_score=7.0)  # High severity threshold
        .execute()
    )

    print(f"Found {results.count} CVEs\n")
    summary = results.summary()
    print("Severity distribution:")
    for severity, count in summary["severity_distribution"].items():
        if count > 0:
            print(f"  {severity}: {count}")

    # Package URL search with additional filters
    print("\n" + "=" * 70)
    print("Example 4: Django CVEs with CVSS >= 8.0")
    print("=" * 70)

    results = (
        search.query()
        .by_purl("pkg:pypi/django")
        .by_cvss(min_score=8.0)
        .sort_by("date", descending=True)
        .execute()
    )

    print(f"Found {results.count} high-severity Django CVEs\n")
    if results.count > 0:
        print("Recent high-severity CVEs:")
        for cve in results.cves.head(5).iter_rows(named=True):
            print(f"  {cve['cve_id']}")

    # Recent CVEs with text search
    print("\n" + "=" * 70)
    print("Example 5: Recent memory corruption CVEs")
    print("=" * 70)

    results = (
        search.query()
        .recent(days=90)
        .text_search("memory corruption")
        .by_cvss(min_score=7.0)  # High severity threshold
        .limit(10)
        .execute()
    )

    print(f"Found {results.count} recent memory corruption CVEs\n")
    if results.count > 0:
        for cve in results.cves.iter_rows(named=True):
            print(f"  {cve['cve_id']}")

    # Get a specific CVE with the query builder
    print("\n" + "=" * 70)
    print("Example 6: Get specific CVE")
    print("=" * 70)

    results = search.query().by_id("CVE-2024-38476").execute()

    if results.count > 0:
        cve = results.cves.row(0, named=True)
        print(f"CVE ID: {cve['cve_id']}")
        print(f"State: {cve['state']}")
        print(f"Published: {cve['date_published']}")

        if results.descriptions is not None and len(results.descriptions) > 0:
            desc = results.descriptions.filter(
                results.descriptions["lang"] == "en"
            ).head(1)
            if len(desc) > 0:
                print(f"Description: {desc.row(0, named=True)['value'][:150]}...")


if __name__ == "__main__":
    main()
