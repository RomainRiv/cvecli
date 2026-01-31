"""Example: Severity and Date Filtering

This example demonstrates how to filter CVEs by severity level,
CVSS score ranges, and publication dates.

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/severity_date_filter.py
"""

from cvecli.constants import SeverityLevel
from cvecli.services.search import CVESearchService


def main() -> None:
    search = CVESearchService()

    # Filter by severity level using SeverityLevel enum
    # Values: SeverityLevel.NONE, LOW, MEDIUM, HIGH, CRITICAL
    print("=" * 70)
    print("Critical Severity CVEs")
    print("=" * 70)

    results = search.query().by_severity(SeverityLevel.CRITICAL).execute()
    print(f"Total critical CVEs: {results.count}")

    # Show year distribution for critical CVEs
    summary = results.summary()
    print("\nCritical CVEs by year (last 5 years):")
    for year, count in sorted(summary["year_distribution"].items(), reverse=True)[:5]:
        print(f"  {year}: {count}")

    # Filter by date range
    print("\n" + "=" * 70)
    print("CVEs from 2024")
    print("=" * 70)

    results_2024 = (
        search.query().by_date(after="2024-01-01", before="2024-12-31").execute()
    )
    print(f"CVEs published in 2024: {results_2024.count}")

    # Combine with severity
    print("\nSeverity distribution for 2024:")
    summary_2024 = results_2024.summary()
    for severity, count in summary_2024["severity_distribution"].items():
        if count > 0:
            print(f"  {severity}: {count}")

    # Combined search: First search by product, then filter by severity
    print("\n" + "=" * 70)
    print("Combined Search: Critical Linux CVEs from 2024")
    print("=" * 70)

    # Search for critical Linux kernel CVEs using chained query
    critical_linux = (
        search.query()
        .by_product("linux")
        .by_vendor("linux_kernel")
        .by_severity(SeverityLevel.CRITICAL)
        .execute()
    )
    print(f"Critical Linux kernel CVEs (all time): {critical_linux.count}")

    # Filter by date using Polars on the DataFrame
    if critical_linux.count > 0:
        critical_2024 = critical_linux.cves.filter(
            critical_linux.cves["date_published"] >= "2024-01-01"
        )
        print(f"Critical Linux kernel CVEs in 2024: {len(critical_2024)}")

        if len(critical_2024) > 0:
            print("\nTop 5 results:")
            for cve in critical_2024.head(5).iter_rows(named=True):
                print(f"  - {cve['cve_id']}")

    # High severity Apache CVEs
    print("\n" + "=" * 70)
    print("High Severity Apache CVEs")
    print("=" * 70)

    high_apache = (
        search.query().by_vendor("apache").by_severity(SeverityLevel.HIGH).execute()
    )
    print(f"High severity Apache CVEs: {high_apache.count}")

    if high_apache.count > 0:
        # Show recent ones
        recent = high_apache.cves.sort("date_published", descending=True).head(5)
        print("\nMost recent:")
        for row in recent.iter_rows(named=True):
            print(f"  - {row['cve_id']} ({row['date_published']})")


if __name__ == "__main__":
    main()
