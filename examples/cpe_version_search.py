"""Example: CPE Search with Version Filtering

This example demonstrates how to search for CVEs using CPE
(Common Platform Enumeration) strings and filter by specific versions.

CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:...

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/cpe_version_search.py
"""

from cvecli.services.search import CVESearchService


def main() -> None:
    search = CVESearchService()

    # Example: Find CVEs for Apache HTTP Server
    cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"

    print("=" * 70)
    print("CPE Search: Apache HTTP Server")
    print("=" * 70)
    print(f"CPE: {cpe}\n")

    # Search without version filter - gets all CVEs
    results = search.query().by_cpe(cpe).execute()
    print(f"Total CVEs for Apache HTTP Server: {results.count}")

    # Search with version filter - only CVEs affecting specific version
    version = "2.4.51"
    print(f"\nFiltering for version {version}...")

    results_filtered = search.query().by_cpe(cpe, check_version=version).execute()
    print(f"CVEs affecting version {version}: {results_filtered.count}")

    if results_filtered.count > 0:
        print("\nCVEs affecting this version:")
        for cve in results_filtered.cves.head(10).iter_rows(named=True):
            print(f"  - {cve['cve_id']}")

        # Show severity distribution
        summary = results_filtered.summary()
        print("\nSeverity distribution:")
        for severity, count in summary["severity_distribution"].items():
            if count > 0:
                print(f"  {severity}: {count}")

    # Another example with Microsoft Windows
    print("\n" + "=" * 70)
    print("CPE Search: Microsoft Windows 10")
    print("=" * 70)

    cpe_windows = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
    results_windows = search.query().by_cpe(cpe_windows).execute()
    print(f"Total CVEs for Windows 10: {results_windows.count}")

    # Show year distribution
    summary = results_windows.summary()
    print("\nCVEs by year:")
    for year, count in sorted(summary["year_distribution"].items(), reverse=True)[:5]:
        print(f"  {year}: {count}")


if __name__ == "__main__":
    main()
