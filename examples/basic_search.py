"""Example: Basic CVE Search

This example demonstrates how to use cvecli as a library to search for CVEs.

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/basic_search.py
"""

from cvecli.services.search import CVESearchService


def main() -> None:
    # Initialize the search service (uses default data directory)
    search = CVESearchService()

    # Search by product name
    print("=" * 60)
    print("Searching for CVEs affecting 'apache http_server'...")
    print("=" * 60)

    results = search.query().by_product("http_server").by_vendor("apache").execute()
    print(f"Found {results.count} CVEs\n")

    # Show first 5 results
    for i, cve in enumerate(results.cves.head(5).iter_rows(named=True)):
        print(f"  {cve['cve_id']}: {cve['state']}")

    # Get severity distribution
    print("\nSeverity Distribution:")
    summary = results.summary()
    for severity, count in summary["severity_distribution"].items():
        if count > 0:
            print(f"  {severity}: {count}")

    # Search by CVE ID
    print("\n" + "=" * 60)
    print("Getting details for a specific CVE...")
    print("=" * 60)

    result = search.query().by_id("CVE-2024-38476").execute()
    if result.count > 0:
        cve = result.cves.row(0, named=True)
        print(f"CVE ID: {cve['cve_id']}")
        print(f"State: {cve['state']}")

        # Get description if available
        if result.descriptions is not None and len(result.descriptions) > 0:
            desc = result.descriptions.filter(result.descriptions["lang"] == "en").head(
                1
            )
            if len(desc) > 0:
                print(f"Description: {desc.row(0, named=True)['value'][:200]}...")

    # Search by CWE
    print("\n" + "=" * 60)
    print("Searching for SQL Injection vulnerabilities (CWE-89)...")
    print("=" * 60)

    results = search.query().by_cwe("CWE-89").execute()
    print(f"Found {results.count} CVEs with CWE-89")


if __name__ == "__main__":
    main()
