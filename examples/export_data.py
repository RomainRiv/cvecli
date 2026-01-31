"""Example: Export CVE Data to Different Formats

This example demonstrates how to export CVE search results to various
formats for further analysis or integration with other tools.

Prerequisites:
    - Install cvecli: uv add cvecli
    - Download the database: cvecli db update

Usage:
    python examples/export_data.py
"""

import json
from pathlib import Path

from cvecli.services.search import CVESearchService

# Output directory relative to this script
SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR / "output"


def main() -> None:
    search = CVESearchService()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Search for CVEs
    print("=" * 70)
    print("Searching for Django CVEs to export...")
    print("=" * 70)

    results = search.query().by_product("django").by_vendor("djangoproject").execute()
    print(f"Found {results.count} CVEs\n")

    if results.count == 0:
        print("No results found. Make sure the database is downloaded.")
        return

    # Export to JSON
    print("Exporting to JSON...")
    json_file = OUTPUT_DIR / "django_cves.json"

    # Convert to list of dicts for JSON export
    cves_list = results.cves.to_dicts()
    with open(json_file, "w") as f:
        json.dump(cves_list, f, indent=2, default=str)
    print(f"  Saved: {json_file}")

    # Export to CSV using Polars
    print("Exporting to CSV...")
    csv_file = OUTPUT_DIR / "django_cves.csv"
    results.cves.write_csv(csv_file)
    print(f"  Saved: {csv_file}")

    # Export to Parquet (efficient for large datasets)
    print("Exporting to Parquet...")
    parquet_file = OUTPUT_DIR / "django_cves.parquet"
    results.cves.write_parquet(parquet_file)
    print(f"  Saved: {parquet_file}")

    # Export with related data (descriptions, metrics)
    print("\nExporting with full details...")

    full_export = {
        "cves": results.cves.to_dicts(),
        "descriptions": (
            results.descriptions.to_dicts() if results.descriptions is not None else []
        ),
        "metrics": results.metrics.to_dicts() if results.metrics is not None else [],
        "products": results.products.to_dicts() if results.products is not None else [],
    }

    full_json_file = OUTPUT_DIR / "django_cves_full.json"
    with open(full_json_file, "w") as f:
        json.dump(full_export, f, indent=2, default=str)
    print(f"  Saved: {full_json_file}")

    # Show summary statistics
    print("\n" + "=" * 70)
    print("Export Summary")
    print("=" * 70)
    print(f"CVEs exported: {results.count}")
    print(f"Descriptions: {len(full_export['descriptions'])}")
    print(f"Metrics: {len(full_export['metrics'])}")
    print(f"Products: {len(full_export['products'])}")
    print(f"\nOutput directory: {OUTPUT_DIR.absolute()}")


if __name__ == "__main__":
    main()
