"""Join CPE identities to their own CVE product/version evidence."""

import polars as pl

from cvecli.services.applicability import version_status
from cvecli.services.cpe import CPE, Relation, compare_names, parse_cpe, product_cpes


def lookup(
    products: pl.DataFrame, versions: pl.DataFrame | None, query: CPE
) -> tuple[dict[str, list[dict]], dict]:
    candidates = []
    missing = 0
    invalid = 0
    for product in products.iter_rows(named=True):
        names = product_cpes(product.get("cpes"))
        if not names:
            missing += 1
            continue
        matches = []
        for name in names:
            try:
                parsed = parse_cpe(name)
            except ValueError:
                invalid += 1
                continue
            relation = compare_names(parsed, query, ignore_version=True)
            reverse = compare_names(query, parsed, ignore_version=True)
            if Relation.DISJOINT not in (relation, reverse):
                matches.append((name, parsed, relation))
        if matches:
            candidates.append((product, matches))
    by_product: dict[tuple[str, str | int], list[dict]] = {}
    if versions is not None and candidates:
        ids = {product["cve_id"] for product, _ in candidates}
        for row in versions.filter(pl.col("cve_id").is_in(ids)).iter_rows(named=True):
            by_product.setdefault((row["cve_id"], row["product_id"]), []).append(row)
    results: dict[str, list[dict]] = {}
    covers = {Relation.EQUAL, Relation.SUPERSET}
    for product, matches in candidates:
        entries = by_product.get((product["cve_id"], product["product_id"]), [])
        assessment: dict = version_status(query.version, product, entries)
        if versions is None:
            assessment = {
                "status": "unknown",
                "reason": "Version table is unavailable",
                "entry": None,
            }
        if not any(identity in covers for _, _, identity in matches):
            assessment["status"] = "unknown"
            assessment["reason"] = (
                "CPE identity or platform constraints do not cover the whole query"
            )
        elif assessment["status"] == "affected" and not any(
            compare_names(parsed, query) in covers for _, parsed, _ in matches
        ):
            assessment["status"] = "unknown"
            assessment["reason"] = (
                "CPE version constraints and version entries do not jointly cover the query"
            )
        constraints = {
            key: product[key]
            for key in ("modules", "program_files", "program_routines", "platforms")
            if product.get(key)
        }
        if constraints:
            assessment["status"] = "unknown"
            assessment["reason"] = "Additional product context is required"
        entry = assessment.pop("entry")
        if entry is not None:
            entry = {
                key: value
                for key, value in entry.items()
                if key not in ("cve_id", "product_id") and value is not None
            }
        evidence = {
            "product_id": product["product_id"],
            "source": product.get("source"),
            "vendor": product.get("vendor"),
            "product": product.get("product"),
            **assessment,
            "version_entry": entry,
            "default_status": product.get("default_status"),
            "context_required": constraints,
            "cpes": [
                {
                    "name": name,
                    "relation": compare_names(parsed, query).value,
                    "identity_relation": identity.value,
                }
                for name, parsed, identity in matches
            ],
        }
        results.setdefault(product["cve_id"], []).append(evidence)
    return results, {
        "products_without_cpes": missing,
        "invalid_cpes": invalid,
        "version_data_available": versions is not None,
        "scope": "affected[].cpes and their product version entries; CPE applicability environment expressions are not evaluated",
    }
