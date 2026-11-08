"""Small, evidence-preserving local CVE reference API."""

import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

import polars as pl

from cvecli.core.config import Config
from cvecli.services.purl import parse_package, same_package

TABLE_COLUMNS = {
    "cves": {"cve_id", "state", "cna_title", "date_published", "date_updated"},
    "descriptions": {"cve_id", "source", "lang", "value"},
    "products": {"cve_id", "source", "product_id", "vendor", "product", "package_url"},
    "versions": {"cve_id", "product_id", "version", "status"},
    "metrics": {"cve_id", "source", "metric_type", "base_score"},
    "references": {"cve_id", "url"},
    "cwes": {"cve_id", "cwe_id"},
}


class ReferenceError(Exception):
    """An expected user-facing failure with a stable machine code."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class SearchRequest:
    query: str = ""
    product: str | None = None
    vendor: str | None = None
    purl: str | None = None
    cwe: str | None = None
    min_score: float | None = None
    after: str | None = None
    before: str | None = None
    state: str = "PUBLISHED"
    limit: int = 20
    offset: int = 0
    cpe: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if self.version is not None and not self.cpe:
            raise ReferenceError("invalid_request", "--version requires --cpe")
        if not 1 <= self.limit <= 100 or self.offset < 0:
            raise ReferenceError(
                "invalid_request", "Limit must be 1–100 and offset nonnegative."
            )
        if self.min_score is not None and not 0 <= self.min_score <= 10:
            raise ReferenceError("invalid_request", "Minimum CVSS score must be 0–10.")
        for value in (self.after, self.before):
            if value is not None:
                try:
                    date.fromisoformat(value)
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                        raise ValueError()
                except ValueError:
                    raise ReferenceError(
                        "invalid_request", "Dates must use YYYY-MM-DD."
                    ) from None
        if self.after and self.before and self.after > self.before:
            raise ReferenceError("invalid_request", "After must not exceed before.")
        if self.state.upper() not in ("PUBLISHED", "REJECTED", "ALL"):
            raise ReferenceError(
                "invalid_request", "State must be published, rejected, or all."
            )


class CVESearchService:
    """A reader pinned to one database snapshot. No network calls; CPE assessments retain their source evidence."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.directory = self.config.database_dir
        self._tables: dict[str, pl.DataFrame] = {}

    def table(self, name: str) -> pl.DataFrame:
        if name not in self._tables:
            path = self.directory / (
                "cves.parquet" if name == "cves" else f"cve_{name}.parquet"
            )
            if not path.is_file():
                raise ReferenceError(
                    "missing_data",
                    f"Required {name} data is missing. Run 'cvecli update'.",
                )
            data = pl.read_parquet(path)
            if not TABLE_COLUMNS[name].issubset(data.columns):
                raise ReferenceError(
                    "invalid_data",
                    f"Invalid {name} table. Run 'cvecli update --force'.",
                )
            self._tables[name] = data
        return self._tables[name]

    def metadata(self) -> dict:
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_text()) if path.exists() else {}
        return {
            "release": manifest.get("release_tag"),
            "built_at": manifest.get("generated_at"),
            "source": "CVE List V5",
            "producer": manifest.get("source"),
            "source_updated_at": manifest.get("source_updated_at"),
            "coverage": manifest.get("coverage"),
            "limitations": [
                "Results describe CVE records, not whether an installed package is vulnerable.",
                "Missing identifiers or annotations do not establish absence of vulnerabilities.",
                "KEV annotations, if present, come from CVE records; no independent catalog is synchronized.",
            ],
        }

    def _related(self, name: str, ids: list[str]) -> pl.DataFrame:
        return self.table(name).filter(pl.col("cve_id").is_in(ids))

    @staticmethod
    def _metric(rows: list[dict]) -> dict | None:
        rows = [
            r
            for r in rows
            if r.get("base_score") is not None
            and str(r.get("metric_type", "")).startswith("cvss")
        ]
        if not rows:
            return None
        versions = {"cvssV4_0": 4, "cvssV3_1": 3, "cvssV3_0": 2, "cvssV2_0": 1}
        row = sorted(
            rows,
            key=lambda r: (
                r.get("source") != "cna",
                -versions.get(str(r.get("metric_type")), 0),
                str(r.get("source")),
                str(r.get("vector_string")),
            ),
        )[0]
        return {
            "score": row["base_score"],
            "severity": row.get("base_severity"),
            "version": row.get("version"),
            "source": row.get("source"),
            "vector": row.get("vector_string"),
        }

    @staticmethod
    def _evidence(row: dict) -> dict:
        result = {
            key: value
            for key, value in row.items()
            if key not in ("cve_id", "product_id") and value is not None
        }
        if isinstance(result.get("changes"), str):
            result["changes"] = json.loads(result["changes"])
        return result

    def _records(
        self, cves: pl.DataFrame, reasons: dict[str, list[str]], detail: bool = False
    ) -> list[dict]:
        ids = cves.get_column("cve_id").to_list()
        if not ids:
            return []
        names = ["descriptions", "metrics"] + (
            ["products", "versions", "references", "cwes"] if detail else []
        )
        related: dict[str, dict[str, list[dict]]] = {}
        for name in names:
            related[name] = {}
            for row in self._related(name, ids).to_dicts():
                related[name].setdefault(row["cve_id"], []).append(row)
        records = []
        for row in cves.to_dicts():
            cve_id = row["cve_id"]
            descriptions = sorted(
                related["descriptions"].get(cve_id, []),
                key=lambda d: (
                    d.get("lang") != "en",
                    d.get("source") != "cna",
                    str(d.get("value")),
                ),
            )
            description = descriptions[0].get("value", "") if descriptions else ""
            record: dict[str, Any] = {
                "id": cve_id,
                "title": row.get("cna_title"),
                "state": row.get("state"),
                "published": row.get("date_published"),
                "updated": row.get("date_updated"),
                "description": description if detail else description[:240],
                "description_truncated": not detail and len(description) > 240,
                "cvss": self._metric(related["metrics"].get(cve_id, [])),
                "matched_fields": reasons.get(cve_id, []),
            }
            if detail:
                record["descriptions"] = descriptions
                record["metrics"] = related["metrics"].get(cve_id, [])
                record["products"] = related["products"].get(cve_id, [])
                for product in record["products"]:
                    product["versions"] = [
                        v
                        for v in related["versions"].get(cve_id, [])
                        if v["product_id"] == product["product_id"]
                    ]
                record["references"] = related["references"].get(cve_id, [])
                record["cwes"] = related["cwes"].get(cve_id, [])
            if detail:
                for field in ("descriptions", "metrics", "references", "cwes"):
                    record[field] = [self._evidence(item) for item in record[field]]
                record["products"] = [
                    {
                        **self._evidence(item),
                        "versions": [self._evidence(v) for v in item["versions"]],
                    }
                    for item in record["products"]
                ]
            records.append(record)
        return records

    def _response(
        self,
        records: list[dict],
        total: int,
        offset: int = 0,
        errors: list[dict] | None = None,
    ) -> dict:
        return {
            "schema_version": 1,
            "database": self.metadata(),
            "metric_policy": "CNA first, then newest CVSS version; all reported metrics available via get.",
            "total": total,
            "offset": offset,
            "next_offset": (
                offset + len(records) if offset + len(records) < total else None
            ),
            "results": records,
            "errors": errors or [],
        }

    def search(self, request: SearchRequest) -> dict:
        cves = self.table("cves")
        if request.state.upper() != "ALL":
            cves = cves.filter(
                pl.col("state").str.to_uppercase() == request.state.upper()
            )
        if request.after:
            cves = cves.filter(
                pl.col("date_published").str.slice(0, 10) >= request.after
            )
        if request.before:
            cves = cves.filter(
                pl.col("date_published").str.slice(0, 10) <= request.before
            )
        reasons: dict[str, list[str]] = {}
        identity = None
        cpe = None
        cpe_results: dict[str, list[dict]] = {}
        cpe_metadata: dict = {}
        if request.cpe:
            from cvecli.services.cpe import parse_cpe, Logical

            try:
                cpe = parse_cpe(request.cpe)
                if request.version is not None:
                    cpe = cpe.with_version(request.version)
                if all(isinstance(cpe.values[index], Logical) for index in (1, 2)):
                    raise ValueError("CPE lookup requires a vendor or product name")
            except ValueError as error:
                raise ReferenceError("invalid_request", str(error)) from error
        if request.purl:
            try:
                identity, _ = parse_package(request.purl)
            except ValueError as error:
                raise ReferenceError("invalid_request", str(error)) from error
        if request.vendor or request.product or identity or cpe:
            products = self.table("products")
            for field, value in (
                ("vendor", request.vendor),
                ("product", request.product),
            ):
                if value:
                    products = products.filter(
                        pl.col(field).fill_null("").str.to_lowercase() == value.lower()
                    )
            if identity:
                products = products.filter(
                    pl.col("package_url")
                    .fill_null("")
                    .map_elements(
                        lambda value: same_package(value, identity),
                        return_dtype=pl.Boolean,
                    )
                )
            if cpe is not None:
                from cvecli.services.cpe_lookup import lookup

                if "cpes" not in products.columns:
                    raise ReferenceError(
                        "missing_data", "CPE data is missing from the products table"
                    )
                products = products.filter(
                    pl.col("cve_id").is_in(cves["cve_id"].to_list())
                )
                versions = (
                    self.table("versions")
                    if self.config.cve_versions_parquet.is_file()
                    else None
                )
                cpe_results, cpe_metadata = lookup(products, versions, cpe)
                products = products.filter(pl.col("cve_id").is_in(list(cpe_results)))
            ids = products.get_column("cve_id").unique().to_list()
            cves = cves.filter(pl.col("cve_id").is_in(ids))
            for cve_id in ids:
                reasons[cve_id] = [
                    field
                    for field, value in (
                        ("vendor", request.vendor),
                        ("product", request.product),
                        ("purl", identity),
                        ("cpe", cpe),
                    )
                    if value
                ]
        if request.cwe:
            cwe = request.cwe.upper()
            if not cwe.startswith("CWE-"):
                cwe = "CWE-" + cwe
            ids = (
                self.table("cwes")
                .filter(pl.col("cwe_id") == cwe)
                .get_column("cve_id")
                .to_list()
            )
            cves = cves.filter(pl.col("cve_id").is_in(ids))
        terms = list(dict.fromkeys(request.query.lower().split()))
        if terms:
            ids = cves.get_column("cve_id").to_list()
            fields = cves.select(
                "cve_id", pl.col("cna_title").fill_null("").alias("text")
            ).with_columns(pl.lit("title").alias("field"))
            for table, columns in (
                ("descriptions", ["value"]),
                ("products", ["vendor", "product"]),
            ):
                data = self._related(table, ids)
                for column in columns:
                    fields = pl.concat(
                        [
                            fields,
                            data.select(
                                "cve_id", pl.col(column).fill_null("").alias("text")
                            ).with_columns(
                                pl.lit(
                                    "description" if column == "value" else column
                                ).alias("field")
                            ),
                        ]
                    )
            fields = fields.with_columns(pl.col("text").str.to_lowercase())
            documents = fields.group_by("cve_id").agg(pl.col("text").str.join(" "))
            for term in terms:
                documents = documents.filter(
                    pl.col("text").str.contains(term, literal=True)
                )
            cves = cves.filter(pl.col("cve_id").is_in(documents["cve_id"].to_list()))
            hits = fields.filter(
                pl.any_horizontal(
                    [pl.col("text").str.contains(term, literal=True) for term in terms]
                )
            )
            for row in hits.select("cve_id", "field").unique().to_dicts():
                reasons.setdefault(row["cve_id"], []).append(row["field"])
        if request.min_score is not None:
            metrics: dict[str, list[dict]] = {}
            for row in self._related("metrics", cves["cve_id"].to_list()).to_dicts():
                metrics.setdefault(row["cve_id"], []).append(row)
            ids = [
                key
                for key, rows in metrics.items()
                if (metric := self._metric(rows)) is not None
                and metric["score"] >= request.min_score
            ]
            cves = cves.filter(pl.col("cve_id").is_in(ids))
        for key in reasons:
            reasons[key] = sorted(set(reasons[key]))
        # Fixed, documented relevance: title matches, then number of matching fields.
        cves = cves.with_columns(
            pl.col("cve_id")
            .map_elements(
                lambda key: (10 if "title" in reasons.get(key, []) else 0)
                + len(reasons.get(key, [])),
                return_dtype=pl.Int64,
            )
            .alias("rank")
        )
        cves = cves.sort(
            ["rank", "date_published", "cve_id"],
            descending=[True, True, False],
            nulls_last=True,
        )
        total = len(cves)
        records = self._records(cves.slice(request.offset, request.limit), reasons)
        if cpe is not None:
            from cvecli.services.applicability import combine_statuses

            for record in records:
                evidence = cpe_results[record["id"]]
                record["applicability"] = {
                    "status": combine_statuses([item["status"] for item in evidence]),
                    "products": evidence,
                }
        response = self._response(records, total, request.offset)
        if cpe is not None:
            response["cpe_query"] = {
                "input": request.cpe,
                "version": cpe.version,
                **cpe_metadata,
            }

        if request.purl:
            response["package_query"] = {
                "identity": identity,
                "version": parse_package(request.purl)[1],
                "version_evaluated": False,
            }
        return response

    def get(self, ids: list[str]) -> dict:
        if not ids or len(ids) > 100:
            raise ReferenceError(
                "invalid_request", "Request between 1 and 100 CVE IDs."
            )
        ids = list(dict.fromkeys(value.upper() for value in ids))
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in ids):
            raise ReferenceError(
                "invalid_request", "Expected CVE-YYYY-NNNN identifiers."
            )
        cves = self.table("cves").filter(pl.col("cve_id").is_in(ids))
        records = self._records(cves, {}, detail=True)
        records.sort(key=lambda record: ids.index(record["id"]))
        found = {record["id"] for record in records}
        errors = [
            {
                "code": "not_found",
                "id": value,
                "message": "Not found in this database snapshot.",
            }
            for value in ids
            if value not in found
        ]
        return self._response(records, len(records), errors=errors)

    def products(self, query: str, limit: int = 20, offset: int = 0) -> dict:
        SearchRequest(limit=limit, offset=offset)
        if not query.strip():
            raise ReferenceError("invalid_request", "Provide a product or vendor name.")
        products = self.table("products")
        products = products.filter(
            pl.any_horizontal(
                [
                    pl.col(field)
                    .fill_null("")
                    .str.to_lowercase()
                    .str.contains(query.lower(), literal=True)
                    for field in ("vendor", "product")
                ]
            )
        )
        products = (
            products.group_by("vendor", "product")
            .agg(pl.col("cve_id").n_unique().alias("record_count"))
            .sort(
                ["record_count", "vendor", "product"],
                descending=[True, False, False],
                nulls_last=True,
            )
        )
        return self._response(
            products.slice(offset, limit).to_dicts(), len(products), offset
        )

    def status(self) -> dict[str, Any]:
        names = [
            "cves",
            "descriptions",
            "products",
            "versions",
            "metrics",
            "references",
            "cwes",
        ]
        missing = [
            name
            for name in names
            if not (
                self.directory
                / ("cves.parquet" if name == "cves" else f"cve_{name}.parquet")
            ).is_file()
        ]
        invalid = []
        for name, columns in TABLE_COLUMNS.items():
            if name in missing:
                continue
            path = self.directory / (
                "cves.parquet" if name == "cves" else f"cve_{name}.parquet"
            )
            try:
                if not columns.issubset(pl.read_parquet_schema(path)):
                    invalid.append(name)
            except (OSError, pl.exceptions.PolarsError):
                invalid.append(name)
        result = {
            "schema_version": 1,
            "ready": not missing and not invalid,
            "directory": str(self.directory),
            "database": self.metadata(),
            "missing_tables": missing,
            "invalid_tables": invalid,
            "errors": [
                {
                    "code": "invalid_data",
                    "message": f"Invalid {name} table. Run cvecli update --force.",
                }
                for name in invalid
            ],
        }
        if "cves" not in missing and "cves" not in invalid:
            cves = self.table("cves")
            result["records"] = len(cves)
            years = sorted(cves["cve_id"].str.slice(4, 4).unique().to_list())
            result["observed_id_years"] = years
        return result
