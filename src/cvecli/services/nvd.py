"""Offline NVD applicability: configurations and authoritative CPE expansions.

NVD range bounds do not declare a version scheme. Match-feed expansions, rather
than guessed numeric ordering, resolve those ranges to official dictionary names.
"""

import gzip
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import polars as pl

from cvecli.core.config import Config
from cvecli.services.cpe import CPE, Relation, compare_names, parse_cpe, concrete

CONFIG_FILE = "cve_cpe_configurations.parquet"
MATCH_FILE = "cpe_matches.parquet"
CONFIG_SCHEMA = {
    "cve_id": pl.String,
    "last_modified": pl.String,
    "configurations": pl.String,
    "products": pl.List(pl.String),
}
MATCH_SCHEMA = {
    "match_id": pl.String,
    "criteria": pl.String,
    "status": pl.String,
    "last_modified": pl.String,
    "names": pl.List(pl.String),
    "bounds": pl.String,
    "product": pl.String,
}
NVD_FILES = {CONFIG_FILE, MATCH_FILE}
BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def leaves(value: Any) -> Iterator[dict]:
    if isinstance(value, dict):
        if "criteria" in value:
            yield value
        for key in ("configurations", "nodes", "children", "cpeMatch"):
            yield from leaves(value.get(key))
    elif isinstance(value, list):
        for child in value:
            yield from leaves(child)


def _items(stream: Any, prefix: str) -> Iterator[dict]:
    # Only database producers need the streaming JSON dependency.
    import ijson

    yield from ijson.items(stream, prefix)


def feed_items(path: Path, prefix: str) -> Iterator[dict]:
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r|gz") as archive:
            for member in archive:
                if member.isfile() and member.name.endswith(".json"):
                    stream = archive.extractfile(member)
                    assert stream is not None
                    with stream:
                        yield from _items(stream, prefix)
    elif path.suffix == ".gz":
        with gzip.open(path, "rb") as gzip_stream:
            yield from _items(gzip_stream, prefix)
    else:
        with path.open("rb") as stream:
            yield from _items(stream, prefix)


def import_nvd(config: Config, cve_feeds: list[Path], match_feed: Path) -> dict:
    """Preserve source trees and expansions, streaming bounded input batches."""
    if (
        config.data_dir / "CURRENT"
    ).exists() or config.data_dir.parent.name == "snapshots":
        raise ValueError("Enrich a build directory, not an installed snapshot")
    known = set(
        pl.read_parquet(config.cves_parquet, columns=["cve_id"])["cve_id"].to_list()
    )
    needed: set[str] = set()
    seen: set[str] = set()
    counts = {"cve_records": 0, "match_criteria": 0, "missing_match_criteria": 0}
    with tempfile.TemporaryDirectory(dir=config.data_dir) as temporary:
        stage = Path(temporary)

        def write_chunks(rows: Iterator[dict], schema: dict, label: str) -> Path:
            batch = []
            chunks: list[Path] = []
            for row in rows:
                batch.append(row)
                if len(batch) >= 1000:
                    chunk = stage / f"{label}-{len(chunks)}.parquet"
                    pl.DataFrame(batch, schema=schema).write_parquet(chunk)
                    chunks.append(chunk)
                    batch = []
            if batch or not chunks:
                chunk = stage / f"{label}-{len(chunks)}.parquet"
                pl.DataFrame(batch, schema=schema).write_parquet(chunk)
                chunks.append(chunk)
            destination = stage / f"{label}.parquet"
            pl.scan_parquet(chunks).sink_parquet(destination)
            return destination

        def configurations() -> Iterator[dict]:
            for feed in cve_feeds:
                for cve in feed_items(feed, "vulnerabilities.item.cve"):
                    if cve["id"] not in known or not cve.get("configurations"):
                        continue
                    if cve["id"] in seen:
                        raise ValueError(
                            f"Duplicate NVD CVE in input feeds: {cve['id']}"
                        )
                    seen.add(cve["id"])
                    for leaf in leaves(cve["configurations"]):
                        if leaf.get("matchCriteriaId"):
                            needed.add(leaf["matchCriteriaId"])
                    products = set()
                    for leaf in leaves(cve["configurations"]):
                        if leaf.get("vulnerable") is not True:
                            continue
                        try:
                            products.add(
                                identity_key(parse_cpe(leaf["criteria"])) or "*"
                            )
                        except ValueError:
                            products.add("*")
                    counts["cve_records"] += 1
                    yield {
                        "cve_id": cve["id"],
                        "last_modified": cve.get("lastModified"),
                        "configurations": json.dumps(
                            cve["configurations"], separators=(",", ":")
                        ),
                        "products": sorted(products),
                    }

        configs = write_chunks(configurations(), CONFIG_SCHEMA, "configs")
        found: set[str] = set()

        def matches() -> Iterator[dict]:
            for item in feed_items(match_feed, "matchStrings.item.matchString"):
                match_id = item["matchCriteriaId"]
                if match_id not in needed:
                    continue
                if match_id in found:
                    raise ValueError(f"Duplicate NVD match criterion: {match_id}")
                found.add(match_id)
                counts["match_criteria"] += 1
                try:
                    product_key = identity_key(parse_cpe(item["criteria"])) or "*"
                except ValueError:
                    product_key = "*"
                yield {
                    "match_id": match_id,
                    "product": product_key,
                    "criteria": item["criteria"],
                    "status": item.get("status", "Unknown"),
                    "last_modified": item.get("cpeLastModified")
                    or item.get("lastModified"),
                    "names": [name["cpeName"] for name in item.get("matches", [])],
                    "bounds": json.dumps(
                        {bound: item[bound] for bound in BOUNDS if item.get(bound)}
                    ),
                }

        match_data = write_chunks(matches(), MATCH_SCHEMA, "matches")
        counts["missing_match_criteria"] = len(needed - found)
        if not counts["cve_records"] or not counts["match_criteria"]:
            raise ValueError(
                "NVD input contains no usable configurations or CPE match expansions"
            )
        os.replace(configs, config.data_dir / CONFIG_FILE)
        os.replace(match_data, config.data_dir / MATCH_FILE)
    metadata = {
        **counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cve_feeds": [feed.name for feed in cve_feeds],
        "match_feed": match_feed.name,
    }
    (config.data_dir / "nvd_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    return metadata


def identity_key(name: CPE) -> str | None:
    parts = [concrete(value) for value in name.values[:3]]
    return (
        json.dumps([value.lower() for value in parts if value is not None])
        if all(value is not None for value in parts)
        else None
    )


def _and(values: list[bool | None]) -> bool | None:
    return False if False in values else None if None in values else True


def _or(values: list[bool | None]) -> bool | None:
    return True if True in values else None if None in values else False


class NVDLookup:
    def __init__(self, directory: Path):
        self.directory = directory

    @property
    def available(self) -> bool:
        return all((self.directory / name).is_file() for name in NVD_FILES)

    def lookup(self, query: CPE, ids: list[str]) -> dict[str, list[dict]]:
        if not self.available:
            return {}
        configs_query = pl.scan_parquet(self.directory / CONFIG_FILE).filter(
            pl.col("cve_id").is_in(ids)
        )
        key = identity_key(query)
        if key is not None:
            configs_query = configs_query.filter(
                pl.col("products").list.contains(key)
                | pl.col("products").list.contains("*")
            )
        configs = configs_query.collect()
        # First narrow by identity; avoid loading expansion lists for other products.
        relevant = []
        match_ids: set[str] = set()
        for row in configs.iter_rows(named=True):
            tree = json.loads(row["configurations"])
            if any(
                self._identity(leaf, query)
                for leaf in leaves(tree)
                if leaf.get("vulnerable") is True
            ):
                relevant.append((row, tree))
                match_ids.update(
                    leaf["matchCriteriaId"]
                    for leaf in leaves(tree)
                    if leaf.get("matchCriteriaId")
                )
        expansions = {
            row["match_id"]: row
            for row in pl.scan_parquet(self.directory / MATCH_FILE)
            .filter(pl.col("match_id").is_in(match_ids))
            .collect()
            .iter_rows(named=True)
        }
        registered = False
        if key is not None:
            known_names = (
                pl.scan_parquet(self.directory / MATCH_FILE)
                .filter(
                    (pl.col("product").is_in([key, "*"]))
                    & (pl.col("status") == "Active")
                )
                .select("names")
                .explode("names")
                .unique()
                .collect()["names"]
            )
            for name in known_names:
                try:
                    if compare_names(parse_cpe(name), query) == Relation.EQUAL:
                        registered = True
                        break
                except ValueError:
                    continue
        results = {}
        for row, tree in relevant:
            evidence: list[dict] = []
            matched_configs = []
            values = []
            for configuration in tree:
                _, applicable, status = self._node(
                    configuration, query, expansions, evidence, registered
                )
                if applicable:
                    values.append(status)
                    matched_configs.append(configuration)
            overall = _or(values)
            overall_status = (
                "affected"
                if overall is True
                else "unaffected" if overall is False else "unknown"
            )
            results[row["cve_id"]] = [
                {
                    "source": "nvd",
                    "status": overall_status,
                    "reason": (
                        "NVD matching or environment requirements remain unresolved"
                        if overall is None
                        else "NVD applicability configurations evaluated against CPE match expansions"
                    ),
                    "last_modified": row["last_modified"],
                    "matched_by_nvd_expansion": any(
                        item["membership"] is True for item in evidence
                    ),
                    "criteria": evidence,
                    "configurations": matched_configs,
                }
            ]
        return results

    @staticmethod
    def _identity(leaf: dict, query: CPE) -> bool:
        try:
            source = parse_cpe(leaf["criteria"])
        except (KeyError, ValueError):
            return False
        return (
            compare_names(source, query, ignore_version=True) != Relation.DISJOINT
            and compare_names(query, source, ignore_version=True) != Relation.DISJOINT
        )

    def _leaf(
        self, leaf: dict, query: CPE, expansions: dict[str, dict], registered: bool
    ) -> tuple[bool | None, str]:
        try:
            source = parse_cpe(leaf["criteria"])
        except (KeyError, ValueError):
            return None, "Invalid recorded CPE criterion"
        relation = compare_names(source, query)
        if relation == Relation.DISJOINT:
            return False, "Disjoint CPE name"
        covers = {Relation.EQUAL, Relation.SUPERSET}
        if not any(leaf.get(bound) for bound in BOUNDS):
            return (
                (True, "CPE name covers query")
                if relation in covers
                else (None, "CPE name only partially covers query")
            )
        expansion = expansions.get(leaf.get("matchCriteriaId", ""))
        if (
            not expansion
            or expansion["status"] != "Active"
            or expansion["criteria"] != leaf["criteria"]
        ):
            return None, "NVD range expansion is missing or inactive"
        if json.loads(expansion["bounds"]) != {
            bound: leaf[bound] for bound in BOUNDS if leaf.get(bound)
        }:
            return None, "NVD configuration and expansion bounds differ"
        for name in expansion["names"]:
            try:
                if compare_names(parse_cpe(name), query) in covers:
                    return True, "NVD-expanded dictionary name covers query"
            except ValueError:
                continue
        if registered:
            return False, "Known dictionary name is outside this NVD expansion"
        # Absence from an expansion does not establish safety for an arbitrary
        # unregistered name; preserve uncertainty rather than order version strings.
        return None, "Query not resolved by the available NVD dictionary expansion"

    def _node(
        self,
        node: dict,
        query: CPE,
        expansions: dict[str, dict],
        evidence: list[dict],
        registered: bool = False,
    ) -> tuple[bool | None, bool, bool | None]:
        children = []
        for leaf in node.get("cpeMatch", []):
            relevant = leaf.get("vulnerable") is True and self._identity(leaf, query)
            if self._identity(leaf, query):
                membership, reason = self._leaf(leaf, query, expansions, registered)
            else:
                membership, reason = (
                    None,
                    "Other installed product or environment context required",
                )
            if relevant:
                evidence.append({**leaf, "membership": membership, "reason": reason})
            children.append((membership, relevant, membership if relevant else None))
        for child in node.get("nodes", []) + node.get("children", []):
            children.append(self._node(child, query, expansions, evidence, registered))
        if not children:
            return None, False, None
        relevant = any(item[1] for item in children)
        operator = node.get("operator", "OR")
        if operator not in ("AND", "OR"):
            return None, relevant, None
        truth = (_and if operator == "AND" else _or)([item[0] for item in children])
        relevant_status = _or([item[2] for item in children if item[1]])
        status = (
            _and([truth, relevant_status]) if operator == "AND" else relevant_status
        )
        if node.get("negate"):
            truth = not truth if truth is not None else None
            status = None
        return truth, relevant, status if relevant else None
