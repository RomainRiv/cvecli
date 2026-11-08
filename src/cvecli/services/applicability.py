"""CVE Record Format version statuses, scoped to a single matched product."""

import json
import re
from functools import cmp_to_key

from semver import Version

STATUSES = {"affected", "unaffected", "unknown"}


def _compare(left: str, right: str) -> int:
    return Version.parse(left).compare(Version.parse(right))


def _compare_changes(left: dict, right: dict) -> int:
    return _compare(left["at"], right["at"])


def _below_upper(version: str, upper: str, inclusive: bool) -> bool:
    parsed = Version.parse(version)
    if upper == "*":
        return True
    if re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?\.\*", upper):
        prefix = tuple(int(part) for part in upper[:-2].split("."))
        return (parsed.major, parsed.minor)[: len(prefix)] <= prefix
    comparison = parsed.compare(Version.parse(upper))
    return comparison <= 0 if inclusive else comparison < 0


def version_status(version: str | None, product: dict, entries: list[dict]) -> dict:
    """Follow the CVE schema's first-matching-entry algorithm.

    Exact strings work for all version schemes. Ordered ranges currently support
    declared semver only; ambiguous comparisons must not fall through to a default.
    """

    def result(status: str, reason: str, entry: dict | None = None) -> dict:
        return {
            "status": status if status in STATUSES else "unknown",
            "reason": reason,
            "entry": entry,
        }

    if version is None:
        return result("unknown", "A concrete version is required for assessment")
    for entry in entries:
        start = entry.get("version")
        if not isinstance(start, str):
            return result("unknown", "Missing version entry", entry)
        status = entry.get("status", "unknown")
        upper = entry.get("less_than") or entry.get("less_than_or_equal")
        if not upper:
            if start == version:
                return result(status, "Exact version entry", entry)
            if start == "*":
                return result(
                    "unknown",
                    "Wildcard version entry has no defined comparison scheme",
                    entry,
                )
            if entry.get("version_type") == "semver":
                try:
                    if _compare(version, start) == 0:
                        return result(status, "Equal semantic version", entry)
                except (ValueError, TypeError):
                    return result("unknown", "Invalid semantic version", entry)
            continue
        if entry.get("version_type") != "semver":
            return result(
                "unknown",
                "Unsupported version scheme: "
                + str(entry.get("version_type") or "unspecified"),
                entry,
            )
        try:
            if entry.get("less_than") and entry.get("less_than_or_equal"):
                return result("unknown", "Conflicting range upper bounds", entry)
            Version.parse(version)
            if start != "0" and _compare(version, start) < 0:
                continue
            if not _below_upper(version, upper, bool(entry.get("less_than_or_equal"))):
                continue
            raw_changes = entry.get("changes") or []
            changes: list[dict] = (
                json.loads(raw_changes) if isinstance(raw_changes, str) else raw_changes
            )
            if not isinstance(changes, list) or any(
                not isinstance(change, dict)
                or not isinstance(change.get("at"), str)
                or change.get("status") not in STATUSES
                for change in changes
            ):
                return result("unknown", "Invalid status changes", entry)
            changes = sorted(changes, key=cmp_to_key(_compare_changes))
            for index, change in enumerate(changes):
                if (
                    index
                    and _compare(change["at"], changes[index - 1]["at"]) == 0
                    and change["status"] != changes[index - 1]["status"]
                ):
                    return result("unknown", "Conflicting status changes", entry)
                if _compare(change["at"], version) <= 0:
                    status = change["status"]
            return result(status, "Matching semantic version range", entry)
        except (ValueError, TypeError, KeyError):
            return result("unknown", "Invalid version range or status changes", entry)
    return result(
        product.get("default_status") or "unknown",
        "Product default status; no version entry matched",
    )


def combine_statuses(statuses: list[str]) -> str:
    known = set(statuses)
    return next(iter(known)) if len(known) == 1 else "unknown"
