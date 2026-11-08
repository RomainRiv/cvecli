"""Package identity parsing for exact PURL searches."""

import re
from urllib.parse import unquote


def parse_package(value: str) -> tuple[str, str | None]:
    """Return a package identity and optional version, excluding qualifiers."""
    if not value.lower().startswith("pkg:"):
        raise ValueError(f"Invalid PURL format: {value}")
    path = value[4:].split("#", 1)[0].split("?", 1)[0]
    kind, separator, name = path.partition("/")
    if not separator or not name or not kind:
        raise ValueError(f"Invalid PURL format: {value}")
    version = None
    if "@" in name.rsplit("/", 1)[-1]:
        name, version = name.rsplit("@", 1)
    name = unquote(name)
    if not name or not name.rsplit("/", 1)[-1]:
        raise ValueError(f"Invalid PURL format: {value}")
    kind = kind.lower()
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif kind == "npm":
        name = name.lower()
    return f"pkg:{kind}/{name}", unquote(version) if version else None


def same_package(value: str, identity: str) -> bool:
    try:
        return parse_package(value)[0] == identity
    except ValueError:
        return False
