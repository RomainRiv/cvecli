"""CPE 2.3 bindings and directional name relations (NIST IR 7695/7696).

CPE version attributes are strings, not ordered version numbers. CVE range
assessment is implemented separately in applicability.py.
"""

import re
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
from itertools import groupby


class Logical(Enum):
    ANY = "*"
    NA = "-"


class Relation(str, Enum):
    EQUAL = "equal"
    SUPERSET = "superset"
    SUBSET = "subset"
    DISJOINT = "disjoint"
    UNDEFINED = "undefined"
    OVERLAP = "overlap"


# Tokens retain the distinction between quoted literals and wildcard operators.
Value = Logical | tuple[tuple[str, bool], ...]
ATTRIBUTES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_LITERAL = r'[a-zA-Z0-9._-]|\\[\\*?!"#$%&\'()+,/:;<=>@\[\]\^`{|}~]'
_COMPONENT = re.compile(rf"(?:\?*|\*?)(?:{_LITERAL})+(?:\?*|\*?)")


def _component(value: str, *, uri: bool = False) -> Value:
    if value == "" and uri or value == "*" and not uri:
        return Logical.ANY
    if value == "-":
        return Logical.NA
    if uri:
        parts = []
        index = 0
        while index < len(value):
            char = value[index]
            if char == "%":
                code = value[index + 1 : index + 3]
                if len(code) != 2 or not re.fullmatch("[0-9a-fA-F]{2}", code):
                    raise ValueError("Invalid CPE percent escape")
                number = int(code, 16)
                if number in (1, 2):
                    parts.append("?" if number == 1 else "*")
                elif 33 <= number <= 126:
                    decoded = chr(number)
                    parts.append(
                        decoded
                        if decoded.isalnum() or decoded in "._-"
                        else "\\" + decoded
                    )
                else:
                    raise ValueError("Invalid CPE URI character")
                index += 3
            elif char.isascii() and (char.isalnum() or char in "._-?"):
                parts.append(char)
                index += 1
            else:
                raise ValueError("Invalid CPE URI character")
        value = "".join(parts)
    if not value or not (
        _COMPONENT.fullmatch(value) or uri and re.fullmatch(r"\?+|\*", value)
    ):
        raise ValueError("Invalid CPE component or embedded wildcard")
    tokens = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            tokens.append((value[index + 1], False))
            index += 2
        else:
            tokens.append((char, char in "*?"))
            index += 1
    return tuple(tokens)


def literal(value: str) -> Value:
    if not value or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("Version must be a nonempty printable ASCII string")
    return tuple((char, False) for char in value)


def concrete(value: Value) -> str | None:
    if isinstance(value, Logical) or any(wild for _, wild in value):
        return None
    return "".join(char for char, _ in value)


@dataclass(frozen=True)
class CPE:
    values: tuple[Value, ...]

    @property
    def version(self) -> str | None:
        return concrete(self.values[3])

    def with_version(self, version: str) -> "CPE":
        values = list(self.values)
        values[3] = literal(version)
        return replace(self, values=tuple(values))


@lru_cache(maxsize=8192)
def parse_cpe(value: str) -> CPE:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Invalid CPE length")
    uri = value.lower().startswith("cpe:/")
    if uri:
        parts = value[5:].split(":")
        if len(parts) > 7:
            raise ValueError("CPE URI has too many components")
        parts += [""] * (7 - len(parts))
        extensions = [""] * 4
        if parts[5].startswith("~"):
            packed = parts[5].split("~")
            if len(packed) != 6:
                raise ValueError("Invalid packed CPE edition")
            parts[5], *extensions = packed[1:]
        parts += extensions
    elif value.startswith("cpe:2.3:"):
        # Consume escape pairs together, so escaped colons never become delimiters.
        parts = []
        current = ""
        index = 8
        while index < len(value):
            char = value[index]
            if char == "\\":
                if index + 1 == len(value):
                    raise ValueError("Trailing CPE escape")
                current += value[index : index + 2]
                index += 2
                continue
            if char == ":":
                parts.append(current)
                current = ""
            else:
                current += char
            index += 1
        parts.append(current)
        if len(parts) != 11:
            raise ValueError("CPE 2.3 requires all eleven components")
    else:
        raise ValueError("Expected cpe:2.3:... or cpe:/... URI")
    values = tuple(_component(part, uri=uri) for part in parts)
    if values[0] not in (Logical.ANY, Logical.NA) and (
        concrete(values[0]) or ""
    ).lower() not in ("a", "o", "h"):
        raise ValueError("Invalid CPE part")
    language = concrete(values[6])
    if language is not None and not re.fullmatch(
        r"[a-zA-Z]{2,3}(?:-(?:[a-zA-Z]{2}|[0-9]{3}))?", language
    ):
        raise ValueError("Invalid CPE language")
    return CPE(values)


def compare_attribute(source: Value, target: Value) -> Relation:
    """Directional relation, including all 17 cases of IR 7696 Table 6-2."""
    if not isinstance(target, Logical) and any(wild for _, wild in target):
        return Relation.UNDEFINED
    if isinstance(source, tuple):
        source = tuple((char.lower(), wild) for char, wild in source)
    if isinstance(target, tuple):
        target = tuple((char.lower(), wild) for char, wild in target)
    if source == target:
        return Relation.EQUAL
    if source == Logical.ANY:
        return Relation.SUPERSET
    if target == Logical.ANY:
        return Relation.SUBSET
    if source == Logical.NA or target == Logical.NA:
        return Relation.DISJOINT
    assert isinstance(source, tuple) and isinstance(target, tuple)
    pieces = []
    for questions, group in groupby(source, key=lambda token: token == ("?", True)):
        if questions:
            # A run of N question marks matches 0..N characters, without an
            # exponential chain of optional regex terms.
            count = sum(1 for _ in group)
            pieces.append(f".{{0,{count}}}")
        else:
            pieces.extend(".*" if wild else re.escape(char) for char, wild in group)
    pattern = "".join(pieces)
    return (
        Relation.SUPERSET
        if re.fullmatch(pattern, "".join(char for char, _ in target))
        else Relation.DISJOINT
    )


def compare_names(
    source: CPE, target: CPE, *, ignore_version: bool = False
) -> Relation:
    relations = {
        compare_attribute(a, b)
        for index, (a, b) in enumerate(zip(source.values, target.values))
        if not (ignore_version and index == 3)
    }
    if Relation.DISJOINT in relations:
        return Relation.DISJOINT
    if Relation.UNDEFINED in relations:
        return Relation.UNDEFINED
    if relations == {Relation.EQUAL}:
        return Relation.EQUAL
    if relations <= {Relation.EQUAL, Relation.SUPERSET}:
        return Relation.SUPERSET
    if relations <= {Relation.EQUAL, Relation.SUBSET}:
        return Relation.SUBSET
    return Relation.OVERLAP


def product_cpes(value: str | None) -> list[str]:
    # Legacy Parquet uses commas; escaped commas inside a name are retained.
    return re.split(r",(?=cpe:(?:2\.3:|/))", value) if value else []
