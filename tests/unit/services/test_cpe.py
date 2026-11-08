"""Offline NIST reference examples, normative relation table and edge cases."""

import json
from pathlib import Path

import pytest

from cvecli.services.cpe import (
    ATTRIBUTES,
    CPE,
    Logical,
    Relation,
    _component,
    compare_attribute,
    compare_names,
    literal,
    parse_cpe,
    product_cpes,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "cpe"


def vectors(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def attr(value):
    return (
        Logical.ANY
        if value == "ANY"
        else Logical.NA if value == "NA" else _component(value)
    )


@pytest.mark.parametrize(
    "case", vectors("nist_table_6_2.json"), ids=lambda c: f"table-6-2-row-{c['row']}"
)
def test_normative_attribute_relations(case):
    assert (
        compare_attribute(attr(case["source"]), attr(case["target"])).value
        == case["relation"]
    )


@pytest.mark.parametrize("case", vectors("nist_matching.json"))
def test_nist_name_matching(case):
    def name(side):
        if side in case:
            return parse_cpe(case[side])
        return CPE(
            tuple(
                (
                    Logical.ANY
                    if value == "ANY"
                    else Logical.NA if value == "NA" else literal(value)
                )
                for value in (case[side + "_wfn"][key] for key in ATTRIBUTES)
            )
        )

    assert compare_names(name("source"), name("target")).value == case["relation"]


@pytest.mark.parametrize("case", vectors("nist_unbinding.json"))
def test_nist_unbinding(case):
    values = parse_cpe(case["input"]).values
    for key, value in zip(ATTRIBUTES, values):
        if isinstance(value, Logical):
            rendered = "ANY" if value == Logical.ANY else "NA"
        else:
            rendered = "".join(
                char if wild or char.isalnum() or char == "_" else "\\" + char
                for char, wild in value
            )
        assert rendered == case["wfn"][key]


@pytest.mark.parametrize(
    "source,target,expected",
    [
        ("9.*", "9.3.2", "superset"),
        ("9.*", "8.3", "disjoint"),
        ("foo?", "foo", "superset"),
        ("foo?", "fooa", "superset"),
        ("foo?", "fooab", "disjoint"),
        ("??foo", "afoo", "superset"),
        (r"foo\?", "foo?", "undefined"),
        (r"foo\?", r"foo\?", "equal"),
        (r"8.\*", "8.1", "disjoint"),
        ("9.1", "9.1.0", "disjoint"),
        ("Mixed", "mixed", "equal"),
        (r"foo\\*", r"foo\\bar", "superset"),
    ],
)
def test_wildcards_escapes_and_opaque_versions(source, target, expected):
    assert compare_attribute(_component(source), _component(target)).value == expected


@pytest.mark.parametrize(
    "value",
    [
        "cpe:2.3:a:vendor:product:1.0",
        "cpe:2.3:a:vendor:bad*middle:*:*:*:*:*:*:*:*",
        "cpe:/z:vendor:product",
        "cpe:/a:vendor:product:%zz",
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:extra",
        "invalid",
    ],
)
def test_malformed_names_are_rejected(value):
    with pytest.raises(ValueError):
        parse_cpe(value)


def test_literal_colon_backslash_and_comma():
    cpe = r"cpe:2.3:a:vendor:foo\:bar\,baz\\:1.0:*:*:*:*:*:*:*"
    assert parse_cpe(cpe).version == "1.0"
    assert product_cpes(cpe + ",cpe:/a:vendor:other") == [cpe, "cpe:/a:vendor:other"]
    assert compare_names(parse_cpe(cpe), parse_cpe(cpe)) == Relation.EQUAL


def test_question_mark_runs_use_nist_zero_to_n_semantics():
    source = _component("?" * 100 + "foo" + "?" * 100)
    assert (
        compare_attribute(source, _component("x" * 100 + "foo" + "x" * 100))
        == Relation.SUPERSET
    )
    assert compare_attribute(source, _component("foo")) == Relation.SUPERSET
    assert compare_attribute(source, _component("x" * 100 + "bar")) == Relation.DISJOINT
