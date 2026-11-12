"""Debug dump of the premise e-graph: its e-classes, data webs and code webs.

Enabled with the environment variable ASMWEBIR_DEBUG_EGRAPH=1 (or
`test_webir.py --egraph`); `KnowledgeStore.__init__` calls `dump_egraph`
before and after `saturate`.

Only terms that the premises mention are listed (every `tv`, `hole`,
`param`, `ret`, `at` and `ptr` they contain). Each term is extracted
(cheapest member of its class) and terms with the same extraction are one
e-class. Extracting does not add facts, so dumping does not change the
e-graph's equalities.
"""
from __future__ import annotations

import sys

import os
from collections import defaultdict

from egglog import EGraph

from ..lift.premises import Access, AllocSize, Bound, Derived, Eq, Kind, Premises, Stride
from .egraph import Code, Encoder, Web


def enabled() -> bool:
    return os.environ.get("ASMWEBIR_DEBUG_EGRAPH", "") not in ("", "0")


def _terms(premises: Premises) -> list[tuple]:
    """Every symbolic type the premises mention, sub-terms included, in premise order."""
    out: dict[tuple, None] = {}

    def walk(t: tuple) -> None:
        out.setdefault(t, None)
        if t[0] == "at":
            walk(t[1])
        elif t[0] == "ptr":
            walk(t[2])

    for p in premises.items:
        if isinstance(p, Eq):
            walk(p.a), walk(p.b)
        elif isinstance(p, Derived):
            walk(p.v), walk(p.p)
        elif isinstance(p, Kind):
            walk(p.t)
        elif isinstance(p, Access):
            walk(("at", p.pointee, p.off))
        elif isinstance(p, (Stride, Bound, AllocSize)):
            walk(p.pointee)
    return list(out)


def _show(t: tuple) -> str:
    tag = t[0]
    if tag == "tv":
        return f"type_of({t[1]})"
    if tag == "hole":
        return f"?[{t[1]}]"
    if tag == "at":
        return f"at({_show(t[1])}, +{t[2]})"
    if tag == "ptr":
        return f"ptr(Web({t[1]}), {_show(t[2])})"
    if tag == "param":
        return f"param({t[1]}, {t[2]})"
    if tag == "ret":
        return f"ret({t[1]})"
    return repr(t)


def dump_egraph(eg: EGraph, enc: Encoder, premises: Premises, title: str) -> None:
    classes: dict[str, list[tuple]] = defaultdict(list)
    for t in _terms(premises):
        classes[str(eg.extract(enc.ty(t)))].append(t)

    print(f"\n===== e-graph {title}: {len(classes)} e-classes =====", file=sys.stderr)
    for i, (rep, members) in enumerate(classes.items(), 1):
        print(f"E{i}  (extracts to {rep})", file=sys.stderr)
        for t in members:
            print(f"    {_show(t)}", file=sys.stderr)

    webs: dict[str, list[str]] = defaultdict(list)
    for base in premises.pointers:
        webs[str(eg.extract(Web(base)))].append(base)
    print(f"--- data webs ({len(webs)}) ---", file=sys.stderr)
    for rep, members in webs.items():
        print(f"  {rep}: {', '.join(members)}", file=sys.stderr)

    codes: dict[str, list[str]] = defaultdict(list)
    for fn in dict.fromkeys(p.fn for p in premises.items):
        codes[str(eg.extract(Code(fn)))].append(fn)
    print(f"--- code webs ({len(codes)}) ---", file=sys.stderr)
    for rep, members in codes.items():
        print(f"  {rep}: {', '.join(members)}", file=sys.stderr)
    print("=" * 40, file=sys.stderr)
