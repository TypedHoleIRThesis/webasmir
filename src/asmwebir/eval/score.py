"""Graded scoring of recovered types against DWARF reference types (RQ4).

Per parameter and return value:
  kind      correct | unknown | wrong   size and class the machine sees
  ptr_level correct | wrong             for reference pointers
  layout    recall / precision of (offset, size) leaves of a pointed-to struct
  exact     the claimed type equals the reference (int width+sign, struct layout)

Unknown is not wrong: a hole with no evidence is honest uncertainty, which is
the point of the representation. Divergence that is compatible with the binary
is reported, never silently counted as an error (proposal, section I.4).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..store.canon import Snapshot
from .dwarf_ref import RefFunction, flat_layout, kind, ptr_level


@dataclass
class ParamScore:
    fn: str
    index: int  # -1 = return value
    ref: tuple
    kind: str  # correct | unknown | wrong
    ptr_level: str | None = None
    layout_recall: float | None = None
    layout_precision: float | None = None
    exact: bool = False


@dataclass
class FunctionScore:
    name: str
    addr: int
    arity_ref: int
    arity_ours: int
    params: list[ParamScore] = field(default_factory=list)


def our_kind(S: Snapshot, t: tuple) -> tuple[str, str]:
    n, _, c = S.kind_of(S.key(t))
    return n, c


def kind_verdict(ours: tuple[str, str], ref: tuple[int, str]) -> str:
    n, c = ours
    rn, rc = ref
    if c == "⊤" and n in ("?", ""):
        return "unknown"
    if "/" in c or "/" in n:
        return "wrong"  # contradictory evidence
    if rc == "agg":  # struct by value: we only see its pieces
        return "correct" if c == "agg" else "unknown"
    if c == "⊤":
        return "correct" if n == str(rn) else ("unknown" if n == "?" else "wrong")
    if c != rc:
        return "wrong"
    if n.startswith(">="):
        return "correct"
    return "correct" if n == str(rn) else "wrong"


def our_ptr_level(S: Snapshot, t: tuple) -> int:
    node, lvl = S.node(t), 0
    while node is not None and node.tag == "ptr" and lvl < 6:
        lvl += 1
        node = node.to
    return lvl


def our_layout(S: Snapshot, t: tuple) -> set[tuple[int, int]]:
    node = S.node(t)
    if node.tag != "ptr" or node.to is None:
        return set()
    k = node.to.key() if hasattr(node.to, "key") else None
    info = S.kinds.get(k) if k else None
    leaves = set()
    if info:
        for o, slot in info.layout.items():
            leaves.add((o, max(slot.sizes)))
    target = S.node_by_key(k) if k else None
    if target is not None and target.tag == "named" and target.name in S.structs:
        from ..store.checks import field_kind

        for o, _, ft in S.structs[target.name].fields:
            fk = field_kind(ft, S.structs)
            if fk:
                leaves.add((o, fk[0]))
    return leaves


def exact(S: Snapshot, t: tuple, ref: tuple) -> bool:
    node = S.node(t)
    if ref[0] == "int":
        return node.tag == "int" and node.bits == ref[1] and node.sign == ref[2]
    if ref[0] == "flt":
        return node.tag == "flt" and node.bits == ref[1]
    if ref[0] == "ptr" and node.tag == "ptr":
        r = ref[1]
        if r[0] in ("struct", "union"):
            ours = our_layout(S, t)
            return bool(ours) and ours == flat_layout(r)
        return node.to is not None and node.to.tag != "hole" and exact_node(node.to, r)
    return False


def exact_node(node, ref) -> bool:
    if ref[0] == "int":
        return node.tag == "int" and node.bits == ref[1] and node.sign == ref[2]
    return False


def score_value(S: Snapshot, fn: str, i: int, t: tuple, ref: tuple) -> ParamScore:
    ps = ParamScore(fn, i, ref, kind_verdict(our_kind(S, t), kind(ref)))
    if ref[0] == "ptr":
        ps.ptr_level = "correct" if our_ptr_level(S, t) == ptr_level(ref) else "wrong"
        pointee = ref[1]
        if pointee[0] in ("struct", "union"):
            want = flat_layout(pointee)
            got = our_layout(S, t)
            hit = len(want & got)
            ps.layout_recall = hit / len(want) if want else None
            ps.layout_precision = hit / len(got) if got else None
    ps.exact = exact(S, t, ref)
    return ps


def score_program(prog, S: Snapshot, ref: dict[int, RefFunction]) -> list[FunctionScore]:
    out = []
    for f in sorted(prog.functions.values(), key=lambda f: f.addr):
        r = ref.get(f.addr)
        if r is None:
            continue
        arity = max(S.arity.get(S.code(f.name), 0), len(f.params))
        fs = FunctionScore(r.name, f.addr, len(r.params), arity)
        for i, (_, rt) in enumerate(r.params):
            t = ("tv", f.params[i].id) if i < len(f.params) else ("param", f.name, i)
            if i >= 6 and i >= len(f.params):
                continue  # stack parameters are not modelled yet
            fs.params.append(score_value(S, f.name, i, t, rt))
        if r.ret[0] != "void" and f.returns_value:
            fs.params.append(score_value(S, f.name, -1, ("ret", f.name), r.ret))
        out.append(fs)
    return out
