"""Contradiction checks over a saturated, frozen snapshot (section 23).

Each check returns `Clash` records whose identity (`ident`) does not depend on
class numbering, so that the same contradiction can be recognised under
different belief sets while QuickXplain shrinks its label.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..claims.dsl import ArityEq, Name, StructDecl, render_fact
from ..lift.premises import Arity
from ..trace import rule
from .canon import Snapshot, TyNode


@dataclass(frozen=True)
class Clash:
    rule: str
    ident: tuple
    message: str
    witness: tuple[int, ...] = ()


def scalar_size(node: TyNode, structs) -> int | None:
    if node.tag == "int" or node.tag == "flt":
        return node.bits // 8
    if node.tag == "ptr":
        return 8
    if node.tag == "named" and node.name in structs:
        return struct_size(structs[node.name], structs)
    if node.tag == "arr" and node.to is not None:
        el = scalar_size(node.to, structs)
        return el * node.bits if el else None
    return None


def type_class(node: TyNode) -> str | None:
    return {"int": "int", "flt": "flt", "ptr": "ptr", "named": "agg", "arr": "agg"}.get(node.tag)


def field_kind(t: tuple, structs) -> tuple[int, int] | None:
    """(size, alignment) of a field type written in a declaration."""
    tag = t[0]
    if tag in ("int", "flt"):
        return t[1] // 8, t[1] // 8
    if tag == "ptr":
        return 8, 8
    if tag == "named" and t[1] in structs:
        d = structs[t[1]]
        return struct_size(d, structs), struct_align(d, structs)
    if tag == "arr":
        k = field_kind(t[1], structs)
        return (k[0] * t[2], k[1]) if k else None
    return None


def struct_align(d: StructDecl, structs, depth=0) -> int:
    al = [field_kind(t, structs)[1] for _, _, t in d.fields if depth < 4 and field_kind(t, structs)]
    return max(al or [1])


def struct_size(d: StructDecl, structs) -> int:
    if d.size:
        return d.size
    end = 0
    for o, _, t in d.fields:
        k = field_kind(t, structs)
        end = max(end, o + (k[0] if k else 0))
    al = struct_align(d, structs)
    return (end + al - 1) // al * al


@rule("K-Struct")
def check_struct_decl(d: StructDecl, structs) -> list[Clash]:
    out = []
    prev_end, prev = -1, None
    for o, n, t in sorted(d.fields):
        k = field_kind(t, structs)
        if k is None:
            continue
        size, align = k
        if o % align:
            out.append(Clash("K-Struct", ("misaligned", d.name, n), f"struct {d.name}: field {n} at +{o} is not {align}-aligned"))
        if prev is not None and o < prev_end:
            out.append(Clash("K-Struct", ("overlap", d.name, prev, n), f"struct {d.name}: fields {prev} and {n} overlap"))
        prev_end, prev = o + size, n
    if d.size is not None and prev_end > d.size:
        out.append(Clash("K-Struct", ("size", d.name), f"struct {d.name}: fields end at {prev_end} > size {d.size}"))
    return out


def _render(node: TyNode) -> str:
    if node.tag == "int":
        return f"{'i' if node.sign == 's' else 'u'}{node.bits}"
    if node.tag == "ptr":
        return "ptr"
    if node.tag == "named":
        return node.name
    if node.tag == "arr":
        return f"{_render(node.to)}[{node.bits}]" if node.to else "array"
    return node.tag


@rule("S-Clash", "S-Clash-Bound")
def check_kinds(S: Snapshot) -> list[Clash]:
    """A class's concrete type must have the kind the binary sees for it."""
    out = []
    for k, info in S.kinds.items():
        node = S.node_by_key(k)
        if node.tag == "hole":
            continue
        size = scalar_size(node, S.structs)
        cls = type_class(node)
        shown = _render(node)
        if node.tag in ("int", "flt", "ptr"):
            for n, wit in sorted(info.sizes.items()):
                if size is not None and n != size:
                    out.append(Clash("S-Clash", ("size", shown, n, tuple(sorted(set(wit)))),
                                     f"{shown} is [{size},{size},{cls}] but the binary accesses {n} bytes",
                                     tuple(sorted(set(wit)))))
        for c, wit in sorted(info.classes.items()):
            if cls is not None and c != cls and not (cls == "agg" and c is None):
                out.append(Clash("S-Clash", ("class", shown, c, tuple(sorted(set(wit)))),
                                 f"{shown} is class {cls} but the binary uses it as {c}", tuple(sorted(set(wit)))))
        if node.tag == "named" and node.name in S.structs:
            out += _check_layout_against_struct(S, node.name, info)
        if node.tag == "arr" and info.bounds and max(info.bounds) > node.bits:
            out.append(Clash("S-Clash-Bound", ("bound", shown, max(info.bounds)),
                             f"{shown} has {node.bits} elements but the binary indexes element {max(info.bounds) - 1}"))
    return out


def _check_layout_against_struct(S: Snapshot, name: str, info) -> list[Clash]:
    d = S.structs[name]
    size = struct_size(d, S.structs)
    out = []
    offsets = {o: (n, t) for o, n, t in d.fields}
    for o, slot in sorted(info.layout.items()):
        if o in offsets:
            continue
        inside = [(fo, n, t) for fo, n, t in d.fields
                  if (k := field_kind(t, S.structs)) and fo < o < fo + k[0]]
        if inside and inside[0][2][0] == "named":
            continue  # reaches into a nested struct (L-Nest)
        wit = tuple(sorted(set(slot.witnesses)))
        if o + max(slot.sizes) > size:
            out.append(Clash("S-Clash", ("beyond", name, o, wit),
                             f"struct {name} has size {size} but the binary accesses +{o}..+{o + max(slot.sizes)}", wit))
        else:
            where = f"inside field {inside[0][1]}" if inside else "padding (no field)"
            out.append(Clash("S-Clash", ("nofield", name, o, wit),
                             f"struct {name}: the binary accesses +{o}, which is {where}", wit))
    for a in info.alloc:
        if a < size:
            out.append(Clash("S-Clash", ("alloc", name, a), f"struct {name} has size {size} but only {a} bytes are allocated"))
    return out


@rule("S-Clash-Arity")
def check_arity(S: Snapshot, facts: list, premises) -> list[Clash]:
    out = []
    for f in facts:
        if isinstance(f, ArityEq):
            c = S.code(f.code)
            need = S.arity.get(c, 0)
            if f.n < need:
                wit = tuple(p.at for p in premises.of(Arity) if S.code(p.code) == c and p.n == need)
                out.append(Clash("S-Clash-Arity", ("arity", f.code, f.n, need),
                                 f"code web of {f.code} takes >= {need} parameters (live-in registers) but the claim says {f.n}", wit))
    return out


@rule("S-Name-Conflict")
def name_targets(S: Snapshot, f: Name, premises) -> str:
    tag = f.target[0]
    if tag == "code":
        return f"code:{S.code(f.target[1])}"
    if tag == "web":
        return f"web:{S.web(f.target[1])}"
    if tag == "value":
        return f"value:{premises.value_webs.get(f.target[1], f.target[1])}"
    if tag == "param":
        return f"param:{S.code(f.target[1])}:{f.target[2]}"
    if tag == "type":
        return f"type:{S.key(f.target[1])}"
    return repr(f.target)


def all_checks(S: Snapshot, facts: list, premises) -> list[Clash]:
    out = []
    for f in facts:
        if isinstance(f, StructDecl):
            out += check_struct_decl(f, S.structs)
    out += check_kinds(S)
    out += check_arity(S, facts, premises)
    return out


__all__ = ["Clash", "all_checks", "name_targets", "render_fact"]
