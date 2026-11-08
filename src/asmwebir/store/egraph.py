"""The egglog half of the knowledge store (Part C, sections 22-23).

egglog owns equality: union-find over types and webs, congruence, and the
injectivity rule that makes pointer webs merge (W-Unify). Kinds, layouts and
contradictions are checked in Python over the canonical classes egglog
produces (`store.kinds`). Labels are not stored in egglog: the knowledge
store re-saturates under subsets of claims (`store.store`).
"""
from __future__ import annotations

from egglog import (
    EGraph, Expr, String, StringLike, function, i64, i64Like, method, relation,
    rule as egg_rule, union, eq, var, vars_,
)

from ..trace import rule


class Web(Expr):
    """A data web #d: everything that can point to the same objects."""

    def __init__(self, name: StringLike) -> None: ...


class Code(Expr):
    """A code web #c: functions callable from the same call sites."""

    def __init__(self, name: StringLike) -> None: ...


class Ty(Expr):
    @method(cost=100)
    @classmethod
    def hole(cls, name: StringLike) -> Ty: ...

    @method(cost=1)
    @classmethod
    def int_(cls, bits: i64Like, sign: StringLike) -> Ty: ...

    @method(cost=1)
    @classmethod
    def flt(cls, bits: i64Like) -> Ty: ...

    @method(cost=1)
    @classmethod
    def ptr(cls, d: Web, t: Ty) -> Ty: ...

    @method(cost=1)
    @classmethod
    def named(cls, name: StringLike) -> Ty: ...

    @method(cost=1)
    @classmethod
    def void(cls) -> Ty: ...

    @method(cost=1)
    @classmethod
    def arr(cls, t: Ty, n: i64Like) -> Ty: ...


@function(cost=1000)
def type_of(term: StringLike) -> Ty: ...


@function(cost=1000)
def at(t: Ty, off: i64Like) -> Ty: ...


@function(cost=1000)
def param(c: Code, i: i64Like) -> Ty: ...


@function(cost=1000)
def ret(c: Code) -> Ty: ...


derived = relation("derived", Ty, Ty, i64)


@rule("W-Unify")
def _w_unify():
    a, b = vars_("a b", Web)
    s, u = vars_("s u", Ty)
    return egg_rule(eq(Ty.ptr(a, s)).to(Ty.ptr(b, u))).then(union(a).with_(b), union(s).with_(u))


@rule("L-Nest")
def _derived_pointer():
    v, p, t = vars_("v p t", Ty)
    d = var("d", Web)
    off = var("off", i64)
    return egg_rule(derived(v, p, off), eq(p).to(Ty.ptr(d, t))).then(union(v).with_(Ty.ptr(d, at(t, off))))


RULES = [_w_unify, _derived_pointer]


class Encoder:
    """Turns symbolic types (see lift.premises) into egglog expressions."""

    def __init__(self, eg: EGraph):
        self.eg = eg
        self._holes_for_at: set[tuple] = set()

    def ty(self, t: tuple) -> Ty:
        tag = t[0]
        if tag == "tv":
            return type_of(t[1])
        if tag == "hole":
            return Ty.hole(t[1])
        if tag == "at":
            inner = self.ty(t[1])
            e = at(inner, t[2])
            key = (t[1], t[2])
            if key not in self._holes_for_at:  # every layout slot is a hole until something fills it
                self._holes_for_at.add(key)
                self.eg.register(union(e).with_(Ty.hole(f"{_name(t[1])}+{t[2]}")))
            return e
        if tag == "param":
            return param(Code(t[1]), t[2])
        if tag == "ret":
            return ret(Code(t[1]))
        if tag == "ptr":
            return Ty.ptr(Web(t[1]), self.ty(t[2]))
        if tag == "int":
            return Ty.int_(t[1], t[2])
        if tag == "flt":
            return Ty.flt(t[1])
        if tag == "named":
            return Ty.named(t[1])
        if tag == "void":
            return Ty.void()
        if tag == "arr":
            return Ty.arr(self.ty(t[1]), t[2])
        raise ValueError(f"unknown symbolic type {t!r}")


def _name(t: tuple) -> str:
    if t[0] in ("hole", "tv", "named"):
        return t[1]
    if t[0] == "at":
        return f"{_name(t[1])}+{t[2]}"
    return repr(t)


def new_egraph() -> EGraph:
    eg = EGraph()
    eg.register(*[r() for r in RULES])
    return eg
