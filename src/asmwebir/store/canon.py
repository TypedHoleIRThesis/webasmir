"""Canonical classes after saturation: kinds, open layouts, arities.

A `Snapshot` is the saturated store 𝔎* under one belief set, seen through
canonical keys: two symbolic types are equal iff their keys are equal
(egglog extracts one representative per e-class).
"""
from __future__ import annotations

import sys

from collections import defaultdict
from dataclasses import dataclass, field

from egglog import EGraph, get_callable_args, get_callable_fn, get_literal_value, run, union

from ..lift.premises import (
    Access, AllocSize, Arity, Bound, CodeWeb, Derived, Eq, Kind, Premises, Stride,
)
from ..trace import rule
from .egraph import Code, Encoder, Ty, Web, derived


@dataclass
class TyNode:
    """Decoded canonical type: tag + args, recursive through ptr."""

    tag: str  # hole | int | flt | ptr | named | void
    name: str = ""  # hole name / struct name
    bits: int = 0
    sign: str = ""
    web: str = ""  # canonical web key for ptr
    to: "TyNode | None" = None

    def key(self) -> str:
        if self.tag == "ptr" and isinstance(self.to, _Lazy):
            return f"ptr[{self.web}]({self.to.k})"
        if self.tag == "ptr":
            return f"ptr[{self.web}]({self.to.key() if self.to else '?'})"
        if self.tag == "int":
            return f"{self.sign}{self.bits}"
        if self.tag == "arr":
            return f"arr({self.to.key() if self.to else '?'},{self.bits})"
        if self.tag in ("hole", "named"):
            return f"{self.tag}:{self.name}"
        return f"{self.tag}{self.bits or ''}"


@dataclass
class KindInfo:
    sizes: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))  # size -> witness addrs
    classes: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))  # cls -> witness addrs
    layout: dict[int, "LayoutSlot"] = field(default_factory=dict)  # offset -> slot (only for pointees)
    alloc: list[int] = field(default_factory=list)
    strides: set[int] = field(default_factory=set)
    bounds: list[int] = field(default_factory=list)


@dataclass
class LayoutSlot:
    off: int
    slot: tuple  # symbolic type at that offset
    sizes: set[int] = field(default_factory=set)
    witnesses: list[int] = field(default_factory=list)


class Snapshot:
    def __init__(self, eg: EGraph, enc: Encoder, premises: Premises, extra: list[tuple] = (), structs=None):
        self.eg, self.enc, self.premises = eg, enc, premises
        self.structs = dict(structs or {})  # name -> StructDecl under these beliefs
        self._key: dict[tuple, str] = {}
        self._node: dict[str, TyNode] = {}
        self._web: dict[str, str] = {}
        self._code: dict[str, str] = {}
        self.kinds: dict[str, KindInfo] = defaultdict(KindInfo)
        self.arity: dict[str, int] = {}
        self.ptr_shape: dict[str, tuple[str, str]] = {}
        self._pointers()
        self._build()
        self._extra = list(extra)

    def freeze(self, functions) -> "Snapshot":
        """Compute every key a view or check can ask for, then drop the e-graph
        (the store pops the claims after this)."""
        P = self.premises
        for t in P.terms:
            self.key(("tv", t))
        for base, h in P.pointers.items():
            self.key(("hole", h))
            self.web(base)
        for p in P.of(Access):
            self.key(("at", p.pointee, p.off))
        for f in functions:
            self.code(f.name)
            self.key(("ret", f.name))
            for i in range(max(len(f.params), 6)):
                self.key(("param", f.name, i))
        for t in self._extra:
            self.key(t)
        for k in list(self._node):
            n = self._node[k]
            while n is not None and n.tag in ("ptr", "arr") and not isinstance(n, _Lazy):
                n = n.to
        self.eg = None
        return self

    @rule("K-Ptr", "W-Unify")
    def _pointers(self) -> None:
        for base, h in self.premises.pointers.items():
            k = self.key(("tv", base))
            self.ptr_shape.setdefault(k, (self.web(base), self.key(("hole", h))))

    # -- canonical keys
    def key(self, t: tuple) -> str:
        k = self._key.get(t)
        if k is None and self.eg is None:
            raise KeyError(f"type {t!r} was not computed before the snapshot was frozen")
        if k is None:
            node = self._decode(self.eg.extract(self.enc.ty(t)))
            k = node.key()
            self._node.setdefault(k, node)
            self._key[t] = k
        return k

    def node(self, t: tuple) -> TyNode:
        return self.node_by_key(self.key(t))

    def node_by_key(self, k: str) -> TyNode:
        """Decoded class. A class containing a pointer constructor is shown as
        that pointer even when extraction picked its hole: by W-Unify every
        pointer constructor in one class has the same web and pointee class."""
        shape = self.ptr_shape.get(k)
        if shape is not None:
            web, pointee_key = shape
            return TyNode("ptr", web=web, to=_Lazy(self, pointee_key))
        return self._node[k]

    def web(self, name: str) -> str:
        w = self._web.get(name)
        if w is None and self.eg is None:
            return name
        if w is None:
            w = str(get_literal_value(get_callable_args(self.eg.extract(Web(name)))[0]))
            self._web[name] = w
        return w

    def code(self, name: str) -> str:
        c = self._code.get(name)
        if c is None and self.eg is None:
            return name
        if c is None:
            c = str(get_literal_value(get_callable_args(self.eg.extract(Code(name)))[0]))
            self._code[name] = c
        return c

    def _decode(self, e) -> TyNode:
        fn = get_callable_fn(e)
        args = get_callable_args(e)
        name = getattr(fn, "ident", None)
        tag = str(name.name if name is not None and hasattr(name, "name") else fn)
        lit = lambda x: get_literal_value(x)  # noqa: E731
        if tag.endswith("hole"):
            return TyNode("hole", name=str(lit(args[0])))
        if tag.endswith("int_"):
            return TyNode("int", bits=int(lit(args[0])), sign=str(lit(args[1])))
        if tag.endswith("flt"):
            return TyNode("flt", bits=int(lit(args[0])))
        if tag.endswith("named"):
            return TyNode("named", name=str(lit(args[0])))
        if tag.endswith("void"):
            return TyNode("void")
        if tag.endswith("arr"):
            return TyNode("arr", bits=int(lit(args[1])), to=self._decode(args[0]))
        if tag.endswith("ptr"):
            web = str(lit(get_callable_args(args[0])[0]))
            return TyNode("ptr", web=self.web(web), to=self._decode(args[1]))
        return TyNode("hole", name=str(e))  # an un-holed function application

    # -- kinds, layouts, arities
    @rule("S-Access", "S-ABI", "S-Bound", "K-Hole", "L-Open")
    def _build(self) -> None:
        P = self.premises
        for p in P.of(Kind):
            k = self.kinds[self.key(p.t)]
            if p.size:
                k.sizes[p.size].append(p.at)
            if p.cls:
                k.classes[p.cls].append(p.at)
        for p in P.of(Access):
            hk = self.key(p.pointee)
            slot_t = ("at", p.pointee, p.off)
            s = self.kinds[hk].layout.setdefault(p.off, LayoutSlot(p.off, slot_t))
            s.sizes.add(p.size)
            s.witnesses.append(p.at)
        for p in P.of(AllocSize):
            self.kinds[self.key(p.pointee)].alloc.append(p.size)
        for p in P.of(Stride):
            self.kinds[self.key(p.pointee)].strides.add(p.step)
        for p in P.of(Bound):
            self.kinds[self.key(p.pointee)].bounds.append(p.n)
        for p in P.of(Arity):
            c = self.code(p.code)
            self.arity[c] = max(self.arity.get(c, 0), p.n)

    def kind_of(self, k: str) -> tuple[str, str, str]:
        """[n, m, k] for display: size (possibly >= n), alignment, class."""
        info = self.kinds.get(k)
        node = self._node.get(k)
        if k in self.ptr_shape or k.startswith("ptr[") or (node is not None and node.tag == "ptr"):
            return ("8", "8", "ptr")
        if node is not None and node.tag == "int":
            n = node.bits // 8
            return (str(n), str(n), "int")
        if info is None:
            return ("?", "?", "⊤")
        if info.layout and (len(info.layout) > 1 or 0 not in info.layout or info.alloc):
            end = max(o + max(s.sizes) for o, s in info.layout.items())
            end = max([end] + info.alloc)
            align = max(min(max(s.sizes), 8) for s in info.layout.values())
            return (f">={end}", str(align), "agg")
        if info.strides and info.layout:
            elem = max(info.layout[0].sizes) if 0 in info.layout else "?"
            return (f">={elem}", str(elem), "agg")
        sizes = sorted(info.sizes)
        classes = sorted(info.classes)
        n = str(sizes[0]) if len(sizes) == 1 else ("?" if not sizes else "/".join(map(str, sizes)))
        cls = classes[0] if len(classes) == 1 else ("⊤" if not classes else "/".join(classes))
        return (n, n, cls)


def saturate(eg: EGraph) -> None:
    eg.run(run().saturate())


def load_premises(eg: EGraph, enc: Encoder, premises: Premises) -> None:
    # print(premises.items)
    print('-' * 64, file=sys.stderr)
    for p in premises.items:
        print(p, file=sys.stderr)
    for p in premises.items:
        if isinstance(p, Eq):
            eg.register(union(enc.ty(p.a)).with_(enc.ty(p.b)))
        elif isinstance(p, Derived):
            eg.register(derived(enc.ty(p.v), enc.ty(p.p), p.off))
        elif isinstance(p, CodeWeb):
            first = p.members[0]
            for m in p.members[1:]:
                eg.register(union(Code(first)).with_(Code(m)))
        elif isinstance(p, (Kind, Access, Stride, Bound, AllocSize)):
            enc.ty(p.t if isinstance(p, Kind) else p.pointee)  # make sure the class exists
            if isinstance(p, Access):
                enc.ty(("at", p.pointee, p.off))


class _Lazy:
    """Pointee reference resolved on access (types can be recursive)."""

    def __init__(self, snap: "Snapshot", k: str):
        self._snap, self.k = snap, k

    def _n(self) -> TyNode:
        return self._snap.node_by_key(self.k)

    tag = property(lambda self: self._n().tag)
    name = property(lambda self: self._n().name)
    bits = property(lambda self: self._n().bits)
    sign = property(lambda self: self._n().sign)
    web = property(lambda self: self._n().web)
    to = property(lambda self: self._n().to)

    def key(self) -> str:
        return self.k if self.k in self._snap.ptr_shape else self._n().key()
