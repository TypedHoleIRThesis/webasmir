"""Render a function's view as AsmWebIR text (the listings of Part A).

Names shown to the LLM are stable across the whole program: holes ?T1.., data
webs #d1.., code webs #c1.., value webs #w1.. are numbered by first
appearance in address order.
"""
from __future__ import annotations

import re

from ..ir.syntax import (
    BinOp, Branch, Call, CallStmt, Const, Conv, Expr, Function, Jump, Let, Load,
    Opaque, Phi, Program, Residual, Return, StackAddr, Store, UnOp, VarRef, split_addr,
)
from ..lift.premises import Premises
from ..store.canon import Snapshot, TyNode

OPS = {
    "Add": "+", "Sub": "-", "Mul": "*", "And": "&", "Or": "|", "Xor": "^", "Shl": "<<",
    "Shr": ">>", "Sar": ">>s", "Div": "/", "Mod": "%", "CmpEQ": "==", "CmpNE": "!=",
    "CmpLT": "<", "CmpLE": "<=", "CmpGT": ">", "CmpGE": ">=", "LogicalAnd": "&&", "LogicalOr": "||",
}


class Namer:
    def __init__(self, prog: Program, S: Snapshot, P: Premises):
        self.S, self.P = S, P
        self.holes: dict[str, str] = {}
        self.webs: dict[str, str] = {}
        self.codes: dict[str, str] = {}
        self.values: dict[str, str] = {}
        for fn in sorted(prog.functions.values(), key=lambda f: f.addr):
            self.code(fn.name)
        for t in P.terms:  # program order
            self.type_key(S.key(("tv", t)))
            self.value(t)

    def code(self, fn: str) -> str:
        c = self.S.code(fn)
        if c not in self.codes:
            self.codes[c] = f"#c{len(self.codes) + 1}"
        return self.codes[c]

    def web(self, w: str) -> str:
        if w not in self.webs:
            self.webs[w] = f"#d{len(self.webs) + 1}"
        return self.webs[w]

    def hole(self, k: str) -> str:
        if k not in self.holes:
            self.holes[k] = f"?T{len(self.holes) + 1}"
        return self.holes[k]

    def value(self, term: str) -> str:
        rep = self.P.value_webs.get(term, term)
        if rep not in self.values:
            self.values[rep] = f"#w{len(self.values) + 1}"
        return self.values[rep]

    def type_key(self, k: str, seen: set | None = None) -> None:
        seen = set() if seen is None else seen
        if k in seen:
            return  # recursive types (node->next)
        seen.add(k)
        node = self.S.node_by_key(k)
        if node.tag == "ptr":
            self.web(node.web)
            if node.to is not None:
                self.type_key(node.to.key(), seen)
        elif node.tag == "hole":
            self.hole(k)


class ViewPrinter:
    def __init__(self, prog: Program, S: Snapshot, P: Premises, namer: Namer | None = None,
                 names: dict[str, str] | None = None):
        self.prog, self.S, self.P = prog, S, P
        self.n = namer or Namer(prog, S, P)
        self.names = names or {}  # canonical name target (see store.checks.name_targets) -> name

    @classmethod
    def for_store(cls, ks, namer: "Namer | None" = None) -> "ViewPrinter":
        """Printer of the store's current beliefs; the namer of the premise-only
        view keeps display numbers stable while claims arrive."""
        from ..claims.dsl import Name
        from ..store.checks import name_targets

        S = ks.snapshot()
        names: dict[str, str] = {}
        for a in sorted(ks.beliefs(), key=lambda c: int(c[1:])):
            f = ks.claims[a].fact
            if isinstance(f, Name):
                names.setdefault(name_targets(S, f, ks.premises), f.name)
        namer = namer or Namer(ks.prog, ks.snapshot(frozenset()), ks.premises)
        pr = cls(ks.prog, S, ks.premises, _Renamer(namer, S), names)
        return pr

    # -- types
    def ty(self, t: tuple) -> str:
        return self.node(self.S.node(t))

    def node(self, node: TyNode, depth: int = 0) -> str:
        if node.tag == "hole":
            return self.n.hole(node.key())
        if node.tag == "ptr":
            inner = self.node(node.to, depth + 1) if node.to is not None and depth < 4 else "…"
            return f"ptr{self.n.web(node.web)} {inner}"
        if node.tag == "int":
            return f"{'i' if node.sign == 's' else 'u'}{node.bits}"
        if node.tag == "named":
            return node.name
        if node.tag == "flt":
            return f"f{node.bits}"
        return "void"

    def kind(self, k: str) -> str:
        n, m, c = self.S.kind_of(k)
        return f"[{n}, {m}, {c}]" if n.startswith(">") else f"[{n},{m},{c}]"

    # -- expressions
    def var(self, v) -> str:
        rep = self.P.value_webs.get(v.id, v.id)
        return self.names.get(f"value:{rep}", v.name)

    def fn_name(self, fn: str) -> str:
        return self.names.get(f"code:{self.S.code(fn)}", fn)

    def field(self, base: Expr, off: int) -> str | None:
        """S-Field view: `base->f` when the pointee is a declared struct with a field at off."""
        if not isinstance(base, VarRef):
            return None
        h = self.P.pointers.get(base.var.id)
        if h is None:
            return None
        node = self.S.node(("hole", h))
        path = []
        while node.tag == "named" and node.name in self.S.structs:
            d = self.S.structs[node.name]
            hit = next(((o, n, t) for o, n, t in d.fields if o == off), None)
            if hit is None:
                from ..store.checks import field_kind
                hit = next(((o, n, t) for o, n, t in d.fields if t[0] == "named"
                            and (k := field_kind(t, self.S.structs)) and o < off < o + k[0]), None)
                if hit is None:
                    return None
                path.append(hit[1])
                off -= hit[0]
                node = TyNode("named", name=hit[2][1])
                continue
            path.append(hit[1])
            return f"{self.var(base.var)}->{'.'.join(path)}"
        return None

    def expr(self, e: Expr) -> str:
        if isinstance(e, VarRef):
            return self.var(e.var)
        if isinstance(e, Const):
            v = e.value
            return str(v) if v < 4096 else hex(v)
        if isinstance(e, Load):
            base, off = split_addr(e.addr)
            f = self.field(base, off)
            if f is not None:
                return f
            slot_cls = self._slot_class(e)
            return f"load[{e.size},{slot_cls}]({self.expr(base)} + {off})"
        if isinstance(e, BinOp):
            if e.op == "CmpEQ" and isinstance(e.b, Const) and e.b.value == 0 and self._is_ptr(e.a):
                return f"{self.expr(e.a)} == null"
            if e.op == "CmpNE" and isinstance(e.b, Const) and e.b.value == 0 and self._is_ptr(e.a):
                return f"{self.expr(e.a)} != null"
            return f"({self.expr(e.a)} {OPS.get(e.op, e.op)} {self.expr(e.b)})"
        if isinstance(e, UnOp):
            return f"{'-' if e.op == 'Neg' else '~'}{self.expr(e.a)}"
        if isinstance(e, Conv):
            if e.from_bits == 32 and e.to_bits == 64 and not e.signed:
                return self.expr(e.a)  # register zero-extension: not a source-level cast
            if e.from_bits == 64 and e.to_bits == 32 and isinstance(e.a, VarRef) and self.P.eff_bits.get(e.a.var.id) == 32:
                return self.expr(e.a)
            return f"({'s' if e.signed else 'u'}{e.to_bits}){self.expr(e.a)}"
        if isinstance(e, Call):
            return self.call(e)
        if isinstance(e, Phi):
            return "φ(" + ", ".join(f"L_{b:x}: {self.expr(v)}" for b, v in e.srcs) + ")"
        if isinstance(e, StackAddr):
            return f"&stack[{e.offset}]"
        if isinstance(e, Opaque):
            return f"⟨{e.text}⟩"
        return str(e)

    def call(self, c: Call) -> str:
        args = ", ".join(self.expr(a) for a in c.args)
        if isinstance(c.target, str):
            if c.target in self.prog.functions:
                return f"{self.fn_name(c.target)}({args})"
            return f"{c.target}({args})"
        cw = self.n.code(c.targets[0]) if c.targets else "#c?"
        return f"call{cw} *{self.expr(c.target)}({args})"

    def _is_ptr(self, e: Expr) -> bool:
        if isinstance(e, VarRef):
            return self.S.node(("tv", e.var.id)).tag == "ptr"
        if isinstance(e, Load):
            return self._slot_class(e) == "ptr"
        return False

    def _slot_class(self, load: Load) -> str:
        base, off = split_addr(load.addr)
        if isinstance(base, VarRef):
            h = self.P.pointers.get(base.var.id)
            if h is not None:
                try:
                    k = self.S.key(("at", ("hole", h), off))
                except KeyError:  # an access the premises modelled differently (indexed / global)
                    return "?"
                return self.S.kind_of(k)[2]
        return "?"

    # -- statements
    def function(self, fn: Function) -> str:
        S, n = self.S, self.n
        ps = [f"{self.var(p)}{n.value(p.id)}: {self.ty(('tv', p.id))}" for p in fn.params]
        arity = S.arity.get(S.code(fn.name), len(fn.params))
        for i in range(len(fn.params), arity):  # A-AddParam: the code web requires more parameters
            pname = self.names.get(f"param:{S.code(fn.name)}:{i}", f"a{i}")
            ps.append(f"{pname}: {self.ty(('param', fn.name, i))}")
        for i, p in enumerate(fn.params):
            nm = self.names.get(f"param:{S.code(fn.name)}:{i}")
            if nm and ps[i].startswith(p.name):
                ps[i] = nm + ps[i][len(p.name):]
        params = ", ".join(ps)
        rt = self.ty(("ret", fn.name)) if fn.returns_value else "void"
        lines = [f"fn{n.code(fn.name)} {self.fn_name(fn.name)}({params}) -> {rt}", "{"]
        defined: set[str] = {p.id for p in fn.params}
        for i, b in enumerate(fn.blocks):
            if i > 0 or any(isinstance(s, Jump | Branch) for s in fn.stmts):
                lines.append(f" L_{b.addr:x}:")
            for s in b.stmts:
                text, at = self.stmt(s, defined)
                if text is None:
                    continue
                lines.append(f"  {text:<58} @{at:x}" if at else f"  {text}")
        lines.append("}")
        holes = self.holes_section(fn)
        if holes:
            lines.append("holes: " + "\n       ".join(holes))
        body = "\n".join(lines)
        structs = [d for d in self.structs_section(fn) if re.search(rf"\b{d.split()[1]}\b", body)]
        if structs:
            lines.append("types: " + "\n       ".join(structs))
        return "\n".join(lines)

    def structs_section(self, fn: Function) -> list[str]:
        from ..claims.dsl import _rt

        out = []
        text = None
        for name, d in sorted(self.S.structs.items()):
            body = "; ".join(f"{o}: {n}: {_rt(t)}" for o, n, t in d.fields)
            out.append(f"struct {name} {{ {body} }}" + (f" size {d.size}" if d.size else ""))
        return out

    def stmt(self, s, defined: set[str]):
        if isinstance(s, Let):
            vid = s.var.id
            head = self.var(s.var)
            if vid not in defined:
                defined.add(vid)
                head = f"let {head}{self.n.value(vid)}: {self.ty(('tv', vid))}"
            return f"{head} = {self.expr(s.expr)};", s.at
        if isinstance(s, Store):
            base, off = split_addr(s.addr)
            f = self.field(base, off)
            if f is not None:
                return f"{f} = {self.expr(s.data)};", s.at
            return f"store[{s.size}]({self.expr(base)} + {off}) = {self.expr(s.data)};", s.at
        if isinstance(s, CallStmt):
            if s.ret is not None:
                defined.add(s.ret.id)
                return f"let {self.var(s.ret)}{self.n.value(s.ret.id)}: {self.ty(('tv', s.ret.id))} = {self.call(s.call)};", s.at
            return f"{self.call(s.call)};", s.at
        if isinstance(s, Branch):
            return f"if ({self.expr(s.cond)}) goto L_{s.then:x} else goto L_{s.els:x};", s.at
        if isinstance(s, Jump):
            return f"goto L_{s.target:x};", s.at
        if isinstance(s, Return):
            return ("return;" if s.value is None else f"return {self.expr(s.value)};"), s.at
        if isinstance(s, Residual):
            return f"asm{{{s.lo:x}..{s.hi:x}}}  // {s.reason}", s.lo
        return str(s), 0

    def holes_section(self, fn: Function) -> list[str]:
        """Every hole visible in this function, with its kind and open layout."""
        keys: list[str] = []

        def visit(node: TyNode | None, depth=0):
            if node is None or depth > 6:
                return
            if node.tag == "hole" and node.key() not in self.S.ptr_shape:
                k = node.key()
                if k not in keys:
                    keys.append(k)
                    info = self.S.kinds.get(k)
                    if info:
                        for o in sorted(info.layout):
                            slot = self.S.node(info.layout[o].slot)
                            if slot.tag != "hole" or self._interesting(slot):
                                visit(slot, depth + 1)
            elif node.tag == "ptr":
                visit(node.to, depth + 1)

        terms = [p.id for p in fn.params] + [
            t for t in self.P.terms if t.startswith(fn.name + ".") and "@" not in t
        ]
        for t in terms:
            visit(self.S.node(("tv", t)))
        if fn.returns_value:
            visit(self.S.node(("ret", fn.name)))
        out = []
        for k in sorted(keys, key=lambda k: int(self.n.hole(k)[2:])):
            info = self.S.kinds.get(k)
            line = f"{self.n.hole(k)} :: {self.kind(k)}"
            if info and info.layout:
                fields = []
                for o in sorted(info.layout):
                    slot = self.S.node(info.layout[o].slot)
                    shown = self.kind(slot.key()) if slot.tag == "hole" and not self._interesting(slot) else self.node(slot)
                    fields.append(f"{o}: {shown}")
                line += "  :> { " + ", ".join(fields) + " }"
            if info and info.strides:
                line += f"  stride {','.join(map(str, sorted(info.strides)))}"
            if info and info.bounds:
                line += f", ?n >= {max(info.bounds)} elements"
            out.append(line)
        return out

    def _interesting(self, slot: TyNode) -> bool:
        info = self.S.kinds.get(slot.key())
        return bool(info and info.layout)


class _Renamer(Namer):
    """Display numbering of an earlier snapshot, re-keyed onto a newer one."""

    def __init__(self, base: Namer, S: Snapshot):
        self.S, self.P = S, base.P
        self.holes, self.webs, self.codes, self.values = {}, {}, {}, dict(base.values)
        bS = base.S
        for k, name in base.holes.items():
            rep = _rep_for(bS, base.P, k)
            if rep is not None:
                nk = S.key(rep)
                self.holes.setdefault(nk, name)
        for w, name in base.webs.items():
            self.webs.setdefault(S.web(w), name)
        for c, name in base.codes.items():
            self.codes.setdefault(S.code(c), name)
        self._next = (len(base.holes), len(base.webs), len(base.codes))

    def hole(self, k):
        if k not in self.holes:
            self.holes[k] = f"?T{self._next[0] + 1 + sum(1 for v in self.holes.values() if int(v[2:]) > self._next[0])}"
        return self.holes[k]


def _rep_for(S: Snapshot, P: Premises, k: str):
    for t, kk in S._key.items():
        if kk == k:
            return t
    return None
