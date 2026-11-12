"""Premise extraction: certain facts read from the lifted binary (label ∅).

The output is plain data. `store.egraph` turns it into egglog facts. Types are
referred to symbolically with small tuples (see `T`) so that premises can be
printed, explained (`why`) and stored in the log without egglog.

Symbolic types `T`:
    ("tv", term)            type_of(term): the type of an SSA value / parameter
    ("hole", name)          a type hole ?α
    ("at", T, off)          the type found at byte offset `off` inside T (open layout)
    ("param", code, i)      i-th parameter type of code web member `code`
    ("ret", code)           return type of `code`
    ("ptr", web, T)         pointer in data web `web` to T
    ("int", bits, sign)     iN / uN (sign "s" or "u"), only from claims
    ("named", name)         a declared struct, only from claims
"""
from __future__ import annotations

import sys

from dataclasses import dataclass, field

from ..ir.syntax import (
    BinOp, Branch, Call, CallStmt, Const, Conv, Expr, Function, Jump, Let, Load,
    Opaque, Phi, Program, Residual, Return, StackAddr, Store, UnOp, Var, VarRef, split_addr,
)
from ..trace import rule

T = tuple

SYSV_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def arg_loc(i: int) -> str:
    return SYSV_ARG_REGS[i] if i < len(SYSV_ARG_REGS) else f"stack+{8 * (i - len(SYSV_ARG_REGS))}"

INT_OPS = {"Mul", "And", "Or", "Xor", "Shl", "Shr", "Sar", "Div", "Mod"}

# External references (section 14.1): ABI-level facts about imported functions.
# Results are polymorphic (fresh per call site) so that two malloc results are
# never merged into one web -- the void* over-merging problem of section 11.
EXTERNALS = {
    "malloc": {"params": [(8, "int")], "ret": "fresh_ptr", "alloc_arg": 0},
    "calloc": {"params": [(8, "int"), (8, "int")], "ret": "fresh_ptr"},
    "realloc": {"params": [(8, "ptr"), (8, "int")], "ret": "fresh_ptr"},
    "free": {"params": [(8, "ptr")], "ret": None},
    "memcpy": {"params": [(8, "ptr"), (8, "ptr"), (8, "int")], "ret": None},
    "memset": {"params": [(8, "ptr"), (4, "int"), (8, "int")], "ret": None},
    "strlen": {"params": [(8, "ptr")], "ret": (8, "int")},
}


def tv(term: str) -> T:
    return ("tv", term)


def hole(name: str) -> T:
    return ("hole", name)


def at(t: T, off: int) -> T:
    return ("at", t, off)


def ptr(web: str, t: T) -> T:
    return ("ptr", web, t)


def code(fn: str) -> str:
    return fn  # code webs are keyed by the function's stable name


@dataclass(frozen=True)
class Premise:
    rule: str  # the Part C rule that justifies it
    at: int  # instruction address (provenance)
    fn: str


@dataclass(frozen=True)
class Eq(Premise):
    a: T
    b: T
    why: str = ""


@dataclass(frozen=True)
class Kind(Premise):
    t: T
    size: int | None
    cls: str | None  # "int" | "ptr" | "flt" | None
    why: str = ""


@dataclass(frozen=True)
class Access(Premise):
    pointee: T  # the hole the base pointer points to
    off: int
    size: int
    write: bool
    base: str = ""  # base term (for display)


@dataclass(frozen=True)
class Arity(Premise):
    code: str
    n: int
    regs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CodeWeb(Premise):
    members: tuple[str, ...]


@dataclass(frozen=True)
class Stride(Premise):
    pointee: T
    step: int


@dataclass(frozen=True)
class Bound(Premise):
    pointee: T
    n: int  # at least n elements


@dataclass(frozen=True)
class AllocSize(Premise):
    pointee: T
    size: int


@dataclass(frozen=True)
class Derived(Premise):
    """`v = p + off` where p may be a pointer: if p : ptr d τ then v : ptr d (τ at off)."""
    v: T
    p: T
    off: int


@dataclass
class Premises:
    items: list[Premise] = field(default_factory=list)
    terms: list[str] = field(default_factory=list)  # every term that has a type, in program order
    pointers: dict[str, str] = field(default_factory=dict)  # term -> pointee hole name
    value_webs: dict[str, str] = field(default_factory=dict)  # term -> value-web representative
    eff_bits: dict[str, int] = field(default_factory=dict)  # term -> effective width
    failed: dict[str, str] = field(default_factory=dict)  # function -> premise extraction error

    def add(self, p: Premise) -> None:
        self.items.append(p)

    def of(self, kind):
        return [p for p in self.items if isinstance(p, kind)]


def extract_premises(prog: Program) -> Premises:
    out = Premises()
    for fn in sorted(prog.functions.values(), key=lambda f: f.addr):
        mark = len(out.items), len(out.terms), dict(out.pointers)
        print('-' * 20, fn.name, '-' * 20, file=sys.stderr)
        # for stmt in fn.stmts:
        #     print(stmt)
        try:
            _Fn(prog, fn, out).run()
        except Exception as exc:  # a premise bug must not sink the binary: drop this function's premises
            del out.items[mark[0]:], out.terms[mark[1]:]
            out.pointers.clear(); out.pointers.update(mark[2])
            out.failed[fn.name] = f"{type(exc).__name__}: {exc}"
    return out


class _Fn:
    def __init__(self, prog: Program, fn: Function, out: Premises):
        self.prog, self.fn, self.out = prog, fn, out
        self.defs: dict[str, Expr] = {}
        self.uf: dict[str, str] = {}
        self.k = 0

    # -- value webs (#w): copies, phis and zero-extensions of one value
    def find(self, x: str) -> str:
        while self.uf.get(x, x) != x:
            self.uf[x] = self.uf.get(self.uf[x], self.uf[x])
            x = self.uf[x]
        return x

    def join(self, a: str, b: str) -> None:
        print(a, ',', b, file=sys.stderr)
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.uf[max(ra, rb)] = min(ra, rb)

    def fresh(self, at: int, what: str) -> str:
        self.k += 1
        t = f"{self.fn.name}.{what}{self.k}@{at:x}"
        self.out.terms.append(t)
        self.out.add(Eq("hole", at, self.fn.name, tv(t), hole(t), "every term has a hole"))
        return t

    def term(self, v: Var) -> str:
        t = v.id
        if t not in self.seen:
            self.seen.add(t)
            self.out.terms.append(t)
            self.out.add(Eq("hole", 0, self.fn.name, tv(t), hole(t), "every term has a hole"))
        return t

    def run(self) -> None:
        # print(fn.name, fn.params)
        fn = self.fn
        self.seen: set[str] = set()
        for s in fn.stmts:
            if isinstance(s, Let):
                self.defs[s.var.id] = s.expr
        self._effective_widths()
        self.params(fn)
        # for item in self.out.items:
        #     print(item)
        self.stride_cands: list[tuple[str, int, int]] = []
        self.branches: list[Branch] = []
        for s in fn.stmts:
            self.stmt(s)
        self.strides()
        for b in self.branches:
            self.loop_bound(b)
        for t in self.seen:
            self.out.value_webs[t] = self.find(t)

    @rule("S-Index")
    def strides(self) -> None:
        """An induction variable that is also used as an address walks an array."""
        for p, step, at in self.stride_cands:
            h = next((h for b, h in self.out.pointers.items()
                      if b.startswith(self.fn.name + ".") and self.find(b) == self.find(p)), None)
            if h is not None:
                self.out.add(Stride("S-Index", at, self.fn.name, hole(h), step))

    # -- widths: x86 zero-extends 32-bit results into 64-bit registers; Clinic
    # keeps 64-bit vvars around 32-bit values. A value's effective width is 32
    # when every definition is a zero-extension of a 32-bit value (or a const).
    def _effective_widths(self) -> None:
        eff: dict[str, int] = {}
        for vid, e in self.defs.items():
            eff[vid] = self._width(e, eff)
        for _ in range(8):
            changed = False
            for vid, e in self.defs.items():
                w = self._width(e, eff)
                if w != eff[vid]:
                    eff[vid], changed = w, True
            if not changed:
                break
        for p in self.fn.params:
            eff[p.id] = p.bits
        self.eff = eff
        self.out.eff_bits.update(eff)

    def _width(self, e: Expr, eff) -> int:
        if isinstance(e, Conv) and e.to_bits == 64 and e.from_bits == 32 and not e.signed:
            return 32
        if isinstance(e, Phi):
            ws = {self._width(v, eff) for _, v in e.srcs if not isinstance(v, Const)} - {0}
            return ws.pop() if len(ws) == 1 else (0 if not ws else 64)
        if isinstance(e, VarRef):
            return eff.get(e.var.id, e.var.bits)
        if isinstance(e, Load):
            return e.size * 8
        if isinstance(e, BinOp):
            return e.bits
        if isinstance(e, Const):
            return 0  # width-agnostic
        return getattr(e, "bits", 64) or 64

    # -- the rules
    @rule("S-ABI", "T-Fn")
    def params(self, fn: Function) -> None:
        print(fn.params, file=sys.stderr)
        for i, p in enumerate(fn.params):
            t = self.term(p)
            self.out.add(Eq("T-Fn", fn.addr, fn.name, tv(t), ("param", code(fn.name), i), "parameter binding"))
            self.out.add(Kind("S-ABI", fn.addr, fn.name, tv(t), p.bits // 8, None, f"live-in {arg_loc(i)} ({p.bits // 8}B)"))
        self.out.add(Arity("S-ABI", fn.addr, fn.name, code(fn.name), len(fn.params),
                           tuple(arg_loc(i) for i in range(len(fn.params)))))

    def stmt(self, s) -> None:
        print("stmt:", s, file=sys.stderr)
        if isinstance(s, Let):
            t = self.term(s.var)
            self.flow_into(t, s.expr, s.at)
        elif isinstance(s, Store):
            self.store(s)
        elif isinstance(s, CallStmt):
            rt = self.call(s.call)
            if s.ret is not None:
                t = self.term(s.ret)
                if rt is not None:
                    self.out.add(Eq("S-Unify", s.at, self.fn.name, tv(t), rt, "call result"))
        elif isinstance(s, Branch):
            self.expr(s.cond, s.at)
            self.branches.append(s)
        elif isinstance(s, Return):
            if s.value is not None:
                v = s.value
                while isinstance(v, Conv) and v.to_bits > v.from_bits:
                    v = v.a  # callers read the low bits of rax: the extension is not the source type
                rt = self.expr(v, s.at)
                if rt is not None:
                    self.out.add(Eq("T-Fn", s.at, self.fn.name, rt, ("ret", code(self.fn.name)), "returned value"))
        elif isinstance(s, (Jump, Residual)):
            pass

    @rule("S-Bound")
    def loop_bound(self, s: Branch) -> None:
        """`if (p == base + K)` where p is an induction pointer starting at base
        with stride c: the array has at least K/c elements."""
        c = s.cond
        if not (isinstance(c, BinOp) and c.op in ("CmpEQ", "CmpNE") and isinstance(c.a, VarRef)):
            return
        end, k = split_addr(c.b)
        if not isinstance(end, VarRef) or k <= 0:
            return
        x, base = c.a.var.id, end.var.id
        if self.find(x) != self.find(base):
            return
        h = next((h for b, h in self.out.pointers.items()
                  if b.startswith(self.fn.name + ".") and self.find(b) == self.find(x)), None)
        if h is None:
            return
        strides = [p.step for p in self.out.of(Stride) if p.pointee == hole(h)]
        if strides and k % strides[0] == 0:
            self.out.add(Bound("S-Bound", s.at, self.fn.name, hole(h), k // strides[0]))

    @rule("S-Unify")
    def flow_into(self, t: str, e: Expr, at: int) -> None:
        """`let t = e`: copies, phis and zero-extensions carry one value (one type)."""
        if isinstance(e, Phi):
            for _, v in e.srcs:
                src = self.expr(v, at)
                if src is not None:
                    self.out.add(Eq("S-Unify", at, self.fn.name, tv(t), src, "phi"))
                if isinstance(v, VarRef):
                    self.join(t, v.var.id)
            return
        if isinstance(e, VarRef):
            self.join(t, self.term(e.var))
        if isinstance(e, BinOp) and e.op == "Add" and isinstance(e.b, Const) and isinstance(e.a, VarRef) and e.bits == 64:
            p = self.term(e.a.var)
            if self._same_flow(t, p):  # induction variable: v = p + step flows back into p
                self.out.add(Eq("S-Unify", at, self.fn.name, tv(t), tv(p), "induction variable"))
                self.join(t, p)
                self.stride_cands.append((p, e.b.value, at))  # a stride only if p is an address
            else:
                self.out.add(Derived("L-Nest", at, self.fn.name, tv(t), tv(p), e.b.value))
            return
        src = self.expr(e, at)
        if src is not None:
            self.out.add(Eq("S-Unify", at, self.fn.name, tv(t), src, "assignment"))

    def _same_flow(self, t: str, p: str) -> bool:
        # does t flow (through copies/phis) back into p?
        seen, todo = set(), [t]
        users: dict[str, list[str]] = {}
        for vid, e in self.defs.items():
            srcs = [v for _, v in e.srcs] if isinstance(e, Phi) else [e]
            for v in srcs:
                if isinstance(v, VarRef):
                    users.setdefault(v.var.id, []).append(vid)
        while todo:
            x = todo.pop()
            if x == p:
                return True
            if x in seen:
                continue
            seen.add(x)
            todo.extend(users.get(x, []))
        return False

    def pointee(self, base: str, at: int) -> str:
        """`base` is used as an address: it is a pointer to a hole (K-Ptr)."""
        h = self.out.pointers.get(base)
        if h is None:
            h = f"*{base}"
            self.out.pointers[base] = h
            self.out.add(Eq("K-Ptr", at, self.fn.name, tv(base), ptr(base, hole(h)), "used as an address"))
            self.out.add(Kind("K-Ptr", at, self.fn.name, tv(base), 8, "ptr", "used as an address"))
        return h

    def base_term(self, e: Expr, at: int) -> str | None:
        if isinstance(e, VarRef):
            return self.term(e.var)
        if isinstance(e, StackAddr):
            return self.stack_obj(e.offset, at)
        if isinstance(e, Const):
            return None  # absolute address: a global (M3)
        t = self.fresh(at, "p")
        src = self.expr(e, at)
        if src is not None:
            self.out.add(Eq("S-Unify", at, self.fn.name, tv(t), src, "address expression"))
        return t

    def stack_obj(self, off: int, at: int) -> str:
        t = f"{self.fn.name}.&stack{off}"
        if t not in self.seen:
            self.seen.add(t)
            self.out.terms.append(t)
            self.out.add(Eq("hole", at, self.fn.name, tv(t), hole(t), "every term has a hole"))
        self.pointee(t, at)
        return t

    def global_array(self, addr: Expr, at: int) -> tuple[str, int, int] | None:
        """`g + idx*c` with g a constant data address: element access of global g."""
        if not (isinstance(addr, BinOp) and addr.op == "Add"):
            return None
        a, b = addr.a, addr.b
        if isinstance(a, Const):
            a, b = b, a
        if not isinstance(b, Const) or b.value < 0x1000:
            return None
        step = 1
        if isinstance(a, BinOp) and a.op == "Mul" and isinstance(a.b, Const):
            step = a.b.value
        elif isinstance(a, BinOp) and a.op == "Shl" and isinstance(a.b, Const):
            step = 1 << a.b.value
        idx = a.a if isinstance(a, BinOp) and a.op in ("Mul", "Shl") else a
        it = self.expr(idx, at)
        if it is not None:
            self.out.add(Kind("T-Index", at, self.fn.name, it, None, "int", "array index"))
        return self.global_obj(b.value, at), 0, step

    def global_obj(self, addr: int, at: int) -> str:
        t = f"&g_{addr:x}"
        if t not in self.out.pointers:
            self.out.terms.append(t)
            self.out.add(Eq("hole", at, self.fn.name, tv(t), hole(t), "every term has a hole"))
        self.pointee(t, at)
        return t

    @rule("S-Access", "T-Load")
    def access(self, addr: Expr, size: int, at: int, write: bool) -> T | None:
        g = self.global_array(addr, at)
        if g is not None:
            base, off, step = g
            h = hole(self.pointee(base, at))
            self.out.add(Stride("S-Index", at, self.fn.name, h, step))
            self.out.add(Access("S-Access", at, self.fn.name, h, off, size, write, base))
            slot = at_(h, off)
            self.out.add(Kind("S-Access", at, self.fn.name, slot, size, None, f"element {size}B of {base}"))
            return slot
        base_e, off = split_addr(addr)
        if isinstance(base_e, Const) and base_e.value >= 0x1000:
            base_e, off = None, off + base_e.value
            gname = self.global_obj(off, at)
            h = hole(self.pointee(gname, at))
            self.out.add(Access("S-Access", at, self.fn.name, h, 0, size, write, gname))
            slot = at_(h, 0)
            self.out.add(Kind("S-Access", at, self.fn.name, slot, size, None, f"global {size}B"))
            return slot
        base = self.base_term(base_e, at)
        if base is None:
            return None
        h = hole(self.pointee(base, at))
        self.out.add(Access("S-Access", at, self.fn.name, h, off, size, write, base))
        slot = at_(h, off)
        self.out.add(Kind("S-Access", at, self.fn.name, slot, size, None, f"{'write' if write else 'read'} {size}B at +{off}"))
        return slot

    def store(self, s: Store) -> None:
        slot = self.access(s.addr, s.size, s.at, True)
        data = self.expr(s.data, s.at)
        if slot is not None and data is not None:
            self.out.add(Eq("S-Unify", s.at, self.fn.name, slot, data, "stored value"))
        if slot is not None and isinstance(s.data, Const) and s.data.value != 0:
            self.out.add(Kind("S-Access", s.at, self.fn.name, slot, s.size, "int", "non-null constant stored"))

    @rule("S-Arg", "T-Call")
    def call(self, c: Call) -> T | None:
        at = c.at
        if isinstance(c.target, str) and c.target in EXTERNALS:
            return self.external(c, EXTERNALS[c.target])
        if isinstance(c.target, str) and c.target in self.prog.functions:
            callee = c.target
        elif c.targets:
            callee = c.targets[0]
            self.out.add(CodeWeb("S-ABI", at, self.fn.name, tuple(c.targets)))
            self.expr(c.target, at) if not isinstance(c.target, str) else None
        else:
            for a in c.args:
                self.expr(a, at)
            return None
        targets = c.targets or (callee,)
        for i, a in enumerate(c.args):
            src = self.arg(a, at, max(self.param_bits(t, i) for t in targets))
            if src is not None:
                self.out.add(Eq("S-Arg", at, self.fn.name, src, ("param", code(callee), i), f"argument {i} ({arg_loc(i)})"))
        return ("ret", code(callee))

    def param_bits(self, callee: str, i: int) -> int:
        f = self.prog.functions.get(callee)
        if f is None or i >= len(f.params):
            return 64
        return f.params[i].bits

    def arg(self, a: Expr, at: int, bits: int) -> T | None:
        """An argument: a 32->64 zero-extension is a register artifact only when
        the callee reads the parameter as 32 bits; otherwise it is a real
        widening at the ABI boundary and the two values have different types."""
        if isinstance(a, Conv) and a.to_bits > a.from_bits and a.from_bits <= 32:
            if bits <= a.from_bits:
                return self.expr(a.a, at)  # the consumer reads only the original width: an artifact
            inner = self.expr(a.a, at)
            if inner is not None:
                self.out.add(Kind("K-Int", at, self.fn.name, inner, a.from_bits // 8, "int", f"extended to {bits} bits"))
            t = self.fresh(at, "conv")
            self.out.add(Kind("T-Cast", at, self.fn.name, tv(t), bits // 8, "int", f"{a.from_bits}->{bits} widening"))
            return tv(t)
        if isinstance(a, VarRef) and bits == 64 and self.eff.get(a.var.id) == 32:
            self.out.add(Kind("K-Int", at, self.fn.name, tv(self.term(a.var)), 4, "int", "zero-extended to 64 bits"))
            t = self.fresh(at, "conv")
            self.out.add(Kind("T-Cast", at, self.fn.name, tv(t), 8, "int", "32->64 widening"))
            return tv(t)
        return self.expr(a, at)

    def external(self, c: Call, sig) -> T | None:
        at = c.at
        for i, a in enumerate(c.args):
            width = sig["params"][i][0] * 8 if i < len(sig["params"]) else 64
            src = self.arg(a, at, width)
            if src is not None and i < len(sig["params"]):
                size, cls = sig["params"][i]
                self.out.add(Kind("ext", at, self.fn.name, src, size, cls, f"{c.target} argument {i}"))
        if sig["ret"] == "fresh_ptr":
            t = self.fresh(at, "ret")
            h = self.pointee(t, at)
            alloc = sig.get("alloc_arg")
            if alloc is not None and alloc < len(c.args) and isinstance(c.args[alloc], Const):
                self.out.add(AllocSize("ext", at, self.fn.name, hole(h), c.args[alloc].value))
            return tv(t)
        if isinstance(sig["ret"], tuple):
            t = self.fresh(at, "ret")
            self.out.add(Kind("ext", at, self.fn.name, tv(t), sig["ret"][0], sig["ret"][1], f"{c.target} result"))
            return tv(t)
        return None

    def expr(self, e: Expr, at: int, narrow: int | None = None) -> T | None:
        if isinstance(e, VarRef):
            return tv(self.term(e.var))
        if isinstance(e, Const):
            return None
        if isinstance(e, Load):
            return self.access(e.addr, e.size, e.at, False)
        if isinstance(e, (BinOp, UnOp)) and e.bits > 64 or isinstance(e, Conv) and max(e.from_bits, e.to_bits) > 64:
            return tv(self.fresh(at, "vec"))
        if isinstance(e, Conv):
            inner = self.expr(e.a, at) if not (e.from_bits == 64 and e.to_bits == 32 and isinstance(e.a, (BinOp, UnOp))) else None
            if e.from_bits == 32 and e.to_bits == 64 and not e.signed:
                return inner  # zero-extension artifact of 32-bit registers
            if e.from_bits == 64 and e.to_bits == 32 and isinstance(e.a, VarRef) and self.eff.get(e.a.var.id) == 32:
                return inner  # truncation of a zero-extended value
            if e.from_bits == 64 and e.to_bits == 32 and isinstance(e.a, (BinOp, UnOp)):
                return self.expr(e.a, at, narrow=32)
            t = self.fresh(at, "conv")
            self.out.add(Kind("T-Cast", at, self.fn.name, tv(t), e.to_bits // 8, None, f"{e.from_bits}->{e.to_bits} conversion"))
            return tv(t)
        if isinstance(e, StackAddr):
            return tv(self.stack_obj(e.offset, at))
        if isinstance(e, Call):
            return self.call(e)
        if isinstance(e, BinOp) and e.op == "And" and e.bits == 64 and isinstance(e.b, Const) and e.b.value == 0xFFFFFFFF:
            return self.expr(e.a, at, narrow=32)
        if isinstance(e, BinOp):
            bits = min(e.bits, narrow) if narrow else e.bits
            sub = narrow if e.op not in ("Shl", "Shr", "Sar") else None
            a = self.arg(e.a, at, 64) if bits == 64 else self.expr(e.a, at, sub)
            b = self.arg(e.b, at, 64) if bits == 64 else self.expr(e.b, at, sub)
            if e.op.startswith("Cmp"):
                return None
            arith_int = e.op in INT_OPS or bits <= 32 or e.op == "Sub" and a is not None and b is not None
            if arith_int:
                size = bits // 8
                for x in (a, b):
                    if x is not None:
                        self.out.add(Kind("K-Int", at, self.fn.name, x, size, "int", f"{e.op} operand ({bits}-bit)"))
                t = self.fresh(at, "e")
                self.out.add(Kind("K-Int", at, self.fn.name, tv(t), size, "int", f"{e.op} result"))
                return tv(t)
            t = self.fresh(at, "e")
            return tv(t)
        if isinstance(e, VarRef) and narrow:
            return tv(self.term(e.var))
        if isinstance(e, UnOp):
            a = self.expr(e.a, at, narrow)
            size = (min(e.bits, narrow) if narrow else e.bits) // 8
            if a is not None:
                self.out.add(Kind("K-Int", at, self.fn.name, a, size, "int", f"{e.op} operand"))
            t = self.fresh(at, "e")
            self.out.add(Kind("K-Int", at, self.fn.name, tv(t), size, "int", f"{e.op} result"))
            return tv(t)
        if isinstance(e, (Phi, Opaque)):
            return None
        return None


def at_(t: T, off: int) -> T:
    return ("at", t, off)
