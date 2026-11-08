"""Render the lifted IR and its premises *before* the store unifies types.

`asmwebir view` shows the extracted view (holes, webs, kinds). This module
shows the two inputs to that view: the raw `ir.syntax` terms produced by
`lift.angr_frontend` (no types, every conversion explicit) and the premises
`lift.premises` reads from them.
"""
from __future__ import annotations

from ..ir.syntax import (
    BinOp, Branch, Call, CallStmt, Const, Conv, Expr, Function, Jump, Let, Load,
    Opaque, Phi, Program, Residual, Return, StackAddr, Store, UnOp, VarRef,
)
from ..lift.premises import Access, AllocSize, Arity, Bound, CodeWeb, Derived, Eq, Kind, Premise, Stride
from .printer import OPS


class RawPrinter:
    """The lifted IR as `lift_binary` produced it: values, sizes and control flow only."""

    def __init__(self, prog: Program):
        self.prog = prog

    def function(self, fn: Function) -> str:
        params = ", ".join(f"{p.name}:{p.bits}" for p in fn.params)
        lines = [f"fn {fn.name}({params}){'' if fn.returns_value else ' -> void'}  @{fn.addr:x} size {fn.size}", "{"]
        for b in fn.blocks:
            lines.append(f" L_{b.addr:x}:")
            for s in b.stmts:
                text, at = self.stmt(s)
                lines.append(f"  {text:<58} @{at:x}")
        lines.append("}")
        return "\n".join(lines)

    def stmt(self, s) -> tuple[str, int]:
        if isinstance(s, Let):
            return f"{s.var.name}:{s.var.bits} = {self.expr(s.expr)};", s.at
        if isinstance(s, Store):
            return f"store[{s.size}]({self.addr(s.addr)}) = {self.expr(s.data)};", s.at
        if isinstance(s, CallStmt):
            head = f"{s.ret.name}:{s.ret.bits} = " if s.ret is not None else ""
            return f"{head}{self.call(s.call)};", s.at
        if isinstance(s, Branch):
            return f"if ({self.expr(s.cond)}) goto L_{s.then:x} else goto L_{s.els:x};", s.at
        if isinstance(s, Jump):
            return f"goto L_{s.target:x};" if s.target >= 0 else "goto ?;  // unresolved target", s.at
        if isinstance(s, Return):
            return ("return;" if s.value is None else f"return {self.expr(s.value)};"), s.at
        if isinstance(s, Residual):
            return f"asm{{{s.lo:x}..{s.hi:x}}}  // {s.reason}", s.lo
        return str(s), 0

    def expr(self, e: Expr) -> str:
        if isinstance(e, VarRef):
            return e.var.name
        if isinstance(e, Const):
            return str(e.value) if e.value < 4096 else hex(e.value)
        if isinstance(e, Load):
            return f"load[{e.size}]({self.addr(e.addr)})"
        if isinstance(e, BinOp):
            op = OPS.get(e.op, e.op) + ("s" if e.signed and e.op.startswith("Cmp") else "")
            return f"({self.expr(e.a)} {op}{e.bits} {self.expr(e.b)})"
        if isinstance(e, UnOp):
            return f"{'-' if e.op == 'Neg' else '~'}{e.bits}{self.expr(e.a)}"
        if isinstance(e, Conv):  # explicit, including the 32->64 zero-extensions the view hides
            return f"{'sext' if e.signed else 'zext' if e.to_bits > e.from_bits else 'trunc'}{e.from_bits}->{e.to_bits}({self.expr(e.a)})"
        if isinstance(e, Call):
            return self.call(e)
        if isinstance(e, Phi):
            return "φ(" + ", ".join(f"L_{b:x}: {self.expr(v)}" for b, v in e.srcs) + ")"
        if isinstance(e, StackAddr):
            return f"&stack[{e.offset}]"
        if isinstance(e, Opaque):
            return f"⟨{e.text}⟩"
        return str(e)

    def addr(self, e: Expr) -> str:
        s = self.expr(e)
        return s[1:-1] if isinstance(e, BinOp) else s  # load[4](a0 +64 8), not load[4]((a0 +64 8))

    def call(self, c: Call) -> str:
        args = ", ".join(self.expr(a) for a in c.args)
        if isinstance(c.target, str):
            return f"{c.target}({args})"
        targets = f"  /* targets: {', '.join(c.targets)} */" if c.targets else ""
        return f"call *{self.expr(c.target)}({args}){targets}"


def premise(p: Premise, fn: str = "") -> str:
    """One premise as a line: rule, address, kind of fact, and the fact itself."""
    t = lambda x: _ty(x, fn)  # noqa: E731
    if isinstance(p, Eq):
        fact = f"{t(p.a)} = {t(p.b)}"
    elif isinstance(p, Kind):
        fact = f"{t(p.t)} :: {p.size if p.size else '?'}B {p.cls or '-'}"  # '-': this premise says nothing about the class
    elif isinstance(p, Access):
        fact = f"{t(p.pointee)} has {p.size}B at +{p.off} ({'write' if p.write else 'read'})"
    elif isinstance(p, Arity):
        fact = f"arity({p.code}) >= {p.n} ({', '.join(p.regs)})"
    elif isinstance(p, CodeWeb):
        fact = f"code web {{{', '.join(p.members)}}}"
    elif isinstance(p, Stride):
        fact = f"{t(p.pointee)} stride {p.step}"
    elif isinstance(p, Bound):
        fact = f"{t(p.pointee)} has >= {p.n} elements"
    elif isinstance(p, AllocSize):
        fact = f"{t(p.pointee)} size >= {p.size}"
    elif isinstance(p, Derived):
        fact = f"{t(p.v)} = {t(p.p)} + {p.off} (if a pointer)"
    else:
        fact = str(p)
    why = getattr(p, "why", "")
    return f"{p.rule:<9} @{p.at:<6x} {type(p).__name__:<9} {fact}" + (f"   [{why}]" if why else "")


def _ty(t: tuple, fn: str) -> str:
    """A symbolic type (see lift.premises) with this function's prefix dropped."""
    short = lambda s: s[len(fn) + 1:] if fn and s.startswith(fn + ".") else s  # noqa: E731
    tag = t[0]
    if tag == "tv":
        return f"type_of({short(t[1])})"
    if tag == "hole":  # "*x" is the pointee hole of x (lift.premises.pointee)
        star = "*" if t[1].startswith("*") else ""
        return f"?[{star}{short(t[1].lstrip('*'))}]"
    if tag == "at":
        return f"{_ty(t[1], fn)}@+{t[2]}"
    if tag == "ptr":
        return f"ptr<web {short(t[1])}> {_ty(t[2], fn)}"
    if tag == "param":
        return f"param({t[1]}, {t[2]})"
    if tag == "ret":
        return f"ret({t[1]})"
    return repr(t)
