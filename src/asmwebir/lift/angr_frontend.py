"""Lift an ELF x86-64 (SysV) binary into AsmWebIR terms using angr.

We use angr for function recovery (CFGFast), the calling-convention analysis
(live-in argument registers) and Clinic's SSA form of AIL. We never import
angr's type guesses, variable names or prototypes' C types: only register
numbers, sizes and dataflow cross this boundary. Everything angr-specific is
confined to this module, which is pinned to angr 9.2.147.
"""
from __future__ import annotations

import logging
from functools import lru_cache

from ..ir.syntax import (
    BinOp, Block, Branch, Call, CallStmt, Const, Conv, Expr, Function, Jump, Let,
    Load, Opaque, Phi, StackAddr, Program, Residual, Return, Store, UnOp, Var, VarRef,
)

log = logging.getLogger(__name__)

SKIP_NAMES = {
    "_start", "_init", "_fini", "deregister_tm_clones", "register_tm_clones",
    "__do_global_dtors_aux", "frame_dummy", "_dl_relocate_static_pie",
}

_BINOPS = {
    "Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Sar", "Div", "Mod",
    "CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE", "LogicalAnd", "LogicalOr",
}


def _angr():
    import angr  # heavy import, keep lazy

    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("pyvex").setLevel(logging.ERROR)
    return angr


def sub_name(addr: int) -> str:
    return f"sub_{addr:x}"


def lift_binary(path: str, only: list[int] | None = None) -> Program:
    angr = _angr()
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

    externals: dict[int, str] = {}
    code: dict[int, object] = {}
    for f in sorted(proj.kb.functions.values(), key=lambda f: f.addr):
        if f.is_plt or f.is_simprocedure:
            externals[f.addr] = f.name
            continue
        sec = proj.loader.main_object.find_section_containing(f.addr)
        if f.is_alignment or f.size == 0 or sec is None or sec.name != ".text":
            continue
        code[f.addr] = f
    keep = user_code(proj, code) if only is None else set(only)
    candidates = [code[a] for a in sorted(keep) if a in code]

    names = {f.addr: sub_name(f.addr) for f in candidates}
    names.update(externals)
    functions: dict[str, Function] = {}
    call_tables: dict[int, tuple[str, ...]] = {}
    for f in candidates:
        fn = _lift_function(proj, cfg, f, names, call_tables)
        functions[fn.name] = fn
    return Program(path=path, functions=functions, externals=externals, call_tables=call_tables)


def user_code(proj, code: dict[int, object]) -> set[int]:
    """User functions = closure over the call graph from main and from code
    pointers stored in data sections (not .init_array/.fini_array, which hold
    the crt's frame_dummy and __do_global_dtors_aux)."""
    roots = {a for a, f in code.items() if f.name == "main"}
    obj = proj.loader.main_object
    for sec in obj.sections:
        if sec.name in {".data", ".data.rel.ro", ".rodata"} and sec.memsize:
            for off in range(0, sec.memsize - 7, 8):
                try:
                    w = proj.loader.memory.unpack_word(sec.vaddr + off)
                except Exception:
                    break
                if w in code:
                    roots.add(w)
    if not roots:  # no main recovered: fall back to every .text function not named by the crt
        return {a for a, f in code.items() if f.name not in SKIP_NAMES}
    seen, todo = set(), list(roots)
    cg = proj.kb.callgraph
    while todo:
        a = todo.pop()
        if a in seen or a not in code:
            continue
        seen.add(a)
        if a in cg:
            todo.extend(cg.successors(a))
    return seen


def _lift_function(proj, cfg, f, names: dict[int, str], call_tables) -> Function:
    angr = _angr()
    name = names[f.addr]
    # Clinic consults callee prototypes recovered by earlier Clinic runs, which
    # makes call-site arguments depend on lifting order. Reset them so every
    # function is lifted as if alone: call arguments then come from the
    # registers defined at the call site (the S-Arg reading of the binary).
    for g in proj.kb.functions.values():
        if not g.is_plt and not g.is_simprocedure:
            g.prototype = None
            g.calling_convention = None
            g.is_prototype_guessed = True
    try:
        clinic = proj.analyses.Clinic(f)
    except Exception as exc:  # pragma: no cover - lifter fragility is reported, not hidden
        log.warning("Clinic failed on %s: %s", name, exc)
        return Function(name, f.addr, f.size, [], [Block(f.addr, [Residual(f.addr, f.addr + f.size, f"clinic: {exc}")])])

    lifter = _AilLifter(proj, name, names, call_tables)
    params: list[Var] = []
    for idx, arg in enumerate(clinic.arg_list):
        bits = arg.size * 8 if getattr(arg, "size", None) else 64
        params.append(Var(name, f"a{idx}", bits))
    lifter.param_by_reg = {arg.reg: params[i] for i, arg in enumerate(clinic.arg_list) if hasattr(arg, "reg")}

    nodes = sorted(clinic.graph.nodes(), key=lambda n: (n.addr, n.idx or 0))
    defined = _defined_vvars(nodes)
    lifter.defined = defined
    blocks = []
    for n in nodes:
        stmts = []
        for s in n.statements:
            try:
                out = lifter.stmt(s)
            except Exception as exc:  # keep the instruction as typed residual code (T-Resid)
                a = getattr(s, "ins_addr", None) or n.addr
                out = Residual(a, a, f"lifter: {type(exc).__name__}: {exc}")
            if out is not None:
                stmts.append(out)
        blocks.append(Block(n.addr, stmts))
    returns_value = any(isinstance(s, Return) and s.value is not None for b in blocks for s in b.stmts)
    return Function(name, f.addr, f.size, params, blocks, returns_value,
                    symbol=None if f.name.startswith("sub_") else f.name)


def _defined_vvars(nodes) -> set[int]:
    import ailment

    out: set[int] = set()
    for n in nodes:
        for s in n.statements:
            if isinstance(s, ailment.Stmt.Assignment) and isinstance(s.dst, ailment.Expr.VirtualVariable):
                out.add(s.dst.varid)
            if isinstance(s, ailment.Stmt.Call) and isinstance(getattr(s, "ret_expr", None), ailment.Expr.VirtualVariable):
                out.add(s.ret_expr.varid)
    return out


class _AilLifter:
    def __init__(self, proj, fn_name, names, call_tables):
        self.proj = proj
        self.fn = fn_name
        self.names = names
        self.call_tables = call_tables
        self.param_by_reg: dict[int, Var] = {}
        self.defined: set[int] = set()

    # -- variables
    def var(self, vv) -> Var | None:
        if vv.was_parameter:
            p = self.param_by_reg.get(vv.parameter_reg_offset)
            if p is not None:
                return p
        return Var(self.fn, f"v{vv.varid}", vv.bits)

    def _undefined(self, vv) -> bool:
        return not vv.was_parameter and vv.varid not in self.defined

    # -- statements
    def stmt(self, s):
        import ailment

        S = ailment.Stmt
        at = getattr(s, "ins_addr", None) or 0
        if isinstance(s, S.Label):
            return None
        if isinstance(s, S.Assignment) and isinstance(s.dst, ailment.Expr.VirtualVariable):
            src = s.src
            # spills of callee-saved registers (initial values never defined here)
            if isinstance(src, ailment.Expr.VirtualVariable) and self._undefined(src):
                return None
            return Let(self.var(s.dst), self.expr(src, at), at)
        if isinstance(s, S.Store):
            return Store(self.expr(s.addr, at), self.expr(s.data, at), s.size, at)
        if isinstance(s, S.Call):
            call = self.call(s, at)
            ret = s.ret_expr if isinstance(getattr(s, "ret_expr", None), ailment.Expr.VirtualVariable) else None
            return CallStmt(call, self.var(ret) if ret is not None else None, at)
        if isinstance(s, S.ConditionalJump):
            return Branch(self.expr(s.condition, at), _target(s.true_target), _target(s.false_target), at)
        if isinstance(s, S.Jump):
            return Jump(_target(s.target), at)
        if isinstance(s, S.Return):
            vals = list(s.ret_exprs or [])
            return Return(self.expr(vals[0], at) if vals else None, at)
        return Residual(at, at, f"unmodelled statement {type(s).__name__}: {s}")

    def call(self, c, at) -> Call:
        import ailment

        args = tuple(self.expr(a, at) for a in (c.args or []))
        tgt = c.target
        if isinstance(tgt, ailment.Expr.Const):
            return Call(self.names.get(tgt.value, sub_name(tgt.value)), args, at)
        if isinstance(tgt, str):
            return Call(tgt, args, at)
        texpr = self.expr(tgt, at)
        targets = self._table_targets(tgt)
        return Call(texpr, args, at, targets)

    def _table_targets(self, tgt) -> tuple[str, ...]:
        """Resolve `call [table + idx*8]`: read consecutive code pointers from the table."""
        import ailment

        if not isinstance(tgt, ailment.Expr.Load):
            return ()
        addr = tgt.addr
        base = None
        if isinstance(addr, ailment.Expr.BinaryOp) and addr.op == "Add":
            for o in addr.operands:
                if isinstance(o, ailment.Expr.Const):
                    base = o.value
        if base is None:
            return ()
        if base in self.call_tables:
            return self.call_tables[base]
        mem = self.proj.loader.memory
        out = []
        for i in range(256):
            try:
                ptr = mem.unpack_word(base + 8 * i)
            except Exception:
                break
            if ptr not in self.names or ptr in getattr(self, "_externals", ()):  # only lifted functions
                break
            out.append(self.names[ptr])
        self.call_tables[base] = tuple(out)
        return tuple(out)

    # -- expressions
    def expr(self, e, at) -> Expr:
        import ailment

        E = ailment.Expr
        if isinstance(e, E.VirtualVariable):
            return VarRef(self.var(e))
        if isinstance(e, E.Const):
            return Const(e.value if isinstance(e.value, int) else 0, e.bits)
        if isinstance(e, E.Load):
            return Load(self.expr(e.addr, at), e.size, getattr(e, "ins_addr", None) or at)
        if isinstance(e, E.BinaryOp):
            op = e.op
            if op not in _BINOPS:
                return Opaque(str(e), e.bits)
            a, b = e.operands
            return BinOp(op, self.expr(a, at), self.expr(b, at), e.bits, bool(getattr(e, "signed", False)))
        if isinstance(e, E.Convert):  # Convert subclasses UnaryOp: test it first
            return Conv(self.expr(e.operand, at), e.from_bits, e.to_bits, bool(e.is_signed))
        if isinstance(e, E.UnaryOp):
            return UnOp(e.op, self.expr(e.operand, at), e.bits)
        if isinstance(e, E.StackBaseOffset):
            return StackAddr(e.offset)
        if isinstance(e, E.Phi):
            return Phi(tuple((src[0] if src else 0, self.expr(v, at)) for src, v in e.src_and_vvars if v is not None))
        if isinstance(e, ailment.Stmt.Call):
            return self.call(e, at)
        return Opaque(str(e), getattr(e, "bits", 64) or 64)


def _target(t) -> int:
    import ailment

    if isinstance(t, ailment.Expr.Const):
        return t.value
    return -1
