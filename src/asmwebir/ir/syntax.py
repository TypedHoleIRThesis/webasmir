"""Lifted AsmWebIR terms (Part C, section 19.1).

These are the *raw* terms produced by the lifter. Types are not stored here:
every variable's type lives in the knowledge store as `type_of(var.id)`.
Every statement carries provenance (`at`, the instruction address).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Var:
    fn: str
    name: str  # "a0" for parameters, "v6" for SSA values
    bits: int = 64

    @property
    def id(self) -> str:
        return f"{self.fn}.{self.name}"


# ---- expressions -----------------------------------------------------------

@dataclass(frozen=True)
class Const:
    value: int
    bits: int


@dataclass(frozen=True)
class VarRef:
    var: Var


@dataclass(frozen=True)
class BinOp:
    op: str  # Add Sub Mul And Or Xor Shl Shr Sar CmpEQ CmpNE CmpLT CmpLE CmpGT CmpGE
    a: "Expr"
    b: "Expr"
    bits: int
    signed: bool = False


@dataclass(frozen=True)
class UnOp:
    op: str  # Neg Not
    a: "Expr"
    bits: int


@dataclass(frozen=True)
class Conv:
    a: "Expr"
    from_bits: int
    to_bits: int
    signed: bool = False


@dataclass(frozen=True)
class Load:
    addr: "Expr"
    size: int  # bytes
    at: int


@dataclass(frozen=True)
class Call:
    target: "Expr | str"  # function name for direct/external calls, expression for indirect
    args: tuple["Expr", ...]
    at: int
    targets: tuple[str, ...] = ()  # resolved targets of an indirect call (call table)


@dataclass(frozen=True)
class Phi:
    srcs: tuple[tuple[int, "Expr"], ...]  # (predecessor block, value)


@dataclass(frozen=True)
class StackAddr:
    """Address of the current frame's stack slot at `offset` (an escaping local)."""
    offset: int


@dataclass(frozen=True)
class Opaque:
    """An AIL expression the lifter does not model; kept with its text."""
    text: str
    bits: int


Expr = Const | VarRef | BinOp | UnOp | Conv | Load | Call | Phi | StackAddr | Opaque


# ---- statements ------------------------------------------------------------

@dataclass(frozen=True)
class Let:
    var: Var
    expr: Expr
    at: int


@dataclass(frozen=True)
class Store:
    addr: Expr
    data: Expr
    size: int
    at: int


@dataclass(frozen=True)
class CallStmt:
    call: Call
    ret: Var | None
    at: int


@dataclass(frozen=True)
class Branch:
    cond: Expr
    then: int
    els: int
    at: int


@dataclass(frozen=True)
class Jump:
    target: int
    at: int


@dataclass(frozen=True)
class Return:
    value: Expr | None
    at: int


@dataclass(frozen=True)
class Residual:
    lo: int
    hi: int
    reason: str


Stmt = Let | Store | CallStmt | Branch | Jump | Return | Residual


@dataclass
class Block:
    addr: int
    stmts: list[Stmt] = field(default_factory=list)


@dataclass
class Function:
    name: str  # stable id, e.g. "sub_401136"
    addr: int
    size: int
    params: list[Var]
    blocks: list[Block]
    returns_value: bool = True
    symbol: str | None = None  # symbol name if the binary has one (never shown as a claim)

    @property
    def stmts(self):
        for b in self.blocks:
            yield from b.stmts


@dataclass
class Program:
    path: str
    functions: dict[str, Function]
    externals: dict[int, str]  # PLT address -> imported name
    call_tables: dict[int, tuple[str, ...]]  # table address -> function names

    def by_addr(self, addr: int) -> Function | None:
        for f in self.functions.values():
            if f.addr == addr:
                return f
        return None


def split_addr(e: Expr) -> tuple[Expr, int]:
    """Decompose `base + const` (possibly nested) into (base, offset)."""
    if isinstance(e, BinOp) and e.op == "Add":
        if isinstance(e.b, Const):
            base, off = split_addr(e.a)
            return base, off + _signed(e.b.value, e.b.bits)
        if isinstance(e.a, Const):
            base, off = split_addr(e.b)
            return base, off + _signed(e.a.value, e.a.bits)
    if isinstance(e, BinOp) and e.op == "Sub" and isinstance(e.b, Const):
        base, off = split_addr(e.a)
        return base, off - _signed(e.b.value, e.b.bits)
    return e, 0


def _signed(v: int, bits: int) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v
