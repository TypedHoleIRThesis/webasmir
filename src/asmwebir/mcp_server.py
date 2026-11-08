"""MCP server exposing the AsmWebIR tool interface (section 16) to any agent.

    claude mcp add asmwebir -- /path/to/.venv/bin/asmwebir-mcp

Tools are thin wrappers over `asmwebir.session.Session`.
"""
from __future__ import annotations

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from .session import Session

INSTRUCTIONS = """AsmWebIR decompilation engine for ELF x86-64 (SysV) binaries.
Workflow: open_binary(path) -> list_functions -> view(fn) -> claim(...) -> view again.
The view shows holes (?Tn) with kinds [size, align, class] and open layouts { offset: kind },
webs (#c code, #d data, #w value) that must agree, and provenance (@addr).
Claims (one per call): `declare struct Node { 0: next: ptr Node; 8: val: i32 } size 16`,
`?T6 = Node`, `type(param 3 of c1) = u64`, `type(ret of c2) = i32`, `type(v15 of sub_401136) = i32`,
`name c2 "list_sum"`, `name w10 "total"`, `name(param 3 of c1) = "len"`, `arity c1 = 3`.
A claim that contradicts the binary returns a NOGOOD with the witness instruction: retract a claim
in its label. Nothing is ever deleted; retraction records why. Only claim what the binary supports
or what source conventions make likely; names and signedness are not checkable."""

mcp = _Server("asmwebir", instructions=INSTRUCTIONS, log_level="WARNING")
_sessions: dict[str, Session] = {}
_current: list[str] = []


def _s() -> Session:
    if not _current:
        raise RuntimeError("call open_binary(path) first")
    return _sessions[_current[-1]]


@mcp.tool()
def open_binary(path: str) -> str:
    """Lift an ELF x86-64 binary and open a session on it (premises only, no claims)."""
    if path not in _sessions:
        _sessions[path] = Session(path)
    _current.append(path)
    return _sessions[path].list_functions()


@mcp.tool()
def list_functions() -> str:
    """Functions with their code web, address, parameter count and open holes."""
    return _s().list_functions()


@mcp.tool()
def view(function: str) -> str:
    """Current view of a function (name, sub_xxx, #cN or hex address) with holes, marks and types."""
    return _s().view(function)


@mcp.tool()
def claim(fact: str, rationale: str = "") -> str:
    """Record one claim. Returns the claim id, new nogoods (with witnesses) and the views that changed."""
    return _s().claim(fact, rationale)


@mcp.tool()
def retract(claim_id: str, reason: str) -> str:
    """Retract a claim (recorded, never deleted). Returns the views that changed."""
    return _s().retract(claim_id, reason)


@mcp.tool()
def blast(claim_id: str) -> str:
    """Dry run: which functions' views depend on a claim."""
    return _s().blast(claim_id)


@mcp.tool()
def why(function: str, value: str) -> str:
    """Premises (instructions) and claims behind the displayed type of a value (a0, v15, ...)."""
    return _s().why(function, value)


@mcp.tool()
def list_holes(function: str = "") -> str:
    """Open holes, for one function or the whole binary."""
    return _s().list_holes(function or None)


@mcp.tool()
def list_nogoods(active_only: bool = True) -> str:
    """Recorded contradictions (labels, rules, witnesses)."""
    return _s().list_nogoods(active_only)


@mcp.tool()
def list_claims() -> str:
    """All claims, including retracted ones."""
    return _s().list_claims()


@mcp.tool()
def complete(function: str) -> str:
    """Check the completion criteria of a function (no marks, no open holes)."""
    return _s().complete(function)


def main() -> None:
    import logging

    for name in ("egglog", "angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
