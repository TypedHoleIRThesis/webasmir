"""The agent-facing tool interface (section 16) end to end on the running example."""
from __future__ import annotations

import pytest

from .conftest import FIX, symbols


@pytest.fixture(scope="module")
def sess():
    from asmwebir.session import Session

    s = Session(str(FIX / "running_example.O1.stripped"))
    s.names = symbols(FIX / "running_example.O1.elf")
    return s


def test_tool_flow(sess):
    """Rules: V-Mark, M-Complete, E-Retract."""
    ls = sess.names["list_sum"]
    assert "open holes" in sess.list_functions()
    v = sess.view(ls)
    t = v.split("ptr#d1 ")[1].split(")")[0]
    out = sess.claim("declare struct Node { 0: next: ptr Node; 8: val: i64 } size 16", "guess")
    assert out.startswith("a1 recorded")
    out = sess.claim(f"{t} = Node")
    assert "NOGOOD" in out and "401140: add eax, dword ptr [rdi + 8]" in out
    assert "⚠" in sess.view(ls) and "marks:" in sess.view(ls)
    assert "not complete" in sess.complete(ls)
    assert "would change" in sess.blast("a2")
    out = sess.retract("a1", "binary reads 4 bytes at +8")
    sess.retract("a2", "depends on a1")
    assert "⚠" not in sess.view(ls)
    sess.claim("declare struct Node { 0: next: ptr Node; 8: val: i32 } size 16")
    out = sess.claim(f"{t} = Node")
    assert "NOGOOD" not in out and "views changed" in out
    w = sess.why(ls, "a0")
    assert "K-Ptr" in w and "claims: a4" in w
    assert "error" in sess.claim("this is not a claim")
