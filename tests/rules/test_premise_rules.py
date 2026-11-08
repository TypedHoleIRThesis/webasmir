"""Premise-level rules (sections 20-23) on the O1 running example."""
from __future__ import annotations


def ty(ks, term):
    return ks.snapshot().node(("tv", term))


def pointee(ks, fn, var):
    S = ks.snapshot()
    return S.key(("hole", ks.premises.pointers[f"{ks.names[fn]}.{var}"]))


def test_K_Ptr(o1):
    """A value used as an address is an 8-byte pointer (list_sum's a0)."""
    n = ty(o1, f"{o1.names['list_sum']}.a0")
    assert n.tag == "ptr"
    assert o1.snapshot().kind_of(n.key()) == ("8", "8", "ptr")


def test_S_Access(o1):
    """Accesses build the open layout { 0: ptr, 8: [4,4,int] } of the list node."""
    S = o1.snapshot()
    h = pointee(o1, "list_sum", "v6")
    lay = S.kinds[h].layout
    assert sorted(lay) == [0, 8]
    assert lay[0].sizes == {8} and lay[8].sizes == {4}
    assert S.kind_of(S.key(lay[8].slot)) == ("4", "4", "int")


def test_W_Unify(o1):
    """The node's next field points to the node itself (recursive type), and
    list_sum, list_push and main's h are one data web #d1."""
    S = o1.snapshot()
    h = pointee(o1, "list_sum", "v6")
    nxt = S.node(S.kinds[h].layout[0].slot)
    assert nxt.tag == "ptr" and nxt.to.key() == h
    webs = {ty(o1, f"{o1.names[f]}.{v}").web for f, v in
            [("list_sum", "a0"), ("list_push", "a0"), ("list_push", "v17")]}
    assert len(webs) == 1


def test_W_Unify_keeps_unrelated_webs_apart(o1):
    """counter_bump's struct has the same shape but no flow to list nodes (#d7 != #d1)."""
    assert ty(o1, f"{o1.names['counter_bump']}.a0").web != ty(o1, f"{o1.names['list_sum']}.a0").web


def test_S_ABI(o1):
    """h_data reads rdx, so every member of the dispatch table's code web takes >= 3 args."""
    S = o1.snapshot()
    ping, data = o1.names["h_ping"], o1.names["h_data"]
    assert S.code(ping) == S.code(data)
    assert S.arity[S.code(ping)] == 3


def test_S_Arg(o1):
    """At the indirect call the arguments are the dispatcher's a1..a3 (rsi, rdx, rcx)."""
    S = o1.snapshot()
    d, data = o1.names["dispatcher"], o1.names["h_data"]
    for i in range(3):
        assert S.key(("tv", f"{d}.a{i + 1}")) == S.key(("param", data, i))


def test_S_Unify(o1):
    """list_push's v has the type of the node's +8 field (\"v: i32, solved by unification\")."""
    S = o1.snapshot()
    h = pointee(o1, "list_sum", "v6")
    assert S.key(("tv", f"{o1.names['list_push']}.a1")) == S.key(S.kinds[h].layout[8].slot)


def test_S_Bound(o1):
    """sum16's loop compares the induction pointer with a0 + 64: >= 16 int elements."""
    S = o1.snapshot()
    h = pointee(o1, "sum16", "v3")
    assert S.kinds[h].strides == {4}
    assert max(S.kinds[h].bounds) == 16


def test_K_Int(o1):
    """32-bit arithmetic gives [4,4,int]; Clinic's 64-bit masks are not 8-byte evidence."""
    S = o1.snapshot()
    assert S.kind_of(S.key(("tv", f"{o1.names['iabs']}.a0"))) == ("4", "4", "int")
    assert S.kind_of(S.key(("ret", o1.names["list_sum"]))) == ("4", "4", "int")
