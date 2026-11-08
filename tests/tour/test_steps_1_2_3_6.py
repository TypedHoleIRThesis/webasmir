"""Part A, Steps 1, 2, 3 and 6 on the real O1 binary."""
from __future__ import annotations

import re

from .helpers import code_of, hole_of_param, view

NODE = "declare struct Node { 0: next: ptr Node; 8: val: i32 } size 16"
NODE64 = "declare struct Node64 { 0: next: ptr Node64; 8: val: i64 } size 16"


def test_step1_claim_structifies_the_whole_web(store):
    """Rules: E-Claim, S-Unify, S-Field, W-Unify, V-Extract, K-Struct."""
    t1 = hole_of_param(store, "list_sum")
    r2 = store.claim(NODE, rationale="linked list node", resolver=store.R)
    r3 = store.claim(f"{t1} = Node", resolver=store.R)
    store.claim(f'name {code_of(store, "list_sum")[1:]} "list_sum"', resolver=store.R)
    assert not r2.nogoods and not r3.nogoods
    s = view(store, "list_sum")
    assert "list_sum(" in s.splitlines()[0]
    assert "ptr#d1 Node" in s.splitlines()[0]
    assert "v6->val" in s and "v6->next" in s
    push = view(store, "list_push")
    assert "v17->next = a0;" in push and "v17->val = a1;" in push
    assert re.search(r"a1#w\d+: i32", push.splitlines()[0])  # v: i32, solved by unification
    # the counter web #d2 is untouched
    assert "a0->" not in view(store, "counter_bump") and "Node" not in view(store, "counter_bump")


def test_step1_raw_forms_stay_in_the_store(store):
    """Rules: V-Raw, Forwardness."""
    t1 = hole_of_param(store, "list_sum")
    store.claim(NODE, resolver=store.R)
    store.claim(f"{t1} = Node", resolver=store.R)
    # premise-only snapshot still has the raw open layout
    before = store.snapshot(frozenset())
    h = before.key(("hole", store.premises.pointers[f"{store.names['list_sum']}.v6"]))
    assert before.node_by_key(h).tag == "hole"


def test_step2_hallucination_is_a_nogood_with_witness(store):
    """Rules: S-Clash, S-Nogood, E-Retract."""
    t1 = hole_of_param(store, "list_sum")
    a = store.claim(NODE64, resolver=store.R)
    b = store.claim(f"{t1} = Node64", resolver=store.R)
    assert len(b.nogoods) == 1
    ng = b.nogoods[0]
    assert ng.rule == "S-Clash"
    assert ng.label == {a.claim.id, b.claim.id}
    assert 0x401140 in ng.witness  # add eax, dword ptr [rdi+0x8]
    # retract, claim the i32 version: no contradiction left; nothing deleted
    store.retract(a.claim.id, "binary reads 4 bytes at +8")
    store.retract(b.claim.id, "depends on retracted Node64")
    store.claim(NODE, resolver=store.R)
    ok = store.claim(f"{t1} = Node", resolver=store.R)
    assert not ok.nogoods and not store.active_nogoods()
    assert len(store.nogoods) == 1 and store.log.of("retract")


def test_step2_known_nogood_is_answered_from_the_record(store):
    """Rules: S-Nogood, E-Claim."""
    t1 = hole_of_param(store, "list_sum")
    a = store.claim(NODE64, resolver=store.R)
    b = store.claim(f"{t1} = Node64", resolver=store.R)
    store.retract(b.claim.id, "wrong")
    again = store.claim(f"{t1} = Node64", agent="agent-B", resolver=store.R)
    assert [n.id for n in again.known] == [b.nogoods[0].id]


def test_step3_signature_across_indirect_call(store):
    """Rules: S-ABI, S-Arg, A-AddParam, T-Call."""
    c = code_of(store, "h_ping")
    assert c == code_of(store, "h_data")  # one code web
    store.claim(f"type(param 3 of {c[1:]}) = u64", resolver=store.R)
    store.claim(f'name(param 3 of {c[1:]}) = "len"', resolver=store.R)
    header = view(store, "h_ping").splitlines()[0]
    assert "len: u64" in header  # h_ping visibly takes len and ignores it
    assert "len" in view(store, "h_data").splitlines()[0]


def test_step3_arity_clash(store):
    """Rules: S-Clash-Arity."""
    c = code_of(store, "h_ping")
    r = store.claim(f"arity {c[1:]} = 2", resolver=store.R)
    assert r.nogoods and r.nogoods[0].rule == "S-Clash-Arity"


def test_step6_undo_keeps_what_was_learned(store):
    """Rules: E-Retract, S-Clash, Retraction Locality."""
    total = view(store, "list_sum").splitlines()[0].split("-> ")[1]  # ?T of the return / total
    before = view(store, "list_sum")
    r = store.claim(f"{total} = i64", resolver=store.R)
    assert r.nogoods and 0x401140 in r.nogoods[0].witness  # add eax, ... is 32-bit
    store.retract(r.claim.id, "add eax is 32-bit")
    assert view(store, "list_sum") == before  # view exactly as before
    assert store.nogoods and not store.active_nogoods()  # ...but the store knows total is not i64


def test_name_conflict_is_not_a_nogood(store):
    """Rules: S-Name-Conflict."""
    t1 = hole_of_param(store, "list_sum")
    store.claim(NODE, resolver=store.R)
    store.claim(f"{t1} = Node", resolver=store.R)
    store.claim('name d1 "Node"', agent="A", resolver=store.R)
    r = store.claim('name d1 "ListItem"', agent="B", resolver=store.R)
    assert r.conflicts and not r.nogoods
