"""Part A, Step 0 -- the engine alone (no LLM)."""
from __future__ import annotations

import re


def test_step0_list_sum_view(o1, o1_view):
    """Rules: K-Hole, L-Open, T-Load, T-Fn, V-Raw."""
    fn = o1.prog.functions[o1.names["list_sum"]]
    text = o1_view.function(fn)
    header = text.splitlines()[0]
    assert re.fullmatch(r"fn#c\d+ sub_[0-9a-f]+\(a0#w\d+: ptr#d\d+ \?T(\d+)\) -> \?T\d+", header), header
    t = re.search(r"ptr#d\d+ (\?T\d+)", header).group(1)
    # ?T1 :: [>=12, 8, agg] :> { 0: ptr#d1 ?T1, 8: [4,4,int] }   (>=16 here: malloc(16) is in the web)
    assert re.search(rf"{re.escape(t)} :: \[>=1[26], 8, agg\]  :> \{{ 0: ptr#d\d+ {re.escape(t)}, 8: \[4,4,int\] \}}", text), text
    assert "load[4,int](v6 + 8)" in text and "load[8,ptr](v6 + 0)" in text
    assert "a0 == null" in text
    assert re.search(r"@40114[0-9a-f]", text)  # provenance on statements


def test_step0_every_function_lifts(o1):
    want = {"list_sum", "list_push", "counter_bump", "h_ping", "h_data", "dispatcher", "sum16", "iabs", "main"}
    assert {o1.names[n] for n in want} <= set(o1.prog.functions)
