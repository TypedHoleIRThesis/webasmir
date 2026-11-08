"""Harness loop with a scripted client (no API calls)."""
from __future__ import annotations

from .conftest import FIX, symbols


class FakeClient:
    """Plays a fixed script of assistant turns; counts real 'API' calls."""

    def __init__(self, script):
        self.script, self.calls = list(script), 0
        self.beta = self
        self.messages = self

    def create(self, **request):
        self.calls += 1
        assert request["model"] == "claude-opus-5-5" and request["output_config"]["effort"] == "high"
        assert all(t["strict"] for t in request["tools"])
        # the history is append-only: every earlier assistant turn is echoed unchanged
        return self.script.pop(0)


def tool(i, name, **inp):
    return {"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}


def turn(*blocks, stop="tool_use"):
    return {"content": list(blocks), "stop_reason": stop, "model": "claude-opus-5-5",
            "usage": {"input_tokens": 100, "output_tokens": 10}}


def test_run_and_replay(tmp_path):
    from asmwebir.harness.loop import ResponseCache, run_agent
    from asmwebir.session import Session

    path = str(FIX / "running_example.O1.stripped")
    ls = symbols(FIX / "running_example.O1.elf")["list_sum"]
    t = Session(path).view(ls).split("ptr#d1 ")[1].split(")")[0]
    script = [
        turn(tool(1, "view", function=ls)),
        turn(tool(2, "claim", fact="declare struct Node { 0: next: ptr Node; 8: val: i64 } size 16", rationale="list")),
        turn(tool(3, "claim", fact=f"{t} = Node", rationale="a0 walks the list")),
        turn(tool(4, "retract", claim_id="a1", reason="witness reads 4 bytes"),
             tool(5, "claim", fact="declare struct Node2 { 0: next: ptr Node2; 8: val: i32 } size 16", rationale="fix")),
        turn({"type": "text", "text": "done"}, stop="end_turn"),
    ]
    cache = ResponseCache(str(tmp_path / "c.sqlite"))
    client = FakeClient(script)
    log = run_agent(Session(path), client, cache, run_index=0, max_turns=10)
    assert log.stop == "end_turn" and log.final_text == "done" and client.calls == 5
    assert log.metrics["nogoods"] == 1 and log.metrics["claims"] == 3
    assert log.turns[1].tool_calls[0].startswith("claim(")
    # replay of run 0 comes entirely from the cache; run 1 would be generated anew
    replay = run_agent(Session(path), FakeClient([]), cache, run_index=0, max_turns=10)
    assert all(t.cached for t in replay.turns) and replay.claims == log.claims
