"""Experiment harness: one LLM agent closes holes in one binary through the
section 16 tools (RQ2-RQ5). Manual tool loop (not the SDK tool runner) because
experiments need exact control of caching, logging and replay.

Reproducibility (proposal, Phase 2.1/2.7):
  * pinned model and effort, logged per turn together with the model that
    actually served the turn (server-side refusal fallbacks can switch it);
  * response cache keyed by (sha256(request), run_index): repeated runs for
    confidence intervals are generated independently, then replayable;
  * append-only history (required for preserved thinking on current models);
  * raw submitted tokens are recorded separately from cache-read tokens.

    asmwebir-run <elf> --runs 3 --max-turns 40 [--no-checker]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..session import Session

MODEL = "claude-opus-5-5"
EFFORT = "high"  # explicit: Claude Opus 5.5 defaults to medium

SYSTEM = """You are a reverse engineer recovering source-level types from a stripped ELF x86-64 binary.
You never see raw assembly as text to rewrite: you work through tools on a typed IR.
The engine already knows everything the binary certifies (kinds, layouts, which values must agree).
Your job is to add what the binary cannot: struct declarations, signedness, names, and which holes are the same type.

Rules:
- Make one claim per `claim` call. Prefer claims that close many holes at once (a struct for a whole web).
- If a claim returns NOGOOD, the binary contradicts it: read the witness instruction and retract a claim in the label.
- Only claim what the evidence (access sizes, offsets, usage, allocation sizes) supports; when unsure, leave the hole.
- Work function by function: list_functions, then view, claim, view again. Call `complete` on a function when done.
- Stop when every function is complete or you have nothing well-founded left to claim; finish with a short summary."""


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


S = {"type": "string"}
TOOLS = [
    {"name": "list_functions", "description": "Functions with code web id, address, parameter count and open holes.",
     "input_schema": _schema({}, [])},
    {"name": "view", "description": "Current view of a function: holes ?Tn with kinds [size, align, class] and open layouts, webs (#c code, #d data, #w value), provenance @addr, marks for contradictions.",
     "input_schema": _schema({"function": {**S, "description": "name, sub_xxx, #cN or hex address"}}, ["function"])},
    {"name": "claim", "description": "Record one claim. Forms: `declare struct Node { 0: next: ptr Node; 8: val: i32 } size 16`, `?T6 = Node`, `type(param 3 of c1) = u64`, `type(ret of c2) = i32`, `type(v15 of sub_401136) = i32`, `name c2 \"list_sum\"`, `name w10 \"total\"`, `name(param 3 of c1) = \"len\"`, `arity c1 = 3`. Types: i8..i64, u8..u64, f32, f64, void, ptr T, T[n], struct names, ?Tn.",
     "input_schema": _schema({"fact": S, "rationale": S}, ["fact", "rationale"])},
    {"name": "retract", "description": "Retract a claim by id (recorded with the reason, never deleted).",
     "input_schema": _schema({"claim_id": S, "reason": S}, ["claim_id", "reason"])},
    {"name": "blast", "description": "Dry run: which functions depend on a claim.",
     "input_schema": _schema({"claim_id": S}, ["claim_id"])},
    {"name": "why", "description": "Premises (instructions) and claims behind the displayed type of a value (a0, v15, ...).",
     "input_schema": _schema({"function": S, "value": S}, ["function", "value"])},
    {"name": "list_holes", "description": "Open holes for one function (or all when function is empty).",
     "input_schema": _schema({"function": S}, ["function"])},
    {"name": "list_nogoods", "description": "Active contradictions with labels and witnesses.",
     "input_schema": _schema({}, [])},
    {"name": "complete", "description": "Check whether a function meets the completion criteria.",
     "input_schema": _schema({"function": S}, ["function"])},
]
for _t in TOOLS:
    _t["strict"] = True


def run_tool(sess: Session, name: str, args: dict) -> str:
    try:
        if name == "list_functions":
            return sess.list_functions()
        if name == "view":
            return sess.view(args["function"])
        if name == "claim":
            return sess.claim(args["fact"], args.get("rationale", ""))
        if name == "retract":
            return sess.retract(args["claim_id"], args["reason"])
        if name == "blast":
            return sess.blast(args["claim_id"])
        if name == "why":
            return sess.why(args["function"], args["value"])
        if name == "list_holes":
            return sess.list_holes(args.get("function") or None)
        if name == "list_nogoods":
            return sess.list_nogoods()
        if name == "complete":
            return sess.complete(args["function"])
    except Exception as exc:  # tool errors go back to the model, never crash the run
        return f"error: {type(exc).__name__}: {exc}"
    return f"error: unknown tool {name}"


class ResponseCache:
    """SQLite cache: (sha256 of the request body, run_index) -> response dict."""

    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS r (h TEXT, run INTEGER, body TEXT, PRIMARY KEY (h, run))")

    @staticmethod
    def key(request: dict) -> str:
        return hashlib.sha256(json.dumps(request, sort_keys=True, default=str).encode()).hexdigest()

    def get(self, h: str, run: int) -> dict | None:
        row = self.db.execute("SELECT body FROM r WHERE h=? AND run=?", (h, run)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, h: str, run: int, body: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO r VALUES (?, ?, ?)", (h, run, json.dumps(body)))
        self.db.commit()


@dataclass
class Turn:
    turn: int
    served_by: str
    stop_reason: str
    input_tokens: int
    output_tokens: int
    cache_read: int
    cache_write: int
    tool_calls: list[str]
    holes_open: int
    cached: bool


@dataclass
class RunLog:
    binary: str
    run_index: int
    model: str
    effort: str
    checker: bool
    turns: list[Turn] = field(default_factory=list)
    final_text: str = ""
    stop: str = ""
    claims: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    seconds: float = 0.0


def holes_open(sess: Session) -> int:
    pr = sess.printer()
    return sum(len(pr.holes_section(f)) for f in sess.ks.prog.functions.values())


def run_agent(sess: Session, client, cache: ResponseCache, run_index: int = 0, max_turns: int = 40,
              model: str = MODEL, effort: str = EFFORT, fallbacks: bool = True) -> RunLog:
    log = RunLog(sess.path, run_index, model, effort, sess.checker)
    t0 = time.time()
    messages: list[dict] = [{"role": "user", "content": f"Recover the types in this binary. Start with list_functions.\n\n{sess.list_functions()}"}]
    for turn in range(max_turns):
        request = {"model": model, "max_tokens": 16000, "system": SYSTEM, "tools": TOOLS, "messages": messages,
                   "output_config": {"effort": effort}, "cache_control": {"type": "ephemeral"}}
        if fallbacks:
            request |= {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        h = cache.key(request)
        body = cache.get(h, run_index)
        cached = body is not None
        if body is None:
            resp = (client.beta.messages if fallbacks else client.messages).create(**request)
            body = resp.to_dict() if hasattr(resp, "to_dict") else dict(resp)
            cache.put(h, run_index, body)
        content = body["content"]
        usage = body.get("usage", {}) or {}
        messages.append({"role": "assistant", "content": content})  # append-only, unchanged
        calls = [b for b in content if b.get("type") == "tool_use"]
        stop = body.get("stop_reason", "")
        results = []
        for b in calls:
            out = run_tool(sess, b["name"], b.get("input") or {})
            results.append({"type": "tool_result", "tool_use_id": b["id"], "content": out,
                            **({"is_error": True} if out.startswith("error") else {})})
        log.turns.append(Turn(turn, body.get("model", model), stop, usage.get("input_tokens", 0),
                              usage.get("output_tokens", 0), usage.get("cache_read_input_tokens", 0) or 0,
                              usage.get("cache_creation_input_tokens", 0) or 0,
                              [f"{b['name']}({json.dumps(b.get('input'))[:80]})" for b in calls],
                              holes_open(sess), cached))
        if stop == "refusal" or stop == "max_tokens" and not calls:
            log.stop = stop
            break
        if not calls:
            log.stop = stop or "end_turn"
            log.final_text = " ".join(b.get("text", "") for b in content if b.get("type") == "text")
            break
        messages.append({"role": "user", "content": results})  # all results in one message
    else:
        log.stop = "max_turns"
    log.claims = [f"{c.id}{'(retracted)' if c.id in sess.ks.retracted else ''}: {c.text}" for c in sess.ks.claims.values()]
    log.metrics = asdict(sess.metrics)
    log.seconds = time.time() - t0
    return log


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="asmwebir-run")
    ap.add_argument("binary")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--effort", default=EFFORT)
    ap.add_argument("--no-checker", action="store_true", help="ablation: nogoods recorded but not reported")
    ap.add_argument("--no-fallbacks", action="store_true")
    ap.add_argument("--cache", default="results/response_cache.sqlite")
    ap.add_argument("--out", default="results/runs")
    a = ap.parse_args(argv)
    import anthropic

    client = anthropic.Anthropic()
    Path(a.out).mkdir(parents=True, exist_ok=True)
    Path(a.cache).parent.mkdir(parents=True, exist_ok=True)
    cache = ResponseCache(a.cache)
    for i in range(a.runs):
        sess = Session(a.binary, checker=not a.no_checker)
        log = run_agent(sess, client, cache, i, a.max_turns, a.model, a.effort, not a.no_fallbacks)
        name = Path(a.binary).parent.name or Path(a.binary).stem
        out = Path(a.out) / f"{name}.{'nochk' if a.no_checker else 'chk'}.run{i}.json"
        out.write_text(json.dumps(asdict(log), indent=2))
        tok = sum(t.input_tokens for t in log.turns), sum(t.output_tokens for t in log.turns)
        print(f"run {i}: {len(log.turns)} turns, stop={log.stop}, claims={len(log.claims)}, "
              f"holes {log.turns[0].holes_open if log.turns else '?'}->{log.turns[-1].holes_open if log.turns else '?'}, "
              f"tokens in/out {tok[0]}/{tok[1]} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
