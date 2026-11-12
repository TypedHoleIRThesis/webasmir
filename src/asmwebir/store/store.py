"""The knowledge store 𝔎: premises from the binary, claims from agents.

Forward-only (conjecture *Forwardness*): claims, retractions and nogoods are
appended, never removed. Beliefs ℰ are the claims not retracted. A fact is
active when it is derivable from premises plus some L ⊆ ℰ.

Labels are computed by re-saturation: the premise e-graph is built once; a
belief set is evaluated by pushing its claims, saturating, freezing a
snapshot, and popping. A contradiction's minimal label is found with
QuickXplain over the active claims (D - Labels via re-saturation and QuickXplain).
"""
from __future__ import annotations

import sys

from dataclasses import dataclass, field

from egglog import union

from ..claims.dsl import ArityEq, Fact, Name, Resolver, StructDecl, TypeEq, parse_claim, render_fact
from ..ir.syntax import Program
from ..lift.angr_frontend import lift_binary
from ..lift.premises import Premises, extract_premises
from ..trace import rule
from .canon import Snapshot, load_premises, saturate
from .checks import Clash, all_checks, name_targets
from .egraph import Encoder, Ty, at, new_egraph
from .log import Log


@dataclass
class Claim:
    id: str
    fact: Fact
    text: str
    agent: str
    rationale: str


@dataclass(frozen=True)
class Nogood:
    id: str
    label: frozenset[str]
    rule: str
    message: str
    witness: tuple[int, ...]
    ident: tuple


@dataclass(frozen=True)
class NameConflict:
    target: str
    names: tuple[tuple[str, str], ...]  # (claim id, name)


@dataclass
class ClaimResult:
    claim: Claim
    nogoods: list[Nogood] = field(default_factory=list)  # new contradictions involving the claim
    known: list[Nogood] = field(default_factory=list)  # answered from the record (same facts as an old nogood)
    conflicts: list[NameConflict] = field(default_factory=list)


class KnowledgeStore:
    def __init__(self, prog: Program, premises: Premises, log_path: str | None = None):
        self.prog = prog
        self.premises = premises
        self.eg = new_egraph()
        self.enc = Encoder(self.eg)
        load_premises(self.eg, self.enc, premises)
        from . import debug  # debug dump of the e-graph: ASMWEBIR_DEBUG_EGRAPH=1

        if debug.enabled():
            debug.dump_egraph(self.eg, self.enc, premises, "after loading premises, before saturation")
        saturate(self.eg)
        if debug.enabled():
            debug.dump_egraph(self.eg, self.enc, premises, "after saturation")
        self.claims: dict[str, Claim] = {}
        self.retracted: dict[str, str] = {}
        self.nogoods: list[Nogood] = []
        self.log = Log(log_path)
        self._snaps: dict[frozenset[str], Snapshot] = {}
        self._clashes: dict[frozenset[str], list[Clash]] = {}
        self.premise_clashes = {c.ident for c in self.clashes(frozenset())}

    @classmethod
    def from_binary(cls, path: str, log_path: str | None = None) -> "KnowledgeStore":
        prog = lift_binary(path)
        print(f"lifted {len(prog.functions)} functions from {path}", file=sys.stderr)
        for f in prog.functions.values():
            print(f"  {f.name} @ {hex(f.addr)}: {len(f.blocks)} blocks, {sum(len(b.stmts) for b in f.blocks)} statements", file=sys.stderr)
        print('-' * 40, file=sys.stderr)
        for external in sorted(prog.externals.items()):
            print(f"  external {external[1]} @ {hex(external[0])}", file=sys.stderr)
        print('-' * 40, file=sys.stderr)
        for table, names in sorted(prog.call_tables.items()):
            print(f"  call table @ {hex(table)}: {', '.join(names)}", file=sys.stderr)
        print(f"found {len(prog.externals)} externals and {len(prog.call_tables)} call tables", file=sys.stderr)
        return cls(prog, extract_premises(prog), log_path)

    # -- beliefs
    def beliefs(self) -> frozenset[str]:
        return frozenset(a for a in self.claims if a not in self.retracted)

    def facts(self, ids) -> list[Fact]:
        return [self.claims[a].fact for a in sorted(ids, key=_num)]

    # -- evaluation of a belief set
    def snapshot(self, beliefs: frozenset[str] | None = None) -> Snapshot:
        b = self.beliefs() if beliefs is None else frozenset(beliefs)
        snap = self._snaps.get(b)
        if snap is None:
            snap = self._evaluate(b)
            self._snaps[b] = snap
        return snap

    @rule("E-Claim", "S-Field", "S-Unify")
    def _evaluate(self, b: frozenset[str]) -> Snapshot:
        facts = self.facts(b)
        structs = {f.name: f for f in facts if isinstance(f, StructDecl)}
        extra: list[tuple] = []
        self.eg.push()
        try:
            for f in facts:
                if isinstance(f, TypeEq):
                    self.eg.register(union(self.enc.ty(f.a)).with_(self.enc.ty(f.b)))
                    extra += [f.a, f.b]
                elif isinstance(f, StructDecl):
                    self.eg.register(Ty.named(f.name))
                    for o, _, t in f.fields:
                        self.eg.register(union(at(Ty.named(f.name), o)).with_(self.enc.ty(t)))
                        extra += [("at", ("named", f.name), o), t]
                    extra.append(("named", f.name))
                elif isinstance(f, Name) and f.target[0] == "type":
                    extra.append(f.target[1])
            saturate(self.eg)
            snap = Snapshot(self.eg, self.enc, self.premises, extra, structs)
            snap.freeze(self.prog.functions.values())
        finally:
            self.eg.pop()
        return snap

    def clashes(self, b: frozenset[str]) -> list[Clash]:
        c = self._clashes.get(b)
        if c is None:
            c = all_checks(self.snapshot(b), self.facts(b), self.premises)
            self._clashes[b] = c
        return c

    # -- edits
    @rule("E-Claim", "S-Nogood")
    def claim(self, text: str, agent: str = "agent", rationale: str = "", resolver: Resolver | None = None) -> ClaimResult:
        structs = {f.name for f in self.facts(self.beliefs()) if isinstance(f, StructDecl)}
        fact = parse_claim(text, resolver, structs)
        cid = f"a{len(self.claims) + 1}"
        c = Claim(cid, fact, text, agent, rationale)
        self.claims[cid] = c
        self.log.append("claim", {"id": cid, "text": text, "fact": render_fact(fact), "agent": agent, "rationale": rationale})
        res = ClaimResult(c)
        res.known = self._known_nogoods(c)
        b = self.beliefs()
        for clash in self.clashes(b):
            if clash.ident in self.premise_clashes:
                continue
            if any(n.ident == clash.ident and n.label <= b for n in self.nogoods):
                continue  # already recorded and still active
            label = self.minimal_label(clash.ident, b)
            if cid not in label:
                continue
            ng = Nogood(f"n{len(self.nogoods) + 1}", label, clash.rule, clash.message, clash.witness, clash.ident)
            self.nogoods.append(ng)
            self.log.append("nogood", {"id": ng.id, "label": sorted(label, key=_num), "rule": ng.rule,
                                       "message": ng.message, "witness": [hex(w) for w in ng.witness]})
            res.nogoods.append(ng)
        res.conflicts = [x for x in self.name_conflicts(b) if any(cid == a for a, _ in x.names)]
        for x in res.conflicts:
            self.log.append("conflict", {"target": x.target, "names": x.names})
        return res

    @rule("E-Retract")
    def retract(self, cid: str, reason: str, agent: str = "agent") -> None:
        if cid not in self.claims:
            raise KeyError(cid)
        if cid in self.retracted:
            return
        self.retracted[cid] = reason
        self.log.append("retract", {"id": cid, "reason": reason, "agent": agent})

    # -- labels
    def minimal_label(self, ident: tuple, b: frozenset[str]) -> frozenset[str]:
        """QuickXplain (Junker 2004): a minimal subset of b under which `ident` still clashes."""
        def holds(s) -> bool:
            return any(c.ident == ident for c in self.clashes(frozenset(s)))

        items = sorted(b, key=_num)
        if holds(()):
            return frozenset()

        def qx(base: list[str], delta: bool, cand: list[str]) -> list[str]:
            if delta and holds(base):
                return []
            if len(cand) == 1:
                return cand
            mid = len(cand) // 2
            c1, c2 = cand[:mid], cand[mid:]
            d2 = qx(base + c1, bool(c1), c2)
            d1 = qx(base + d2, bool(d2), c1)
            return d1 + d2

        return frozenset(qx([], False, items))

    def active_nogoods(self) -> list[Nogood]:
        b = self.beliefs()
        return [n for n in self.nogoods if n.label <= b]

    def _known_nogoods(self, c: Claim) -> list[Nogood]:
        """A recorded nogood whose claims all have the same facts as current beliefs
        plus this claim is answered from the record, before saturation."""
        current = {render_fact(self.claims[a].fact) for a in self.beliefs()}
        mine = render_fact(c.fact)
        out = []
        for n in self.nogoods:
            facts = {render_fact(self.claims[a].fact) for a in n.label}
            if mine in facts and facts <= current and not n.label <= self.beliefs():
                out.append(n)
        return out

    @rule("S-Name-Conflict")
    def name_conflicts(self, b: frozenset[str] | None = None) -> list[NameConflict]:
        b = self.beliefs() if b is None else b
        S = self.snapshot(b)
        by: dict[str, list[tuple[str, str]]] = {}
        for a in sorted(b, key=_num):
            f = self.claims[a].fact
            if isinstance(f, Name):
                by.setdefault(name_targets(S, f, self.premises), []).append((a, f.name))
        return [NameConflict(t, tuple(v)) for t, v in by.items() if len({n for _, n in v}) > 1]

    def resolver(self, namer) -> Resolver:
        return Resolver(namer, self.snapshot(), self.premises, self.prog)


def _num(cid: str) -> int:
    return int(cid[1:])
