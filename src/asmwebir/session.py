"""One agent-facing session over one binary: the section 16 tool interface.

Every method returns plain text meant for an LLM. The MCP server and the
experiment harness are thin wrappers around this class.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .claims.dsl import ClaimSyntaxError, Resolver
from .store.store import ClaimResult, KnowledgeStore, Nogood
from .trace import rule
from .view.printer import Namer, ViewPrinter


@dataclass
class Metrics:
    tool_calls: dict[str, int] = field(default_factory=dict)
    claims: int = 0
    nogoods: int = 0
    retractions: int = 0
    syntax_errors: int = 0

    def hit(self, tool: str) -> None:
        self.tool_calls[tool] = self.tool_calls.get(tool, 0) + 1


class Session:
    def __init__(self, path: str, log_path: str | None = None, checker: bool = True):
        self.path = path
        self.ks = KnowledgeStore.from_binary(path, log_path)
        self.base_namer = Namer(self.ks.prog, self.ks.snapshot(frozenset()), self.ks.premises)
        self.checker = checker  # ablation: with checker=False nogoods are recorded but not reported
        self.metrics = Metrics()
        self._disasm: dict[int, str] | None = None

    # -- helpers
    def printer(self) -> ViewPrinter:
        return ViewPrinter.for_store(self.ks, self.base_namer)

    def resolver(self) -> Resolver:
        pr = self.printer()
        R = Resolver(self.base_namer, self.ks.snapshot(frozenset()), self.ks.premises, self.ks.prog)
        cur = Resolver(pr.n, self.ks.snapshot(), self.ks.premises, self.ks.prog)
        for k, v in cur.hole_rep.items():
            R.hole_rep.setdefault(k, v)
        return R

    def fn(self, ref: str):
        prog = self.ks.prog
        if ref in prog.functions:
            return prog.functions[ref]
        pr = self.printer()
        for f in prog.functions.values():
            if pr.fn_name(f.name) == ref or pr.n.code(f.name) == ref or pr.n.code(f.name) == f"#{ref}":
                return f
        try:
            addr = int(ref, 16)
            return prog.by_addr(addr)
        except ValueError:
            pass
        raise KeyError(f"no function {ref!r}; call list_functions")

    def asm(self, addr: int) -> str:
        if self._disasm is None:
            self._disasm = _disassemble(self.path)
        return self._disasm.get(addr, "?")

    def witness(self, ng: Nogood) -> str:
        return "; ".join(f"{w:x}: {self.asm(w)}" for w in ng.witness[:4])

    # -- tools
    def list_functions(self) -> str:
        self.metrics.hit("list_functions")
        pr = self.printer()
        lines = []
        for f in sorted(self.ks.prog.functions.values(), key=lambda f: f.addr):
            holes = len(pr.holes_section(f))
            lines.append(f"{pr.n.code(f.name):<5} {pr.fn_name(f.name):<20} @{f.addr:x}  {len(f.params)} params  {holes} open holes")
        return "\n".join(lines)

    @rule("V-Extract", "V-Mark")
    def view(self, ref: str) -> str:
        self.metrics.hit("view")
        f = self.fn(ref)
        text = self.printer().function(f)
        marks = [n for n in self.ks.active_nogoods() if any(f.addr <= w < f.addr + f.size for w in n.witness)]
        if marks and self.checker:
            out = []
            for line in text.splitlines():
                tag = [n.id for n in marks if any(line.rstrip().endswith(f"@{w:x}") for w in n.witness)]
                out.append(line + (f"   ⚠ {','.join(tag)}" if tag else ""))
            text = "\n".join(out) + "\nmarks: " + "\n       ".join(
                f"{n.id} {{{', '.join(sorted(n.label))}}}: {n.message} — witness {self.witness(n)}" for n in marks)
        return text

    def claim(self, text: str, rationale: str = "", agent: str = "agent") -> str:
        self.metrics.hit("claim")
        before = self._views()
        try:
            r: ClaimResult = self.ks.claim(text, agent, rationale, self.resolver())
        except (ClaimSyntaxError, KeyError) as exc:
            self.metrics.syntax_errors += 1
            return f"error: {exc}"
        self.metrics.claims += 1
        self.metrics.nogoods += len(r.nogoods)
        lines = [f"{r.claim.id} recorded: {text}"]
        if self.checker:
            for n in r.known:
                lines.append(f"known nogood {n.id} (from the record): {n.message} — witness {self.witness(n)}")
            for n in r.nogoods:
                lines.append(f"NOGOOD {n.id} {{{', '.join(sorted(n.label))}}} [{n.rule}]: {n.message} — witness {self.witness(n)}")
                lines.append("  retract one of the claims in the label (retract(id, reason)) or explain why the binary is misread")
        for c in r.conflicts:
            lines.append(f"name conflict on {c.target}: " + ", ".join(f"{a}={n!r}" for a, n in c.names) + " (sent to review; not a contradiction)")
        changed = self._changed(before)
        lines.append("views changed: " + (", ".join(changed) if changed else "none"))
        return "\n".join(lines)

    @rule("E-Retract")
    def retract(self, cid: str, reason: str) -> str:
        self.metrics.hit("retract")
        before = self._views()
        try:
            self.ks.retract(cid, reason)
        except KeyError:
            return f"error: no claim {cid}"
        self.metrics.retractions += 1
        changed = self._changed(before)
        return f"{cid} retracted ({reason}). views changed: " + (", ".join(changed) if changed else "none")

    def blast(self, cid: str) -> str:
        """Dry run: which functions' views depend on a claim (blast radius)."""
        self.metrics.hit("blast")
        if cid not in self.ks.claims:
            return f"error: no claim {cid}"
        b = self.ks.beliefs()
        if cid not in b:
            return f"{cid} is already retracted"
        now = self._views(b)
        without = self._views(b - {cid})
        pr = self.printer()
        hit = [pr.fn_name(k) for k in now if now[k] != without.get(k)]
        return f"retracting {cid} would change: " + (", ".join(hit) if hit else "nothing")

    @rule("S-Access", "S-ABI")
    def why(self, ref: str, var: str) -> str:
        """Premises (with instructions) and claims behind a value's displayed type."""
        self.metrics.hit("why")
        f = self.fn(ref)
        term = f"{f.name}.{var}" if not var.startswith(f.name) else var
        P, S = self.ks.premises, self.ks.snapshot()
        if term not in P.value_webs and not any(p.id == term for p in f.params):
            return f"error: no value {var} in {f.name}"
        k = S.key(("tv", term))
        lines = [f"{var}: {self.printer().ty(('tv', term))}  kind {S.kind_of(k)}"]
        from .lift.premises import Kind

        for p in P.items:
            if isinstance(p, Kind) and S.key(p.t) == k:
                lines.append(f"  premise {p.rule} @{p.at:x} {self.asm(p.at) if p.at else ''}: {p.why}")
            if len(lines) > 12:
                lines.append("  …")
                break
        label = self._label_of(("tv", term))
        lines.append("  claims: " + (", ".join(f"{a} ({self.ks.claims[a].text})" for a in sorted(label)) if label else "none (certain)"))
        return "\n".join(lines)

    def list_holes(self, ref: str | None = None) -> str:
        self.metrics.hit("list_holes")
        pr = self.printer()
        fns = [self.fn(ref)] if ref else sorted(self.ks.prog.functions.values(), key=lambda f: f.addr)
        out = []
        for f in fns:
            hs = pr.holes_section(f)
            if hs:
                out.append(f"{pr.fn_name(f.name)}: " + "; ".join(hs))
        return "\n".join(out) or "no open holes"

    def list_nogoods(self, active_only: bool = True) -> str:
        self.metrics.hit("list_nogoods")
        ns = self.ks.active_nogoods() if active_only else self.ks.nogoods
        return "\n".join(f"{n.id} {{{', '.join(sorted(n.label))}}} [{n.rule}] {n.message} — witness {self.witness(n)}"
                         for n in ns) or "none"

    def list_claims(self) -> str:
        self.metrics.hit("list_claims")
        return "\n".join(f"{c.id}{' (retracted)' if c.id in self.ks.retracted else ''}: {c.text}" for c in self.ks.claims.values()) or "none"

    @rule("M-Complete")
    def complete(self, ref: str) -> str:
        self.metrics.hit("complete")
        f = self.fn(ref)
        marks = [n for n in self.ks.active_nogoods() if any(f.addr <= w < f.addr + f.size for w in n.witness)]
        holes = self.printer().holes_section(f)
        problems = []
        if marks:
            problems.append(f"{len(marks)} active contradiction(s): " + ", ".join(n.id for n in marks))
        if holes:
            problems.append(f"{len(holes)} open hole(s): " + "; ".join(h.split(" ::")[0] for h in holes))
        return "complete" if not problems else "not complete: " + " | ".join(problems)

    # -- internals
    def _views(self, beliefs=None) -> dict[str, str]:
        if beliefs is not None:
            pr = ViewPrinter.for_store(_AtBeliefs(self.ks, beliefs), self.base_namer)
        else:
            pr = self.printer()
        return {f.name: pr.function(f) for f in self.ks.prog.functions.values()}

    def _changed(self, before: dict[str, str]) -> list[str]:
        after = self._views()
        pr = self.printer()
        return [pr.fn_name(k) for k, v in after.items() if v != before.get(k)]

    def _label_of(self, t: tuple) -> frozenset[str]:
        """Minimal claims under which t still displays as it does now (deletion minimisation)."""
        b = self.ks.beliefs()
        target = self._shape(self.ks.snapshot(b), t)
        if self._shape(self.ks.snapshot(frozenset()), t) == target:
            return frozenset()
        keep = set(b)
        for a in sorted(b, key=lambda c: int(c[1:])):
            trial = frozenset(keep - {a})
            if self._shape(self.ks.snapshot(trial), t) == target:
                keep.discard(a)
        return frozenset(keep)

    @staticmethod
    def _shape(S, t, depth=0) -> str:
        n = S.node(t)
        return _shape_node(n)


def _shape_node(n, depth=0) -> str:
    if n is None or depth > 3:
        return "…"
    if n.tag == "ptr":
        return f"ptr({_shape_node(n.to, depth + 1)})"
    if n.tag == "hole":
        return "?"
    if n.tag == "int":
        return f"{n.sign}{n.bits}"
    if n.tag == "named":
        return n.name
    return n.tag


class _AtBeliefs:
    """A read-only view of a store at another belief set (for blast radius)."""

    def __init__(self, ks: KnowledgeStore, beliefs):
        self._ks, self._b = ks, frozenset(beliefs)
        self.prog, self.premises, self.claims = ks.prog, ks.premises, ks.claims

    def snapshot(self, beliefs=None):
        return self._ks.snapshot(self._b if beliefs is None else beliefs)

    def beliefs(self):
        return self._b


def _disassemble(path: str) -> dict[int, str]:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from elftools.elf.elffile import ELFFile

    out: dict[int, str] = {}
    with open(path, "rb") as fp:
        elf = ELFFile(fp)
        text = elf.get_section_by_name(".text")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = 1  # intel
        for ins in md.disasm(text.data(), text["sh_addr"]):
            out[ins.address] = f"{ins.mnemonic} {ins.op_str}".strip()
    return out
