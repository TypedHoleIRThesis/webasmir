"""asmwebir-eval: graded type-reconstruction scores against DWARF (RQ4/RQ5).

    asmwebir-eval --opt O0,O1,O2,O3            # engine alone (premises, no LLM)
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

DEFAULT_SUITE = Path(__file__).resolve().parents[3] / ".." / "llm-decompile-test/artifacts_result_only/x86_64-linux-gnu-11.4.0"


def run(suite: Path, levels: list[str], out_dir: Path, programs: list[str] | None = None) -> Path:
    from ..store.store import KnowledgeStore
    from .dwarf_ref import load_reference
    from .score import score_program

    rows = []
    for lvl in levels:
        for d in sorted((suite / lvl).iterdir()):
            if programs and not any(d.name.startswith(p) for p in programs):
                continue
            t0 = time.time()
            ks = KnowledgeStore.from_binary(str(d / "stripped.elf"))
            ref = load_reference(str(d / "oracle.elf"))
            for fs in score_program(ks.prog, ks.snapshot(), ref):
                for p in fs.params:
                    rows.append({
                        "opt": lvl, "program": d.name, "function": fs.name, "index": p.index,
                        "ref": _rt(p.ref), "kind": p.kind, "ptr_level": p.ptr_level or "",
                        "layout_recall": "" if p.layout_recall is None else f"{p.layout_recall:.3f}",
                        "layout_precision": "" if p.layout_precision is None else f"{p.layout_precision:.3f}",
                        "exact": int(p.exact), "arity_ref": fs.arity_ref, "arity_ours": fs.arity_ours,
                    })
            print(f"{lvl} {d.name:<24} {time.time() - t0:5.1f}s", file=sys.stderr, flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    tsv = out_dir / f"engine_alone_{stamp}.tsv"
    with open(tsv, "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(rows[0]), delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    md = out_dir / f"engine_alone_{stamp}.md"
    md.write_text(summary(rows, levels))
    return md


def summary(rows: list[dict], levels: list[str]) -> str:
    by = defaultdict(list)
    for r in rows:
        by[r["opt"]].append(r)
    lines = [
        "# Engine alone vs DWARF reference types",
        "",
        "Premises only (no LLM claims). Values = parameters and return values of functions",
        "that survive in the binary. *unknown* = an honest hole (no evidence), not an error.",
        "",
        "| Opt | Values | Kind correct | Kind unknown | Kind wrong | Ptr level (ptr refs) | Layout recall | Layout precision | Exact | Arity exact |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for lvl in levels + ["ALL"]:
        rs = rows if lvl == "ALL" else by.get(lvl, [])
        if not rs:
            continue
        n = len(rs)
        pct = lambda k, v: 100 * sum(r[k] == v for r in rs) / n  # noqa: E731
        ptr = [r for r in rs if r["ptr_level"]]
        rec = [float(r["layout_recall"]) for r in rs if r["layout_recall"]]
        prec = [float(r["layout_precision"]) for r in rs if r["layout_precision"]]
        fns = {(r["opt"], r["program"], r["function"]): r for r in rs}
        ar = sum(r["arity_ref"] == r["arity_ours"] for r in fns.values()) / max(1, len(fns))
        lines.append(
            f"| {lvl} | {n} | {pct('kind', 'correct'):.1f}% | {pct('kind', 'unknown'):.1f}% | {pct('kind', 'wrong'):.1f}% | "
            f"{100 * sum(r['ptr_level'] == 'correct' for r in ptr) / max(1, len(ptr)):.1f}% (n={len(ptr)}) | "
            f"{statistics.mean(rec) if rec else 0:.2f} (n={len(rec)}) | {statistics.mean(prec) if prec else 0:.2f} | "
            f"{100 * sum(int(r['exact']) for r in rs) / n:.1f}% | {100 * ar:.1f}% (n={len(fns)}) |")
    lines += ["", "Kind wrong, by reference type (ALL):", ""]
    wrong = defaultdict(int)
    for r in rows:
        if r["kind"] == "wrong":
            wrong[r["ref"]] += 1
    for k, v in sorted(wrong.items(), key=lambda kv: -kv[1])[:12]:
        lines.append(f"- `{k}`: {v}")
    return "\n".join(lines) + "\n"


def _rt(t: tuple) -> str:
    tag = t[0]
    if tag == "int":
        return f"{'i' if t[2] == 's' else 'u'}{t[1]}"
    if tag == "ptr":
        return "ptr " + _rt(t[1])
    if tag in ("struct", "union"):
        return f"{tag} {t[1]}"
    if tag == "arr":
        return f"{_rt(t[1])}[{t[2]}]"
    if tag == "flt":
        return f"f{t[1]}"
    return tag


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="asmwebir-eval")
    ap.add_argument("--suite", default=str(DEFAULT_SUITE))
    ap.add_argument("--opt", default="O0,O1,O2")
    ap.add_argument("--programs", default="")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[3] / "results"))
    a = ap.parse_args(argv)
    md = run(Path(a.suite).resolve(), a.opt.split(","), Path(a.out), [p for p in a.programs.split(",") if p])
    print(md.read_text())
    print(f"written {md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
