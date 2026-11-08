"""asmwebir command line.

    asmwebir view <elf> [function...]              the view: holes, webs, kinds (after unification)
    asmwebir ir   <elf> [function...] [--premises] the lifted IR (and its premises), before unification
"""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="asmwebir")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("view", help="print the current view of functions")
    v.add_argument("binary")
    v.add_argument("functions", nargs="*", help="sub_xxxx names or hex addresses (default: all)")
    r = sub.add_parser("ir", help="print the lifted IR before type unification")
    r.add_argument("binary")
    r.add_argument("functions", nargs="*", help="sub_xxxx names or hex addresses (default: all)")
    r.add_argument("--premises", action="store_true", help="also list each function's premises")
    a = ap.parse_args(argv)

    if a.cmd == "ir":
        return _ir(a)

    from .store.store import KnowledgeStore
    from .view.printer import ViewPrinter

    ks = KnowledgeStore.from_binary(a.binary)
    pr = ViewPrinter(ks.prog, ks.snapshot(), ks.premises)
    for f in _select(ks.prog, a.functions):
        print(pr.function(f))
        print()
    return 0


def _ir(a) -> int:
    from .lift.angr_frontend import lift_binary
    from .view.raw import RawPrinter, premise

    prog = lift_binary(a.binary)
    P = None
    if a.premises:
        from .lift.premises import extract_premises

        P = extract_premises(prog)
    pr = RawPrinter(prog)
    for f in _select(prog, a.functions):
        print(pr.function(f))
        if P is not None:
            print(f"premises ({f.name}):")
            for p in P.items:
                if p.fn == f.name:
                    print("  " + premise(p, f.name))
            if f.name in P.failed:
                print(f"  premise extraction failed: {P.failed[f.name]}")
        print()
    if prog.call_tables:
        for base, names in sorted(prog.call_tables.items()):
            print(f"call table @{base:x}: {', '.join(names)}")
    return 0


def _select(prog, wanted: list[str]):
    fns = sorted(prog.functions.values(), key=lambda f: f.addr)
    if wanted:
        want = {x if x.startswith("sub_") else f"sub_{int(x, 16):x}" for x in wanted}
        fns = [f for f in fns if f.name in want]
    return fns


if __name__ == "__main__":
    sys.exit(main())
