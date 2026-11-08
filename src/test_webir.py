from collections import defaultdict
import argparse
import os

from asmwebir.session import Session
from asmwebir.view.raw import RawPrinter, premise

DEFAULT_BINARY = "/Users/albuscorleone/Documents/BKISC/Thesis/experiments/webasmir/hand_example/tiny.O0.stripped"


def print_premises(store) -> None:
    """The lifted IR and each function's premises, before the store unified them."""
    raw = RawPrinter(store.prog)
    print("\n=== Lifted IR and premises (before unification) ===")
    for function in sorted(store.prog.functions.values(), key=lambda f: f.addr):
        print(raw.function(function))
        print(f"premises ({function.name}):")
        for p in store.premises.items:
            if p.fn == function.name:
                print("  " + premise(p, function.name))
        if function.name in store.premises.failed:
            print(f"  premise extraction failed: {store.premises.failed[function.name]}")
        print()


def main(binary_path: str, show_premises: bool = False) -> None:
    session = Session(binary_path)
    store = session.ks
    snapshot = store.snapshot()
    printer = session.printer()

    if show_premises:
        print_premises(store)

    print("\n=== Functions ===")
    print(session.list_functions())

    code_webs = defaultdict(list)
    for function in store.prog.functions.values():
        canonical = snapshot.code(function.name)
        code_webs[canonical].append(function.name)

    print("\n=== Code webs ===")
    for canonical, members in sorted(code_webs.items()):
        print(f"{printer.n.code(members[0])}:")
        for member in sorted(members):
            print(f"  {member}")

    data_webs = defaultdict(list)
    for term in store.premises.pointers:
        canonical = snapshot.web(term)
        data_webs[canonical].append(term)

    print("\n=== Data webs ===")
    for canonical, members in sorted(data_webs.items()):
        print(f"{printer.n.web(canonical)}:")
        for member in sorted(members):
            print(f"  {member}")

    value_webs = defaultdict(list)
    for term, representative in store.premises.value_webs.items():
        value_webs[representative].append(term)

    print("\n=== Value webs ===")
    for representative, members in sorted(value_webs.items()):
        print(f"{printer.n.value(representative)}:")
        for member in sorted(members):
            print(f"  {member}")

    print("\n=== Lifted views with inferred webs and holes ===")
    for function in sorted(store.prog.functions.values(), key=lambda f: f.addr):
        print(session.view(function.name))
        print()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Webs and views of a stripped binary")
    ap.add_argument("binary", nargs="?", default=DEFAULT_BINARY)
    ap.add_argument("--premises", action="store_true", help="also print the lifted IR and premises before unification")
    ap.add_argument("--egraph", action="store_true", help="print the e-graph before and after saturation")
    a = ap.parse_args()
    if a.egraph:
        os.environ["ASMWEBIR_DEBUG_EGRAPH"] = "1"  # read by asmwebir.store.debug
    main(a.binary, a.premises)
