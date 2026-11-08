from __future__ import annotations

import re

from asmwebir.view.printer import ViewPrinter


def view(ks, src_name: str) -> str:
    pr = ViewPrinter.for_store(ks, ks.namer)
    return pr.function(ks.prog.functions[ks.names[src_name]])


def hole_of_param(ks, src_name: str, i: int = 0) -> str:
    """The ?T shown as the pointee of a function's i-th parameter in the premise-only view."""
    pr = ViewPrinter(ks.prog, ks.snapshot(frozenset()), ks.premises, ks.namer)
    header = pr.function(ks.prog.functions[ks.names[src_name]]).splitlines()[0]
    return re.findall(r"ptr#d\d+ (\?T\d+)", header)[i]


def code_of(ks, src_name: str) -> str:
    return ks.namer.code(ks.names[src_name])
