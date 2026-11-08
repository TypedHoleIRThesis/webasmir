from __future__ import annotations

from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

FIX = Path(__file__).parent / "fixtures"


def symbols(path: Path) -> dict[str, str]:
    """Source name -> stable AsmWebIR name (sub_xxx), read from the unstripped twin."""
    with open(path, "rb") as fp:
        elf = ELFFile(fp)
        tab = elf.get_section_by_name(".symtab")
        return {s.name: f"sub_{s['st_value']:x}" for s in tab.iter_symbols()
                if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]}


@pytest.fixture(scope="session")
def o1():
    """Knowledge store of the stripped O1 running example (premises only)."""
    from asmwebir.store.store import KnowledgeStore

    ks = KnowledgeStore.from_binary(str(FIX / "running_example.O1.stripped"))
    ks.names = symbols(FIX / "running_example.O1.elf")
    return ks


@pytest.fixture(scope="session")
def o1_view(o1):
    from asmwebir.view.printer import ViewPrinter

    return ViewPrinter(o1.prog, o1.snapshot(), o1.premises)


@pytest.fixture(scope="session")
def o1_lifted():
    from asmwebir.lift.angr_frontend import lift_binary
    from asmwebir.lift.premises import extract_premises

    prog = lift_binary(str(FIX / "running_example.O1.stripped"))
    return prog, extract_premises(prog)


@pytest.fixture
def store(o1_lifted):
    """A fresh knowledge store (no claims) over the O1 running example."""
    from asmwebir.store.store import KnowledgeStore
    from asmwebir.view.printer import Namer

    prog, P = o1_lifted
    ks = KnowledgeStore(prog, P)
    ks.names = symbols(FIX / "running_example.O1.elf")
    ks.namer = Namer(prog, ks.snapshot(frozenset()), P)
    ks.R = ks.resolver(ks.namer)
    return ks
