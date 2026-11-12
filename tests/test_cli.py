"""`asmwebir ir`: the lifted IR and its premises, before type unification."""
from __future__ import annotations

from .conftest import FIX, symbols


def test_ir_command(capsys):
    from asmwebir.cli import main

    ls = symbols(FIX / "running_example.O1.elf")["list_sum"]
    assert main(["ir", str(FIX / "running_example.O1.stripped"), ls, "--premises"]) == 0
    out = capsys.readouterr().out
    body = out[out.index(f"fn {ls}("):]
    # raw terms: sizes and explicit conversions, no holes or webs
    assert "load[4](v6 +64 8)" in body and "zext32->64(" in body
    assert "?T" not in body and "#d" not in body
    # premises are listed per function, with rule and witness address
    assert f"premises ({ls}):" in body
    assert "K-Ptr" in body and "S-Access" in body and "has 4B at +8 (read)" in body
