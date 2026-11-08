#!/usr/bin/env python3
"""Lift + saturate every stripped benchmark binary; report coverage and failures."""
from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

ART = Path(__file__).resolve().parents[2] / "llm-decompile-test/artifacts_result_only/x86_64-linux-gnu-11.4.0"


def main(levels=("O0", "O1", "O2", "O3")) -> int:
    from asmwebir.ir.syntax import Residual
    from asmwebir.store.store import KnowledgeStore
    from asmwebir.view.printer import ViewPrinter

    rows = []
    for lvl in levels:
        for d in sorted((ART / lvl).iterdir()):
            elf = d / "stripped.elf"
            t = time.time()
            try:
                ks = KnowledgeStore.from_binary(str(elf))
                S = ks.snapshot()
                pr = ViewPrinter(ks.prog, S, ks.premises)
                for f in ks.prog.functions.values():
                    pr.function(f)
                fns = len(ks.prog.functions)
                resid = sum(1 for f in ks.prog.functions.values() if any(isinstance(s, Residual) for s in f.stmts))
                rows.append((lvl, d.name, "ok", fns, resid, len(ks.premise_clashes), time.time() - t, ""))
            except Exception as e:  # noqa: BLE001
                rows.append((lvl, d.name, "FAIL", 0, 0, 0, time.time() - t, f"{type(e).__name__}: {e}".splitlines()[0][:120]))
                traceback.print_exc(file=open(f"/tmp/sweep_{lvl}_{d.name}.txt", "w"))
            r = rows[-1]
            print(f"{r[0]} {r[1]:<24} {r[2]:<4} fns={r[3]:<3} residual_fns={r[4]:<2} premise_clashes={r[5]:<3} {r[6]:5.1f}s {r[7]}", flush=True)
    ok = sum(r[2] == "ok" for r in rows)
    print(f"\n{ok}/{len(rows)} binaries processed")
    return 0


if __name__ == "__main__":
    sys.exit(main(tuple(sys.argv[1:]) or ("O0", "O1", "O2", "O3")))
