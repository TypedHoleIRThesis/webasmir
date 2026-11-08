"""Traceability between code and the formal rules of AsmWebIR Part C.

`@rule("S-Clash")` marks a function as an implementation of a rule. The
registry is read by tools/sync_kb.py to update `impl_status` in the vault
notes under kb/30 Rules/.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable)

RULES: dict[str, list[str]] = defaultdict(list)


def rule(*ids: str) -> Callable[[F], F]:
    def mark(fn: F) -> F:
        for rid in ids:
            RULES[rid].append(f"{fn.__module__}.{fn.__qualname__}")
        fn.__asmwebir_rules__ = ids  # type: ignore[attr-defined]
        return fn

    return mark
