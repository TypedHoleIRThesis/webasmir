#!/usr/bin/env python3
"""Sync implementation status into the Obsidian vault (kb/30 Rules/*.md).

impl_status:  spec-only   no code marks the rule
              prototyped  code carries @rule("ID")
              tested      ... and a passing test names the rule (test_<ID> or "Rules: ID" in its docstring)
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KB = ROOT.parents[1] / "kb" / "30 Rules"
sys.path.insert(0, str(ROOT / "src"))


def implemented() -> dict[str, list[str]]:
    import asmwebir
    from asmwebir.trace import RULES

    for m in pkgutil.walk_packages(asmwebir.__path__, "asmwebir."):
        if m.name.endswith(("mcp_server", "harness.loop")):
            continue
        importlib.import_module(m.name)
    return dict(RULES)


def tested(rule_ids: set[str]) -> dict[str, list[str]]:
    xml = ROOT / ".pytest-sync.xml"
    subprocess.run([sys.executable, "-m", "pytest", "-q", f"--junitxml={xml}"], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    passed = set()
    for case in ET.parse(xml).getroot().iter("testcase"):
        if not list(case):  # no failure/error/skipped child
            passed.add(case.get("name"))
    xml.unlink(missing_ok=True)
    out: dict[str, list[str]] = {}
    for f in (ROOT / "tests").rglob("test_*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.FunctionDef) and node.name in passed:
                doc = ast.get_docstring(node) or ""
                named = {r for r in rule_ids if node.name.startswith("test_" + r.replace("-", "_"))}
                m = re.search(r"Rules:\s*(.+)", doc)
                if m:
                    named |= {x.strip().rstrip(".") for x in m.group(1).split(",")} & rule_ids
                for r in named:
                    out.setdefault(r, []).append(f"{f.relative_to(ROOT)}::{node.name}")
    return out


def main() -> int:
    notes = {p.stem: p for p in KB.glob("*.md") if p.stem != "Rules MOC"}
    impl = implemented()
    tests = tested(set(notes))
    counts = {"spec-only": 0, "prototyped": 0, "tested": 0}
    for rid, path in sorted(notes.items()):
        status = "tested" if rid in impl and rid in tests else "prototyped" if rid in impl else "spec-only"
        counts[status] += 1
        text = path.read_text()
        text = re.sub(r"^impl_status: .*$", f"impl_status: {status}", text, count=1, flags=re.M)
        where = ", ".join(f"`{x}`" for x in impl.get(rid, [])) or "—"
        tlist = ", ".join(f"`{x}`" for x in tests.get(rid, [])) or "—"
        row = f"| Implementation | `{status}` — code: {where}; tests: {tlist} |"
        text = re.sub(r"^\| Implementation \|.*$", row.replace("\\", "\\\\"), text, count=1, flags=re.M)
        path.write_text(text)
    print(counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
