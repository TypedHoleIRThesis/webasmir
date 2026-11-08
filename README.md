# AsmWebIR

LLM decompilation by forward edits: a lifter turns an ELF x86-64 (SysV) binary into a typed, hole-bearing IR plus certain *premises*; LLM agents add labelled *claims* to an append-only knowledge store; contradictions become *nogoods* with instruction witnesses; *webs* make one claim apply everywhere it must agree.

Design and formal rules: `asmwebir-full.pdf` and the Obsidian vault `../../kb/` (start at `kb/Home.md`).

```sh
uv pip install --python .venv/bin/python -e '.[dev]'
./tools/build_fixtures.sh          # pinned GCC in Docker
.venv/bin/pytest
```
