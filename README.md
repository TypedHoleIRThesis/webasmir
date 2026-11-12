# AsmWebIR

LLM decompilation by forward edits: a lifter turns an ELF x86-64 (SysV) binary into a typed, hole-bearing IR plus certain *premises*; LLM agents add labelled *claims* to an append-only knowledge store; contradictions become *nogoods* with instruction witnesses; *webs* make one claim apply everywhere it must agree.

Design and formal rules: `asmwebir-full.pdf` and the Obsidian vault `../../kb/` (start at `kb/Home.md`).

```sh
uv pip install --python .venv/bin/python -e '.[dev]'
./tools/build_fixtures.sh          # pinned GCC in Docker
.venv/bin/pytest
```

Benchmark design: [`benchmark/README.md`](benchmark/README.md) defines the raw,
REA, and WebAsmIR comparison, scoring, instrumentation, and work needed before
running it. The model-neutral guide is
[`webasmir-recovery/SKILL.md`](benchmark/skills/webasmir-recovery/SKILL.md).

Launch existing stripped binaries with [`benchmark/run_models.sh`](benchmark/run_models.sh).
See [`benchmark/LAUNCH.md`](benchmark/LAUNCH.md) for preparation, preflight,
model matrices, REA configuration, and measurement limits.
