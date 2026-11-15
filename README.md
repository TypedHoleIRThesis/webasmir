# AsmWebIR

LLM decompilation by forward edits: a lifter turns an ELF x86-64 (SysV) binary into a typed, hole-bearing IR plus certain *premises*; LLM agents add labelled *claims* to an append-only knowledge store; contradictions become *nogoods* with instruction witnesses; *webs* make one claim apply everywhere it must agree.

Design and formal rules: `asmwebir-full.pdf` and the Obsidian vault `../../kb/` (start at `kb/Home.md`).

```sh
uv pip install --python .venv/bin/python -e '.[dev]'
./tools/build_fixtures.sh          # pinned GCC in Docker
.venv/bin/pytest
```

<!-- | Benchmark file | Purpose |
|---|---|
| [benchmark/README.md](benchmark/README.md) | Research protocol: comparison conditions, experiment design, scoring, and remaining work. |
| [benchmark/LAUNCH.md](benchmark/LAUNCH.md) | How to prepare and launch model trials, configure REA, and check the setup. |
| [benchmark/EVALUATE.md](benchmark/EVALUATE.md) | How to compile and test recovered C, calculate behavioral accuracy, and read reports. |
| [benchmark/TYPE_METRICS.md](benchmark/TYPE_METRICS.md) | Type matching rules, metric denominators, DWARF reference requirements, and limitations. |
| [benchmark/skills/webasmir-recovery/SKILL.md](benchmark/skills/webasmir-recovery/SKILL.md) | Guidance given to models using the WebAsmIR MCP tools. |
| [benchmark/prompts/launch.md](benchmark/prompts/launch.md) | Task prompt used by the current model launcher. |
| [benchmark/prompts/task.md](benchmark/prompts/task.md) | Proposed task prompt for the broader research protocol. |
| [benchmark/reports/tiny-gpt-6.1-sol-2026-11-15.md](benchmark/reports/tiny-gpt-6.1-sol-2026-11-15.md) | Tiny-example results, source/type comparisons, signedness explanation, and token/time measurements. |
| [benchmark/run_models.sh](benchmark/run_models.sh) | Script that launches model trials. |
| [benchmark/evaluate_models.sh](benchmark/evaluate_models.sh) | Script that evaluates submitted C and type predictions. | -->
