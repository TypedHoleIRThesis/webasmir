# Launch benchmark runs

`run_models.sh` launches Codex CLI on existing stripped ELF x86-64 inputs,
using raw evidence, REA, or WebAsmIR. It supports multiple Codex-accessible model
IDs, repetitions, shuffled scheduling, preparation, and preflight. It follows the
sibling repo's CLI approach; it is not an Anthropic/Gemini API adapter.

This is the **codex-cli-static-v1** implementation profile. It supplies bounded
raw evidence, artifact submission, optional compiler feedback, and the selected
analysis MCP. Runtime/public/hidden tests and the method-neutral type evaluator
remain future work. This profile does not implement every proposed feature in
[the full research protocol](README.md).

## 1. Select original input binaries

Run commands from the WebAsmIR repository root. Explicit paths work independently
of the sibling directory layout:

```sh
./benchmark/run_models.sh --prepare-only \
  --conditions raw,webasmir \
  path/to/original/stripped.elf
```

Or select a corpus directory:

```sh
./benchmark/run_models.sh --prepare-only \
  --corpus ../llm-decompile-test/artifacts_result_only \
  --pattern '**/stripped.elf'
```

Discovery does not select prior `candidate.elf` outputs or `oracle.elf` reference
binaries. Inputs are checked for ELF architecture and remaining static/debug
symbols. Custom filenames are accepted as explicit paths or with a custom glob.

At implementation time this local sibling checkout contained prior
`evaluation/.../candidate.elf` files, but no `stripped.elf` or `oracle.elf` corpus,
including ignored files. Point `--corpus` to your actual compiled artifacts.
To regenerate the sibling suite if needed, use its `result_only/build_matrix.sh`.
The local `hand_example/tiny.O1.stripped` is available for launcher smoke checks.

## 2. Evidence and compiler prerequisites

Use the repository Python environment, installed with the existing project
requirements. The launcher needs Python 3.11/3.12, MCP, and pyelftools, already
included in `pyproject.toml`. Set `ASMWEBIR_PYTHON` to select another compatible
interpreter. No extra model SDK or API key is required beyond Codex CLI login.

By default, evidence and compiler feedback use the sibling repo's Linux Docker
image. If it is not already built:

```sh
docker build --platform linux/amd64 \
  -t type-recovery-bench:ubuntu22.04 \
  -f ../llm-decompile-test/benchmark/Dockerfile \
  ../llm-decompile-test/benchmark
```

The launcher does not silently build/download images or install REA. It records
image IDs and objdump versions. For a local preparation check on this Mac:

```sh
./benchmark/run_models.sh --prepare-only \
  --conditions raw,webasmir --objdump /usr/bin/objdump --no-build \
  hand_example/tiny.O1.stripped
```

`--objdump` selects an explicit host executable and detects GNU versus LLVM
syntax; `--no-build` disables compiler feedback equally across conditions. Keep
these options identical across compared runs. Host and Docker evidence profiles
have separate provenance and should not be pooled without reporting that change.

## 3. Authenticate and preflight

Use a dedicated authentication home, as in the sibling launcher:

```sh
CODEX_HOME="$HOME/.codex-webasmir-benchmark" codex login

./benchmark/run_models.sh --check \
  --bench-home "$HOME/.codex-webasmir-benchmark" \
  --conditions raw,webasmir \
  path/to/original/stripped.elf
```

`--check` starts disposable MCP processes, lists their actual schemas, reads
common evidence, opens the assigned binary for each analysis condition, and
checks Codex configuration/authentication. It sends no model request. With a
corpus it checks the first binary per selected condition. Preparation requires
neither Codex credentials nor a running analysis backend.

The dedicated authentication home persists so Codex can refresh credentials.
Each trial has fresh runtime SQLite storage and work directories; runs use
`--ephemeral`, `--ignore-user-config`, `--ignore-rules`, disabled host skill
lookup, and explicit tool configuration. Credentials are not copied to results.
Do not reuse your normal working Codex home for experiments.

The generated flags were checked with installed Codex CLI 0.167.0. A different
CLI can reject unsupported settings during preflight; do not remove isolation
flags just to bypass that error. The CLI usage follows the official
[non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode)
and [MCP configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

## 4. Launch one run or a matrix

```sh
./benchmark/run_models.sh \
  --model EXACT_MODEL_ID \
  --conditions raw,webasmir --repeats 1 \
  --bench-home "$HOME/.codex-webasmir-benchmark" \
  path/to/original/stripped.elf
```

Repeat `--model` for multiple models:

```sh
./benchmark/run_models.sh \
  --model FIRST_MODEL_ID --model SECOND_MODEL_ID \
  --conditions raw,webasmir --repeats 3 \
  --bench-home "$HOME/.codex-webasmir-benchmark" \
  --corpus ../llm-decompile-test/artifacts_result_only \
  --output results/benchmark
```

The schedule is shuffled reproducibly by `--seed`. Work is serial to keep
resource contention controlled. There is no automatic retry or response replay.
Every invocation creates new UUIDs rather than overwriting or resuming trials.
A failed job is recorded and the remaining scheduled jobs continue; the launcher
returns nonzero when any job fails. Ctrl-C records cancellation and stops.

Optional settings:

- `--timeout 1200`: hard timeout for the Codex process group, including its MCP
  children. Preparation/preflight time is recorded separately.
- `--max-tool-calls 120`: shared atomic budget across common and analysis tools;
  rejected calls consume budget too. Leave room to submit the three artifacts.
- `--track objdump-complete`: default, includes code and section contents.
  `asm-only` is available as a distinct, information-limited track.
- `--case-contract FILE`: a public input/behavior contract applied to each
  selected case. Use separate invocations for different contracts. Never supply
  source, DWARF, private tests, or expected hidden outputs.
- `--config benchmark/run.local.json`: JSON defaults; CLI options override them.
  Copy `run.example.json`, edit it, and pass exact model IDs. Paths resolve from
  the invocation's working directory. This runtime config is different from the
  earlier `experiment.example.json` research-design artifact.

## 5. REA condition

REA must already have a working pinned installation and native backend. Copy
`rea.example.json` to `rea.local.json` and supply the actual stdio launch argv,
upstream skill file, selected native provider, and a static tool subset available
in that version. The example entry-script path is deliberately not an assumed
REA installation layout. Use the argv from your working REA registration.

```sh
./benchmark/run_models.sh --check \
  --conditions rea --rea-config benchmark/rea.local.json \
  --bench-home "$HOME/.codex-webasmir-benchmark" \
  path/to/original/stripped.elf

./benchmark/run_models.sh \
  --model EXACT_MODEL_ID --repeats 3 \
  --conditions raw,rea,webasmir \
  --rea-config benchmark/rea.local.json \
  --bench-home "$HOME/.codex-webasmir-benchmark" \
  path/to/original/stripped.elf
```

The launcher loads the upstream skill text and copies its Markdown references
into the public case bundle. References are read through the common evidence
tool, so reads are logged. Server instructions and schemas are archived during
preflight. The relay enforces the selected `provider_id`, maps the public name
`/input/program.elf` to the one staged binary, and rejects other target paths,
nonallowlisted tools, and nonbenchmark MCP resource/prompt methods. It never
silently substitutes another native backend.

The relay's supported static tool names are in
[`relay.py`](../src/asmwebir/benchmark/relay.py). This is a deliberately bounded
REA static-analysis profile; script execution, browser/runtime tools, arbitrary
exports, and target switching are unavailable. Both analysis backends are
trusted local processes, not OS-sandboxed by the relay. Use a dedicated worker
machine/container for adversarial targets or stronger filesystem isolation.
REA itself was not installed in the inspected environment; its live integration
must pass your `--check` before model trials.

## 6. Results and measurement limits

Each trial lives under `results/benchmark/runs/<uuid>/`:

| File | Meaning |
|---|---|
| `manifest.json`, `status.txt` | Input/model/condition/repetition, hashes, versions, timings, final status |
| `public/` | Exact public ELF, canonical evidence, schema, contract, guidance/reference files |
| `prompt.txt` | Exact task sent on stdin; no original source/corpus label |
| `mcp-preflight.json` | Actual initialize responses and tool schemas |
| `trace.jsonl`, `codex.stderr`, `final-response.txt` | Raw CLI output; final chat is retained separately from submitted C |
| `common-events.jsonl`, `analysis-events.jsonl` | Full tool arguments/results, errors, output sizes derivable from records, and durations |
| `artifacts/recovered.c`, `types.json`, `notes.md` | Exact model submissions; never manually repaired |
| `metrics.json` | Reported token usage, tool timing/counts, trace integrity, missing artifacts |
| `error.txt` | Preparation/preflight/runner failure, when applicable |

`manifest.jsonl` at the output root is a locked append-only run index. Per-run
manifests are authoritative. Prepared, failed, timed-out, incomplete, and
cancelled trials retain terminal status. `SUBMITTED` means artifacts exist and
the CLI succeeded; it does not mean the C compiles, the type JSON is valid, or
behavior matches the original. Evaluate these separately and keep failures in
score denominators. The new manifests are not directly interchangeable with the
sibling evaluator's TSV format.

CLI `turn.completed.usage` supplies aggregate input/output/cache/reasoning
counts where available. Cached input and reasoning are subsets of their totals,
not extra quantities to add. Missing fields stay null. The CLI does not provide
reliable per-request peak context, exact internal request counts, or a verified
served-model ID in this profile; those remain null. Raw traces are kept for
future richer adapters. No dollar cost or source accuracy is fabricated.

`model_wall_seconds` includes the actual run's fresh MCP startup and analysis.
`end_to_end_work_seconds` adds evidence preparation; `total_wall_seconds` also
includes disposable preflight and authentication checks. Analysis/common tool
latencies are separately summarized. The tool budget and wall timeout are hard
limits; the research protocol's cumulative token budgets and exact input-context
cap are not implemented by this CLI adapter. Automatic compaction is discouraged
with a high configured threshold, but internal host behavior is not claimed to
be fully observed or controlled. Use a request-level API adapter for strict
context/budget experiments.

No paid model trials are needed to run the launcher tests:

```sh
.venv/bin/pytest -q tests/test_benchmark.py
```
