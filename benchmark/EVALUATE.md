# Evaluate recovered code

Run this after `run_models.sh`. The evaluator compiles each unchanged submission
as GNU C11 and compares its output and exit code with the original stripped ELF.
No model requests are made. This follows the sibling `llm-decompile-test`
re-executability evaluator and accepts this repository's UUID run directories.

## Quick start for the current tiny runs

From the WebAsmIR repository root:

```sh
./benchmark/evaluate_models.sh \
  --image gcc:13 \
  --tests benchmark/tests.tiny.json
```

`gcc:13` is an available Linux amd64 image on this development machine. For a
repeatable corpus experiment, use the sibling's Ubuntu compiler image instead:

```sh
docker build --platform linux/amd64 \
  -t type-recovery-bench:ubuntu22.04 \
  -f ../llm-decompile-test/benchmark/Dockerfile \
  ../llm-decompile-test/benchmark

./benchmark/evaluate_models.sh --runs results/benchmark
```

The default image is `type-recovery-bench:ubuntu22.04`. Every evaluation records
the resolved image ID and uses that ID for all compilation and execution. Use
the same image and test vectors across conditions. Docker runs through OrbStack
on this Mac; the evaluator never executes Linux binaries on the macOS host.

Without `--tests`, there is one test with no arguments and empty stdin, matching
the sibling's fixed-input suite. The tiny example returns `argc` through its
exit status, so `tests.tiny.json` checks exit codes 1, 2, 3, and 6. Matching a
normal nonzero return code is valid; assuming every correct program returns 0
would incorrectly fail this example.

## Select runs and private tests

```sh
# Select a model and condition; all matching repetitions remain in the report.
./benchmark/evaluate_models.sh \
  --runs results/benchmark --model gpt-6.1-sol --condition webasmir \
  --image gcc:13 --tests benchmark/tests.tiny.json

# Evaluate exactly one run, or repeat --run-id to select an explicit cohort.
./benchmark/evaluate_models.sh \
  --run-id YOUR_RUN_ID --image gcc:13 \
  --tests benchmark/tests.tiny.json
```

`--runs` accepts the benchmark output root, its `runs/` directory, or one UUID
run directory. The evaluator reads each run's authoritative `manifest.json`,
not a possibly stale aggregate index. It verifies the staged binary and
submitted artifact hashes. It never changes model submissions or run metrics.

Private test JSON is a nonempty array:

```json
[
  {"name": "empty", "argv": [], "stdin": ""},
  {"name": "with-input", "argv": ["--count", "3"], "stdin": "10 20 30\n"}
]
```

Arguments exclude `argv[0]`; stdin is UTF-8 text. These vectors apply to **every
selected binary**, so select a compatible cohort or evaluate individual cases
with their own vectors. The bundled tiny vectors are a development smoke test,
not a hidden or exhaustive validation suite. Supply private held-out vectors
for accuracy claims. Filesystem inputs and nondeterministic or interactive
programs are not supported by this initial evaluator.

The original and candidate execute in separate containers with only their
respective executable mounted. Candidates cannot read the reference ELF,
source, expected outputs, other runs, or repository. Compilation uses a
temporary copy of the exact submitted C, without repair. Containers have no
network, a read-only root, resource limits, and bounded stdout/stderr files;
executables run as an unprivileged user. Named containers are removed after
timeouts. Defaults are 60 seconds to compile and 5 seconds per execution;
override with `--compile-timeout` and `--run-timeout`.

GNU `timeout` reserves exit codes 124 and 137; Docker/command errors use
125–127 and signals conventionally use 128+. This evaluator treats these as
timeout/execution failures, so targets intentionally using those return codes
need a different execution adapter. A failing oracle produces an evaluation
error, never a model accuracy score.

## Reuse the sibling's recorded stdout

To reproduce its single-vector stdout/exit-0 criterion:

```sh
./benchmark/evaluate_models.sh \
  --runs results/benchmark --oracle-mode recorded
```

This requires the original corpus path from each selected manifest to contain
the matching `stripped.elf` and sibling `stripped.stdout`. The original binary's
hash must match the run. Recorded mode does not accept `--tests` or stderr
comparison because the sibling only records default-invocation stdout and
expects exit 0. Custom inputs such as `tiny.O1.stripped` use the default
`--oracle-mode binary` instead.

## Meaning of the percentages

| Metric | Definition |
|---|---|
| Compile % | Unmodified submissions that compile / scored trials |
| Accuracy % | Mean across scored trials of `100 × passed tests / total tests` |
| Behavior pass % | Trials passing every supplied test / scored trials |
| Output similarity | Normalized token-level Levenshtein similarity, diagnostic only |

A test passes when stdout matches byte for byte and the exit code matches,
without a timeout. Add `--compare-stderr` to require matching stderr too.
Otherwise stderr is retained and compared diagnostically, as in the sibling
evaluator. Output similarity is null when the token comparison exceeds four
million edit-distance cells. Empty outputs can have 100% similarity even when
exit codes differ; similarity does not determine behavioral accuracy.

Incomplete model attempts, model errors, invalid traces, timeouts, and compile
failures score zero. The current evaluator requires `SUBMITTED` for candidate
execution; it does not salvage partial artifacts from timed-out runs. Prepared,
check-only, cancelled, unfinished, setup-failed, and approval-blocked runs are
excluded with counts and reasons. Legacy approval-blocked `INCOMPLETE` runs are
recognized from their trace. Missing or modified artifacts/oracles are reported
as `EVALUATION_ERROR`, excluded, and make the evaluator exit nonzero. Check
these exclusions before using scores. Zero scored trials yields `n/a`, not 0%.

Summaries keep model, condition, reasoning, track, suite, and compiler separate;
optimization-specific tables are also saved. Aggregation weights each trial
equally. Select balanced case/repetition cohorts for comparisons; this script
does not compute family-weighted estimates or confidence intervals. These are
behavioral test scores, **not recovered type accuracy, textual source similarity,
or a proof of semantic equivalence**. Add `--types` for independent reference type
scoring, or use `--types-only` without Docker. See [type metrics](TYPE_METRICS.md)
for matching rules, percentages, and the distinction between DWARF agreement and
observable type recovery.

## Reports

Each invocation creates a new directory under `results/benchmark/evaluation/`.
Use `--output PATH` to choose another new directory; existing reports are never
overwritten. The console prints the report path and summary table.

| File | Contents |
|---|---|
| `summary.md`, `summary.json`, `summary.tsv` | Accuracy and compile percentages by model/condition, plus timing/token means in JSON/TSV |
| `summary_by_optimization.tsv` | Same metrics separated by optimization |
| `case_metrics.json`, `case_metrics.tsv` | Every selected trial, score, status, and exclusion reason |
| `tests.json`, `evaluation.json` | Exact vectors, image ID, evaluator hash, settings, selected paths |
| `details/<run-id>/metrics.json` | Individual result, preserved if other cases fail |
| `details/<run-id>/tests.json` | Per-vector output/exit comparisons |
| `details/<run-id>/compile/` | Compiler logs and candidate ELF |
| `details/<run-id>/oracle-*/`, `candidate-*/` | Execution commands, stdin, stdout, stderr, exit codes, and timing |

Quality failures are successfully evaluated results and do not make the script
exit nonzero. Configuration errors exit 2; evaluation errors exit 1. This makes
batch reports possible even when some recovered programs fail to compile.
