# GPT-6.1-Sol: raw versus WebAsmIR on the tiny example

Date: 2026-11-15. Scope: one stripped binary, one completed model trial per
condition, and four behavioral test vectors. REA was not evaluated in this run.

Both conditions recovered C that compiled and passed all four behavioral tests.
They also achieved identical field-layout and sign-independent structural type
scores. Raw had higher strict DWARF-reference agreement: 57.1% versus 28.6%.
The difference is explained entirely by two additional unknown signedness
predictions in WebAsmIR's `types.json`. Both recovered C files actually use
signed types for those two values. This result does not establish worse
executable C recovery with WebAsmIR.

## Experiment and evidence

| Setting | Value |
|---|---|
| Requested model | `gpt-6.1-sol` |
| Reasoning effort | `medium` |
| Input | [`hand_example/tiny.O1.stripped`](../../hand_example/tiny.O1.stripped) |
| Original source | [`hand_example/tiny.c`](../../hand_example/tiny.c) |
| Type reference | [`hand_example/tiny.O1.dbg`](../../hand_example/tiny.O1.dbg) |
| Evidence track | `objdump-complete` |
| Conditions | Raw evidence; WebAsmIR MCP with guidance and raw evidence |
| Compiler feedback during model trials | Disabled (`--no-build`) |
| Offline evaluation image | `gcc:13`, Linux amd64 |
| Image ID | `sha256:13a199a1e64a8e2657802d4ef72d71cac94f088f37f56a9ce1ab40eac53f445d` |
| Behavioral comparison | Exact stdout and matching exit status; stderr not required to match |
| Type-scoring profile | `dwarf-reference-v1` |

The evaluator verifies that the debug reference and staged stripped binary
have identical allocated images. The candidate and reference executables run
in separate isolated containers. Submitted C is compiled without repair.

The scored runs are:

| Condition | Run ID | Artifacts |
|---|---|---|
| Raw | `8e555edc06e64145a7935645922e4d8a` | [C](../../results/benchmark/runs/8e555edc06e64145a7935645922e4d8a/artifacts/recovered.c), [types](../../results/benchmark/runs/8e555edc06e64145a7935645922e4d8a/artifacts/types.json), [notes](../../results/benchmark/runs/8e555edc06e64145a7935645922e4d8a/artifacts/notes.md) |
| WebAsmIR | `f6119b182e1e4e389cac8cefdbfc84c2` | [C](../../results/benchmark/runs/f6119b182e1e4e389cac8cefdbfc84c2/artifacts/recovered.c), [types](../../results/benchmark/runs/f6119b182e1e4e389cac8cefdbfc84c2/artifacts/types.json), [notes](../../results/benchmark/runs/f6119b182e1e4e389cac8cefdbfc84c2/artifacts/notes.md) |

The evaluation selected six run records. Four earlier setup/approval failures
were excluded: two per condition. These are not four incorrect recoveries.
The percentages and efficiency figures below describe only the two scored
trials; they do not include the token/time cost of those failed setup attempts.

## Behavioral and structural results

The original program allocates a 16-byte object, stores `7` and `argc`, reads
back the second field, and returns it. It produces no output. The four tests
invoke it with zero, one, two, and five additional arguments, expecting exit
statuses 1, 2, 3, and 6 respectively. All use empty stdin.

| Metric | Raw | WebAsmIR |
|---|---:|---:|
| Unmodified C compiles | Yes | Yes |
| Behavioral tests passed | 4/4 (100%) | 4/4 (100%) |
| Functions matched by address | 3/3 (100%) | 3/3 (100%) |
| Root type prediction coverage | 6/7 (85.7%) | 6/7 (85.7%) |
| Type kind and width agreement | 6/7 (85.7%) | 6/7 (85.7%) |
| Pointer-class agreement | 6/7 (85.7%) | 6/7 (85.7%) |
| Pointer-depth agreement | 2/3 (66.7%) | 2/3 (66.7%) |
| Aggregate-kind agreement | 2/2 (100%) | 2/2 (100%) |
| Aggregate-size agreement | 2/2 (100%) | 2/2 (100%) |
| Field-layout precision / recall / F1 | 100% / 100% / 100% | 100% / 100% / 100% |
| Primitive width agreement | 4/4 (100%) | 4/4 (100%) |
| Primitive exact agreement, including signedness | 4/4 (100%) | 2/4 (50%) |
| Structural type agreement, signedness ignored | 6/7 (85.7%) | 6/7 (85.7%) |
| Strict reference type agreement | 4/7 (57.1%) | 2/7 (28.6%) |
| Function arity agreement | 2/3 (66.7%) | 2/3 (66.7%) |
| Complete prototype agreement, signedness ignored | 2/3 (66.7%) | 2/3 (66.7%) |
| Complete prototype agreement, including signedness | 0/3 (0%) | 0/3 (0%) |

Aggregate metrics count two anchored uses of the same aggregate: the getter's
parameter and the constructor's return. Layout therefore has four matching
field instances across those two roots, representing two unique struct fields.
These are not independent discoveries of two different structures.

The type percentages above evaluate `types.json`. The behavioral result
evaluates `recovered.c`. The current evaluator does not extract and score the
types declared in the recovered C itself.

## What 57.1% versus 28.6% means

The strict score is:

```text
100 × exactly matched parameter/return type graphs
    / supported reference parameter/return type graphs
```

There are seven scored entities: four parameters and three return values.
Function names and aggregate names do not need to match. Functions are matched
by original binary address and parameters by index. Exact comparison of a
pointer to a struct follows the pointer and checks the struct's fields, sizes,
and signedness. Unknown signedness does not receive exact-match credit, but
it is an abstention rather than an explicit assertion of the wrong sign.

The original declarations are:

```c
struct Pair { long key; int val; };

int get_val(struct Pair *p);        /* 0x401126 */
struct Pair *make(int v);           /* 0x40112a */
int main(int argc, char **argv);    /* 0x401143 */
```

On the target used here, `long` is signed 64-bit and `int` is signed 32-bit.

| Entity | Original type | Raw JSON result | WebAsmIR JSON result |
|---|---|---|---|
| `get_val` parameter `p` | Pointer to `Pair` | Not exact: `key` signedness unknown | Not exact: `key` and `val` signedness unknown |
| `get_val` return | Signed 32-bit integer | Exact | Signedness unknown |
| `make` parameter `v` | Signed 32-bit integer | Exact | Signedness unknown |
| `make` return | Pointer to `Pair` | Not exact: `key` signedness unknown | Not exact: `key` and `val` signedness unknown |
| `main` parameter `argc` | Signed 32-bit integer | Exact | Exact |
| `main` parameter `argv` | `char **` | Missing prediction | Missing prediction |
| `main` return | Signed 32-bit integer | Exact | Exact |
| **Exact total** | **7 entities** | **4/7 = 57.1%** | **2/7 = 28.6%** |

For the getter's return and constructor's argument, raw predicts:

```json
{"kind": "integer", "bits": 32, "signed": true}
```

WebAsmIR predicts:

```json
{"kind": "integer", "bits": 32, "signed": null}
```

Those two differences account for the entire 28.6-percentage-point gap. An
in-memory diagnostic changing only these two WebAsmIR values to `true` produced
4/7 exact matches, or 57.1%. This diagnostic did not alter the saved submission
and is not a new model result.

Both submissions already fail exact matching on the two aggregate-pointer
roots because the first field's signedness is unknown. WebAsmIR's additional
uncertainty about the second field does not lose another root point: exact
agreement is all-or-nothing per root. Thus one uncertainty in a shared type
can affect multiple scored function interfaces.

## Comparing the actual recovered C

| Declaration | Original | Raw recovered C | WebAsmIR recovered C |
|---|---|---|---|
| First field | `long key` | `uint64_t tag` | `uint64_t tag` |
| Second field | `int val` | `int value` | `int32_t value` |
| Getter return | `int` | `int` | `int32_t` |
| Constructor argument | `int` | `int` | `int32_t` |
| Main signature | `int main(int argc, char **argv)` | Same | Same |

The recovered aggregate declarations are:

```c
/* Raw */
struct record {
    uint64_t tag;
    int value;
};

/* WebAsmIR */
typedef struct Record {
    uint64_t tag;
    int32_t value;
} Record;
```

Both place the first field at offset 0, the second at offset 8, and give the
struct a size of 16 bytes. Both preserve the allocation, field writes, getter,
and propagation of `argc` to the program's return value.

`int32_t` is signed. Consequently WebAsmIR's executable C uses the original
width and signedness for both values responsible for the JSON score gap.
Its source chooses concrete types, while its JSON records the signedness as
unproven. Raw's C and JSON both assert signedness for these values.

Both C files include `argv` and ignore it. It is omitted only from the type
predictions, where both also leave `main`'s exact arity unknown. This distinction
explains why the C declarations can be conventional and complete while the
reference coverage score is below 100%.

The shared source-level mismatch is the first field: the original `long` is
signed, while both reconstructions use unsigned `uint64_t`. Both have the
correct width and store the same value, `7`. The program never reads that field,
so the supplied executions do not distinguish the two signedness choices.
The raw getter additionally uses a `const` pointer; this qualifier is normalized
away by the type scorer and does not explain the score difference.

## Why the predictions differ

The raw run's notes justify interpreting the payload as `int` through its flow
from `argc` to `main`'s return. The WebAsmIR run's notes explicitly say the field
accesses do not establish signedness, so it records unknown signs in JSON while
choosing `uint64_t` and `int32_t` for compilable source.

The getter contains this instruction:

```asm
mov eax, dword ptr [rdi + 0x8]
```

It establishes a 32-bit load from offset 8. By itself, it does not establish
whether the original source used a signed or unsigned integer. Raw makes a
stronger inference from the surrounding program context. WebAsmIR's submission
is more conservative in its structured predictions.

This is evidence about these two outputs, not proof that the MCP inherently
causes conservative signedness predictions. The same model was used, but each
condition has only one scored trial, and the WebAsmIR condition changes both
the available analysis tools and the guidance.

## Tokens, time, and tool use

| Measurement | Raw | WebAsmIR |
|---|---:|---:|
| Model wall time | 52.09 s | 83.57 s |
| Evidence preparation plus model work | 52.18 s | 83.66 s |
| Aggregate input tokens | 109,020 | 203,067 |
| Cached input tokens, included above | 78,720 | 166,656 |
| Uncached input tokens, derived by subtraction | 30,300 | 36,411 |
| Aggregate output tokens | 1,681 | 2,387 |
| Reasoning output tokens, included above | 439 | 529 |
| Common evidence/artifact tool calls | 5 | 5 |
| Analysis tool calls | 0 | 17 |
| Summed analysis tool duration | 0 s | 1.24 s |
| Exact peak context | Unavailable | Unavailable |
| Verified served-model ID / internal request count | Unavailable | Unavailable |

WebAsmIR took approximately 1.60 times the model wall time and reported 1.86
times the aggregate input tokens in these completed trials. Much of the input
was cached. Cached input and reasoning output are subsets of their respective
totals and must not be added again. Aggregate input tokens count repeated
context across internal requests; they are not the peak context window size.

The 17 analysis calls comprise one `open_binary`, six `view`, six `claim`, three
`complete`, and one `list_nogoods`. Summed backend execution time alone does not
explain total model wall time; model processing and tool round trips are also
part of the workflow. These observations are not a general performance ranking.

## Interpretation and limits

The measured outcome is equal tested behavior and equal sign-independent
structural recovery, with different levels of commitment in the JSON type
predictions. The strict reference score alone is insufficient to conclude
that WebAsmIR recovered worse C.

DWARF describes the original source, including details that may not be
identifiable from the stripped binary. The unused `argv` parameter and integer
signedness illustrate this distinction. The current type scorer measures
normalized reference agreement; it does not have an independently validated
observability mask for every entity.

The four argument-count tests cover this small program's normal behavior. They
are not proof of equivalence and do not test allocation failure. There is only
one binary and one scored trial per condition, so this report provides no
confidence intervals, statistical significance claim, or evidence about REA.

For broader comparisons, keep behavior, sign-independent type shape, strict
reference agreement, prediction coverage, and efficiency separate. Unknown
predictions should remain distinguishable from explicit wrong predictions.
Assessing types extracted from recovered C would be a separate measurement
from the current JSON declaration score.

## Reproduction and supporting files

From the repository root, evaluate exactly the two reported trials:

```sh
./benchmark/evaluate_models.sh \
  --run-id 8e555edc06e64145a7935645922e4d8a \
  --run-id f6119b182e1e4e389cac8cefdbfc84c2 \
  --image gcc:13 \
  --tests benchmark/tests.tiny.json \
  --types
```

To require the same local image content, replace `gcc:13` with the image ID
listed above. The image must be present locally. Evaluation makes no model
requests and writes a new report directory. Selecting these two IDs reproduces
their scored metrics but omits the four excluded records from the report count.

- [Combined evaluation summary](../../results/benchmark/evaluation/20261115T081214Z-095d9586/summary.md)
- [Machine-readable summary](../../results/benchmark/evaluation/20261115T081214Z-095d9586/summary.json)
- [Evaluation settings, image identity, and evaluator source hashes](../../results/benchmark/evaluation/20261115T081214Z-095d9586/evaluation.json)
- [Raw per-entity type scores](../../results/benchmark/evaluation/20261115T081214Z-095d9586/details/8e555edc06e64145a7935645922e4d8a/type-metrics.json)
- [WebAsmIR per-entity type scores](../../results/benchmark/evaluation/20261115T081214Z-095d9586/details/f6119b182e1e4e389cac8cefdbfc84c2/type-metrics.json)
- [Raw token/tool metrics](../../results/benchmark/runs/8e555edc06e64145a7935645922e4d8a/metrics.json)
- [WebAsmIR token/tool metrics](../../results/benchmark/runs/f6119b182e1e4e389cac8cefdbfc84c2/metrics.json)
- [Behavioral test vectors](../tests.tiny.json)
- [Behavior evaluator documentation](../EVALUATE.md)
- [Type definitions, matching rules, and unsupported features](../TYPE_METRICS.md)

The files under `results/benchmark/` are local, Git-ignored experiment artifacts.
Their links require this checkout's result directories; sharing this report
alone will not publish those artifacts. The principal measurements and the
source/JSON comparison are included above so the explanation remains readable
without them.
