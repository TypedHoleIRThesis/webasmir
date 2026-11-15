# Compare submitted types across conditions

The shared scorer reads each run's submitted `types.json`. It does not rebuild
WebAsmIR state and does not depend on which functions WebAsmIR discovered.
The same validation, identities, and denominators apply to raw, REA, and WebAsmIR.

## Commands

```sh
# Types only: no Docker or model request required. Auto-find matching .dbg/oracle.elf.
./benchmark/evaluate_models.sh --types-only

# Behavior, efficiency, and reference type agreement in one report.
./benchmark/evaluate_models.sh --image gcc:13 \
  --tests benchmark/tests.tiny.json --types

# Explicit full debug ELF for runs of a particular binary.
./benchmark/evaluate_models.sh --types-only \
  --run-id YOUR_RUN_ID --reference hand_example/tiny.O1.dbg
```

The evaluator discovers `oracle.elf` next to corpus `stripped.elf` inputs, or
`tiny.O1.dbg` next to `tiny.O1.stripped`. It verifies all allocated section bytes,
addresses, sizes, flags, entry point, and architecture against the staged ELF.
A different optimization/build is rejected. Detached `.debug` files cannot
prove this pairing and are not accepted by this adapter. References stay in
offline evaluator storage, outside the model's tools and prompt.

## What is matched

Functions match by original binary entry address; parameters by that address
and zero-based index; returns by function address. Aggregate IDs and names
are local identifiers, not comparison targets. A submitted `Record` can match
a reference `Pair` when their shapes agree. Aggregate correspondence starts at
matched parameters/returns and follows field offsets/types. Recursive pointers
use cycle-aware structural comparison; union member ordering is ignored.

The initial ABI subset is scalar/pointer parameters and returns, including
ordinary scalar floating point. By-value aggregates, hidden/artificial arguments,
variadic prototypes, stack/split-register cases, and unsupported direct ABI types
are excluded with reasons. Function range lists without a supported entry
address are also counted as excluded. Locals and globals have no identity fields
in prediction schema v1 and are not scored.

## Metrics and denominators

Each metric stores `correct`, `total`, and `pct` in
`details/<run-id>/type-metrics.json`; every parameter/return comparison is recorded.
Aggregate layout has its own true-positive, predicted-field, and gold-field counts.

| Metric | Comparison and denominator |
|---|---|
| Function coverage | Predicted entries / supported reference functions |
| Prediction coverage | Non-unknown root types / supported reference parameters and returns |
| Kind accuracy | Integer, float, pointer, array, struct, union, or void class / supported reference roots |
| Kind/width accuracy | Class and storage width / roots with a known reference width |
| Pointer class accuracy | Pointer versus non-pointer / supported roots; missing/unknown is incorrect |
| Pointer depth accuracy | Exact indirection depth / reference pointer roots whose depth is known |
| Primitive width accuracy | Integer/float class and bit width / primitive reference roots |
| Primitive exact accuracy | Width/class plus integer signedness / primitive reference roots |
| Aggregate kind accuracy | Struct/union kind / aggregate roots reachable through parameter/return pointer chains |
| Aggregate size accuracy | Declared byte size / those roots with known reference size |
| Field layout precision/recall/F1 | Multiset intersection of `(offset, width, scalar class)` leaves, anchored to each matched root |
| Structural accuracy, sign ignored | Complete normalized type graph agreement ignoring integer signedness / fully supported roots |
| Reference exact accuracy | Same graph comparison including signedness / fully supported roots |
| Arity accuracy | Exact parameter count / supported functions |
| Prototype structural/reference exact | Arity, parameter index set, all parameter types, and return type agree / fully supported prototypes |

Layout flattens nested by-value structures and fixed arrays, but does not follow
pointer fields into new objects. Pointer fields contribute their own pointer
width/class. Full graph agreement follows those pointers and checks recursion.
Overlapping union members are a multiset, so duplicate offset/width/class entries
are not silently collapsed. Expansion above 4,096 nodes is marked unsupported.

Root coverage is not field coverage: `pointer to unknown` covers the pointer
root, but does not count as exact structure or known pointer depth. Missing gold
predictions and explicit unknowns remain in each applicable denominator. Null
signedness is incorrect for strict signedness agreement but ignored by the
sign-independent metric. A case with gold fields and no predicted fields has
recall/F1 0 and undefined precision. An absent metric denominator produces `n/a`.

Unsupported features remain visible: function-pointer signatures, enums and
other unrepresented types, bitfields, dynamic/nonconstant member locations, and
incomplete aggregate definitions are not silently treated as exact matches.
Known outer pointer kinds, aggregate sizes, or field pointer widths can still
be scored when their richer target type is unsupported; each metric has its
own denominator. Typedef names and qualifiers are normalized away. Boolean
base types are normalized to their unsigned integer storage representation.

Predictions are validated against the shipped JSON schema and semantic rules:
duplicate canonical addresses, aggregate IDs or parameter indices; dangling
references; out-of-range parameter indices; by-value cycles; overlapping struct
members; and fields beyond a known aggregate extent are invalid. Pointer cycles
and overlapping union members are legal. Invalid model predictions score zero
against the same gold denominator; the validation error is retained. Modified
submissions or mismatched/missing debug builds are evaluation errors, not zero
accuracy. Extra function identities are reported, and extra members reduce
layout precision and graph/prototype agreement. Unanchored type declarations
are not scored just because their names resemble gold declarations.

## Reference agreement is not observability

This implementation is deliberately labeled **`dwarf-reference-v1`**. Its gold
set consists of concrete DWARF functions in the matching executable, not only
entities identifiable in machine instructions. It counts parameters lacking
direct DWARF locations but does not use location presence as proof of use.

For example, `tiny`'s original `main` declares `argv`, even though its body never
uses it. Both current model submissions omit it, reducing reference coverage
and pointer-depth agreement. Likewise, a positive integer store may be equally
consistent with signed and unsigned source types. Leaving signedness unknown
lowers strict reference agreement without changing the sign-independent score.

Therefore these are useful **source-reference diagnostics**, not the proposed
headline observable-type accuracy metric. That still needs an independently
validated, frozen observability/ABI mapping for each corpus, plus supported
local/global identities. Do not use raw DWARF declarations to claim every
missed type was recoverable. The existing engine-only `asmwebir-eval` remains a
separate diagnostic and is not used by this cross-condition scorer.

## Reports and other measurements

`summary.md` adds a readable type table. JSON/TSV include all type percentages
and the number of contributing trials per metric. `type-reference.json` stores
the normalized reference graph with unsupported reasons; `type-metrics.json`
stores per-entity comparisons, denominators, and validation status. Excluded
setup/approval trials stay excluded. Failed/incomplete model attempts receive
empty predictions and score zero wherever a verified reference is available.
Summaries macro-average trial percentages and keep model/condition/reasoning/
track/suite/compiler separate; they do not pool all entities across programs.

The overall benchmark currently reports:

| Dimension | Implementation |
|---|---|
| Compilation and tested behavior | Offline Docker evaluator with supplied argv/stdin vectors |
| Reference type agreement | Shared scorer described above |
| Tokens and cache usage | Codex reported aggregate usage in run metrics and report means |
| Speed | Model wall time and tool timings; report includes mean model wall time |
| Exact peak context / internal request count | Unavailable from this CLI trace; remains null |
| Observable local/global type accuracy | Not implemented; requires new identities and gold matching |
| Confidence intervals / family-weighted significance | Not implemented by this reporting script |

Keep these dimensions separate. A single blended “accuracy” percentage would
hide tradeoffs and arbitrary weights between behavior, type shape, and efficiency.
