---
name: webasmir-recovery
description: Recover source-level types and C behavior from ELF x86-64 SysV binaries using the AsmWebIR MCP server, with evidence-backed claims and contradiction repair. Use when that server is available for binary recovery.
---

# WebAsmIR recovery

Use the connected `asmwebir` tool schemas as the interface contract. This skill
does not install or register the server. If it is unavailable, report that
limitation and continue only with evidence/tools permitted by the task.

The server supplies a typed IR and consistency checks. Your deliverable is the
source/type artifact requested by the task. A completed IR is not a proof of
correct source recovery, and `view` output is not compilable C.

## Open and inspect

Call `open_binary(path)` on the supplied stripped ELF. It returns the function
inventory; avoid immediately duplicating it with `list_functions()`. Open only
the assigned binary. Reopening a path reuses the current process's old claims;
it does not reset the experiment. Do not switch targets or issue parallel
state-dependent calls in one server process.

Use `view(function)` for a relevant function, then follow calls and shared data
as needed. Function references may be the original `sub_...` name, displayed
name, code web, or hexadecimal address. Record addresses for final output;
names are annotations, not stable evidence of the original source name.

Read the notation:

- `?Tn`: unresolved type, with size/alignment/class and access-layout evidence.
- `#cN`: code web; `#dN`: data web; `#wN`: value web. Agreement within a web
  can propagate a claim across functions.
- `@addr`: instruction provenance. `NOGOOD`/marks: contradictory active claims
  under the engine's checks; inspect their labels and witnesses.
- `asm{...}`, opaque expressions, or other residuals: lifting/representation
  gaps. Consult raw evidence if available, and retain uncertainty if not.

Use `why(function, value)` for a specific unclear value such as `a0` or `v15`.
Use `list_holes(function)` for focused unresolved types. Request whole-program
views or complete history only when they answer a concrete outstanding question.

## Make supported claims

Identify access widths, offsets, pointer use, allocation extent, call arguments,
and return uses before proposing a type. Distinguish observed constraints from
source conventions. Signedness and names are not validated by this checker;
even accepted claims can be wrong because lifting and checking are incomplete.
Equal layout alone does not establish that two data structures are the same type.

Make one fact per `claim(fact, rationale)` call. State the relevant evidence
and uncertainty in the rationale. Prefer a justified shared declaration/binding
when it resolves related uses; do not fill holes merely to improve completion.

The following are **syntax examples**, not facts about the assigned binary:

```text
declare struct Record { 0: count: u32; 8: link: ptr Record } size 16
?T17 = Record
type(param 1 of c3) = ptr Record
type(ret of c3) = i32
type(v15 of sub_401200) = u64
arity c3 = 1
name c3 "read_count"
name w10 "count"
name(param 1 of c3) = "record"
```

Only reuse IDs that actually appear in the session. Supported type syntax is
`i8/i16/i32/i64`, `u8/u16/u32/u64`, `f32/f64`, `void`, `ptr T`, `T[n]`, named
types, and current holes. Fields use decimal byte offsets and semicolons.
The claim DSL's `param 1` is the first parameter; displayed `a0` and the
benchmark JSON's index `0` denote that same first parameter.

A declaration alone does not bind an observed hole to it. Bind the appropriate
hole or parameter after checking whether the hole represents the pointee or the
pointer itself. Do not add an extra pointer level by copying an example blindly.
The DSL is not C: unions, bitfields, arbitrary C declarations, and function
pointer declarators cannot be assumed to parse. Express only supported facts
and record the remaining source-level structure in the requested artifact.

After a claim, read its result and re-view the functions needed to verify the
reported changes. A response naming changed views does not contain their full
new text. Prefer current visible IDs and original function references for
subsequent claims; resolve an unknown target rather than inventing an ID.

## Resolve contradictions

1. Read the nogood's claim label, rule, and witness instruction. A contradiction
   can involve several claims; the newest claim is not necessarily the wrong one.
2. Use `why` or a focused raw instruction read when the cause is unclear.
   `blast(claim_id)` is a dry run showing affected functions before retraction.
3. Retract an unsupported claim in the label with `retract(claim_id, reason)`.
   If other active claims depend on a declaration being replaced, reconsider
   those bindings too. Retraction records history; it does not delete it.
4. Re-view affected functions and check `list_nogoods()`. Add a corrected claim
   only when evidence supports it. Do not repeat the same rejected hypothesis
   without new evidence or a corrected dependency.

For a syntax/unknown-reference error, use the current schema and view to repair
the call. For a persistent engine or lifting error, report the unresolved
limitation rather than repeatedly consuming the budget. Do not automatically
replay a mutating claim after a transport timeout: inspect `list_claims()` first
if the connection survives, because the original call may already have applied.

## Finish the requested recovery

Preserve control flow, memory effects, widths, casts, call behavior, and input
handling when translating the IR and raw evidence into C. Residual instructions
require separate analysis. Inspect both callers and callees where a shared type
or prototype changes behavior. Keep unresolved hypotheses explicit.

Call `complete(function)` when its type work is finished, but interpret it only
as the server's hole/contradiction check. It does not establish executable
equivalence, prove residual code understood, or validate original names.
Use permitted compilation and public tests to validate the actual candidate.

Submit the task's requested files, including recovered source if requested;
do not finish with only a narrative or a list of claims. For the benchmark,
produce `recovered.c`, address-anchored `types.json`, and concise `notes.md`.
Use unknown types where appropriate. Stop when the artifact is ready, no
supported improvement remains, or the task budget requires submission. Do not
claim hidden-test success or exact original-source recovery without evidence.
