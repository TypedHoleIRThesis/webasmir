"""Compile unchanged submissions and compare behavior in separate Linux containers."""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile
import uuid

from .common import digest, run_process, save, trace_metrics

ROOT = Path(__file__).resolve().parents[3]
GROUP = ('model', 'condition', 'reasoning', 'track', 'suite', 'compiler')
SKIP = {'PREPARED', 'CHECKED', 'STARTED', 'CANCELLED', 'FAILED', 'TOOL_APPROVAL_BLOCKED'}


def test_vectors(path):
    values = json.loads(path.read_text()) if path else [{'name': 'default', 'argv': [], 'stdin': ''}]
    if not isinstance(values, list) or not values:
        raise ValueError('Test file must contain a nonempty JSON array')
    result = []
    for i, value in enumerate(values):
        if not isinstance(value, dict) or set(value) - {'name', 'argv', 'stdin'}:
            raise ValueError('Each test accepts only name, argv, stdin')
        argv, stdin = value.get('argv', []), value.get('stdin', '')
        name = value.get('name', str(i + 1))
        if not isinstance(name, str) or not isinstance(argv, list) or not all(isinstance(a, str) and '\0' not in a for a in argv):
            raise ValueError('Test name must be a string; argv must be a list of NUL-free strings')
        if not isinstance(stdin, str):
            raise ValueError('Test stdin must be a UTF-8 string')
        result.append({'name': name, 'argv': argv, 'stdin': stdin})
    return result


def similarity(left, right):
    """Sibling evaluator's token Levenshtein score, bounded for large output."""
    a, b = re.findall(rb'\S+', left), re.findall(rb'\S+', right)
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    if len(a) * len(b) > 4_000_000:
        return None
    previous = list(range(len(a) + 1))
    for i, token in enumerate(b, 1):
        current = [i]
        for j, other in enumerate(a, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (other != token)))
        previous = current
    return 1 - previous[-1] / max(len(a), len(b))


class Docker:
    def __init__(self, image):
        result = subprocess.run(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError(f'Docker image unavailable: {image}. Build the sibling benchmark/Dockerfile or choose --image.')
        self.image = result.stdout.strip()  # Pin every invocation to the resolved image.

    def execute(self, folder, command, detail, timeout, stdin=b'', writable=False):
        detail.mkdir(parents=True, exist_ok=True)
        name = 'asmwebir-eval-' + uuid.uuid4().hex
        # Bound both output streams inside the container before copying them out.
        wrapper = ('limit=$1; shift; timeout --signal=KILL "$limit" "$@" '
                   '>/tmp/stdout 2>/tmp/stderr; code=$?; '
                   'cat /tmp/stdout; cat /tmp/stderr >&2; exit "$code"')
        argv = ['docker', 'run', '--rm', '--name', name, '--platform', 'linux/amd64',
                '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '512m',
                '--pids-limit', '64', '--ulimit', 'fsize=1048576:1048576',
                '--tmpfs', '/tmp:rw,nosuid,size=128m', '-e', 'LC_ALL=C', '-e', 'TZ=UTC',
                '-v', f'{folder}:/input:{"rw" if writable else "ro"}', '-w', '/tmp', '-i']
        if not writable:
            argv += ['--user', '65534:65534']
        argv += [self.image, 'sh', '-c', wrapper, 'sh', f'{timeout}s', *command]
        save(detail / 'command.json', argv)
        (detail / 'stdin').write_bytes(stdin)
        try:
            with (detail / 'stdin').open('rb') as inp, (detail / 'stdout').open('wb') as out, (detail / 'stderr').open('wb') as err:
                code, timed_out, seconds = run_process(argv, timeout=timeout + 15, stdin=inp, stdout=out, stderr=err)
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)
        result = {'exit_code': code, 'timed_out': timed_out or code in (124, 137), 'seconds': seconds}
        save(detail / 'result.json', result)
        if code in (125, 126, 127) and not timed_out:
            raise ValueError(f'Container/tool execution failed (exit {code}); see {detail / "stderr"}')
        return {**result, 'stdout': (detail / 'stdout').read_bytes(), 'stderr': (detail / 'stderr').read_bytes()}

    def compile(self, source, detail, timeout):
        with tempfile.TemporaryDirectory(prefix='asmwebir-eval-build-') as tmp:
            stage = Path(tmp)
            shutil.copyfile(source, stage / 'recovered.c')
            result = self.execute(stage, ['gcc', '-std=gnu11', '-O0', '-Wall', '-Wextra',
                                  '-Wno-unused-function', '/input/recovered.c', '-o', '/input/program', '-lm'],
                                  detail, timeout, writable=True)
            if result['exit_code'] == 0 and not result['timed_out'] and (stage / 'program').is_file():
                shutil.copyfile(stage / 'program', detail / 'candidate.elf')
            return result

    def run(self, binary, vector, detail, timeout):
        # Only this executable is mounted: candidate never sees oracle/source/tests.
        with tempfile.TemporaryDirectory(prefix='asmwebir-eval-run-') as tmp:
            stage = Path(tmp)
            stage.chmod(0o755)
            shutil.copyfile(binary, stage / 'program')
            (stage / 'program').chmod(0o555)
            return self.execute(stage, ['/input/program', *vector['argv']], detail, timeout,
                                vector['stdin'].encode())


def case_labels(manifest):
    path = Path(manifest['binary_path'])
    suite, compiler = 'custom', 'unknown'
    for folder, label in [('artifacts_result_only', 'result-only'), ('artifacts', 'readable')]:
        if folder in path.parts:
            i = path.parts.index(folder)
            suite = label
            if i + 1 < len(path.parts):
                compiler = path.parts[i + 1]
            break
    match = re.search(r'(?:^|[/.])O([0-3sfgz])(?:[/.]|$)', str(path))
    return {'suite': suite, 'compiler': compiler, 'optimization': 'O' + match[1] if match else 'unknown',
            'program': path.parent.name if path.name == 'stripped.elf' else path.name}


def initial_row(run, vectors):
    manifest = json.loads((run / 'manifest.json').read_text())
    trace = trace_metrics(run / 'trace.jsonl')
    row = {k: manifest.get(k) for k in ('model', 'condition', 'reasoning', 'track', 'repetition')}
    row.update(case_labels(manifest), run_id=run.name, run_path=str(run), launch_status=manifest['status'],
               evaluation_status='EXCLUDED', included=False, reason='', compile_ok=False,
               behavior_pass=False, tests_passed=0, tests_total=len(vectors), accuracy_pct=None,
               stdout_token_similarity=None, model_wall_seconds=manifest.get('model_wall_seconds'),
               input_tokens=trace['input_tokens'], output_tokens=trace['output_tokens'])
    return manifest, trace, row


def evaluate(run, output, backend, args, vectors):
    manifest, trace, row = initial_row(run, vectors)
    detail = output / 'details' / run.name
    detail.mkdir(parents=True)
    try:
        if trace['tool_approval_errors']:
            row['reason'] = 'MCP approval blocked (including legacy INCOMPLETE runs)'
            return row
        if manifest['status'] in SKIP:
            row['reason'] = 'No completed model attempt or launcher/setup failure'
            return row
        if manifest['status'] not in {'SUBMITTED', 'INCOMPLETE', 'TIMEOUT', 'MODEL_FAILED', 'INVALID_TRACE'}:
            raise ValueError('Unknown launch status')
        binary = run / 'public/program.elf'
        if not binary.is_file() or digest(binary) != manifest['binary_sha256']:
            raise ValueError('Staged original ELF is missing or does not match manifest hash')
        save(detail / 'launch-manifest.json', manifest)
        expected = []
        if args.oracle_mode == 'recorded':
            original = Path(manifest['binary_path'])
            if original.name != 'stripped.elf' or not original.is_file() or digest(original) != manifest['binary_sha256']:
                raise ValueError('Recorded mode requires the matching original corpus stripped.elf')
            oracle = original.with_name('stripped.stdout')
            data = oracle.read_bytes()
            (detail / 'recorded.stdout').write_bytes(data)
            save(detail / 'oracle.json', {'path': str(oracle), 'sha256': digest(oracle), 'exit_code': 0})
            expected = [{'exit_code': 0, 'stdout': data, 'stderr': b'', 'timed_out': False}]
        else:
            for i, vector in enumerate(vectors):
                result = backend.run(binary, vector, detail / f'oracle-{i:03}', args.run_timeout)
                if result['timed_out'] or result['exit_code'] < 0 or result['exit_code'] >= 128:
                    raise ValueError(f'Oracle timed out or crashed for test {i}; cannot score')
                expected.append(result)
        row.update(included=True, evaluation_status='FAIL', accuracy_pct=0.0)
        if manifest['status'] != 'SUBMITTED':
            row['reason'] = 'Model did not submit a complete valid result'
            return row
        if not (run / 'trace.jsonl').is_file() or trace['invalid_trace_lines'] or trace['prohibited_tool_events'] or trace['failure_events']:
            row['reason'] = 'Missing, malformed, failed, or prohibited model trace'
            return row
        for name in ('recovered.c', 'types.json', 'notes.md'):
            file = run / 'artifacts' / name
            if not file.is_file() or digest(file) != manifest.get('artifact_hashes', {}).get(name):
                raise ValueError(f'Submitted artifact missing or modified: {name}')
        source = detail / 'recovered.c'
        shutil.copyfile(run / 'artifacts/recovered.c', source)
        compiled = backend.compile(source, detail / 'compile', args.compile_timeout)
        row['compile_warnings'] = len(re.findall(rb'\bwarning:', compiled['stderr']))
        candidate = detail / 'compile/candidate.elf'
        row['compile_ok'] = compiled['exit_code'] == 0 and not compiled['timed_out'] and candidate.is_file()
        if not row['compile_ok']:
            row['reason'] = 'Unmodified C did not compile within the limit'
            return row
        scores, tests = [], []
        for i, (vector, oracle) in enumerate(zip(vectors, expected)):
            actual = backend.run(candidate, vector, detail / f'candidate-{i:03}', args.run_timeout)
            exit_match = actual['exit_code'] == oracle['exit_code']
            stdout_match = actual['stdout'] == oracle['stdout']
            stderr_match = actual['stderr'] == oracle['stderr']
            passed = not actual['timed_out'] and exit_match and stdout_match and (stderr_match or not args.compare_stderr)
            score = similarity(actual['stdout'], oracle['stdout']) if not actual['timed_out'] else 0.0
            scores.append(score)
            tests.append({'name': vector['name'], 'passed': passed, 'exit_match': exit_match,
                          'stdout_exact': stdout_match, 'stderr_exact': stderr_match,
                          'stdout_token_similarity': score})
        save(detail / 'tests.json', tests)
        row['tests_passed'] = sum(t['passed'] for t in tests)
        row['accuracy_pct'] = 100 * row['tests_passed'] / len(vectors)
        row['behavior_pass'] = row['tests_passed'] == len(vectors)
        row['stdout_token_similarity'] = statistics.fmean(scores) if all(s is not None for s in scores) else None
        row['evaluation_status'] = 'PASS' if row['behavior_pass'] else 'FAIL'
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        row.update(included=False, evaluation_status='EVALUATION_ERROR', accuracy_pct=None, reason=str(exc))
    finally:
        save(detail / 'metrics.json', row)
    return row


def attach_types(row, run, output, reference):
    from .type_metrics import evaluate_types
    trace = trace_metrics(run / 'trace.jsonl')
    if row['launch_status'] in SKIP or trace['tool_approval_errors']:
        row.update(type_status='EXCLUDED', type_included=False)
        return
    invalid_trace = (not (run / 'trace.jsonl').is_file() or trace['invalid_trace_lines']
                     or trace['prohibited_tool_events'] or trace['failure_events'])
    result = evaluate_types(run, output, reference,
                            force_empty=row['launch_status'] != 'SUBMITTED' or bool(invalid_trace))
    row.update(type_status=result['status'], type_included=result['included'])
    for name, metric in result.get('metrics', {}).items():
        row['type_' + name + '_pct'] = metric['pct']
    for name in ('precision_pct', 'recall_pct', 'f1_pct'):
        row['type_field_layout_' + name] = result.get('field_layout', {}).get(name)
    if result.get('error'):
        row['type_error'] = result['error']


def summarize(rows, by_optimization=False):
    groups = defaultdict(list)
    keys = GROUP + (('optimization',) if by_optimization else ())
    for row in rows:
        groups[tuple(row.get(k) for k in keys)].append(row)
    summaries = []
    for group, values in sorted(groups.items(), key=lambda v: str(v[0])):
        valid = [v for v in values if v['included']]
        n = len(valid)
        summary = dict(zip(keys, group))
        summary.update(selected=len(values), scored=n, excluded=len(values)-n,
                       evaluation_errors=sum(v['evaluation_status'] == 'EVALUATION_ERROR' for v in values),
                       compile_pct=100 * sum(v['compile_ok'] for v in valid) / n if n else None,
                       behavior_pass_pct=100 * sum(v['behavior_pass'] for v in valid) / n if n else None,
                       accuracy_pct=statistics.fmean(v['accuracy_pct'] for v in valid) if n else None)
        for metric in ('stdout_token_similarity', 'model_wall_seconds', 'input_tokens', 'output_tokens'):
            observed = [v[metric] for v in valid if v.get(metric) is not None]
            summary['mean_' + metric] = statistics.fmean(observed) if observed else None
        typed = [v for v in values if v.get('type_included')]
        if any('type_status' in v for v in values):
            summary.update(type_scored=len(typed), type_excluded=len(values)-len(typed),
                           type_reference_errors=sum(v.get('type_status') == 'REFERENCE_ERROR' for v in values))
            for metric in sorted({k for v in values for k in v if k.startswith('type_') and k.endswith('_pct')}):
                observations = [v[metric] for v in typed if v.get(metric) is not None]
                summary[metric] = statistics.fmean(observations) if observations else None
                summary[metric + '_trials'] = len(observations)
        summaries.append(summary)
    return summaries


def table(path, rows):
    columns = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t')
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runs', type=Path, default=ROOT / 'results/benchmark', help='Benchmark output root, runs directory, or one run')
    p.add_argument('--run-id', action='append', help='Select exact run ID; repeat to select several')
    p.add_argument('--model')
    p.add_argument('--condition', choices=['raw', 'rea', 'webasmir'])
    p.add_argument('--output', type=Path, help='New report directory; existing directories are never overwritten')
    p.add_argument('--image', default='type-recovery-bench:ubuntu22.04')
    p.add_argument('--tests', type=Path, help='Private JSON array of argv/stdin test vectors, applied to every selected binary')
    p.add_argument('--oracle-mode', choices=['binary', 'recorded'], default='binary')
    p.add_argument('--compare-stderr', action='store_true')
    p.add_argument('--types', action='store_true', help='Also score types.json against matching DWARF reference types')
    p.add_argument('--types-only', action='store_true', help='Only score types; no Docker required')
    p.add_argument('--reference', type=Path, help='Full matching debug ELF; otherwise find oracle.elf or sibling .dbg automatically')
    p.add_argument('--run-timeout', type=int, default=5)
    p.add_argument('--compile-timeout', type=int, default=60)
    args = p.parse_args(argv)
    try:
        if min(args.run_timeout, args.compile_timeout) < 1:
            raise ValueError('Timeouts must be positive')
        vectors = test_vectors(args.tests)
        if args.oracle_mode == 'recorded' and (args.tests or args.compare_stderr):
            raise ValueError('Recorded mode supports only the default no-input test and stdout/exit-0 comparison')
        root = args.runs.expanduser().resolve()
        paths = [root / 'manifest.json'] if (root / 'manifest.json').is_file() else sorted(root.glob('*/manifest.json'))
        if not paths:
            paths = sorted((root / 'runs').glob('*/manifest.json'))
        selected = []
        for path in paths:
            m = json.loads(path.read_text())
            if (not args.run_id or path.parent.name in args.run_id) and (not args.model or m['model'] == args.model) and (not args.condition or m['condition'] == args.condition):
                selected.append(path.parent)
        if not selected:
            raise ValueError('No runs matched')
        if args.run_id and set(args.run_id) - {r.name for r in selected}:
            raise ValueError('Some requested run IDs were not found or were filtered out')
        args.types = args.types or args.types_only or args.reference is not None
        backend = None if args.types_only else Docker(args.image)
        output = args.output or ROOT / 'results/benchmark/evaluation' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8])
        output = output.expanduser().resolve()
        output.mkdir(parents=True, exist_ok=False)
        save(output / 'evaluation.json', {'image_id': backend.image if backend else None, 'requested_image': args.image,
             'oracle_mode': args.oracle_mode, 'compare_stderr': args.compare_stderr,
             'types': args.types, 'types_only': args.types_only,
             'reference': str(args.reference) if args.reference else 'auto',
             'run_timeout': args.run_timeout, 'compile_timeout': args.compile_timeout,
             'evaluator_sha256': digest(Path(__file__)),
             'evaluator_source_hashes': {p.name: digest(p) for p in Path(__file__).parent.glob('*.py')},
             'runs': [str(r) for r in selected]})
        save(output / 'tests.json', vectors)
        rows = []
        for run in selected:
            if args.types_only:
                _, _, row = initial_row(run, vectors)
                row.update(evaluation_status='NOT_REQUESTED', reason='Behavior evaluation not requested')
            else:
                row = evaluate(run, output, backend, args, vectors)
            if args.types:
                attach_types(row, run, output, args.reference)
                print(f'TYPES {row["type_status"]}: {row["model"]} / {row["condition"]} / {run.name}', flush=True)
            rows.append(row)
            print(f'{row["evaluation_status"]}: {row["model"]} / {row["condition"]} / {run.name}: {row["tests_passed"]}/{row["tests_total"]} tests; {row["reason"]}', flush=True)
        summary = summarize(rows)
        save(output / 'case_metrics.json', rows)
        table(output / 'case_metrics.tsv', rows)
        save(output / 'summary.json', summary)
        table(output / 'summary.tsv', summary)
        table(output / 'summary_by_optimization.tsv', summarize(rows, True))
        text = ['# Recovery accuracy', '',
                'Accuracy is the mean percentage of exact behavioral tests passed per scored trial. '
                'Behavior pass requires every test to pass. Output similarity is diagnostic, not source/type accuracy. '
                'Setup failures are excluded and counted; incomplete model attempts and compilation failures score zero.', '',
                '| Model | Condition | Reasoning | Track | Suite/compiler | Scored | Excluded | Compile % | Accuracy % | Behavior pass % |',
                '|---|---|---|---|---|---:|---:|---:|---:|---:|']
        def pct(value):
            return 'n/a' if value is None else f'{value:.1f}'
        for s in summary:
            text.append(f'| {s["model"]} | {s["condition"]} | {s["reasoning"]} | {s["track"]} | {s["suite"]}/{s["compiler"]} | {s["scored"]} | {s["excluded"]} | {pct(s["compile_pct"])} | {pct(s["accuracy_pct"])} | {pct(s["behavior_pass_pct"])} |')
        if args.types:
            text += ['', '## DWARF reference type agreement', '',
                     'Reference-only diagnostic: DWARF includes source details not necessarily observable in stripped code. '
                     'Names are ignored; functions and parameters are matched by address and index. '
                     'Percentages macro-average eligible trials; full numerators, denominators, exclusions, and entity details are in type-metrics.json.', '',
                     '| Model | Condition | Reasoning | Track | Suite/compiler | Type scored/excluded | Coverage % | Kind/width % | Pointer depth % | Field F1 % | Structural (sign ignored) % | Reference exact % | Prototype (sign ignored) % |',
                     '|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
            for s in summary:
                cells = [pct(s.get('type_' + k + '_pct')) for k in ('prediction_coverage', 'kind_width_accuracy',
                         'pointer_depth_accuracy', 'field_layout_f1', 'structural_accuracy_sign_ignored',
                         'reference_exact_accuracy', 'prototype_structural_sign_ignored')]
                text.append(f'| {s["model"]} | {s["condition"]} | {s["reasoning"]} | {s["track"]} | {s["suite"]}/{s["compiler"]} | {s["type_scored"]}/{s["type_excluded"]} | ' + ' | '.join(cells) + ' |')
        (output / 'summary.md').write_text('\n'.join(text) + '\n')
        print('\n' + '\n'.join(text) + f'\n\nReports: {output}')
        return 1 if any(r['evaluation_status'] == 'EVALUATION_ERROR' or r.get('type_status') == 'REFERENCE_ERROR' for r in rows) else 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        p.exit(2, f'{exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
