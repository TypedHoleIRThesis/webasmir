"""Behavior scoring and denominators without model requests or Docker dependency."""
from argparse import Namespace
import json
from pathlib import Path

import pytest

from asmwebir.benchmark.common import digest, save
from asmwebir.benchmark.evaluate import evaluate, similarity, summarize, test_vectors as load_vectors


def result(code=0, stdout=b'', stderr=b'', timeout=False):
    return {'exit_code': code, 'stdout': stdout, 'stderr': stderr, 'timed_out': timeout}


class Backend:
    def __init__(self, oracle, candidate, compile_ok=True):
        self.oracle = oracle
        self.candidate = candidate
        self.compile_ok = compile_ok
        self.calls = []

    def compile(self, source, detail, timeout):
        self.calls.append('compile')
        detail.mkdir()
        if self.compile_ok:
            (detail / 'candidate.elf').write_bytes(b'candidate')
        return result(0 if self.compile_ok else 1)

    def run(self, binary, vector, detail, timeout):
        self.calls.append(binary.name)
        values = self.oracle if binary.name == 'program.elf' else self.candidate
        return values[int(vector['name'])]


@pytest.fixture
def trial(tmp_path):
    run = tmp_path / 'run'
    (run / 'public').mkdir(parents=True)
    (run / 'public/program.elf').write_bytes(b'original')
    (run / 'artifacts').mkdir()
    for name in ('recovered.c', 'types.json', 'notes.md'):
        (run / 'artifacts' / name).write_text('model submission')
    manifest = {'model': 'test', 'condition': 'raw', 'reasoning': 'medium', 'track': 'objdump-complete',
                'binary_path': '/corpus/artifacts_result_only/gcc/O1/test/stripped.elf',
                'status': 'SUBMITTED', 'binary_sha256': digest(run / 'public/program.elf'),
                'artifact_hashes': {p.name: digest(p) for p in (run / 'artifacts').iterdir()}}
    save(run / 'manifest.json', manifest)
    (run / 'trace.jsonl').write_text(json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 100, 'output_tokens': 10}}))
    args = Namespace(oracle_mode='binary', compare_stderr=False, compile_timeout=60, run_timeout=5)
    vectors = [{'name': '0', 'argv': [], 'stdin': ''}, {'name': '1', 'argv': ['a'], 'stdin': ''}]
    return run, tmp_path / 'evaluation', args, vectors


def score(trial, backend):
    run, output, args, vectors = trial
    return evaluate(run, output, backend, args, vectors)


def test_nonzero_exit_is_behavior_and_partial_score(trial):
    backend = Backend([result(1), result(2)], [result(1), result(1)])
    row = score(trial, backend)
    assert row['included'] and row['compile_ok']
    assert row['accuracy_pct'] == 50 and not row['behavior_pass']
    # Empty stdout is a perfect diagnostic match, but exit mismatch still fails.
    assert row['stdout_token_similarity'] == 1


@pytest.mark.parametrize('candidate', [result(0, b'wrong'), result(1, b'right'), result(0, b'right', timeout=True)])
def test_wrong_output_exit_or_timeout_fails(trial, candidate):
    row = score(trial, Backend([result(0, b'right')]*2, [candidate]*2))
    assert row['accuracy_pct'] == 0 and row['included']


def test_compile_failure_stays_in_denominator(trial):
    row = score(trial, Backend([result()]*2, [], compile_ok=False))
    assert row['included'] and row['accuracy_pct'] == 0
    assert summarize([row])[0]['compile_pct'] == 0


def test_oracle_timeout_is_not_model_failure(trial):
    row = score(trial, Backend([result(timeout=True)], []))
    assert row['evaluation_status'] == 'EVALUATION_ERROR'
    assert not row['included'] and row['accuracy_pct'] is None


def test_legacy_approval_failure_excluded(trial):
    run = trial[0]
    manifest = json.loads((run / 'manifest.json').read_text())
    manifest['status'] = 'INCOMPLETE'
    save(run / 'manifest.json', manifest)
    (run / 'trace.jsonl').write_text(json.dumps({'type': 'item.completed', 'item': {
        'type': 'mcp_tool_call', 'server': 'benchmark', 'tool': 'read_evidence',
        'error': {'message': 'MCP tool call requires approval, but approval policy is never'}}}))
    backend = Backend([], [])
    row = score(trial, backend)
    assert not row['included'] and not backend.calls
    assert summarize([row])[0]['accuracy_pct'] is None


def test_model_incomplete_counts_zero(trial):
    manifest = json.loads((trial[0] / 'manifest.json').read_text())
    manifest['status'] = 'INCOMPLETE'
    save(trial[0] / 'manifest.json', manifest)
    backend = Backend([result()]*2, [])
    row = score(trial, backend)
    assert row['included'] and row['accuracy_pct'] == 0
    assert 'compile' not in backend.calls


def test_modified_artifact_not_executed(trial):
    (trial[0] / 'artifacts/recovered.c').write_text('repaired code')
    backend = Backend([result()]*2, [])
    row = score(trial, backend)
    assert row['evaluation_status'] == 'EVALUATION_ERROR'
    assert 'compile' not in backend.calls


def test_optional_stderr_comparison(trial):
    trial[2].compare_stderr = True
    row = score(trial, Backend([result()]*2, [result(stderr=b'extra')]*2))
    assert row['accuracy_pct'] == 0


def test_recorded_sibling_stdout(trial):
    run, output, args, vectors = trial
    source = run.parent / 'stripped.elf'
    source.write_bytes(b'original')
    source.with_name('stripped.stdout').write_bytes(b'gold\n')
    manifest = json.loads((run / 'manifest.json').read_text())
    manifest['binary_path'] = str(source)
    save(run / 'manifest.json', manifest)
    args.oracle_mode = 'recorded'
    backend = Backend([], [result(stdout=b'gold\n')])
    row = evaluate(run, output, backend, args, vectors[:1])
    assert row['accuracy_pct'] == 100
    assert 'program.elf' not in backend.calls


def test_grouping_keeps_conditions_and_tracks_separate(trial):
    row = score(trial, Backend([result()]*2, [result()]*2))
    summary = summarize([row, dict(row, condition='webasmir', accuracy_pct=50, behavior_pass=False),
                         dict(row, track='asm-only')])
    assert len(summary) == 3
    assert {s['accuracy_pct'] for s in summary} == {50, 100}


def test_vectors_and_output_similarity(tmp_path):
    assert load_vectors(None)[0]['argv'] == []
    path = tmp_path / 'tests.json'
    path.write_text('[{"argv": "not a list"}]')
    with pytest.raises(ValueError):
        load_vectors(path)
    assert similarity(b'a b c', b'a x c') == pytest.approx(2/3)
    assert similarity(b'', b'') == 1
    assert similarity(b'a ' * 3000, b'b ' * 3000) is None
