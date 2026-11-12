"""Launcher invariants and real MCP integration, without model API requests."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys

import pytest

from asmwebir.benchmark.common import consume_budget, tool_metrics, trace_metrics
from asmwebir.benchmark.relay import guard_call
from asmwebir.benchmark.runner import discover, main, make_servers, parse_args, smoke, toml
from .conftest import FIX


def test_discovery_refuses_ground_truth_and_candidates(tmp_path):
    with pytest.raises(ValueError, match='not fully stripped'):
        discover([str(FIX / 'running_example.O1.dbg')], None, '**/stripped.elf')
    candidate = tmp_path / 'candidate.elf'
    candidate.write_bytes((FIX / 'running_example.O1.stripped').read_bytes())
    with pytest.raises(ValueError, match='evaluator output'):
        discover([str(candidate)], None, '**/stripped.elf')
    assert discover([], str(FIX), '*.stripped')
    with pytest.raises(ValueError, match='No input binaries'):
        discover([], str(tmp_path), '**/stripped.elf')


def test_relay_blocks_other_targets_and_tools():
    config = {'tools': ['open_binary', 'view'], 'binary': '/tmp/public/program.elf'}
    def call(name, **args):
        return {'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}}
    valid = guard_call(call('open_binary', path='/input/program.elf'), config)
    assert valid['params']['arguments']['path'] == config['binary']
    for msg in [call('open_binary', path='/private/oracle.elf'), call('run_script', code='evil'),
                call('open_binary', path='/input/program.elf', database='/private/oracle')]:
        with pytest.raises(ValueError):
            guard_call(msg, config)


def test_usage_does_not_confuse_turn_total_with_context(tmp_path):
    trace = tmp_path / 'trace'
    trace.write_text('\n'.join(json.dumps(e) for e in [
        {'type': 'turn.completed', 'usage': {'input_tokens': 200, 'cached_input_tokens': 100, 'output_tokens': 40, 'reasoning_output_tokens': 30}},
        {'type': 'turn.completed', 'usage': {'input_tokens': 300, 'cached_input_tokens': 200, 'output_tokens': 50, 'reasoning_output_tokens': 40}},
        {'type': 'item.completed', 'item': {'id': 'x', 'type': 'command_execution'}},
    ]))
    result = trace_metrics(trace)
    assert result['input_tokens'] == 500  # cached tokens already included
    assert result['output_tokens'] == 90  # reasoning is a subset
    assert result['peak_context_tokens'] is None
    assert result['prohibited_tool_events'] == ['x']
    assert trace_metrics(tmp_path / 'missing')['input_tokens'] is None


def test_shared_budget(tmp_path):
    config = {'budget_path': str(tmp_path / 'budget.sqlite'), 'max_calls': 2}
    consume_budget(config)
    consume_budget(config)
    with pytest.raises(ValueError, match='budget exhausted'):
        consume_budget(config)


def test_truncated_tool_log_preserves_completed_calls(tmp_path):
    (tmp_path / 'common-events.jsonl').write_text('{"tool":"read_evidence","seconds":0.2}\n{"tool":')
    metrics = tool_metrics(tmp_path)
    assert metrics['common_calls'] == 1
    assert metrics['common_invalid_event_lines'] == 1


def test_config_overrides_and_toml_escaping(tmp_path):
    import tomllib
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'models': ['old'], 'repeats': 3}))
    args = parse_args(['--config', str(config), '--model', 'new', '--repeats', '2'])
    assert args.models == ['new'] and args.repeats == 2
    value = {'command': 'a path/with "quotes"', 'args': ['$(never-execute)', 'line\nnext'], 'required': True}
    assert tomllib.loads('server=' + toml(value))['server'] == value


def test_real_mcp_stdio_and_artifact_boundary(tmp_path):
    public = tmp_path / 'public'
    public.mkdir()
    (public / 'program.elf').write_bytes((FIX / 'running_example.O1.stripped').read_bytes())
    (public / 'program.objdump.txt').write_text('binary evidence')
    run = tmp_path / 'run'
    run.mkdir()
    args = parse_args(['--prepare-only', '--no-build'])
    servers = make_servers(tmp_path, run, 'webasmir', args)
    snapshots = asyncio.run(smoke(servers, run, open_binary=True))
    assert len(snapshots['analysis']['tools']['tools']) == 11
    assert 'protocol_error' not in (run / 'analysis-events.jsonl').read_text()
    assert 'Failed to parse' not in (run / 'analysis-preflight.stderr').read_text()

    async def artifact_checks():
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        cfg = servers['benchmark']
        params = StdioServerParameters(command=cfg['command'], args=cfg['args'], env=cfg['env'])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for name, arguments in [
                    ('read_evidence', {'name': '../oracle.c'}),
                    ('write_artifact', {'name': '../escape', 'content': 'bad'}),
                ]:
                    result = (await session.call_tool(name, arguments)).model_dump(by_alias=True)
                    assert result['isError']
                result = (await session.call_tool('write_artifact', {'name': 'recovered.c', 'content': 'int main(void){return 0;}'})).model_dump(by_alias=True)
                assert not result.get('isError')
    asyncio.run(artifact_checks())
    assert (run / 'artifacts/recovered.c').read_text() == 'int main(void){return 0;}'
    assert not (run / 'escape').exists()


@pytest.fixture
def fake_cli(tmp_path):
    script = tmp_path / 'codex-test'
    script.write_text(f'#!{sys.executable}\n' + '''
import asyncio, json, pathlib, sys, tomllib
if '--version' in sys.argv:
    print('fake-codex-test')
    raise SystemExit(0)
if 'doctor' in sys.argv:
    print(json.dumps({'checks': {'config.load': {'status':'ok'}, 'auth.credentials': {'status':'ok'}}}))
    raise SystemExit(0)
mode_file = pathlib.Path(__file__).with_suffix('.mode')
mode = mode_file.read_text() if mode_file.exists() else ''
if mode == 'fail':
    raise SystemExit(7)
if mode == 'sleep':
    import time
    time.sleep(20)
async def main():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    settings = next(s for s in sys.argv if s.startswith('mcp_servers='))
    cfg = tomllib.loads(settings)['mcp_servers']['benchmark']
    async with stdio_client(StdioServerParameters(command=cfg['command'],args=cfg['args'],env=cfg['env'])) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
            for name, content in [('recovered.c','int main(void){return 0;}'),('types.json','{"schema_version":1,"functions":[],"aggregates":[]}'),('notes.md','test')]:
                await s.call_tool('write_artifact', {'name':name,'content':content})
    pathlib.Path(sys.argv[sys.argv.index('--output-last-message')+1]).write_text('Submitted.')
    print(json.dumps({'type':'turn.completed','usage':{'input_tokens':12,'cached_input_tokens':4,'output_tokens':8}}))
asyncio.run(main())
''')
    script.chmod(0o700)
    home = tmp_path / 'auth'
    home.mkdir()
    (home / 'auth.json').write_text('{}')
    return script, home


def test_launcher_end_to_end_and_distinct_run_ids(tmp_path, fake_cli):
    objdump = __import__('shutil').which('objdump')
    if not objdump:
        pytest.skip('objdump unavailable')
    cli, home = fake_cli
    output = tmp_path / 'results'
    command = ['--model', 'fake-model', '--conditions', 'raw', '--no-build',
               '--objdump', objdump, '--output', str(output), '--codex', str(cli),
               '--bench-home', str(home), '--repeats', '2', str(FIX / 'running_example.O1.stripped')]
    assert main(command) == 0
    runs = list((output / 'runs').iterdir())
    assert len(runs) == 2
    for run in runs:
        assert (run / 'status.txt').read_text().strip() == 'SUBMITTED'
        assert json.loads((run / 'metrics.json').read_text())['input_tokens'] == 12
        assert (run / 'artifacts/recovered.c').is_file()
        assert not list(run.rglob('auth.json'))


@pytest.mark.parametrize('mode,status', [('fail', 'MODEL_FAILED'), ('sleep', 'TIMEOUT')])
def test_failed_trials_retain_terminal_records(tmp_path, fake_cli, mode, status):
    objdump = __import__('shutil').which('objdump')
    if not objdump:
        pytest.skip('objdump unavailable')
    cli, home = fake_cli
    cli.with_suffix('.mode').write_text(mode)
    output = tmp_path / 'results'
    assert main(['--model', 'fake-model', '--conditions', 'raw', '--no-build',
                 '--objdump', objdump, '--output', str(output), '--codex', str(cli),
                 '--bench-home', str(home), '--timeout', '1',
                 str(FIX / 'running_example.O1.stripped')]) == 1
    run = next((output / 'runs').iterdir())
    assert (run / 'status.txt').read_text().strip() == status
    assert json.loads((run / 'manifest.json').read_text())['status'] == status
    assert json.loads((run / 'metrics.json').read_text())['input_tokens'] is None
