"""Launch isolated Codex CLI trials against existing stripped binaries."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import itertools
import importlib.metadata
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from elftools.elf.elffile import ELFFile

from .common import digest, run_process, save, tool_metrics, trace_metrics
from .relay import REA_STATIC_TOOLS

ROOT = Path(__file__).resolve().parents[3]
BENCH = ROOT / 'benchmark'
WEB_TOOLS = ['open_binary', 'list_functions', 'view', 'claim', 'retract', 'blast',
             'why', 'list_holes', 'list_nogoods', 'list_claims', 'complete']


def utc():
    return datetime.now(timezone.utc).isoformat()


def toml(value):
    if isinstance(value, dict):
        return '{' + ', '.join(f'{json.dumps(k)} = {toml(v)}' for k, v in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ', '.join(toml(v) for v in value) + ']'
    return json.dumps(value)


def validate_binary(path: Path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or elf['e_machine'] != 'EM_X86_64' or not elf.little_endian:
            raise ValueError(f'Expected little-endian ELF x86-64: {path}')
        if elf['e_type'] not in ('ET_EXEC', 'ET_DYN'):
            raise ValueError(f'Expected executable/shared ELF: {path}')
        names = [s.name for s in elf.iter_sections()]
        if any(n.startswith(('.debug', '.zdebug')) or n in ('.symtab', '.gnu_debuglink') for n in names):
            raise ValueError(f'Input is not fully stripped: {path}')


def discover(paths, corpus, pattern):
    candidates = [Path(p).expanduser().resolve() for p in paths]
    if corpus:
        candidates += sorted(Path(corpus).expanduser().resolve().glob(pattern))
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        raise ValueError('No input binaries found. Supply original stripped ELF paths or --corpus DIR --pattern GLOB; candidate.elf outputs are not corpus inputs.')
    for p in candidates:
        if p.name in ('candidate.elf', 'oracle.elf'):
            raise ValueError(f'Refusing evaluator output/reference as input: {p}')
        validate_binary(p)
    return candidates


def executable(command):
    found = shutil.which(command)
    if not found:
        raise ValueError(f'Executable not found: {command}')
    return str(Path(found).absolute())


def checked(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, **kwargs)
    if result.returncode:
        raise ValueError(f'{command[0]} failed: {result.stderr[-2000:]}')
    return result.stdout


def evidence(public: Path, args):
    if args.objdump:
        cmd = [executable(args.objdump)]
        version = checked(cmd + ['--version'])
        flags = ['-d', '-s', '-x'] if args.track == 'objdump-complete' else ['-d']
        flags += ['--x86-asm-syntax=intel'] if 'LLVM' in version else ['-M', 'intel']
        text = checked(cmd + flags + ['program.elf'], cwd=public)
        identity = {'kind': 'host_objdump', 'version': version, 'command': cmd + flags + ['program.elf']}
    else:
        executable('docker')
        image = checked(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}']).strip()
        flags = ['-d', '-s', '-x', '-M', 'intel'] if args.track == 'objdump-complete' else ['-d', '-M', 'intel']
        cmd = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
               '-e', 'LC_ALL=C', '-v', f'{public}:/input:ro', args.image, 'objdump']
        version = checked(cmd + ['--version'])
        text = checked(cmd + flags + ['/input/program.elf'])
        identity = {'kind': 'docker_objdump', 'image_id': image, 'version': version, 'flags': flags}
    if not text.strip():
        raise ValueError('objdump returned empty evidence')
    (public / 'program.objdump.txt').write_text(text)
    return identity


def python_server(module, config):
    return {'command': sys.executable, 'args': ['-m', module, str(config)],
            'env': {'PYTHONPATH': str(ROOT / 'src')}, 'cwd': str(config.parent),
            'startup_timeout_sec': 120, 'tool_timeout_sec': 360, 'required': True}


def make_servers(scratch: Path, run: Path, condition: str, args):
    common = {'public_root': str(scratch / 'public'), 'artifacts': str(run / 'artifacts'),
              'events': str(run / 'common-events.jsonl'),
              'budget_path': str(scratch / 'budget.sqlite'), 'max_calls': args.max_tool_calls,
              'build_image': None if args.no_build else args.image}
    save(scratch / 'common.json', common)
    servers = {'benchmark': python_server('asmwebir.benchmark.tools', scratch / 'common.json')}
    if condition == 'raw':
        return servers
    relay = {'cwd': str(scratch / 'public'), 'binary': str(scratch / 'public/program.elf'),
             'events': str(run / 'analysis-events.jsonl'), 'max_calls': args.max_tool_calls,
             'budget_path': str(scratch / 'budget.sqlite')}
    if condition == 'webasmir':
        relay.update(command=[sys.executable, '-m', 'asmwebir.mcp_server'], tools=WEB_TOOLS,
                     env={'PYTHONPATH': str(ROOT / 'src')})
    else:
        if not args.rea_config:
            raise ValueError('REA condition requires --rea-config JSON (pinned command, skill, provider and static tools)')
        rea = json.loads(Path(args.rea_config).read_text())
        command = rea['command']
        if not isinstance(command, list) or not command or not all(isinstance(v, str) for v in command):
            raise ValueError('REA command must be a nonempty argv array')
        command = [executable(command[0]), *command[1:]]
        selected = rea.get('tools', ['open_binary', 'list_procedures', 'analyze_function', 'close_binary'])
        if not selected or not set(selected) <= REA_STATIC_TOOLS or 'open_binary' not in selected:
            raise ValueError('REA tool selection must include open_binary and use only the static tool allowlist')
        if not rea.get('provider_id'):
            raise ValueError('Pin REA provider_id in its configuration')
        skill_root = Path(rea['skill']).expanduser().resolve().parent
        skill = skill_root / 'SKILL.md'
        if not skill.is_file():
            raise ValueError(f'REA skill missing: {skill}')
        (scratch / 'public/condition-skill.md').write_bytes(skill.read_bytes())
        references = skill_root / 'references'
        if references.is_dir():
            for file in references.rglob('*.md'):
                if file.is_symlink() or not file.resolve().is_relative_to(skill_root):
                    raise ValueError('REA references must stay inside the skill directory')
                target = scratch / 'public/references' / file.relative_to(references)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(file.read_bytes())
        relay.update(command=command, tools=selected, env=rea.get('env', {}), provider_id=rea['provider_id'])
    save(scratch / 'relay.json', relay)
    servers['analysis'] = python_server('asmwebir.benchmark.relay', scratch / 'relay.json')
    return servers


async def smoke(servers, run: Path, open_binary=False):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    snapshots = {}
    for name, cfg in servers.items():
        params = StdioServerParameters(command=cfg['command'], args=cfg['args'], env=cfg['env'], cwd=cfg['cwd'])
        with (run / f'{name}-preflight.stderr').open('w') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = (await session.initialize()).model_dump(by_alias=True)
                    listed = (await session.list_tools()).model_dump(by_alias=True)
                    snapshots[name] = {'initialize': initialized, 'tools': listed}
                    names = {t['name'] for t in listed['tools']}
                    if name == 'analysis':
                        if 'open_binary' not in names or len(names) < 2:
                            raise ValueError('Analysis backend did not advertise usable native tools')
                        if open_binary:
                            result = (await session.call_tool('open_binary', {'path': '/input/program.elf'})).model_dump(by_alias=True)
                            if result.get('isError'):
                                raise ValueError(f'Backend open_binary failed: {result}')
                            snapshots[name]['open_binary'] = result
                    else:
                        result = (await session.call_tool('read_evidence', {'limit': 80})).model_dump(by_alias=True)
                        if result.get('isError'):
                            raise ValueError('Common evidence tools failed preflight')
    save(run / 'mcp-preflight.json', snapshots)
    return snapshots


def policy_args(servers, scratch: Path, reasoning):
    disabled = ['shell_tool', 'multi_agent', 'multi_agent_v2', 'goals', 'apps', 'plugins',
                'hooks', 'browser_use', 'computer_use', 'image_generation', 'view_image',
                'skill_search', 'skill_mcp_dependency_install']
    command = list(itertools.chain.from_iterable(('--disable', name) for name in disabled))
    command += ['--enable', 'skip_host_skill_discovery']
    values = {'web_search': 'disabled', 'approval_policy': 'never', 'agents.enabled': False,
              'memories.use_memories': False, 'memories.generate_memories': False,
              'history.persistence': 'none', 'sqlite_home': str(scratch / 'sqlite'),
              'model_reasoning_effort': reasoning, 'mcp_servers': servers,
              'model_auto_compact_token_limit': 1_000_000_000}
    for key, value in values.items():
        command += ['-c', f'{key}={toml(value)}']
    return command


def auth_home(scratch, args):
    if not args.bench_home:
        raise ValueError('Provide --bench-home with a dedicated Codex home containing auth.json')
    source = Path(args.bench_home).expanduser().resolve() / 'auth.json'
    if not source.is_file():
        raise ValueError(f'Authentication file missing: {source}. Authenticate the dedicated home first.')
    # Keep OAuth refresh updates in the dedicated authentication home. Runtime
    # SQLite state is temporary; exec ignores this home's config/rules/skills.
    return {**os.environ, 'CODEX_HOME': str(source.parent)}


def make_prompt(public, condition, snapshots, args):
    prompt = (BENCH / 'prompts/launch.md').read_text()
    prompt += '\n\nCase contract:\n' + (public / 'case.txt').read_text()
    prompt += '\n\nType output schema:\n' + (public / 'types.schema.json').read_text()
    prompt += f'\n\nLimits: {args.timeout} seconds; {args.max_tool_calls} shared tool calls. '
    prompt += 'Submit artifacts before the deadline. '
    prompt += 'Compiler feedback is available (three attempts).' if not args.no_build else 'Compiler feedback is unavailable in this run profile.'
    if condition != 'raw':
        prompt += '\n\nCondition guidance:\n' + (public / 'condition-skill.md').read_text()
        prompt += '\n\nThe analysis server is registered as analysis. Open /input/program.elf. '
        prompt += 'Read skill references through benchmark.read_evidence using references/<relative-name>.\n'
        if snapshots:
            prompt += '\nServer instructions:\n' + (snapshots['analysis']['initialize'].get('instructions') or '')
    return prompt


def run_trial(binary, model, condition, repetition, args):
    run_id = uuid.uuid4().hex
    run = Path(args.output).expanduser().resolve() / 'runs' / run_id
    run.mkdir(parents=True)
    (run / 'artifacts').mkdir()
    manifest = {'run_id': run_id, 'started_utc': utc(), 'binary_path': str(binary),
                'binary_sha256': digest(binary), 'model': model, 'condition': condition,
                'repetition': repetition, 'track': args.track, 'reasoning': args.reasoning,
                'profile': 'codex-cli-static-v1', 'timeout_seconds': args.timeout,
                'max_tool_calls': args.max_tool_calls, 'compiler_feedback': not args.no_build,
                'status': 'STARTED', 'accuracy': None}
    manifest['packages'] = {name: importlib.metadata.version(name)
                            for name in ('asmwebir', 'angr', 'egglog', 'mcp')}
    started = time.monotonic()
    save(run / 'manifest.json', manifest)
    status = 'FAILED'
    try:
        with tempfile.TemporaryDirectory(prefix='asmwebir-trial-') as tmp:
            scratch = Path(tmp)
            public = scratch / 'public'
            public.mkdir()
            (scratch / 'work').mkdir()
            shutil.copyfile(binary, public / 'program.elf')
            shutil.copyfile(BENCH / 'schemas/types.schema.json', public / 'types.schema.json')
            contract = Path(args.case_contract).read_text() if args.case_contract else (
                'Recover the whole program and its existing main entry point. No separate input grammar or public tests are supplied. Infer inputs from the binary. This is a legacy corpus trial, not hidden-test semantic validation.')
            (public / 'case.txt').write_text(contract)
            prep_start = time.monotonic()
            manifest['evidence_tool'] = evidence(public, args)
            manifest['preparation_seconds'] = time.monotonic() - prep_start
            if condition == 'webasmir':
                shutil.copyfile(BENCH / 'skills/webasmir-recovery/SKILL.md', public / 'condition-skill.md')
            servers = make_servers(scratch, run, condition, args)
            if condition != 'raw':
                backend = json.loads((scratch / 'relay.json').read_text())
                manifest['analysis_backend'] = {key: backend[key] for key in ('command', 'tools', 'provider_id') if key in backend}
                manifest['analysis_backend']['environment_keys'] = sorted(backend.get('env', {}))
            snapshots = None
            if not args.prepare_only:
                snapshots = asyncio.run(asyncio.wait_for(smoke(servers, run, args.check), timeout=480))
                # Preflight processes are disposable; actual model run gets a fresh store/budget.
                for filename in ('common-events.jsonl', 'analysis-events.jsonl'):
                    if (run / filename).exists():
                        (run / filename).rename(run / ('preflight-' + filename))
                for file in scratch.glob('budget.sqlite*'):
                    file.unlink()
                if not args.no_build:
                    manifest['compiler_image_id'] = checked(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}']).strip()
            prompt = make_prompt(public, condition, snapshots, args)
            (run / 'prompt.txt').write_text(prompt)
            shutil.copytree(public, run / 'public')
            manifest['public_hashes'] = {str(f.relative_to(public)): digest(f) for f in sorted(public.rglob('*')) if f.is_file()}
            manifest['prompt_sha256'] = digest(run / 'prompt.txt')
            manifest['source_hashes'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted((ROOT / 'src/asmwebir').rglob('*.py'))}
            manifest['git_commit'] = checked(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip()
            manifest['git_dirty'] = bool(checked(['git', 'status', '--porcelain'], cwd=ROOT).strip())
            if args.prepare_only:
                status = 'PREPARED'
            else:
                codex = executable(args.codex)
                manifest['codex_version'] = checked([codex, '--version']).strip()
                env = auth_home(scratch, args)
                policy = policy_args(servers, scratch, args.reasoning)
                doctor = checked([codex, '--strict-config', *policy, 'doctor', '--json'], env=env, cwd=scratch / 'work')
                report = json.loads(doctor)
                if any(report.get('checks', {}).get(k, {}).get('status') != 'ok' for k in ('config.load', 'auth.credentials')):
                    raise ValueError('Codex config/authentication preflight failed; run codex doctor in your dedicated home')
                if args.check:
                    status = 'CHECKED'
                else:
                    command = [codex, 'exec', '--model', model, '--ephemeral', '--ignore-user-config',
                               '--ignore-rules', '--skip-git-repo-check', '--sandbox', 'read-only',
                               '--strict-config', *policy, '-C', str(scratch / 'work'), '--json',
                               '--output-last-message', str(run / 'final-response.txt'), '-']
                    save(run / 'command.json', command)
                    with (run / 'prompt.txt').open() as inp, (run / 'trace.jsonl').open('w') as trace, (run / 'codex.stderr').open('w') as err:
                        code, timeout, seconds = run_process(command, env=env, cwd=scratch / 'work', timeout=args.timeout,
                                                            stdin=inp, stdout=trace, stderr=err)
                    manifest.update(exit_code=code, timed_out=timeout, model_wall_seconds=seconds)
                    metrics = trace_metrics(run / 'trace.jsonl', servers)
                    metrics.update(tool_metrics(run))
                    metrics['end_to_end_work_seconds'] = manifest['preparation_seconds'] + seconds
                    status = 'TIMEOUT' if timeout else 'MODEL_FAILED' if code or metrics['failure_events'] else 'SUBMITTED'
                    if status == 'SUBMITTED' and (metrics['prohibited_tool_events'] or metrics['invalid_trace_lines'] or metrics['analysis_protocol_errors']):
                        status = 'INVALID_TRACE'
                    missing = [n for n in ('recovered.c', 'types.json', 'notes.md') if not (run / 'artifacts' / n).is_file()]
                    if status == 'SUBMITTED' and (missing or not (run / 'artifacts/recovered.c').stat().st_size):
                        status = 'INCOMPLETE'
                    metrics['missing_artifacts'] = missing
                    save(run / 'metrics.json', metrics)
    except KeyboardInterrupt:
        status = 'CANCELLED'
        raise
    except Exception as exc:
        (run / 'error.txt').write_text(f'{type(exc).__name__}: {exc}\n')
        print(f'{run_id}: {exc}', file=sys.stderr)
    finally:
        manifest.update(status=status, finished_utc=utc(), total_wall_seconds=time.monotonic() - started)
        manifest['artifact_hashes'] = {p.name: digest(p) for p in (run / 'artifacts').iterdir() if p.is_file()}
        save(run / 'manifest.json', manifest)
        (run / 'status.txt').write_text(status + '\n')
        if not (run / 'metrics.json').exists():
            save(run / 'metrics.json', trace_metrics(run / 'trace.jsonl'))
        with (run.parent.parent / 'manifest.jsonl').open('a') as out:
            import fcntl
            fcntl.flock(out, fcntl.LOCK_EX)
            out.write(json.dumps(manifest) + '\n')
    print(f'{status}: {model or "prepare"} / {condition} / repeat {repetition}: {run}', flush=True)
    return status in ('PREPARED', 'CHECKED', 'SUBMITTED')


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binaries', nargs='*')
    p.add_argument('--config', type=Path, help='JSON defaults; explicit CLI options take precedence')
    p.add_argument('--corpus', help='Directory containing original stripped input ELFs')
    p.add_argument('--pattern', default='**/stripped.elf')
    p.add_argument('--model', action='append', dest='models', help='Repeat for multiple exact Codex-accessible model IDs')
    p.add_argument('--conditions', default='raw,webasmir')
    p.add_argument('--repeats', type=int, default=1)
    p.add_argument('--reasoning', default='high')
    p.add_argument('--output', default=str(ROOT / 'results/benchmark'))
    p.add_argument('--bench-home')
    p.add_argument('--codex', default='codex')
    p.add_argument('--image', default='type-recovery-bench:ubuntu22.04')
    p.add_argument('--objdump', help='Use an explicitly selected host objdump instead of Docker')
    p.add_argument('--track', choices=['asm-only', 'objdump-complete'], default='objdump-complete')
    p.add_argument('--rea-config', help='JSON with command argv, skill path, provider_id, optional static tools/env')
    p.add_argument('--case-contract', help='Public input contract text; never an oracle/source file')
    p.add_argument('--timeout', type=int, default=1200)
    p.add_argument('--max-tool-calls', type=int, default=120)
    p.add_argument('--seed', type=int, default=20261112)
    p.add_argument('--no-build', action='store_true', help='Disable compiler feedback uniformly in all conditions')
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--prepare-only', action='store_true', help='Prepare evidence/prompts without starting Codex or MCP backends')
    modes.add_argument('--check', action='store_true', help='Preflight auth/tools and open a binary without a model request')
    preliminary, _ = p.parse_known_args(argv)
    if preliminary.config:
        defaults = json.loads(preliminary.config.read_text())
        keys = {a.dest for a in p._actions} - {'config', 'help', 'binaries'}
        if set(defaults) - keys:
            p.error('Unknown configuration keys: ' + ', '.join(sorted(set(defaults) - keys)))
        # argparse append retains defaults; explicit --model must replace config's list.
        if any(v == '--model' or v.startswith('--model=') for v in (argv if argv is not None else sys.argv[1:])):
            defaults.pop('models', None)
        p.set_defaults(**defaults)
    args = p.parse_args(argv)
    if not isinstance(args.conditions, str):
        p.error('conditions must be a comma-separated string')
    if args.models is not None and (not isinstance(args.models, list) or not all(isinstance(m, str) and m.strip() for m in args.models)):
        p.error('models must be a list of nonempty model IDs')
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in (args.repeats, args.timeout, args.max_tool_calls)):
        p.error('Repeats, timeout, and tool budget must be integers')
    args.conditions = args.conditions.split(',')
    if not args.conditions or set(args.conditions) - {'raw', 'rea', 'webasmir'}:
        p.error('--conditions must contain raw, rea, and/or webasmir')
    if min(args.repeats, args.timeout, args.max_tool_calls) < 1:
        p.error('Repeats, timeout, and tool budget must be positive')
    if not args.models and not args.prepare_only and not args.check:
        p.error('At least one --model is required for real runs')
    if args.prepare_only and args.check:
        p.error('Choose either --prepare-only or --check')
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        binaries = discover(args.binaries, args.corpus, args.pattern)
        jobs = list(itertools.product(binaries, args.models or [None], args.conditions, range(1, args.repeats + 1)))
        random.Random(args.seed).shuffle(jobs)
        if args.check:
            jobs = [(binaries[0], (args.models or [None])[0], c, 1) for c in args.conditions]
        print(f'{len(binaries)} binaries; {len(jobs)} scheduled trials; no model requests' if args.prepare_only or args.check else f'{len(binaries)} binaries; {len(jobs)} model trials')
        good = True
        for binary, model, condition, repetition in jobs:
            good = run_trial(binary, model, condition, repetition, args) and good
        return 0 if good else 1
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
