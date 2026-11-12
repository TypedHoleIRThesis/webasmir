"""Bounded evidence/artifact tools; no generic filesystem or shell interface."""
from __future__ import annotations

import argparse
import functools
import json
from pathlib import Path
import tempfile
import threading
import time

from ..mcp_server import _Server
from .common import consume_budget, digest, run_process

ARTIFACTS = {'recovered.c', 'types.json', 'notes.md'}


def create_server(config: dict):
    root = Path(config['public_root']).resolve()
    output = Path(config['artifacts']).resolve()
    output.mkdir(parents=True, exist_ok=True)
    event_path = Path(config['events'])
    call_lock = threading.Lock()
    server = _Server('benchmark', instructions='Read bounded binary evidence and submit recovery artifacts.', log_level='WARNING')

    def tool(fn):
        @functools.wraps(fn)
        def logged(*args, **kwargs):
            with call_lock:
                return invoke(*args, **kwargs)

        def invoke(*args, **kwargs):
            start = time.monotonic()
            error = None
            result = None
            try:
                consume_budget(config)
                result = fn(*args, **kwargs)
                return result
            except Exception as exc:
                error = str(exc)
                raise
            finally:
                with event_path.open('a') as log:
                    log.write(json.dumps({'tool': fn.__name__, 'arguments': kwargs,
                        'seconds': time.monotonic() - start, 'error': error,
                        'result': result}, ensure_ascii=False) + '\n')
        server.add_tool(logged)
        return logged

    def source(name):
        allowed = {'program.objdump.txt', 'types.schema.json', 'case.txt'}
        if name not in allowed and not name.startswith('references/'):
            raise ValueError('Only evidence, schema, case contract, and supplied references are readable')
        p = (root / name).resolve()
        if not p.is_relative_to(root) or not p.is_file():
            raise ValueError('Unknown public evidence file')
        return p

    @tool
    def read_evidence(name: str = 'program.objdump.txt', offset: int = 0, limit: int = 12000) -> str:
        """Read a character slice. Response includes total length and next offset; maximum 24000 chars."""
        if offset < 0 or not 1 <= limit <= 24000:
            raise ValueError('offset >= 0 and 1 <= limit <= 24000 required')
        text = source(name).read_text()
        return json.dumps({'text': text[offset:offset+limit], 'total_chars': len(text),
                           'next_offset': min(offset + limit, len(text))})

    @tool
    def search_evidence(query: str, name: str = 'program.objdump.txt', offset: int = 0) -> str:
        """Literal case-sensitive search; at most 30 matching line snippets from a character offset."""
        if not query or len(query) > 500 or offset < 0:
            raise ValueError('Provide a bounded nonempty query and nonnegative offset')
        text = source(name).read_text()
        hits = []
        pos = offset
        while len(hits) < 30:
            pos = text.find(query, pos)
            if pos < 0:
                break
            hits.append({'offset': pos, 'text': text[max(0, pos-100):pos+300]})
            pos += len(query)
        return json.dumps({'matches': hits, 'next_offset': pos if len(hits) == 30 else None})

    @tool
    def read_bytes(offset: int, size: int = 256) -> str:
        """Read up to 4096 bytes at a file offset in the assigned ELF; returns hex."""
        if offset < 0 or not 1 <= size <= 4096:
            raise ValueError('Invalid byte range')
        with (root / 'program.elf').open('rb') as f:
            f.seek(offset)
            return f.read(size).hex()

    @tool
    def write_artifact(name: str, content: str) -> str:
        """Replace recovered.c, types.json, or notes.md with the supplied exact contents."""
        if name not in ARTIFACTS or len(content.encode()) > 2_000_000:
            raise ValueError('Invalid artifact name or artifact exceeds 2 MB')
        (output / name).write_text(content)
        return f'saved {name}, sha256={digest(output / name)}'

    @tool
    def read_artifact(name: str, offset: int = 0, limit: int = 12000) -> str:
        """Read a bounded slice of a submitted artifact."""
        if name not in ARTIFACTS or offset < 0 or not 1 <= limit <= 24000:
            raise ValueError('Invalid artifact or range')
        return (output / name).read_text()[offset:offset+limit]

    if config.get('build_image'):
        builds = 0

        @tool
        def build_candidate() -> str:
            """Compile submitted C in Linux Docker; at most three attempts. Does not execute it."""
            nonlocal builds
            if builds >= 3:
                raise ValueError('Build attempt budget exhausted')
            builds += 1
            candidate = output / 'recovered.c'
            if not candidate.is_file():
                raise ValueError('Submit recovered.c first')
            with tempfile.TemporaryDirectory(prefix='asmwebir-compile-') as tmp:
                staged = Path(tmp)
                (staged / 'recovered.c').write_bytes(candidate.read_bytes())
                diagnostics = staged / 'diagnostics.txt'
                container = 'asmwebir-build-' + staged.name.rsplit('-', 1)[-1]
                command = ['docker', 'run', '--rm', '--name', container, '--platform', 'linux/amd64',
                    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                    '--memory', '512m', '--cpus', '1', '--ulimit', 'fsize=1048576:1048576',
                    '--tmpfs', '/tmp:rw,size=128m', '-v', f'{staged}:/input:ro',
                    config['build_image'], 'gcc', '-std=gnu11', '-O0',
                    '/input/recovered.c', '-o', '/tmp/candidate', '-lm']
                try:
                    with diagnostics.open('w') as log:
                        code, timeout, seconds = run_process(command, timeout=45, stdout=log, stderr=log)
                finally:
                    import subprocess
                    subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=15)
                return json.dumps({'compiled': code == 0 and not timeout, 'exit_code': code,
                    'timed_out': timeout, 'seconds': seconds,
                    'source_sha256': digest(candidate),
                    'diagnostics': diagnostics.read_text(errors='replace')[:12000]})

    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    create_server(json.loads(args.config.read_text())).run()


if __name__ == '__main__':
    main()
