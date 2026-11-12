"""Stdio MCP relay: restrict tools/target, preserve messages, log full calls.

This is a tool/target boundary, not an OS sandbox for the analysis backend.
Only trusted, pinned static-analysis backends belong in its configuration.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import time

from .common import consume_budget

# These tools inspect the active native binary/evidence; no script/runtime tools.
REA_STATIC_TOOLS = {
    'open_binary', 'close_binary', 'binary_session', 'binary_overview',
    'list_procedures', 'procedure_info', 'analyze_function', 'pseudocode',
    'assembly', 'xrefs', 'callers', 'callees', 'read_bytes', 'list_strings',
    'list_names', 'inspect_analysis_view',
}


def guard_call(message: dict, config: dict) -> dict:
    params = message.get('params', {})
    name = params.get('name')
    if name not in config['tools']:
        raise ValueError('Tool is outside this benchmark condition')
    if name == 'open_binary':
        arguments = dict(params.get('arguments') or {})
        if arguments.get('path') not in ('/input/program.elf', config['binary']):
            raise ValueError('Only /input/program.elf is available in this trial')
        if set(arguments) - {'path', 'provider_id'}:
            raise ValueError('Only path and the configured provider are accepted when opening a benchmark target')
        arguments['path'] = config['binary']
        if config.get('provider_id'):
            arguments['provider_id'] = config['provider_id']
        elif 'provider_id' in arguments:
            raise ValueError('No provider selector is supported for this backend')
        message = {**message, 'params': {**params, 'arguments': arguments}}
    return message


async def relay(config: dict):
    env = {**os.environ, **config.get('env', {})}
    child = await asyncio.create_subprocess_exec(*config['command'], env=env,
        cwd=config['cwd'], stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=sys.stderr, limit=16 * 1024 * 1024)
    pending = {}
    tool_gate = asyncio.Lock()
    log = Path(config['events']).open('a', buffering=1)

    def emit(message):
        sys.stdout.write(json.dumps(message, ensure_ascii=False) + '\n')
        sys.stdout.flush()

    def record(event):
        log.write(json.dumps({'monotonic_ns': time.monotonic_ns(), **event}, ensure_ascii=False) + '\n')

    async def requests():
        reader = asyncio.StreamReader(limit=16 * 1024 * 1024)
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        while line := await reader.readline():
            message = json.loads(line)
            method = message.get('method')
            if method not in ('initialize', 'ping', 'tools/list', 'tools/call',
                              'notifications/initialized', 'notifications/cancelled'):
                if 'id' in message:
                    emit({'jsonrpc': '2.0', 'id': message['id'], 'error': {
                        'code': -32601, 'message': 'Method is outside the benchmark interface'}})
                continue
            if method == 'tools/call':
                await tool_gate.acquire()
                try:
                    consume_budget(config)
                    message = guard_call(message, config)
                except ValueError as exc:
                    tool_gate.release()
                    record({'event': 'rejected', 'request': message, 'error': str(exc)})
                    emit({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {
                        'isError': True, 'content': [{'type': 'text', 'text': str(exc)}]}})
                    continue
            if 'id' in message and method:
                pending[message['id']] = (time.monotonic(), message)
            child.stdin.write(json.dumps(message).encode() + b'\n')
            await child.stdin.drain()
        child.stdin.close()

    async def responses():
        while line := await child.stdout.readline():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                record({'event': 'protocol_error', 'line': line.decode(errors='replace')})
                raise RuntimeError('Backend emitted non-JSON stdout')
            started, request = pending.pop(message.get('id'), (None, {}))
            method = request.get('method')
            if method == 'tools/call':
                tool_gate.release()
            if method == 'tools/list' and 'result' in message:
                message['result']['tools'] = [t for t in message['result'].get('tools', [])
                                              if t['name'] in config['tools']]
            if method:
                record({'event': method, 'request': request, 'response': message,
                        'seconds': time.monotonic() - started})
            emit(message)

    tasks = [asyncio.create_task(requests()), asyncio.create_task(responses())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if child.returncode is None:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), 2)
            except asyncio.TimeoutError:
                child.kill()
                await child.wait()
        log.close()


if __name__ == '__main__':
    asyncio.run(relay(json.loads(Path(sys.argv[1]).read_text())))
