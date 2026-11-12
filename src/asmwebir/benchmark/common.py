"""Shared serialization, process cleanup, and CLI trace metrics."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def stop_group(proc: subprocess.Popen) -> None:
    # Always clean the group, even if the CLI exited leaving an MCP child alive.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_process(command, *, cwd=None, env=None, timeout=60, stdin=None,
                stdout=None, stderr=None):
    started = time.monotonic()
    proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=stdin,
                            stdout=stdout, stderr=stderr, start_new_session=True)
    timed_out = False
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        code = -signal.SIGTERM
    finally:
        stop_group(proc)
    return code, timed_out, time.monotonic() - started


def trace_metrics(path: Path, allowed_servers=('benchmark', 'analysis')) -> dict:
    """Codex turn.completed usage is aggregate turn usage, NOT peak context."""
    usage = []
    bad_lines = 0
    failures = 0
    prohibited = []
    tools = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            bad_lines += 1
            continue
        if not isinstance(event, dict):
            bad_lines += 1
            continue
        if event.get('type') == 'turn.completed':
            usage.append(event.get('usage') or {})
        if event.get('type') in ('turn.failed', 'error'):
            failures += 1
        item = event.get('item') or {}
        if not isinstance(item, dict):
            bad_lines += 1
            continue
        if event.get('type') != 'item.completed':
            continue
        kind = item.get('type')
        if kind == 'mcp_tool_call':
            key = f"{item.get('server', '?')}.{item.get('tool', '?')}"
            tools[key] = tools.get(key, 0) + 1
            if item.get('server') not in allowed_servers:
                prohibited.append(item.get('id', key))
        elif kind in ('command_execution', 'file_change', 'web_search',
                       'image_generation', 'computer_use', 'collab_tool_call'):
            prohibited.append(item.get('id', kind))
    def total(key):
        return sum(u[key] for u in usage) if usage and all(isinstance(u.get(key), int) for u in usage) else None
    return {
        'input_tokens': total('input_tokens'),
        'output_tokens': total('output_tokens'),
        'cached_input_tokens': total('cached_input_tokens'),
        'reasoning_output_tokens': total('reasoning_output_tokens'),
        'usage_records': usage,
        'usage_source': 'codex_turn_completed',
        'peak_context_tokens': None,
        'peak_context_unavailable_reason': 'CLI turn usage aggregates internal requests; it is not per-request context.',
        'served_model': None,
        'model_request_count': None,
        'accuracy': None,
        'tool_calls': tools,
        'invalid_trace_lines': bad_lines,
        'failure_events': failures,
        'prohibited_tool_events': prohibited,
    }


def tool_metrics(run: Path) -> dict:
    result = {}
    for kind in ('common', 'analysis'):
        path = run / f'{kind}-events.jsonl'
        records = []
        invalid = 0
        for line in path.read_text().splitlines() if path.exists() else []:
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError('Expected event object')
                records.append(record)
            except ValueError:
                invalid += 1
        result[f'{kind}_invalid_event_lines'] = invalid
        calls = [r for r in records if kind == 'common' or r.get('event') == 'tools/call']
        result[f'{kind}_calls'] = len(calls)
        result[f'{kind}_seconds'] = sum(r.get('seconds', 0) for r in calls)
        result[f'{kind}_result_bytes'] = sum(len(json.dumps(r.get('result', r.get('response')), ensure_ascii=False).encode()) for r in calls)
        if kind == 'analysis':
            result['analysis_rejections'] = sum(r.get('event') == 'rejected' for r in records)
            result['analysis_protocol_errors'] = sum(r.get('event') == 'protocol_error' for r in records)
    return result


def consume_budget(config: dict) -> None:
    """An atomic shared counter across the common-tools process and MCP relay."""
    import sqlite3
    with sqlite3.connect(config['budget_path'], timeout=10) as db:
        db.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY, used INTEGER NOT NULL)')
        db.execute('INSERT OR IGNORE INTO budget VALUES (1, 0)')
        db.execute('UPDATE budget SET used = used + 1 WHERE id = 1')
        used = db.execute('SELECT used FROM budget WHERE id = 1').fetchone()[0]
    if used > config['max_calls']:
        raise ValueError('Shared tool-call budget exhausted; submit using the remaining response only')
