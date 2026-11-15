"""Score submitted type graphs by binary identity, independently of analysis tools."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from elftools.common.exceptions import ELFError, DWARFError

from .common import digest, save
from .dwarf_types import load_gold

UNKNOWN = {'kind': 'unknown'}
SCHEMA = Path(__file__).resolve().parents[3] / 'benchmark/schemas/types.schema.json'


def graphs(document):
    return {a['id']: a for a in document['aggregates']}


def resolved(node, graph):
    return graph[node['id']] if node['kind'] == 'named' else node


def size(node, graph, seen=frozenset()):
    kind = node['kind']
    if kind == 'named':
        if node['id'] in seen:
            raise ValueError('Illegal by-value recursive aggregate')
        return graph[node['id']]['size_bytes']
    if kind in ('integer', 'float'):
        return node['bits'] // 8 if node['bits'] % 8 == 0 else None
    if kind == 'pointer':
        return 8
    if kind == 'array':
        width = size(node['of'], graph, seen)
        return width * node['count'] if width is not None and node['count'] is not None else None
    return 0 if kind == 'void' else None


def validate(document):
    errors = sorted(Draft202012Validator(json.loads(SCHEMA.read_text())).iter_errors(document), key=lambda e: str(e.path))
    if errors:
        raise ValueError('Invalid types.json schema: ' + errors[0].message[:400])
    graph = graphs(document)
    if len(graph) != len(document['aggregates']):
        raise ValueError('Duplicate aggregate ID')
    addresses = [int(f['address'], 16) for f in document['functions']]
    if len(addresses) != len(set(addresses)):
        raise ValueError('Duplicate canonical function address')

    def check(node, visiting=frozenset(), behind_pointer=False):
        kind = node['kind']
        if kind == 'named':
            identifier = node['id']
            if identifier not in graph:
                raise ValueError('Dangling named aggregate reference')
            if identifier in visiting:
                raise ValueError('Illegal by-value recursive aggregate')
            if not behind_pointer:
                for field in graph[identifier]['fields']:
                    check(field['type'], visiting | {identifier})
        elif kind == 'pointer':
            # Verify references, but pointer edges break by-value cycles.
            check(node['to'], frozenset(), behind_pointer=True)
        elif kind == 'array':
            if node['of']['kind'] == 'void':
                raise ValueError('Array of void')
            check(node['of'], visiting, behind_pointer)

    for aggregate in graph.values():
        check({'kind': 'named', 'id': aggregate['id']})
        spans = []
        for field in aggregate['fields']:
            node, offset = field['type'], field['offset_bytes']
            if node['kind'] == 'void':
                raise ValueError('Void aggregate member')
            width = size(node, graph)
            total = aggregate['size_bytes']
            if total is not None and (offset > total or (width is not None and offset + width > total)):
                raise ValueError('Field extends beyond declared aggregate size')
            if width:
                if aggregate['kind'] == 'struct' and any(offset < end and start < offset + width for start, end in spans):
                    raise ValueError('Overlapping struct members; use union for overlapping fields')
                spans.append((offset, offset + width))
    for function in document['functions']:
        indices = [p['index'] for p in function['parameters']]
        if len(indices) != len(set(indices)):
            raise ValueError('Duplicate parameter index')
        if function['arity'] is not None and any(i >= function['arity'] for i in indices):
            raise ValueError('Parameter index outside declared arity')
        for param in function['parameters']:
            if param['type']['kind'] == 'void':
                raise ValueError('Void parameter')
            check(param['type'])
        check(function['return'])
    return document


def supported(node, graph, seen=frozenset()):
    kind = node['kind']
    if kind in ('unknown', 'unsupported'):
        return False
    if kind == 'named':
        if node['id'] in seen:
            return True
        aggregate = graph[node['id']]
        return (not aggregate.get('unsupported') and aggregate['size_bytes'] is not None
                and all(supported(f['type'], graph, seen | {node['id']}) for f in aggregate['fields']))
    if kind == 'pointer':
        return supported(node['to'], graph, seen)
    if kind == 'array':
        return node['count'] is not None and supported(node['of'], graph, seen)
    return True


def equal(pred, gold, pg, gg, signed=True, seen=frozenset()):
    if pred['kind'] in ('unknown', 'unsupported') or gold['kind'] in ('unknown', 'unsupported'):
        return False
    if pred['kind'] != gold['kind']:
        return False
    kind = gold['kind']
    if kind == 'named':
        pair = pred['id'], gold['id']
        if pair in seen:
            return True
        pa, ga = pg[pred['id']], gg[gold['id']]
        if pa['kind'] != ga['kind'] or pa['size_bytes'] != ga['size_bytes'] or pa['size_bytes'] is None or ga.get('unsupported'):
            return False
        remaining = list(pa['fields'])
        for gf in ga['fields']:
            index = next((i for i, pf in enumerate(remaining) if pf['offset_bytes'] == gf['offset_bytes']
                          and equal(pf['type'], gf['type'], pg, gg, signed, seen | {pair})), None)
            if index is None:
                return False
            remaining.pop(index)
        return not remaining
    if kind == 'pointer':
        return equal(pred['to'], gold['to'], pg, gg, signed, seen)
    if kind == 'array':
        return gold['count'] is not None and pred['count'] == gold['count'] and equal(pred['of'], gold['of'], pg, gg, signed, seen)
    if kind in ('integer', 'float'):
        return pred['bits'] == gold['bits'] and (kind == 'float' or not signed or pred['signed'] is not None and pred['signed'] == gold['signed'])
    return kind == 'void'


def pointer_depth(node):
    depth = 0
    while node['kind'] == 'pointer':
        depth += 1
        node = node['to']
    return None if node['kind'] in ('unknown', 'unsupported') else depth


def aggregate_root(node):
    depth = 0
    while node['kind'] == 'pointer':
        depth += 1
        node = node['to']
    return (depth, node['id']) if node['kind'] == 'named' else None


def leaves(node, graph, offset=0, seen=frozenset(), budget=None):
    """Multiset of (offset, byte width, class); preserve overlapping union members."""
    budget = [4096] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError('Layout expansion exceeds 4096 nodes')
    kind = node['kind']
    if kind == 'named':
        if node['id'] in seen:
            raise ValueError('By-value cycle')
        aggregate = graph[node['id']]
        if aggregate.get('unsupported'):
            raise ValueError('Unsupported aggregate layout')
        result = Counter()
        for field in aggregate['fields']:
            result.update(leaves(field['type'], graph, offset + field['offset_bytes'], seen | {node['id']}, budget))
        return result
    if kind == 'array':
        width = size(node['of'], graph)
        if node['count'] is None or width is None or node['count'] > budget[0]:
            raise ValueError('Unknown or excessive array extent')
        result = Counter()
        for i in range(node['count']):
            result.update(leaves(node['of'], graph, offset + width * i, seen, budget))
        return result
    if kind in ('unsupported', 'void'):
        raise ValueError('Unsupported leaf layout')
    return Counter({(offset, size(node, graph), kind): 1})


def score(prediction, gold):
    """Every metric has its own fixed gold denominator and explicit support count."""
    pg, gg = graphs(prediction), graphs(gold)
    predictions = {int(f['address'], 16): f for f in prediction['functions']}
    gold_functions = {int(f['address'], 16): f for f in gold['functions']}
    metrics, entities = {}, []
    counts = {'gold_functions': len(gold_functions), 'unsupported_functions': len(gold.get('excluded_functions', [])),
              'gold_entities': 0, 'missing_entities': 0, 'unknown_entities': 0,
              'unsupported_entity_kinds': 0, 'unsupported_exact_entities': 0,
              'unsupported_layout_roots': 0, 'unknown_prediction_layout_roots': 0,
              'parameters_without_location': 0, 'extra_functions': len(set(predictions) - set(gold_functions))}
    layout = {'true_positive': 0, 'predicted': 0, 'gold': 0, 'roots': 0}

    def add(name, ok):
        metric = metrics.setdefault(name, {'correct': 0, 'total': 0})
        metric['correct'] += int(bool(ok))
        metric['total'] += 1

    for address, function in sorted(gold_functions.items()):
        if function.get('unsupported'):
            counts['unsupported_functions'] += 1
            continue
        pf = predictions.get(address)
        add('function_coverage', pf is not None)
        add('arity_accuracy', pf is not None and pf['arity'] == function['arity'])
        params = {p['index']: p['type'] for p in pf['parameters']} if pf else {}
        pairs = [(f'param:{p["index"]}', params.get(p['index']), p['type']) for p in function['parameters']]
        pairs.append(('return', pf['return'] if pf else None, function['return']))
        counts['parameters_without_location'] += sum(not p.get('has_location', True) for p in function['parameters'])
        exacts, shapes = [], []
        for slot, predicted, reference in pairs:
            counts['gold_entities'] += 1
            missing = predicted is None
            p = predicted or UNKNOWN
            pk, gk = resolved(p, pg)['kind'], resolved(reference, gg)['kind']
            known = pk != 'unknown'
            counts['missing_entities'] += int(missing)
            counts['unknown_entities'] += int(not missing and not known)
            row = {'address': hex(address), 'slot': slot, 'missing': missing, 'prediction': p, 'reference': reference}
            if gk not in ('unsupported', 'unknown'):
                add('prediction_coverage', known)
                add('kind_accuracy', known and pk == gk)
                add('pointer_class_accuracy', known and (pk == 'pointer') == (gk == 'pointer'))
                width = size(reference, gg)
                if width is not None:
                    add('kind_width_accuracy', known and pk == gk and size(p, pg) == width)
                if gk == 'pointer' and pointer_depth(reference) is not None:
                    add('pointer_depth_accuracy', pointer_depth(p) == pointer_depth(reference))
                if gk in ('integer', 'float'):
                    add('primitive_exact_accuracy', equal(p, reference, pg, gg))
                    add('primitive_width_accuracy', equal(p, reference, pg, gg, signed=False))
            else:
                counts['unsupported_entity_kinds'] += 1
            if supported(reference, gg):
                strict, shape = equal(p, reference, pg, gg), equal(p, reference, pg, gg, signed=False)
                add('reference_exact_accuracy', strict)
                add('structural_accuracy_sign_ignored', shape)
                row.update(reference_exact=strict, structural_sign_ignored=shape)
                exacts.append(strict)
                shapes.append(shape)
            else:
                counts['unsupported_exact_entities'] += 1
            root = aggregate_root(reference)
            if root:
                predicted_root = aggregate_root(p)
                ga = gg[root[1]]
                pa = pg[predicted_root[1]] if predicted_root and predicted_root[0] == root[0] else None
                add('aggregate_kind_accuracy', pa is not None and pa['kind'] == ga['kind'])
                if ga['size_bytes'] is not None:
                    add('aggregate_size_accuracy', pa is not None and pa['size_bytes'] == ga['size_bytes'])
                try:
                    want = leaves({'kind': 'named', 'id': root[1]}, gg)
                except ValueError:
                    counts['unsupported_layout_roots'] += 1
                else:
                    try:
                        got = leaves({'kind': 'named', 'id': predicted_root[1]}, pg) if pa else Counter()
                    except ValueError:
                        counts['unknown_prediction_layout_roots'] += 1
                        got = Counter()
                    layout['roots'] += 1
                    layout['gold'] += sum(want.values())
                    layout['predicted'] += sum(got.values())
                    layout['true_positive'] += sum((want & got).values())
            entities.append(row)
        if len(exacts) == len(pairs):
            signature = pf is not None and pf['arity'] == function['arity'] and set(params) == set(range(function['arity']))
            add('prototype_reference_exact', signature and all(exacts))
            add('prototype_structural_sign_ignored', signature and all(shapes))
    for metric in metrics.values():
        metric['pct'] = 100 * metric['correct'] / metric['total'] if metric['total'] else None
    tp, predicted, want = layout['true_positive'], layout['predicted'], layout['gold']
    layout.update(precision_pct=100 * tp / predicted if predicted else None,
                  recall_pct=100 * tp / want if want else None,
                  f1_pct=200 * tp / (predicted + want) if predicted + want else None)
    return {'metrics': metrics, 'counts': counts, 'field_layout': layout, 'entities': entities}


def find_reference(manifest, explicit=None):
    if explicit:
        return Path(explicit).expanduser().resolve()
    binary = Path(manifest['binary_path'])
    candidates = ([binary.with_name('oracle.elf')] if binary.name == 'stripped.elf' else [])
    if binary.suffix == '.stripped':
        candidates.append(binary.with_suffix('.dbg'))
    for path in candidates:
        if path.is_file():
            return path
    raise ValueError('Matching DWARF ELF unavailable; use --reference PATH (full debug ELF, not a detached .debug file)')


def evaluate_types(run, output, explicit=None, force_empty=False):
    """No Docker required. Invalid/missing model predictions score zero on known gold."""
    manifest = json.loads((run / 'manifest.json').read_text())
    detail = output / 'details' / run.name
    detail.mkdir(parents=True, exist_ok=True)
    result = {'profile': 'dwarf-reference-v1', 'status': 'REFERENCE_ERROR', 'included': False}
    try:
        binary = run / 'public/program.elf'
        if digest(binary) != manifest['binary_sha256']:
            raise ValueError('Staged ELF hash mismatch')
        reference = find_reference(manifest, explicit)
        gold = load_gold(reference, binary)
        result.update(reference_path=str(reference), reference_sha256=digest(reference))
        save(detail / 'type-reference.json', gold)
        prediction = {'schema_version': 1, 'functions': [], 'aggregates': []}
        status = 'NO_SUBMISSION' if force_empty else 'SCORED'
        if not force_empty:
            path = run / 'artifacts/types.json'
            if path.is_file():
                if digest(path) != manifest.get('artifact_hashes', {}).get('types.json'):
                    raise ValueError('types.json was changed after submission')
                try:
                    prediction = validate(json.loads(path.read_text()))
                except (ValueError, RecursionError) as exc:
                    status = 'INVALID_PREDICTION'
                    result['prediction_error'] = str(exc)
                    prediction = {'schema_version': 1, 'functions': [], 'aggregates': []}
            else:
                status = 'NO_SUBMISSION'
        result.update(score(prediction, gold), status=status, included=True)
    except (ValueError, OSError, RecursionError, ELFError, DWARFError) as exc:
        result['error'] = str(exc)
    save(detail / 'type-metrics.json', result)
    return result
