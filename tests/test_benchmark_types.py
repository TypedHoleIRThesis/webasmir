"""Method-neutral graph matching, denominators, schema semantics, and DWARF pairing."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from asmwebir.benchmark.common import digest, save
from asmwebir.benchmark.dwarf_types import load_gold
from asmwebir.benchmark.type_metrics import evaluate_types, score, validate
from asmwebir.benchmark.evaluate import main
from .conftest import FIX

ROOT = Path(__file__).resolve().parents[1]
I32 = {'kind': 'integer', 'bits': 32, 'signed': True}
VOID = {'kind': 'void'}
UNKNOWN = {'kind': 'unknown'}


def ptr(node):
    return {'kind': 'pointer', 'to': deepcopy(node)}


def document(recursive=True):
    named = {'kind': 'named', 'id': 'Node'}
    return {'schema_version': 1, 'functions': [
        {'address': '0x401000', 'arity': 1, 'parameters': [{'index': 0, 'type': ptr(named)}], 'return': deepcopy(I32)}],
        'aggregates': [{'id': 'Node', 'kind': 'struct', 'size_bytes': 16, 'fields': [
            {'offset_bytes': 0, 'type': ptr(named) if recursive else {'kind': 'integer', 'bits': 64, 'signed': True}},
            {'offset_bytes': 8, 'type': deepcopy(I32)}]}]}


def pct(result, name):
    return result['metrics'][name]['pct']


def test_recursive_graph_names_and_order_do_not_matter():
    gold = document()
    prediction = deepcopy(gold)
    prediction['functions'][0]['parameters'][0]['type']['to']['id'] = 'InventedName'
    prediction['aggregates'][0]['id'] = 'InventedName'
    prediction['aggregates'][0]['fields'][0]['type']['to']['id'] = 'InventedName'
    prediction['aggregates'][0]['fields'].reverse()
    result = score(validate(prediction), gold)
    assert pct(result, 'reference_exact_accuracy') == 100
    assert pct(result, 'prototype_reference_exact') == 100
    assert result['field_layout']['f1_pct'] == 100


def test_unknown_sign_is_not_exact_but_structure_is_correct():
    gold = document()
    prediction = deepcopy(gold)
    prediction['aggregates'][0]['fields'][1]['type']['signed'] = None
    result = score(validate(prediction), gold)
    assert pct(result, 'reference_exact_accuracy') == 50
    assert pct(result, 'structural_accuracy_sign_ignored') == 100
    assert pct(result, 'prototype_reference_exact') == 0
    assert result['field_layout']['f1_pct'] == 100


def test_omitted_and_unknown_entities_keep_fixed_denominator():
    gold = document()
    prediction = {'schema_version': 1, 'functions': [], 'aggregates': []}
    result = score(validate(prediction), gold)
    assert result['counts']['missing_entities'] == 2
    assert pct(result, 'prediction_coverage') == 0
    assert pct(result, 'reference_exact_accuracy') == 0
    assert result['field_layout']['precision_pct'] is None
    assert result['field_layout']['recall_pct'] == 0
    assert result['field_layout']['f1_pct'] == 0
    prediction = deepcopy(gold)
    prediction['functions'][0]['parameters'][0]['type'] = UNKNOWN
    result = score(validate(prediction), gold)
    assert pct(result, 'prediction_coverage') == 50
    assert result['counts']['unknown_entities'] == 1
    assert pct(result, 'pointer_class_accuracy') == 50


def test_missing_pointee_and_wrong_pointer_depth():
    gold = document()
    prediction = deepcopy(gold)
    prediction['functions'][0]['parameters'][0]['type'] = ptr(UNKNOWN)
    result = score(validate(prediction), gold)
    assert pct(result, 'prediction_coverage') == 100
    assert pct(result, 'kind_width_accuracy') == 100
    assert pct(result, 'pointer_depth_accuracy') == 0
    prediction['functions'][0]['parameters'][0]['type'] = ptr(ptr({'kind': 'named', 'id': 'Node'}))
    result = score(validate(prediction), gold)
    assert pct(result, 'pointer_depth_accuracy') == 0
    assert result['field_layout']['f1_pct'] == 0


def test_extra_field_reduces_precision_and_exactness():
    gold = document()
    prediction = deepcopy(gold)
    prediction['aggregates'][0]['fields'].append({'offset_bytes': 12, 'type': deepcopy(I32)})
    result = score(validate(prediction), gold)
    assert result['field_layout']['precision_pct'] == pytest.approx(200/3)
    assert result['field_layout']['recall_pct'] == 100
    assert result['field_layout']['f1_pct'] == 80
    assert pct(result, 'reference_exact_accuracy') == 50


def test_union_overlap_is_counted_as_multiset():
    gold = document(False)
    aggregate = gold['aggregates'][0]
    aggregate.update(kind='union', size_bytes=4, fields=[{'offset_bytes':0,'type':deepcopy(I32)},
                                                      {'offset_bytes':0,'type':dict(I32, signed=False)}])
    prediction = deepcopy(gold)
    prediction['aggregates'][0]['fields'].pop()
    result = score(validate(prediction), gold)
    assert result['field_layout']['gold'] == 2
    assert result['field_layout']['predicted'] == 1
    assert result['field_layout']['recall_pct'] == 50


@pytest.mark.parametrize('mutation,message', [
    ('duplicate_function', 'canonical function'), ('duplicate_aggregate', 'aggregate ID'),
    ('duplicate_parameter', 'parameter index'), ('dangling', 'Dangling'),
    ('out_of_range', 'outside'), ('cycle', 'by-value'), ('extent', 'beyond'), ('overlap', 'Overlapping')])
def test_semantic_validation(mutation, message):
    prediction = document()
    function, aggregate = prediction['functions'][0], prediction['aggregates'][0]
    if mutation == 'duplicate_function':
        prediction['functions'].append(dict(function, address='0x0401000'))
    elif mutation == 'duplicate_aggregate':
        prediction['aggregates'].append(deepcopy(aggregate))
    elif mutation == 'duplicate_parameter':
        function['parameters'].append(deepcopy(function['parameters'][0]))
    elif mutation == 'dangling':
        function['parameters'][0]['type']['to']['id'] = 'missing'
    elif mutation == 'out_of_range':
        function['arity'] = 0
    elif mutation == 'cycle':
        aggregate['fields'][0]['type'] = {'kind':'named', 'id':'Node'}
    elif mutation == 'extent':
        aggregate['size_bytes'] = 8
    elif mutation == 'overlap':
        aggregate['fields'][1]['offset_bytes'] = 4
    with pytest.raises(ValueError, match=message):
        validate(prediction)


def test_unsupported_layout_not_silently_correct():
    gold = document()
    gold['aggregates'][0]['unsupported'] = ['bitfield']
    result = score(document(), gold)
    assert result['counts']['unsupported_exact_entities'] == 1
    assert result['counts']['unsupported_layout_roots'] == 1
    assert result['field_layout']['f1_pct'] is None
    assert result['metrics']['reference_exact_accuracy']['total'] == 1  # only int return
    assert 'prototype_reference_exact' not in result['metrics']


def test_real_dwarf_matches_only_same_build():
    gold = load_gold(ROOT / 'hand_example/tiny.O1.dbg', ROOT / 'hand_example/tiny.O1.stripped')
    assert len(gold['functions']) == 3
    main = next(f for f in gold['functions'] if f['name'] == 'main')
    assert main['arity'] == 2 and main['parameters'][1]['type']['kind'] == 'pointer'
    aggregate = gold['aggregates'][0]
    assert aggregate['size_bytes'] == 16
    assert [f['offset_bytes'] for f in aggregate['fields']] == [0, 8]
    with pytest.raises(ValueError, match='does not match'):
        load_gold(ROOT / 'hand_example/tiny.O0.dbg', ROOT / 'hand_example/tiny.O1.stripped')


def test_real_recursive_dwarf_roundtrip():
    gold = load_gold(FIX / 'running_example.O1.dbg', FIX / 'running_example.O1.stripped')
    prediction = {'schema_version':1, 'functions':[], 'aggregates':[]}
    for function in gold['functions']:
        prediction['functions'].append({k: deepcopy(function[k]) for k in ['address','arity','return']})
        prediction['functions'][-1]['parameters'] = [{k:deepcopy(p[k]) for k in ['index','type']} for p in function['parameters']]
    for aggregate in gold['aggregates']:
        prediction['aggregates'].append({k:deepcopy(aggregate[k]) for k in ['id','kind','size_bytes','fields']})
    result = score(validate(prediction), gold)
    assert pct(result, 'reference_exact_accuracy') == 100
    assert result['field_layout']['f1_pct'] == 100


def test_invalid_prediction_scores_zero_and_cli_needs_no_docker(tmp_path):
    run = tmp_path / 'run'
    (run / 'public').mkdir(parents=True)
    (run / 'artifacts').mkdir()
    binary = ROOT / 'hand_example/tiny.O1.stripped'
    (run / 'public/program.elf').write_bytes(binary.read_bytes())
    (run / 'artifacts/types.json').write_text('{"bad":"schema"}')
    save(run / 'manifest.json', {'status':'SUBMITTED', 'model':'test', 'condition':'raw', 'reasoning':'medium',
         'track':'objdump-complete', 'binary_path':str(binary), 'binary_sha256':digest(binary),
         'artifact_hashes':{'types.json':digest(run / 'artifacts/types.json')}})
    (run / 'trace.jsonl').write_text('{"type":"turn.completed","usage":{}}\n')
    report = tmp_path / 'report'
    assert main(['--types-only', '--runs', str(run), '--output', str(report), '--image', 'nonexistent-image']) == 0
    metrics = json.loads((report / 'details/run/type-metrics.json').read_text())
    assert metrics['status'] == 'INVALID_PREDICTION'
    assert pct(metrics, 'reference_exact_accuracy') == 0
    assert metrics['counts']['gold_entities'] == 7
    assert metrics['counts']['missing_entities'] == 7


def test_multidimensional_array_layout_and_count():
    gold = document(False)
    matrix = {'kind':'array', 'count':2, 'of':{'kind':'array', 'count':3, 'of':deepcopy(I32)}}
    gold['aggregates'][0].update(size_bytes=24, fields=[{'offset_bytes':0,'type':matrix}])
    result = score(validate(deepcopy(gold)), gold)
    assert result['field_layout']['gold'] == 6
    assert result['field_layout']['f1_pct'] == 100
    prediction = deepcopy(gold)
    prediction['aggregates'][0]['fields'][0]['type']['count'] = 1
    result = score(validate(prediction), gold)
    assert result['field_layout']['recall_pct'] == 50
