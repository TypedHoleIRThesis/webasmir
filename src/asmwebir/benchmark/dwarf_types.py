"""Independent DWARF reference graph; never derives its denominator from a lifter."""
from __future__ import annotations

import hashlib
from pathlib import Path

from elftools.elf.elffile import ELFFile


def allocated_image(path):
    """Debug/stripped companions must contain identical addressed allocated sections."""
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        identity = (elf.elfclass, elf.little_endian, elf['e_machine'], elf['e_type'], elf['e_entry'])
        sections = sorted((s.name, s['sh_addr'], s['sh_size'], s['sh_flags'], s['sh_type'],
                           None if s['sh_type'] == 'SHT_NOBITS' else hashlib.sha256(s.data()).hexdigest())
                          for s in elf.iter_sections() if s['sh_flags'] & 2)
        return identity, sections


def attribute(die, name, visited=None):
    visited = set() if visited is None else visited
    if die.offset in visited:
        return None
    visited.add(die.offset)
    if name in die.attributes:
        return die, die.attributes[name]
    for link in ('DW_AT_abstract_origin', 'DW_AT_specification'):
        if link in die.attributes:
            found = attribute(die.get_DIE_from_attribute(link), name, visited)
            if found:
                return found
    return None


def value(die, name, default=None):
    found = attribute(die, name)
    return found[1].value if found else default


def target(die):
    found = attribute(die, 'DW_AT_type')
    return found[0].get_DIE_from_attribute('DW_AT_type') if found else None


def children(die):
    params = [c for c in die.iter_children() if c.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters')]
    if params:
        return params
    for link in ('DW_AT_abstract_origin', 'DW_AT_specification'):
        if link in die.attributes:
            return children(die.get_DIE_from_attribute(link))
    return []


def load_gold(path, binary):
    if allocated_image(path) != allocated_image(binary):
        raise ValueError('DWARF reference does not match the staged binary allocated image')
    aggregates, functions, excluded = {}, {}, []
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        if elf['e_machine'] != 'EM_X86_64' or elf.elfclass != 64:
            raise ValueError('Type evaluator currently supports x86-64 SysV only')
        if not elf.has_dwarf_info(strict=True):
            raise ValueError('Reference has no DWARF information')
        dwarf = elf.get_dwarf_info()

        def unsupported(reason):
            return {'kind': 'unsupported', 'reason': reason}

        def norm(die, visiting=frozenset()):
            if die is None:
                return {'kind': 'void'}
            tag = die.tag
            if tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                identifier = f'die_{die.offset:x}'
                if identifier not in aggregates:
                    aggregate = {'id': identifier, 'kind': 'struct' if tag == 'DW_TAG_structure_type' else 'union',
                                 'size_bytes': value(die, 'DW_AT_byte_size'), 'fields': [], 'unsupported': []}
                    aggregates[identifier] = aggregate
                    if value(die, 'DW_AT_declaration', False):
                        aggregate['unsupported'].append('incomplete aggregate declaration')
                    for field in die.iter_children():
                        if field.tag == 'DW_TAG_inheritance':
                            aggregate['unsupported'].append('C++ inheritance')
                        if field.tag != 'DW_TAG_member':
                            continue
                        if attribute(field, 'DW_AT_bit_size') or attribute(field, 'DW_AT_data_bit_offset'):
                            aggregate['unsupported'].append('bitfield has no v1 bit-offset representation')
                            continue
                        offset = value(field, 'DW_AT_data_member_location', 0 if aggregate['kind'] == 'union' else None)
                        if not isinstance(offset, int):
                            aggregate['unsupported'].append('nonconstant/missing member location')
                            continue
                        aggregate['fields'].append({'offset_bytes': offset, 'type': norm(target(field))})
                return {'kind': 'named', 'id': identifier}
            if die.offset in visiting:
                return unsupported('recursive non-aggregate type')
            visiting = visiting | {die.offset}
            if tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_restrict_type', 'DW_TAG_atomic_type'):
                return norm(target(die), visiting)
            if tag == 'DW_TAG_pointer_type':
                return {'kind': 'pointer', 'to': norm(target(die), visiting)}
            if tag == 'DW_TAG_base_type':
                size, encoding = value(die, 'DW_AT_byte_size'), value(die, 'DW_AT_encoding')
                if not isinstance(size, int):
                    return unsupported('missing base size')
                if encoding == 4:
                    return {'kind': 'float', 'bits': size * 8}
                if encoding in (2, 5, 6, 7, 8):
                    return {'kind': 'integer', 'bits': size * 8, 'signed': encoding in (5, 6)}
                return unsupported(f'base encoding {encoding}')
            if tag == 'DW_TAG_array_type':
                dimensions = []
                for dimension in die.iter_children():
                    if dimension.tag != 'DW_TAG_subrange_type':
                        continue
                    count = value(dimension, 'DW_AT_count')
                    if count is None:
                        upper, lower = value(dimension, 'DW_AT_upper_bound'), value(dimension, 'DW_AT_lower_bound', 0)
                        count = upper - lower + 1 if isinstance(upper, int) and isinstance(lower, int) else None
                    if count is not None and (not isinstance(count, int) or count < 0):
                        return unsupported('dynamic array bound')
                    dimensions.append(count)
                item = norm(target(die), visiting)
                for count in reversed(dimensions or [None]):
                    item = {'kind': 'array', 'of': item, 'count': count}
                return item
            return unsupported(tag)  # enums, function signatures, vectors, references, etc.

        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_subprogram':
                    continue
                # Only concrete address-bearing definitions, not inline instances/declarations.
                if 'DW_AT_low_pc' not in die.attributes:
                    if 'DW_AT_ranges' in die.attributes:
                        excluded.append({'die': die.offset, 'reason': 'range-only function has no supported entry identity'})
                    continue
                addr = die.attributes['DW_AT_low_pc'].value
                params = children(die)
                function = {'address': hex(addr), 'name': value(die, 'DW_AT_name', b'').decode(errors='replace'),
                            'parameters': [], 'return': norm(target(die)), 'unsupported': []}
                for param in params:
                    if param.tag == 'DW_TAG_unspecified_parameters':
                        function['unsupported'].append('variadic prototype')
                        continue
                    if value(param, 'DW_AT_artificial', False):
                        function['unsupported'].append('artificial/hidden parameter')
                    function['parameters'].append({'index': len(function['parameters']), 'type': norm(target(param)),
                        'has_location': 'DW_AT_location' in param.attributes})
                function['arity'] = len(function['parameters'])
                roots = [p['type'] for p in function['parameters']] + [function['return']]
                if any(t['kind'] in ('named', 'array') for t in roots):
                    function['unsupported'].append('by-value aggregate ABI/sret normalization not implemented')
                if any(t['kind'] == 'unsupported' for t in roots):
                    function['unsupported'].append('unsupported direct ABI type')
                gp = sum(p['type']['kind'] in ('integer', 'pointer') for p in function['parameters'])
                fp = sum(p['type']['kind'] == 'float' for p in function['parameters'])
                if gp > 6 or fp > 8 or any(t.get('bits', 0) > 64 for t in roots):
                    function['unsupported'].append('stack/split-register argument ABI not implemented')
                if addr in functions:
                    function['unsupported'].append('multiple DWARF functions share entry address')
                functions[addr] = function
    if not functions:
        raise ValueError('No concrete DWARF function entries found')
    return {'functions': list(functions.values()), 'aggregates': list(aggregates.values()),
            'excluded_functions': excluded, 'profile': 'dwarf-reference-v1'}
