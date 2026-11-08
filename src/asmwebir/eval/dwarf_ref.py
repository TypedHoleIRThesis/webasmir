"""DWARF reference types (the proposal's "reference types, not ground truth").

Reads the debug build of a benchmark program and returns, per function address,
its parameter and return types in a normalised symbolic form:

    ("int", bits, "s"|"u") ("flt", bits) ("ptr", T) ("void",)
    ("struct", name, size, ((off, name, T), ...)) ("union", name, size, members)
    ("arr", T, n) ("enum", bits) ("fn",) ("unknown",)

typedef / const / volatile are stripped. Recursive structs are cut with a
("ref", name) node.
"""
from __future__ import annotations

from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


@dataclass
class RefFunction:
    name: str
    addr: int
    params: list[tuple[str, tuple]]
    ret: tuple


def load_reference(path: str) -> dict[int, RefFunction]:
    out: dict[int, RefFunction] = {}
    with open(path, "rb") as fp:
        elf = ELFFile(fp)
        if not elf.has_dwarf_info():
            return out
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                addr = die.attributes["DW_AT_low_pc"].value
                origin = _origin(die)  # out-of-line copies of inlined/optimised functions
                name = _name(origin)
                params = []
                for ch in die.iter_children():
                    if ch.tag == "DW_TAG_formal_parameter":
                        o = _origin(ch)
                        params.append((_name(o), norm(_type_die(o))))
                if not params and origin is not die:
                    params = [(_name(ch), norm(_type_die(ch))) for ch in origin.iter_children()
                              if ch.tag == "DW_TAG_formal_parameter"]
                ret = norm(_type_die(origin)) if "DW_AT_type" in origin.attributes else ("void",)
                out[addr] = RefFunction(name, addr, params, ret)
    return out


def _origin(die):
    """Follow DW_AT_abstract_origin / DW_AT_specification to the DIE holding names and types."""
    for _ in range(4):
        for attr in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if attr in die.attributes:
                die = die.get_DIE_from_attribute(attr)
                break
        else:
            return die
    return die


def _name(die) -> str:
    a = die.attributes.get("DW_AT_name")
    return a.value.decode() if a else ""


def _type_die(die):
    if "DW_AT_type" not in die.attributes:
        return None
    return die.get_DIE_from_attribute("DW_AT_type")


def norm(die, seen: frozenset = frozenset()) -> tuple:
    if die is None:
        return ("void",)
    tag = die.tag
    if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type", "DW_TAG_atomic_type"):
        return norm(_type_die(die), seen)
    if tag == "DW_TAG_base_type":
        size = die.attributes["DW_AT_byte_size"].value
        enc = die.attributes["DW_AT_encoding"].value
        if enc == 0x04:  # DW_ATE_float
            return ("flt", size * 8)
        signed = enc in (0x05, 0x06, 0x0D)  # signed, signed_char, signed_fixed
        if enc == 0x02:  # boolean
            signed = False
        return ("int", size * 8, "s" if signed else "u")
    if tag == "DW_TAG_pointer_type":
        return ("ptr", norm(_type_die(die), seen))
    if tag == "DW_TAG_enumeration_type":
        return ("enum", die.attributes["DW_AT_byte_size"].value * 8)
    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
        name = _name(die) or f"anon_{die.offset:x}"
        kind = "struct" if tag == "DW_TAG_structure_type" else "union"
        if die.offset in seen:
            return ("ref", name)
        size = die.attributes.get("DW_AT_byte_size")
        members = []
        for ch in die.iter_children():
            if ch.tag != "DW_TAG_member":
                continue
            off = ch.attributes.get("DW_AT_data_member_location")
            o = off.value if off is not None and isinstance(off.value, int) else 0
            members.append((o, _name(ch), norm(_type_die(ch), seen | {die.offset})))
        return (kind, name, size.value if size else 0, tuple(members))
    if tag == "DW_TAG_array_type":
        n = 0
        for ch in die.iter_children():
            if ch.tag == "DW_TAG_subrange_type":
                ub = ch.attributes.get("DW_AT_upper_bound") or ch.attributes.get("DW_AT_count")
                if ub is not None and isinstance(ub.value, int):
                    n = ub.value + (1 if "DW_AT_upper_bound" in ch.attributes else 0)
        return ("arr", norm(_type_die(die), seen), n)
    if tag == "DW_TAG_subroutine_type":
        return ("fn",)
    return ("unknown",)


def kind(t: tuple) -> tuple[int, str]:
    """(size in bytes, class) the machine sees for a reference type."""
    tag = t[0]
    if tag == "int":
        return t[1] // 8, "int"
    if tag == "enum":
        return t[1] // 8, "int"
    if tag == "flt":
        return t[1] // 8, "flt"
    if tag == "ptr" or tag == "fn":
        return 8, "ptr"
    if tag in ("struct", "union"):
        return t[2], "agg"
    if tag == "arr":
        k = kind(t[1])
        return k[0] * t[2], "agg"
    return 0, "⊤"


def ptr_level(t: tuple) -> int:
    n = 0
    while t[0] == "ptr":
        n += 1
        t = t[1]
    return n


def flat_layout(t: tuple, base: int = 0, depth: int = 0) -> set[tuple[int, int]]:
    """(offset, size) of every scalar leaf of a struct/union/array (nested flattened)."""
    out: set[tuple[int, int]] = set()
    if depth > 4:
        return out
    if t[0] in ("struct", "union"):
        for o, _, mt in t[3]:
            out |= flat_layout(mt, base + o, depth + 1)
    elif t[0] == "arr" and t[2] and t[2] <= 64:
        size, _ = kind(t[1])
        for i in range(t[2]):
            out |= flat_layout(t[1], base + i * size, depth + 1)
    else:
        size, _ = kind(t)
        if size:
            out.add((base, size))
    return out
