"""The claim language agents write (Part A, Steps 1-3; E-Claim).

    declare struct Node { 0: next: ptr Node; 8: val: i32 } size 16
    ?T1 = Node                       type equality (a hole, a param, a return...)
    type(param 3 of c4) = u64
    type(ret of c2) = i32
    type(v15 of sub_401136) = i32    a value's type
    name c1 "list_sum"               names for code / data / value webs and params
    name w2 "total"
    name(param 3 of c4) = "len"
    arity c4 = 3                     exact parameter count of a code web

Display names (?T6, #c2, #d1, #w10) are resolved against the view the agent
saw, and stored as stable symbolic references so later renumbering cannot
change what a claim means.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

T = tuple


@dataclass(frozen=True)
class TypeEq:
    a: T
    b: T


@dataclass(frozen=True)
class StructDecl:
    name: str
    fields: tuple[tuple[int, str, T], ...]  # (offset, field name, type)
    size: int | None


@dataclass(frozen=True)
class Name:
    target: tuple  # ("code", fn) | ("web", base-term) | ("value", term) | ("param", fn, i) | ("type", T)
    name: str


@dataclass(frozen=True)
class ArityEq:
    code: str
    n: int


Fact = TypeEq | StructDecl | Name | ArityEq


class ClaimSyntaxError(ValueError):
    pass


class Resolver:
    """Maps display names of a view back to stable references."""

    def __init__(self, namer, snapshot, premises, prog):
        self.n, self.S, self.P, self.prog = namer, snapshot, premises, prog
        self.hole_rep: dict[str, T] = {}
        for t in premises.terms:
            k = snapshot.key(("tv", t))
            self.hole_rep.setdefault(namer.hole(k), ("tv", t)) if k in namer.holes else None
        for base, h in premises.pointers.items():
            k = snapshot.key(("hole", h))
            if k in namer.holes:
                self.hole_rep.setdefault(namer.holes[k], ("hole", h))
        for k, name in namer.holes.items():  # anything else the namer numbered
            if name not in self.hole_rep:
                node = snapshot.node_by_key(k)
                if node.tag == "hole":
                    self.hole_rep[name] = ("hole", node.name)
        self.code_rep = {v: k for k, v in namer.codes.items()}
        self.web_rep = {v: k for k, v in namer.webs.items()}
        self.value_rep = {v: k for k, v in namer.values.items()}

    def code(self, ref: str) -> str:
        ref = ref if ref.startswith("#") else f"#{ref}"
        if ref in self.code_rep:
            return self.code_rep[ref]
        if ref[1:] in self.prog.functions:
            return ref[1:]
        raise ClaimSyntaxError(f"unknown code web {ref}")

    def fn(self, ref: str) -> str:
        if ref in self.prog.functions:
            return ref
        return self.code(ref)


_TY = re.compile(r"\s*(ptr\b|\?T\d+|[iuf](?:8|16|32|64)\b|void\b|[A-Za-z_][A-Za-z0-9_]*)\s*")


def parse_type(text: str, R: Resolver | None, structs: set[str]) -> T:
    text = text.strip()
    arr = re.fullmatch(r"(.+)\[(\d+)\]", text)
    if arr:
        return ("arr", parse_type(arr.group(1), R, structs), int(arr.group(2)))
    if text.startswith("ptr "):
        inner = parse_type(text[4:], R, structs)
        return ("ptr", f"claim:{_slug(text[4:])}", inner)
    m = re.fullmatch(r"([iu])(8|16|32|64)", text)
    if m:
        return ("int", int(m.group(2)), "s" if m.group(1) == "i" else "u")
    m = re.fullmatch(r"f(32|64)", text)
    if m:
        return ("flt", int(m.group(1)))
    if text == "void":
        return ("void",)
    if re.fullmatch(r"\?T\d+", text):
        if R is None or text not in R.hole_rep:
            raise ClaimSyntaxError(f"unknown hole {text}")
        return R.hole_rep[text]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        return ("named", text)
    t = _target_type(text, R)
    if t is not None:
        return t
    raise ClaimSyntaxError(f"cannot parse type {text!r}")


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s.strip())


def _target_type(text: str, R: Resolver | None) -> T | None:
    """`type(param 3 of c4)` / `type(ret of c2)` / `type(v15 of sub_401136)` / `param 3 of c4`."""
    m = re.fullmatch(r"(?:type\()?\s*param\s+(\d+)\s+of\s+(#?\w+)\s*\)?", text)
    if m:
        return ("param", R.code(m.group(2)) if R else m.group(2), int(m.group(1)) - 1)
    m = re.fullmatch(r"(?:type\()?\s*ret\s+of\s+(#?\w+)\s*\)?", text)
    if m:
        return ("ret", R.code(m.group(1)) if R else m.group(1))
    m = re.fullmatch(r"(?:type\()?\s*([av]\d+)\s+of\s+(#?\w+)\s*\)?", text)
    if m:
        fn = R.fn(m.group(2)) if R else m.group(2)
        return ("tv", f"{fn}.{m.group(1)}")
    return None


def parse_claim(text: str, R: Resolver | None, structs: set[str] = frozenset()) -> Fact:
    s = text.strip().rstrip(";")
    m = re.fullmatch(r"declare\s+struct\s+(\w+)\s*\{(.*)\}\s*(?:size\s+(\d+))?", s, re.S)
    if m:
        name, body, size = m.group(1), m.group(2), m.group(3)
        fields = []
        for part in [p.strip() for p in body.split(";") if p.strip()]:
            fm = re.fullmatch(r"(\d+)\s*:\s*(\w+)\s*:\s*(.+)", part)
            if not fm:
                raise ClaimSyntaxError(f"bad field {part!r} (want `off: name: type`)")
            fields.append((int(fm.group(1)), fm.group(2), parse_type(fm.group(3), R, structs | {name})))
        return StructDecl(name, tuple(fields), int(size) if size else None)
    m = re.fullmatch(r"name\s*\(\s*param\s+(\d+)\s+of\s+(#?\w+)\s*\)\s*=\s*\"([^\"]+)\"", s)
    if m:
        return Name(("param", R.code(m.group(2)) if R else m.group(2), int(m.group(1)) - 1), m.group(3))
    m = re.fullmatch(r"name\s+(#?[cdw]\d+|\?T\d+|[av]\d+\s+of\s+#?\w+)\s+\"([^\"]+)\"", s)
    if m:
        return Name(_name_target(m.group(1), R), m.group(2))
    m = re.fullmatch(r"arity\s+(#?c\d+|sub_[0-9a-f]+)\s*=\s*(\d+)", s)
    if m:
        return ArityEq(R.code(m.group(1)) if R else m.group(1), int(m.group(2)))
    m = re.fullmatch(r"(.+?)\s*=\s*(.+)", s)
    if m:
        return TypeEq(parse_type(m.group(1), R, structs), parse_type(m.group(2), R, structs))
    raise ClaimSyntaxError(f"cannot parse claim {text!r}")


def _name_target(ref: str, R: Resolver | None) -> tuple:
    ref = ref.strip()
    if ref.startswith("?T"):
        return ("type", R.hole_rep[ref] if R else ("hole", ref))
    m = re.fullmatch(r"([av]\d+)\s+of\s+(#?\w+)", ref)
    if m:
        fn = R.fn(m.group(2)) if R else m.group(2)
        return ("value", f"{fn}.{m.group(1)}")
    r = ref if ref.startswith("#") else f"#{ref}"
    if r.startswith("#c"):
        return ("code", R.code(r) if R else r)
    if r.startswith("#d"):
        return ("web", R.web_rep[r] if R else r)
    if r.startswith("#w"):
        return ("value", R.value_rep[r] if R else r)
    raise ClaimSyntaxError(f"cannot name {ref}")


def render_fact(f: Fact) -> str:
    if isinstance(f, StructDecl):
        body = "; ".join(f"{o}: {n}: {_rt(t)}" for o, n, t in f.fields)
        return f"declare struct {f.name} {{ {body} }}" + (f" size {f.size}" if f.size else "")
    if isinstance(f, TypeEq):
        return f"{_rt(f.a)} = {_rt(f.b)}"
    if isinstance(f, Name):
        return f"name {f.target} \"{f.name}\""
    if isinstance(f, ArityEq):
        return f"arity {f.code} = {f.n}"
    return str(f)


def _rt(t: T) -> str:
    tag = t[0]
    if tag == "int":
        return f"{'i' if t[2] == 's' else 'u'}{t[1]}"
    if tag == "ptr":
        return f"ptr {_rt(t[2])}"
    if tag == "named":
        return t[1]
    if tag == "arr":
        return f"{_rt(t[1])}[{t[2]}]"
    if tag == "param":
        return f"param {t[2] + 1} of {t[1]}"
    if tag == "ret":
        return f"ret of {t[1]}"
    if tag == "tv":
        fn, v = t[1].split(".", 1)
        return f"{v} of {fn}"
    if tag == "hole":
        return f"?{t[1]}"
    if tag == "flt":
        return f"f{t[1]}"
    return tag
