"""a call through a module's import stub, written as C++ that makes the same call: the function's
exact name from the module's import table, its parameters from the executable's exported
names (signatures.csv), its declaration from its class's header or written in place.

used by tools/tiny.py. what it takes: a member function of a class (called through a pointer
cast to the class, the header included) or a function of a namespace (declared in the file),
whose parameters are built-in types or pointers to classes (declared ahead, or their header
included when they are nested). what it leaves (Skip): constructors, destructors, operators,
templates, references, floats, classes or enums by value, names without a signature.
"""
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

BUILTIN = {"void", "bool", "char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int",
           "long", "unsigned long", "long long", "unsigned long long", "wchar_t"}
_sig = _classes = _exports = None


class Unsupported(Exception):
    pass


def tables():
    global _sig, _classes, _exports
    if _sig is None:
        _sig = {}
        with open(config.CONFIG / "signatures.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                _sig[r["mangled"]] = (r["demangled"], int(r["address"], 16))
        _classes = set()
        with open(config.CONFIG / "classes.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                _classes.add(r["class"])
        # classes the exports show (a constructor, a destructor or a const member function)
        for demangled, _ in _sig.values():
            if "(" in demangled and "<" not in demangled:
                cls, _, last = demangled[:demangled.index("(")].rpartition("::")
                if cls and (last.lstrip("~") == cls.rsplit("::", 1)[-1] or demangled.endswith(" const")):
                    _classes.add(cls)
    return _sig, _classes


def header_of(cls):
    """the header that declares a class: its own, or its outermost enclosing class's."""
    _, classes = tables()
    parts = cls.split("::")
    for k in range(1, len(parts) + 1):
        outer = "::".join(parts[:k])
        if outer in classes:
            path = Path(*parts[:k - 1], parts[k - 1] + ".h")
            if (config.ROOT / "include" / path).exists():
                return path.as_posix(), k == len(parts)
            return None, False
    return None, False


def split_params(inner):
    out, depth, start = [], 0, 0
    for j, c in enumerate(inner):
        depth += c in "(<"
        depth -= c in ")>"
        if c == "," and depth == 0:
            out.append(inner[start:j].strip())
            start = j + 1
    if inner.strip():
        out.append(inner[start:].strip())
    return out


class Import:
    """one imported function: how many registers its call passes, and how to write it."""

    def __init__(self, mangled):
        sig, classes = tables()
        if not mangled.startswith("_Z") or mangled not in sig:
            raise Unsupported("no signature")
        demangled, self.address = sig[mangled]
        if "<" in demangled or "operator" in demangled or not demangled.endswith((")", ") const")):
            raise Unsupported("template or operator")
        self.const = demangled.endswith(" const")
        text = demangled[:-6] if self.const else demangled
        open_at = text.index("(")
        qual, inner = text[:open_at], text[open_at + 1:-1]
        owner, _, self.name = qual.rpartition("::")
        if owner and self.name.lstrip("~") == owner.rsplit("::", 1)[-1]:
            raise Unsupported("constructor or destructor")
        self.member = owner in classes
        if owner and not self.member and any("::".join(owner.split("::")[:k]) in classes for k in range(1, owner.count("::") + 2)):
            raise Unsupported("in a class without a header")
        self.owner, self.qual = owner, qual
        self.params, self.decls, self.includes = [], [], set()
        for p in split_params(inner):
            if p == "void":
                continue
            self.params.append(self.param(p))
        self.args = len(self.params) + (1 if self.member else 0)
        self.void_member = False
        if self.member:
            path, own = header_of(owner)
            if not path:
                raise Unsupported("no header for the class")
            self.includes.add(path)
            line = next((l for l in (config.ROOT / "include" / path).read_text(encoding="utf-8", errors="replace").splitlines()
                         if f"code.bin:{self.address:08X}" in l and f" {self.name}(" in l), None)
            if line is None:
                raise Unsupported("not declared in its header")
            self.void_member = bool(re.match(r"\s*(?:(?:static|virtual|inline)\s+)*void\s", line))

    def param(self, p):
        if "&" in p or "float" in p or "double" in p:
            raise Unsupported("reference or float parameter")
        base = " ".join(re.sub(r"\bconst\b|\*", " ", p).split())
        if base in BUILTIN:
            return p
        if "*" not in p or not re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", base):
            raise Unsupported("a class or enum by value")
        _, classes = tables()
        path, own = header_of(base)
        if path:
            self.includes.add(path)
        elif base in classes or "::" not in base or not any(
                "::".join(base.split("::")[:k]) in classes for k in range(1, base.count("::") + 1)):
            parts = base.split("::")
            self.decls.append("".join(f"namespace {n} {{ " for n in parts[:-1]) + f"class {parts[-1]};"
                              + " }" * (len(parts) - 1))
        else:
            raise Unsupported("a nested class without a header")
        return re.sub(r"(?<![\w:])(" + re.escape(base) + r")\b", r"::\1", p)

    def declarations(self):
        """the lines a file needs before the call: includes, forward declarations, the
        declaration of a namespace's function."""
        out = [f'#include "{h}"' for h in sorted(self.includes)] + self.decls
        if not self.member:
            parts = self.qual.split("::")
            out.append("".join(f"namespace {n} {{ " for n in parts[:-1]) + f"u32 {parts[-1]}({', '.join(self.params)});"
                       + " }" * (len(parts) - 1))
        return out

    def call(self, args):
        """the call's text, args: the registers' expressions as numbers, r0 first."""
        if len(args) != self.args:
            raise Unsupported("arguments")
        if self.member:
            this, rest = args[0], args[1:]
            casted = [f"({t})({a})" for t, a in zip(self.params, rest)]
            return f"((::{self.owner} *)({this}))->{self.name}({', '.join(casted)})"
        casted = [f"({t})({a})" for t, a in zip(self.params, args)]
        return f"::{self.qual}({', '.join(casted)})"


_cache = {}


def resolve(image, stub):
    """the Import of the stub at stub in a module's image, or raises Unsupported."""
    key = (image.name, stub)
    if key not in _cache:
        loaded = image.reloc(stub + 4) if image.word(stub) == 0xE51FF004 else None
        if not loaded or loaded[0] != "name" or loaded[1][1] != 0:
            _cache[key] = Unsupported("not an import stub")
        else:
            try:
                _cache[key] = Import(loaded[1][0])
            except Unsupported as why:
                _cache[key] = why
    if isinstance(_cache[key], Exception):
        raise _cache[key]
    return _cache[key]
